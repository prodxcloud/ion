//! Task dispatch: read ABI frames, execute, time, emit result frames.
//!
//! ## Framing
//!
//! The ABI header is self-describing, so a stream of tasks needs no envelope:
//!
//! ```text
//! [93-byte task header][payload_len bytes][93-byte task header][payload_len bytes]...
//! ```
//!
//! [`dispatch_loop`] reads exactly that, writes one [`ResultFrame`] per task, and
//! stops cleanly at EOF on a header boundary. A partial header mid-stream is an
//! error, not a clean stop — silently discarding a truncated task would lose work.
//!
//! ## Failure is a result, not an error
//!
//! Once a task header has been decoded, the loop always emits a result frame.
//! A panicking or failing task becomes [`TaskState::Failed`] with the error text
//! as the payload, because a host waiting on a result must not be left waiting
//! because a URL 404'd.
//!
//! ## Payload schema
//!
//! Payloads are JSON, tagged by `op`:
//!
//! ```json
//! {"op": "noop"}
//! {"op": "scrape", "url": "https://example.com", "select": "h1", "mode": "text"}
//! {"op": "fetch_many", "urls": ["https://a", "https://b"], "select": "title"}
//! {"op": "links", "url": "https://example.com"}
//! {"op": "dns_encode", "zone": "example.com.", "name": "h.example.com.",
//!  "ip": "192.0.2.7", "ttl": 60, "action": "add"}
//! ```

use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::abi::{
    AbiError, ResultFrame, Task, TaskHeader, TaskState, VX_TASK_HEADER_SIZE, VxStatus,
};
use crate::config::Config;
use crate::dns::name::Name;
use crate::dns::tsig::to_hex;
use crate::dns::update::UpdateBuilder;
use crate::scrape::{Extract, Page, Scraper, links, select, title};

// ---------------------------------------------------------------------------
// Task payloads
// ---------------------------------------------------------------------------

/// A unit of work, decoded from the task payload.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum TaskSpec {
    /// Do nothing. Used to measure end-to-end dispatch overhead.
    Noop,
    /// Fetch one URL and optionally extract from it.
    Scrape {
        /// The URL to fetch.
        url: String,
        /// A CSS selector to apply. When absent, the body is summarised only.
        #[serde(default)]
        select: Option<String>,
        /// Extraction mode: `text`, `html`, or `attr:<name>`.
        #[serde(default)]
        mode: Option<String>,
    },
    /// Fetch many URLs concurrently, subject to the configured semaphore.
    FetchMany {
        /// The URLs to fetch.
        urls: Vec<String>,
        /// An optional CSS selector applied to each successful response.
        #[serde(default)]
        select: Option<String>,
        /// Extraction mode for `select`.
        #[serde(default)]
        mode: Option<String>,
    },
    /// Fetch one URL and return every link on it, resolved absolutely.
    Links {
        /// The URL to fetch.
        url: String,
    },
    /// Encode an RFC 2136 `UPDATE` packet and return its hex. No network I/O.
    DnsEncode {
        /// The zone to update.
        zone: String,
        /// The name to add or remove.
        name: String,
        /// The address, for `add` and `delete`.
        #[serde(default)]
        ip: Option<String>,
        /// TTL for `add`.
        #[serde(default)]
        ttl: Option<u32>,
        /// `add`, `delete`, or `delete_rrset`.
        #[serde(default)]
        action: Option<String>,
        /// Fixed message id, for reproducible output.
        #[serde(default)]
        id: Option<u16>,
    },
}

/// The JSON body of a successful result frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaskOutput {
    /// Which operation ran.
    pub op: &'static str,
    /// Per-URL fetch summaries, when the operation fetched anything.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pages: Vec<PageSummary>,
    /// Extracted strings, when a selector was supplied.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extracted: Vec<String>,
    /// Hex of an encoded DNS packet, for `dns_encode`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_hex: Option<String>,
    /// Byte length of that packet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_len: Option<usize>,
}

impl TaskOutput {
    /// An output carrying nothing but the operation name.
    #[must_use]
    pub const fn bare(op: &'static str) -> Self {
        Self {
            op,
            pages: Vec::new(),
            extracted: Vec::new(),
            packet_hex: None,
            packet_len: None,
        }
    }
}

/// The metadata retained about one fetched page.
///
/// Deliberately excludes the body: a result frame is a report, not a cache, and
/// echoing megabytes back through the ring would defeat the memory budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PageSummary {
    /// The URL as requested.
    pub url: String,
    /// The URL after redirects, when it differs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    /// HTTP status.
    pub status: u16,
    /// Negotiated protocol version.
    pub version: String,
    /// Bytes retained.
    pub bytes: usize,
    /// Whether the size cap cut the body short.
    pub truncated: bool,
    /// Wall-clock milliseconds.
    pub elapsed_ms: u64,
    /// The document title, when the response was HTML with one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Why this URL failed, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl PageSummary {
    fn from_page(page: &Page) -> Self {
        Self {
            url: page.url.clone(),
            final_url: if page.final_url == page.url {
                None
            } else {
                Some(page.final_url.clone())
            },
            status: page.status,
            version: page.version.clone(),
            bytes: page.body.len(),
            truncated: page.truncated,
            elapsed_ms: page.elapsed_ms,
            title: title(&page.text()),
            error: None,
        }
    }

    fn failed(url: &str, error: &str) -> Self {
        Self {
            url: url.to_owned(),
            final_url: None,
            status: 0,
            version: String::new(),
            bytes: 0,
            truncated: false,
            elapsed_ms: 0,
            title: None,
            error: Some(error.to_owned()),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a task could not be executed, or a stream could not be dispatched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    /// The ABI frame was malformed.
    Abi(AbiError),
    /// The payload was not the JSON the operation expects.
    BadPayload(String),
    /// A scrape operation failed.
    Scrape(String),
    /// A DNS packet could not be built.
    Dns(String),
    /// Reading or writing the task stream failed.
    Io {
        /// What we were doing.
        context: &'static str,
        /// The OS error text.
        detail: String,
    },
    /// The stream ended part-way through a frame.
    TruncatedStream {
        /// Bytes we needed.
        need: usize,
        /// Bytes we got.
        got: usize,
    },
}

impl From<AbiError> for RuntimeError {
    fn from(e: AbiError) -> Self {
        Self::Abi(e)
    }
}

impl core::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Abi(e) => write!(f, "abi: {e}"),
            Self::BadPayload(r) => write!(f, "bad task payload: {r}"),
            Self::Scrape(r) => write!(f, "scrape: {r}"),
            Self::Dns(r) => write!(f, "dns: {r}"),
            Self::Io { context, detail } => write!(f, "{context}: {detail}"),
            Self::TruncatedStream { need, got } => {
                write!(f, "stream ended mid-frame: needed {need} bytes, got {got}")
            }
        }
    }
}

impl std::error::Error for RuntimeError {}

impl RuntimeError {
    /// The ABI status code this maps onto.
    #[must_use]
    pub const fn status(&self) -> VxStatus {
        match self {
            Self::Abi(e) => e.status(),
            Self::BadPayload(_) => VxStatus::InvalidArg,
            Self::Scrape(_) | Self::Dns(_) => VxStatus::InvalidArg,
            Self::Io { .. } | Self::TruncatedStream { .. } => VxStatus::RingEmpty,
        }
    }
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

/// Executes decoded tasks. Holds the HTTP client so a batch reuses connections.
#[derive(Debug, Clone)]
pub struct Executor {
    cfg: Arc<Config>,
    scraper: Scraper,
}

impl Executor {
    /// Build an executor from configuration.
    ///
    /// # Errors
    /// [`RuntimeError::Scrape`] if the HTTP client cannot be constructed.
    pub fn new(cfg: Config) -> Result<Self, RuntimeError> {
        let scraper = Scraper::new(&cfg.http).map_err(|e| RuntimeError::Scrape(e.to_string()))?;
        Ok(Self {
            cfg: Arc::new(cfg),
            scraper,
        })
    }

    /// The configuration this executor was built with.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Run one task and produce the frame the host expects, timing included.
    ///
    /// Never returns an error: a failure becomes a [`TaskState::Failed`] frame
    /// whose payload is the error text.
    pub async fn execute(&self, task: &Task<'_>) -> ResultFrame {
        let started = Instant::now();
        let task_id = task.task_id();

        let outcome = self.run(task.payload).await;
        let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);

        match outcome {
            Ok(output) => {
                let body = serde_json::to_vec(&output).unwrap_or_else(|e| {
                    format!("{{\"error\":\"result serialisation failed: {e}\"}}").into_bytes()
                });
                ResultFrame::new(task_id, TaskState::Completed, 0, duration_us, body)
            }
            Err(e) => ResultFrame::new(
                task_id,
                TaskState::Failed,
                e.status().code(),
                duration_us,
                e.to_string().into_bytes(),
            ),
        }
    }

    /// Decode a payload and dispatch it.
    ///
    /// # Errors
    /// [`RuntimeError::BadPayload`] for malformed JSON, or whatever the chosen
    /// operation fails with.
    pub async fn run(&self, payload: &[u8]) -> Result<TaskOutput, RuntimeError> {
        let spec: TaskSpec =
            serde_json::from_slice(payload).map_err(|e| RuntimeError::BadPayload(e.to_string()))?;
        self.run_spec(&spec).await
    }

    /// Dispatch an already-decoded task.
    ///
    /// # Errors
    /// Whatever the chosen operation fails with.
    pub async fn run_spec(&self, spec: &TaskSpec) -> Result<TaskOutput, RuntimeError> {
        match spec {
            TaskSpec::Noop => Ok(TaskOutput::bare("noop")),

            TaskSpec::Scrape { url, select, mode } => {
                let page = self
                    .scraper
                    .fetch(url)
                    .await
                    .map_err(|e| RuntimeError::Scrape(e.to_string()))?;
                let extracted = match select {
                    Some(css) => {
                        let mode = parse_mode(mode.as_deref())?;
                        select_from(&page, css, &mode)?
                    }
                    None => Vec::new(),
                };
                Ok(TaskOutput {
                    op: "scrape",
                    pages: vec![PageSummary::from_page(&page)],
                    extracted,
                    ..TaskOutput::bare("scrape")
                })
            }

            TaskSpec::FetchMany { urls, select, mode } => {
                let results = self.scraper.fetch_many(urls).await;
                let mode = parse_mode(mode.as_deref())?;
                let mut pages = Vec::with_capacity(results.len());
                let mut extracted = Vec::new();
                for (url, result) in urls.iter().zip(results.iter()) {
                    match result {
                        Ok(page) => {
                            if let Some(css) = select {
                                extracted.extend(select_from(page, css, &mode)?);
                            }
                            pages.push(PageSummary::from_page(page));
                        }
                        Err(e) => pages.push(PageSummary::failed(url, &e.to_string())),
                    }
                }
                Ok(TaskOutput {
                    op: "fetch_many",
                    pages,
                    extracted,
                    ..TaskOutput::bare("fetch_many")
                })
            }

            TaskSpec::Links { url } => {
                let page = self
                    .scraper
                    .fetch(url)
                    .await
                    .map_err(|e| RuntimeError::Scrape(e.to_string()))?;
                let found = links(&page.text(), Some(&page.final_url))
                    .map_err(|e| RuntimeError::Scrape(e.to_string()))?;
                Ok(TaskOutput {
                    op: "links",
                    pages: vec![PageSummary::from_page(&page)],
                    extracted: found,
                    ..TaskOutput::bare("links")
                })
            }

            TaskSpec::DnsEncode {
                zone,
                name,
                ip,
                ttl,
                action,
                id,
            } => {
                let packet = encode_dns_packet(
                    zone,
                    name,
                    ip.as_deref(),
                    ttl.unwrap_or(self.cfg.dns.ttl),
                    action.as_deref().unwrap_or("add"),
                    *id,
                )?;
                Ok(TaskOutput {
                    op: "dns_encode",
                    packet_hex: Some(to_hex(&packet)),
                    packet_len: Some(packet.len()),
                    ..TaskOutput::bare("dns_encode")
                })
            }
        }
    }
}

fn parse_mode(spec: Option<&str>) -> Result<Extract, RuntimeError> {
    Extract::parse(spec.unwrap_or("text")).map_err(|e| RuntimeError::BadPayload(e.to_string()))
}

fn select_from(page: &Page, css: &str, mode: &Extract) -> Result<Vec<String>, RuntimeError> {
    select(&page.text(), css, mode).map_err(|e| RuntimeError::Scrape(e.to_string()))
}

/// Build an `UPDATE` packet for the `dns_encode` operation.
///
/// # Errors
/// [`RuntimeError::Dns`] for a malformed zone, name, address, or action.
pub fn encode_dns_packet(
    zone: &str,
    name: &str,
    ip: Option<&str>,
    ttl: u32,
    action: &str,
    id: Option<u16>,
) -> Result<Vec<u8>, RuntimeError> {
    let zone_name = Name::from_ascii(zone).map_err(|e| RuntimeError::Dns(e.to_string()))?;
    let record_name = Name::from_ascii(name).map_err(|e| RuntimeError::Dns(e.to_string()))?;

    let mut builder = match id {
        Some(fixed) => UpdateBuilder::with_id(zone_name, fixed),
        None => UpdateBuilder::new(zone_name),
    };

    let addr = match ip {
        Some(raw) => Some(
            raw.parse::<std::net::IpAddr>()
                .map_err(|_| RuntimeError::Dns(format!("{raw:?} is not a literal IP address")))?,
        ),
        None => None,
    };

    match action {
        "add" => {
            let addr = addr.ok_or_else(|| RuntimeError::Dns("add requires an ip".to_owned()))?;
            builder
                .add_address(&record_name, ttl, addr)
                .map_err(|e| RuntimeError::Dns(e.to_string()))?;
        }
        "delete" => {
            let addr = addr.ok_or_else(|| RuntimeError::Dns("delete requires an ip".to_owned()))?;
            builder
                .delete_address(&record_name, addr)
                .map_err(|e| RuntimeError::Dns(e.to_string()))?;
        }
        "delete_rrset" => {
            builder
                .delete_all_rrsets(&record_name)
                .map_err(|e| RuntimeError::Dns(e.to_string()))?;
        }
        other => {
            return Err(RuntimeError::Dns(format!(
                "unknown action {other:?} (expected \"add\", \"delete\", or \"delete_rrset\")"
            )));
        }
    }

    builder
        .encode()
        .map_err(|e| RuntimeError::Dns(e.to_string()))
}

// ---------------------------------------------------------------------------
// Dispatch loop
// ---------------------------------------------------------------------------

/// Read task frames from `input`, execute each, write result frames to `output`.
///
/// Returns the number of tasks dispatched. Stops cleanly when `input` reaches EOF
/// on a frame boundary.
///
/// # Errors
/// - [`RuntimeError::Io`] on a read or write failure.
/// - [`RuntimeError::TruncatedStream`] if EOF arrives mid-frame.
/// - [`RuntimeError::Abi`] if a header is structurally invalid — the stream is
///   then desynchronised and cannot safely be resumed.
pub async fn dispatch_loop<R, W>(
    input: &mut R,
    output: &mut W,
    executor: &Executor,
) -> Result<usize, RuntimeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut dispatched = 0usize;
    let mut header_buf = [0u8; VX_TASK_HEADER_SIZE];

    loop {
        match read_exact_or_eof(input, &mut header_buf).await? {
            ReadOutcome::Eof => break,
            ReadOutcome::Partial(got) => {
                return Err(RuntimeError::TruncatedStream {
                    need: VX_TASK_HEADER_SIZE,
                    got,
                });
            }
            ReadOutcome::Full => {}
        }

        let header = TaskHeader::decode(&header_buf)?;
        let payload_len = usize::try_from(header.payload_len).unwrap_or(usize::MAX);
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            match read_exact_or_eof(input, &mut payload).await? {
                ReadOutcome::Full => {}
                ReadOutcome::Eof => {
                    return Err(RuntimeError::TruncatedStream {
                        need: payload_len,
                        got: 0,
                    });
                }
                ReadOutcome::Partial(got) => {
                    return Err(RuntimeError::TruncatedStream {
                        need: payload_len,
                        got,
                    });
                }
            }
        }

        let task = Task {
            header,
            payload: &payload,
        };
        let frame = executor.execute(&task).await;
        output
            .write_all(&frame.encode())
            .await
            .map_err(|e| RuntimeError::Io {
                context: "write result frame",
                detail: e.to_string(),
            })?;
        output.flush().await.map_err(|e| RuntimeError::Io {
            context: "flush result frame",
            detail: e.to_string(),
        })?;
        dispatched += 1;
    }

    Ok(dispatched)
}

/// How a framed read ended.
enum ReadOutcome {
    /// The buffer was filled.
    Full,
    /// Nothing at all was available: a clean stop.
    Eof,
    /// Some bytes arrived and then the stream ended.
    Partial(usize),
}

async fn read_exact_or_eof<R: AsyncRead + Unpin>(
    input: &mut R,
    buf: &mut [u8],
) -> Result<ReadOutcome, RuntimeError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        // `filled < buf.len()` guarantees this slice exists; the `None` arm keeps
        // the function panic-free without an `unwrap`.
        let Some(slice) = buf.get_mut(filled..) else {
            break;
        };
        let n = input.read(slice).await.map_err(|e| RuntimeError::Io {
            context: "read task frame",
            detail: e.to_string(),
        })?;
        if n == 0 {
            return Ok(if filled == 0 {
                ReadOutcome::Eof
            } else {
                ReadOutcome::Partial(filled)
            });
        }
        filled += n;
    }
    Ok(ReadOutcome::Full)
}

/// Build a tokio runtime honouring [`crate::config::RuntimeConfig`].
///
/// Current-thread by default. This is the single most important footprint
/// decision in the crate: the multi-thread scheduler eagerly spawns one worker
/// thread per core, each with its own 2 MiB stack reservation and its own
/// allocator arena, which on a many-core host costs more resident memory than
/// everything `ion` actually does.
///
/// # Errors
/// [`RuntimeError::Io`] if the runtime cannot be created.
pub fn build_tokio_runtime(
    cfg: &crate::config::RuntimeConfig,
) -> Result<tokio::runtime::Runtime, RuntimeError> {
    let mut builder = if cfg.multi_thread {
        let mut b = tokio::runtime::Builder::new_multi_thread();
        if let Some(threads) = cfg.worker_threads {
            b.worker_threads(threads.max(1));
        }
        b
    } else {
        tokio::runtime::Builder::new_current_thread()
    };
    builder.enable_all().build().map_err(|e| RuntimeError::Io {
        context: "build tokio runtime",
        detail: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{Engine, VX_RESULT_HEADER_SIZE};

    fn frame(task_id: u64, payload: &[u8]) -> Vec<u8> {
        let header = TaskHeader::new(
            task_id,
            "acme",
            Engine::Ion,
            8,
            100_000,
            payload.len() as u64,
        )
        .expect("header");
        Task::encode(&header, payload).expect("frame")
    }

    #[tokio::test]
    async fn noop_round_trips_through_the_dispatch_loop() {
        let executor = Executor::new(Config::default()).expect("executor");
        let bytes = frame(11, br#"{"op":"noop"}"#);
        let mut input: &[u8] = &bytes;
        let mut output: Vec<u8> = Vec::new();

        let count = dispatch_loop(&mut input, &mut output, &executor)
            .await
            .expect("dispatch");
        assert_eq!(count, 1);

        let result = ResultFrame::decode(&output).expect("result");
        assert_eq!(result.header.task_id, 11);
        assert_eq!(result.header.state().unwrap(), TaskState::Completed);
        assert_eq!(result.header.exit_code, 0);
        let json: serde_json::Value = serde_json::from_slice(&result.payload).expect("json");
        assert_eq!(json["op"], "noop");
    }

    #[tokio::test]
    async fn several_tasks_stream_back_to_back() {
        let executor = Executor::new(Config::default()).expect("executor");
        let mut bytes = frame(1, br#"{"op":"noop"}"#);
        bytes.extend_from_slice(&frame(2, br#"{"op":"noop"}"#));
        bytes.extend_from_slice(&frame(3, br#"{"op":"noop"}"#));

        let mut input: &[u8] = &bytes;
        let mut output: Vec<u8> = Vec::new();
        let count = dispatch_loop(&mut input, &mut output, &executor)
            .await
            .expect("dispatch");
        assert_eq!(count, 3);

        // Walk the concatenated result frames and check the ids come back in order.
        let mut offset = 0usize;
        for expected_id in [1u64, 2, 3] {
            let slice = output.get(offset..).expect("slice");
            let result = ResultFrame::decode(slice).expect("result");
            assert_eq!(result.header.task_id, expected_id);
            offset += VX_RESULT_HEADER_SIZE + result.payload.len();
        }
        assert_eq!(offset, output.len());
    }

    #[tokio::test]
    async fn a_failing_task_still_produces_a_result_frame() {
        let executor = Executor::new(Config::default()).expect("executor");
        let bytes = frame(9, b"this is not json");
        let mut input: &[u8] = &bytes;
        let mut output: Vec<u8> = Vec::new();
        let count = dispatch_loop(&mut input, &mut output, &executor)
            .await
            .expect("dispatch");
        assert_eq!(count, 1);

        let result = ResultFrame::decode(&output).expect("result");
        assert_eq!(result.header.state().unwrap(), TaskState::Failed);
        assert_eq!(result.header.exit_code, VxStatus::InvalidArg.code());
        let text = String::from_utf8_lossy(&result.payload);
        assert!(text.contains("bad task payload"), "got {text}");
    }

    #[tokio::test]
    async fn empty_input_is_a_clean_stop() {
        let executor = Executor::new(Config::default()).expect("executor");
        let mut input: &[u8] = &[];
        let mut output: Vec<u8> = Vec::new();
        assert_eq!(
            dispatch_loop(&mut input, &mut output, &executor)
                .await
                .unwrap(),
            0
        );
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn a_truncated_header_is_an_error() {
        let executor = Executor::new(Config::default()).expect("executor");
        let full = frame(1, br#"{"op":"noop"}"#);
        let mut input: &[u8] = full.get(..40).expect("prefix");
        let mut output: Vec<u8> = Vec::new();
        assert!(matches!(
            dispatch_loop(&mut input, &mut output, &executor).await,
            Err(RuntimeError::TruncatedStream { .. })
        ));
    }

    #[tokio::test]
    async fn a_truncated_payload_is_an_error() {
        let executor = Executor::new(Config::default()).expect("executor");
        let full = frame(1, br#"{"op":"noop"}"#);
        let cut = full.len() - 4;
        let mut input: &[u8] = full.get(..cut).expect("prefix");
        let mut output: Vec<u8> = Vec::new();
        assert!(matches!(
            dispatch_loop(&mut input, &mut output, &executor).await,
            Err(RuntimeError::TruncatedStream { .. })
        ));
    }

    #[tokio::test]
    async fn dns_encode_runs_entirely_offline() {
        let executor = Executor::new(Config::default()).expect("executor");
        let payload = br#"{"op":"dns_encode","zone":"example.com.",
            "name":"host.example.com.","ip":"192.0.2.7","ttl":60,
            "action":"add","id":4660}"#;
        let output = executor.run(payload).await.expect("run");
        assert_eq!(output.op, "dns_encode");
        assert_eq!(output.packet_len, Some(61));
        let hex = output.packet_hex.expect("hex");
        assert!(hex.starts_with("12342800"), "got {hex}");
        assert!(hex.ends_with("c0000207"), "got {hex}");
    }

    #[test]
    fn dns_encode_rejects_bad_input() {
        assert!(
            encode_dns_packet("example.com.", "h.example.com.", None, 60, "add", None).is_err()
        );
        assert!(
            encode_dns_packet(
                "example.com.",
                "h.example.com.",
                Some("not-an-ip"),
                60,
                "add",
                None
            )
            .is_err()
        );
        assert!(
            encode_dns_packet(
                "example.com.",
                "h.example.com.",
                Some("192.0.2.1"),
                60,
                "sideways",
                None
            )
            .is_err()
        );
        assert!(
            encode_dns_packet(
                "example.com.",
                "h.example.org.",
                Some("192.0.2.1"),
                60,
                "add",
                None
            )
            .is_err(),
            "an out-of-zone name must be refused"
        );
    }

    #[test]
    fn task_specs_deserialise_from_the_documented_json() {
        let noop: TaskSpec = serde_json::from_str(r#"{"op":"noop"}"#).unwrap();
        assert_eq!(noop, TaskSpec::Noop);

        let scrape: TaskSpec =
            serde_json::from_str(r#"{"op":"scrape","url":"https://x","select":"h1"}"#).unwrap();
        assert_eq!(
            scrape,
            TaskSpec::Scrape {
                url: "https://x".to_owned(),
                select: Some("h1".to_owned()),
                mode: None
            }
        );

        let many: TaskSpec =
            serde_json::from_str(r#"{"op":"fetch_many","urls":["a","b"]}"#).unwrap();
        assert!(matches!(many, TaskSpec::FetchMany { .. }));

        assert!(serde_json::from_str::<TaskSpec>(r#"{"op":"teleport"}"#).is_err());
    }

    #[test]
    fn current_thread_is_the_default_runtime() {
        let cfg = crate::config::RuntimeConfig::default();
        assert!(!cfg.multi_thread);
        let rt = build_tokio_runtime(&cfg).expect("runtime");
        rt.block_on(async {});

        let multi = crate::config::RuntimeConfig {
            multi_thread: true,
            worker_threads: Some(2),
        };
        let rt = build_tokio_runtime(&multi).expect("runtime");
        rt.block_on(async {});
    }
}
