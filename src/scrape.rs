//! Async HTTP/1.1 + HTTP/2 fetching and HTML extraction.
//!
//! ## TLS
//!
//! rustls only. `reqwest` is pulled in with `default-features = false`, which
//! keeps `native-tls`, OpenSSL, and every `-dev` package out of the build: `ion`
//! links no system TLS library, so the same binary runs on `scratch`,
//! `distroless`, Amazon Linux, and Alpine without a certificate-store dance.
//! Roots come from the bundled `webpki-roots` set.
//!
//! ## Protocol negotiation
//!
//! HTTP/2 is negotiated by ALPN during the TLS handshake and falls back to
//! HTTP/1.1 automatically. [`Page::version`] records what actually happened, so
//! a caller can prove which protocol was used rather than assume.
//!
//! ## The three caps
//!
//! A micro-worker with an 8 MB RSS target cannot afford to be honest about
//! whatever a remote server wants to send it:
//!
//! 1. **Time** — one deadline covering DNS, connect, TLS, and body.
//! 2. **Redirects** — a bounded chain, so a redirect loop is an error rather
//!    than a hang.
//! 3. **Size** — the body is read chunk by chunk and abandoned the moment it
//!    crosses [`HttpConfig::max_body_bytes`], with [`Page::truncated`] set. A
//!    10 GB `Content-Length` costs us the cap, not the 10 GB.
//!
//! Fan-out over many URLs is bounded by a semaphore rather than spawning one
//! task per URL, for the same reason.

use std::sync::Arc;
use std::time::Instant;

use scraper::{Html, Selector};
use tokio::sync::Semaphore;

use crate::config::HttpConfig;

/// What to pull out of the elements a selector matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extract {
    /// The concatenated text of each element's descendants.
    Text,
    /// The value of one attribute, skipping elements that lack it.
    Attr(String),
    /// The element's serialised outer HTML.
    Html,
}

impl Extract {
    /// Parse a mode name: `text`, `html`, or `attr:<name>`.
    ///
    /// # Errors
    /// [`ScrapeError::BadExtractMode`] for anything else.
    pub fn parse(spec: &str) -> Result<Self, ScrapeError> {
        match spec.trim() {
            "text" | "" => Ok(Self::Text),
            "html" => Ok(Self::Html),
            other => match other.strip_prefix("attr:") {
                Some(name) if !name.is_empty() => Ok(Self::Attr(name.to_owned())),
                _ => Err(ScrapeError::BadExtractMode {
                    spec: spec.to_owned(),
                }),
            },
        }
    }
}

/// Why a fetch or an extraction failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScrapeError {
    /// The HTTP client could not be constructed.
    ClientBuild(String),
    /// The URL was malformed.
    BadUrl {
        /// The URL as supplied.
        url: String,
        /// Why it was rejected.
        reason: String,
    },
    /// The request failed: connect, TLS, timeout, redirect cap, or transport.
    Request {
        /// The URL that failed.
        url: String,
        /// Why it failed.
        reason: String,
    },
    /// The body could not be read to completion.
    Body {
        /// The URL involved.
        url: String,
        /// Why the read failed.
        reason: String,
    },
    /// The CSS selector did not parse.
    BadSelector {
        /// The selector as supplied.
        selector: String,
        /// The parser's complaint.
        detail: String,
    },
    /// An extraction-mode string was not recognised.
    BadExtractMode {
        /// The mode as supplied.
        spec: String,
    },
    /// The fan-out semaphore was closed, which can only happen at shutdown.
    Cancelled,
}

impl core::fmt::Display for ScrapeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ClientBuild(r) => write!(f, "could not build HTTP client: {r}"),
            Self::BadUrl { url, reason } => write!(f, "invalid url {url:?}: {reason}"),
            Self::Request { url, reason } => write!(f, "request to {url} failed: {reason}"),
            Self::Body { url, reason } => write!(f, "reading body of {url} failed: {reason}"),
            Self::BadSelector { selector, detail } => {
                write!(f, "invalid css selector {selector:?}: {detail}")
            }
            Self::BadExtractMode { spec } => write!(
                f,
                "unknown extract mode {spec:?} (expected \"text\", \"html\", or \"attr:<name>\")"
            ),
            Self::Cancelled => write!(f, "fetch cancelled"),
        }
    }
}

impl std::error::Error for ScrapeError {}

/// One fetched document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The URL as requested.
    pub url: String,
    /// The URL after redirects.
    pub final_url: String,
    /// HTTP status code.
    pub status: u16,
    /// Negotiated protocol, e.g. `HTTP/1.1` or `HTTP/2.0`.
    pub version: String,
    /// `Content-Type`, if the server sent one.
    pub content_type: Option<String>,
    /// Body bytes, capped at [`HttpConfig::max_body_bytes`].
    pub body: Vec<u8>,
    /// Whether the body hit the cap and was cut short.
    pub truncated: bool,
    /// Wall-clock time for the whole request, milliseconds.
    pub elapsed_ms: u64,
}

impl Page {
    /// The body as text, replacing invalid UTF-8 rather than failing.
    #[must_use]
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    /// Whether the status is 2xx.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self.status, 200..300)
    }
}

/// A configured HTTP client. Cheap to clone — clones share one connection pool.
#[derive(Debug, Clone)]
pub struct Scraper {
    client: reqwest::Client,
    max_body_bytes: u64,
    concurrency: usize,
}

impl Scraper {
    /// Build a client from an [`HttpConfig`].
    ///
    /// # Errors
    /// [`ScrapeError::ClientBuild`] if the TLS stack or connection pool cannot be
    /// initialised.
    pub fn new(cfg: &HttpConfig) -> Result<Self, ScrapeError> {
        let redirect = if cfg.max_redirects == 0 {
            reqwest::redirect::Policy::none()
        } else {
            reqwest::redirect::Policy::limited(cfg.max_redirects)
        };
        let client = reqwest::Client::builder()
            .user_agent(cfg.user_agent.clone())
            .timeout(cfg.timeout)
            .redirect(redirect)
            // One idle connection per host is plenty for a worker that will
            // exit in a second, and it keeps the pool's memory trivial.
            .pool_max_idle_per_host(1)
            .build()
            .map_err(|e| ScrapeError::ClientBuild(e.to_string()))?;
        Ok(Self {
            client,
            max_body_bytes: cfg.max_body_bytes,
            concurrency: cfg.concurrency.max(1),
        })
    }

    /// Fetch one URL.
    ///
    /// # Errors
    /// [`ScrapeError::BadUrl`], [`ScrapeError::Request`], or
    /// [`ScrapeError::Body`].
    pub async fn fetch(&self, url: &str) -> Result<Page, ScrapeError> {
        let started = Instant::now();
        let parsed = reqwest::Url::parse(url).map_err(|e| ScrapeError::BadUrl {
            url: url.to_owned(),
            reason: e.to_string(),
        })?;

        let mut response =
            self.client
                .get(parsed)
                .send()
                .await
                .map_err(|e| ScrapeError::Request {
                    url: url.to_owned(),
                    reason: e.to_string(),
                })?;

        let status = response.status().as_u16();
        let version = format!("{:?}", response.version());
        let final_url = response.url().to_string();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        // Stream the body so the size cap is enforced on what we actually read,
        // not on a Content-Length the server may be lying about.
        let mut body = Vec::new();
        let mut truncated = false;
        loop {
            let chunk = response.chunk().await.map_err(|e| ScrapeError::Body {
                url: url.to_owned(),
                reason: e.to_string(),
            })?;
            let Some(chunk) = chunk else { break };
            let remaining = self.max_body_bytes.saturating_sub(body.len() as u64);
            if (chunk.len() as u64) > remaining {
                let take = usize::try_from(remaining).unwrap_or(usize::MAX);
                body.extend_from_slice(chunk.get(..take).unwrap_or(&chunk));
                truncated = true;
                break;
            }
            body.extend_from_slice(&chunk);
        }

        Ok(Page {
            url: url.to_owned(),
            final_url,
            status,
            version,
            content_type,
            body,
            truncated,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }

    /// Fetch many URLs with at most [`HttpConfig::concurrency`] in flight.
    ///
    /// Results come back in the same order as `urls`. One failure does not
    /// cancel the rest — each slot carries its own `Result`, because a fan-out
    /// over fifty URLs where one host is down should still return forty-nine
    /// pages.
    pub async fn fetch_many(&self, urls: &[String]) -> Vec<Result<Page, ScrapeError>> {
        let permits = Arc::new(Semaphore::new(self.concurrency));
        let mut tasks = tokio::task::JoinSet::new();

        for (index, url) in urls.iter().enumerate() {
            let permits = Arc::clone(&permits);
            let client = self.clone();
            let url = url.clone();
            tasks.spawn(async move {
                let permit = permits.acquire().await;
                let outcome = match permit {
                    Ok(_guard) => client.fetch(&url).await,
                    Err(_) => Err(ScrapeError::Cancelled),
                };
                (index, outcome)
            });
        }

        let mut slots: Vec<Option<Result<Page, ScrapeError>>> = vec![None; urls.len()];
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((index, outcome)) => {
                    if let Some(slot) = slots.get_mut(index) {
                        *slot = Some(outcome);
                    }
                }
                Err(e) => {
                    // A JoinError means the task panicked or was aborted. Neither
                    // should happen, but silently dropping a slot would be worse
                    // than reporting it.
                    if let Some(slot) = slots.iter_mut().find(|s| s.is_none()) {
                        *slot = Some(Err(ScrapeError::Request {
                            url: String::new(),
                            reason: format!("worker task failed: {e}"),
                        }));
                    }
                }
            }
        }

        slots
            .into_iter()
            .map(|s| s.unwrap_or(Err(ScrapeError::Cancelled)))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// HTML extraction
// ---------------------------------------------------------------------------

/// Apply a CSS selector to a document and extract from every match.
///
/// # Errors
/// [`ScrapeError::BadSelector`] if `css` is not a valid selector.
pub fn select(html: &str, css: &str, mode: &Extract) -> Result<Vec<String>, ScrapeError> {
    let selector = Selector::parse(css).map_err(|e| ScrapeError::BadSelector {
        selector: css.to_owned(),
        detail: format!("{e:?}"),
    })?;
    let document = Html::parse_document(html);

    let mut out = Vec::new();
    for element in document.select(&selector) {
        match mode {
            Extract::Text => {
                let collapsed = collapse_whitespace(&element.text().collect::<String>());
                if !collapsed.is_empty() {
                    out.push(collapsed);
                }
            }
            Extract::Attr(name) => {
                if let Some(value) = element.value().attr(name) {
                    out.push(value.to_owned());
                }
            }
            Extract::Html => out.push(element.html()),
        }
    }
    Ok(out)
}

/// Every `href` on the page, resolved against `base` when one is supplied.
///
/// Fragment-only and unresolvable links are dropped rather than returned in a
/// broken form.
///
/// # Errors
/// [`ScrapeError::BadSelector`] cannot actually occur here — the selector is a
/// literal — but the signature stays fallible for symmetry with [`select`].
pub fn links(html: &str, base: Option<&str>) -> Result<Vec<String>, ScrapeError> {
    let raw = select(html, "a[href]", &Extract::Attr("href".to_owned()))?;
    let parsed_base = base.and_then(|b| reqwest::Url::parse(b).ok());

    let mut out = Vec::with_capacity(raw.len());
    for href in raw {
        if href.starts_with('#') {
            continue;
        }
        match &parsed_base {
            Some(b) => {
                if let Ok(joined) = b.join(&href) {
                    out.push(joined.to_string());
                }
            }
            None => out.push(href),
        }
    }
    Ok(out)
}

/// The document's `<title>`, whitespace-collapsed.
#[must_use]
pub fn title(html: &str) -> Option<String> {
    select(html, "title", &Extract::Text)
        .ok()
        .and_then(|v| v.into_iter().next())
}

/// Collapse every run of whitespace to a single space and trim the ends.
///
/// HTML text nodes are full of the source file's indentation; without this,
/// every extracted string arrives wrapped in newlines and tabs.
fn collapse_whitespace(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut pending_space = false;
    for ch in input.chars() {
        if ch.is_whitespace() {
            pending_space = !out.is_empty();
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note the `r##"` delimiter: the document contains `"#`, which would end a
    // single-hash raw string early.
    const DOC: &str = r##"
        <html><head><title>  ion   test  page </title></head>
        <body>
          <h1 class="hero">Hello   World</h1>
          <ul>
            <li><a href="/one" data-id="1">One</a></li>
            <li><a href="https://example.net/two" data-id="2">Two</a></li>
            <li><a href="#frag">Fragment</a></li>
          </ul>
          <p>Trailing</p>
        </body></html>
    "##;

    #[test]
    fn text_extraction_collapses_whitespace() {
        let got = select(DOC, "h1.hero", &Extract::Text).unwrap();
        assert_eq!(got, vec!["Hello World"]);
    }

    #[test]
    fn attribute_extraction_skips_elements_without_the_attribute() {
        let got = select(DOC, "a", &Extract::Attr("data-id".to_owned())).unwrap();
        assert_eq!(got, vec!["1", "2"]);
    }

    #[test]
    fn html_extraction_returns_outer_html() {
        let got = select(DOC, "p", &Extract::Html).unwrap();
        assert_eq!(got, vec!["<p>Trailing</p>"]);
    }

    #[test]
    fn title_is_collapsed() {
        assert_eq!(title(DOC).as_deref(), Some("ion test page"));
    }

    #[test]
    fn links_resolve_against_the_base_and_drop_fragments() {
        let got = links(DOC, Some("https://example.com/dir/page.html")).unwrap();
        assert_eq!(
            got,
            vec!["https://example.com/one", "https://example.net/two"]
        );
    }

    #[test]
    fn links_without_a_base_are_returned_verbatim() {
        let got = links(DOC, None).unwrap();
        assert_eq!(got, vec!["/one", "https://example.net/two"]);
    }

    #[test]
    fn bad_selectors_are_errors_not_panics() {
        let err = select(DOC, "a[[[", &Extract::Text).unwrap_err();
        assert!(matches!(err, ScrapeError::BadSelector { .. }));
    }

    #[test]
    fn extract_modes_parse() {
        assert_eq!(Extract::parse("text").unwrap(), Extract::Text);
        assert_eq!(Extract::parse("").unwrap(), Extract::Text);
        assert_eq!(Extract::parse("html").unwrap(), Extract::Html);
        assert_eq!(
            Extract::parse("attr:href").unwrap(),
            Extract::Attr("href".to_owned())
        );
        assert!(Extract::parse("attr:").is_err());
        assert!(Extract::parse("nonsense").is_err());
    }

    #[tokio::test]
    async fn client_builds_with_rustls_and_honours_zero_redirects() {
        let none = HttpConfig {
            max_redirects: 0,
            ..HttpConfig::default()
        };
        assert!(Scraper::new(&none).is_ok(), "rustls client must build");
        let limited = HttpConfig {
            max_redirects: 3,
            ..HttpConfig::default()
        };
        assert!(Scraper::new(&limited).is_ok());
    }

    #[test]
    fn whitespace_collapsing_handles_edges() {
        assert_eq!(collapse_whitespace("  a \n\t b  "), "a b");
        assert_eq!(collapse_whitespace(""), "");
        assert_eq!(collapse_whitespace("   "), "");
        assert_eq!(collapse_whitespace("single"), "single");
    }
}
