//! `ion` — command-line entry point.
//!
//! Argument parsing is hand-rolled. `clap` would add roughly 300 KB and a
//! handful of transitive crates to a binary whose entire premise is being small,
//! and the surface here is five subcommands with flat `--flag value` options.
//!
//! The tokio runtime is only created for subcommands that actually need one:
//! `--version` and `selftest` do no I/O, so they never pay for a reactor. That is
//! deliberate — it is what makes the measured cold start what it is.

use std::process::ExitCode;

use ion::abi::{Engine, ResultFrame, Task, TaskHeader};
use ion::config::{Config, TsigSettings, parse_server_addr};
use ion::dns::message::{Message, random_id};
use ion::dns::name::Name;
use ion::dns::tsig::{TsigAlgorithm, TsigKey, now_unix, sign_and_encode, to_hex};
use ion::dns::update::UpdateBuilder;
use ion::registrar::{Registrar, endpoint_name, send_update};
use ion::runtime::{Executor, build_tokio_runtime, dispatch_loop};
use ion::scrape::{Extract, Scraper, links, select, title};

const USAGE: &str = "\
ion — VxCloud micro-worker

USAGE:
    ion <COMMAND> [OPTIONS]

COMMANDS:
    run [FILE]          Read VxCloud ABI task frames, execute them, write result frames
    scrape <URL>        Fetch a URL and optionally extract with a CSS selector
    dns register        Send an RFC 2136 UPDATE that adds this worker's A record
    dns delete          Send an RFC 2136 UPDATE that removes it
    selftest            Encode ABI and DNS packets and print them as hex (no network)
    help                Print this message

GLOBAL OPTIONS:
    -V, --version       Print version and ABI level
    -h, --help          Print this message
        --timing        Print ion's own main-entry-to-exit time to stderr

run OPTIONS:
    [FILE]              Positional shorthand for --input
    --input <FILE>      Read task frames from FILE instead of stdin
    --output <FILE>     Write result frames to FILE instead of stdout
                        (result frames are binary; redirect them or use --output)

scrape OPTIONS:
    --select <CSS>      CSS selector to apply
    --mode <MODE>       text (default) | html | attr:<name>
    --links             List every link on the page, resolved absolutely
    --timeout-ms <N>    Override VX_HTTP_TIMEOUT_MS
    --max-bytes <N>     Override VX_HTTP_MAX_BODY_BYTES
    --json              Emit a JSON report instead of plain text

dns OPTIONS:
    --zone <ZONE>       Zone to update, e.g. vxcloud.io.
    --name <FQDN>       Record name; defaults to <task-id>.<tenant>.<base-domain>
    --ip <ADDR>         Address to add or remove; defaults to the detected local IP
    --server <ADDR>     Authoritative server as IP or IP:port (default 127.0.0.1:53)
    --ttl <N>           TTL in seconds (default 60)
    --key-name <NAME>   TSIG key name
    --key-secret <B64>  TSIG secret, base64. Prefer the VX_TSIG_SECRET environment
                        variable: process arguments are world-readable in /proc.
    --algorithm <ALG>   hmac-sha256 (default) | hmac-sha512
    --rrset             delete: remove the whole RRset instead of one RR
    --dry-run           Build and print the packet as hex; send nothing

ENVIRONMENT:
    Every option above has a VX_* environment equivalent; see the config module
    documentation. Flags win over the environment.
";

fn main() -> ExitCode {
    // First statement in the process: everything after this point is `ion`'s own
    // cost, as opposed to the kernel's `execve` and the dynamic loader's work.
    // `--timing` reports it, which is how the README's cold-start figure is
    // measured without the surrounding shell's fork/exec dominating the result.
    let entered = std::time::Instant::now();
    let code = match dispatch() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("ion: {message}");
            ExitCode::from(1)
        }
    };
    if std::env::args().any(|a| a == "--timing") {
        eprintln!(
            "ion: in-process time {} us (main entry to exit)",
            entered.elapsed().as_micros()
        );
    }
    code
}

/// A parsed argument list: the subcommand path, positional arguments, and flags.
struct Args {
    positional: Vec<String>,
    flags: std::collections::HashMap<String, String>,
    switches: std::collections::HashSet<String>,
}

impl Args {
    /// Split `argv` into positionals, `--key value` flags, and bare `--switch`es.
    ///
    /// `known_switches` disambiguates the two: anything listed there consumes no
    /// value, everything else beginning with `--` consumes the next argument.
    fn parse<I: IntoIterator<Item = String>>(
        argv: I,
        known_switches: &[&str],
    ) -> Result<Self, String> {
        let mut positional = Vec::new();
        let mut flags = std::collections::HashMap::new();
        let mut switches = std::collections::HashSet::new();
        let mut iter = argv.into_iter();

        while let Some(arg) = iter.next() {
            if let Some(name) = arg.strip_prefix("--") {
                if name.is_empty() {
                    // A bare "--" ends option parsing.
                    positional.extend(iter);
                    break;
                }
                // Support --key=value as well as --key value.
                if let Some((k, v)) = name.split_once('=') {
                    flags.insert(k.to_owned(), v.to_owned());
                    continue;
                }
                if known_switches.contains(&name) {
                    switches.insert(name.to_owned());
                    continue;
                }
                let value = iter
                    .next()
                    .ok_or_else(|| format!("--{name} requires a value"))?;
                flags.insert(name.to_owned(), value);
            } else if let Some(short) = arg.strip_prefix('-') {
                match short {
                    "V" => switches.insert("version".to_owned()),
                    "h" => switches.insert("help".to_owned()),
                    other => return Err(format!("unknown short option -{other}")),
                };
            } else {
                positional.push(arg);
            }
        }
        Ok(Self {
            positional,
            flags,
            switches,
        })
    }

    fn flag(&self, name: &str) -> Option<&str> {
        self.flags.get(name).map(String::as_str)
    }

    fn has(&self, name: &str) -> bool {
        self.switches.contains(name)
    }

    fn positional_at(&self, index: usize) -> Option<&str> {
        self.positional.get(index).map(String::as_str)
    }

    fn u64_flag(&self, name: &str) -> Result<Option<u64>, String> {
        match self.flag(name) {
            None => Ok(None),
            Some(raw) => raw
                .parse::<u64>()
                .map(Some)
                .map_err(|_| format!("--{name} must be a non-negative integer, got {raw:?}")),
        }
    }
}

const SWITCHES: &[&str] = &[
    "version", "help", "json", "links", "dry-run", "rrset", "timing",
];

fn dispatch() -> Result<ExitCode, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = Args::parse(argv, SWITCHES)?;

    if args.has("version") {
        println!("{}", ion::banner());
        return Ok(ExitCode::SUCCESS);
    }
    if args.has("help") || args.positional.is_empty() {
        print!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }

    let command = args.positional_at(0).unwrap_or("help");
    match command {
        "help" => {
            print!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        "selftest" => cmd_selftest(),
        "run" => cmd_run(&args),
        "scrape" => cmd_scrape(&args),
        "dns" => cmd_dns(&args),
        other => Err(format!(
            "unknown command {other:?}; run `ion help` for usage"
        )),
    }
}

// ---------------------------------------------------------------------------
// selftest — no network, no runtime
// ---------------------------------------------------------------------------

fn cmd_selftest() -> Result<ExitCode, String> {
    println!("{}", ion::banner());
    println!();

    // --- ABI ---------------------------------------------------------------
    let payload = br#"{"op":"noop"}"#;
    let header = TaskHeader::new(0x0102_0304_0506_0708, "acme", Engine::Ion, 8, 100_000, 0)
        .map_err(|e| e.to_string())?;
    let frame = Task::encode(&header, payload).map_err(|e| e.to_string())?;
    let parsed = Task::parse(&frame).map_err(|e| e.to_string())?;
    println!("ABI task frame     {} bytes", frame.len());
    println!(
        "  header           {}",
        to_hex(frame.get(..93).unwrap_or(&[]))
    );
    println!("  task_id          {:#018x}", parsed.header.task_id);
    println!(
        "  tenant_id        {:?}",
        parsed.tenant().map_err(|e| e.to_string())?
    );
    println!("  payload_len      {}", parsed.header.payload_len);

    let result = ResultFrame::new(
        parsed.header.task_id,
        ion::abi::TaskState::Completed,
        0,
        1234,
        b"{}".to_vec(),
    );
    let result_bytes = result.encode();
    println!("ABI result frame   {} bytes", result_bytes.len());
    println!(
        "  header           {}",
        to_hex(result_bytes.get(..29).unwrap_or(&[]))
    );
    println!();

    // --- DNS UPDATE: add ---------------------------------------------------
    let zone = Name::from_ascii("example.com.").map_err(|e| e.to_string())?;
    let host = Name::from_ascii("host.example.com.").map_err(|e| e.to_string())?;

    let mut add = UpdateBuilder::with_id(zone.clone(), 0x1234);
    add.add_a(&host, 60, std::net::Ipv4Addr::new(192, 0, 2, 7))
        .map_err(|e| e.to_string())?;
    let add_wire = add.encode().map_err(|e| e.to_string())?;
    println!("RFC 2136 UPDATE add A  {} bytes", add_wire.len());
    println!("  {}", to_hex(&add_wire));
    annotate_update(&add_wire);
    println!();

    // --- DNS UPDATE: delete one RR ----------------------------------------
    let mut del = UpdateBuilder::with_id(zone.clone(), 0x1234);
    del.delete_a(&host, std::net::Ipv4Addr::new(192, 0, 2, 7))
        .map_err(|e| e.to_string())?;
    let del_wire = del.encode().map_err(|e| e.to_string())?;
    println!(
        "RFC 2136 UPDATE delete RR (CLASS NONE)  {} bytes",
        del_wire.len()
    );
    println!("  {}", to_hex(&del_wire));
    println!();

    // --- DNS UPDATE: delete RRset -----------------------------------------
    let mut del_set = UpdateBuilder::with_id(zone.clone(), 0x1234);
    del_set
        .delete_rrset(&host, ion::dns::message::RecordType::A)
        .map_err(|e| e.to_string())?;
    let del_set_wire = del_set.encode().map_err(|e| e.to_string())?;
    println!(
        "RFC 2136 UPDATE delete RRset (CLASS ANY)  {} bytes",
        del_set_wire.len()
    );
    println!("  {}", to_hex(&del_set_wire));
    println!();

    // --- TSIG --------------------------------------------------------------
    // A published, deliberately worthless demonstration key. Real deployments
    // supply the secret through VX_TSIG_SECRET.
    let demo_secret = "aWY6eW91LWNhbi1yZWFkLXRoaXMtaXQtaXMtbm90LWEtc2VjcmV0";
    let key = TsigKey::from_base64("selftest.key.", TsigAlgorithm::HmacSha256, demo_secret)
        .map_err(|e| e.to_string())?;
    let mut signed = add.message().map_err(|e| e.to_string())?;
    let (signed_wire, mac) =
        sign_and_encode(&mut signed, &key, 1_700_000_000, 300).map_err(|e| e.to_string())?;
    println!(
        "TSIG hmac-sha256 signed UPDATE  {} bytes",
        signed_wire.len()
    );
    println!("  wire             {}", to_hex(&signed_wire));
    println!("  mac              {}", to_hex(&mac));
    println!("  key name         {}", key.name());
    println!("  time signed      1700000000 fudge 300");
    println!("  additional count {}", signed.header.adcount());
    let decoded = Message::decode(&signed_wire).map_err(|e| e.to_string())?;
    println!(
        "  round-trip       {} additional record(s), last is {}",
        decoded.additional.len(),
        decoded
            .additional
            .last()
            .map_or_else(|| "none".to_owned(), |r| r.rtype.to_string())
    );
    println!();

    // --- name limits -------------------------------------------------------
    let ok_label = "a".repeat(63);
    let bad_label = "a".repeat(64);
    println!("RFC 1035 limits");
    println!(
        "  63-byte label    {}",
        if Name::from_ascii(&ok_label).is_ok() {
            "accepted"
        } else {
            "REJECTED (bug)"
        }
    );
    println!(
        "  64-byte label    {}",
        if Name::from_ascii(&bad_label).is_err() {
            "rejected"
        } else {
            "ACCEPTED (bug)"
        }
    );
    println!("selftest ok");
    Ok(ExitCode::SUCCESS)
}

/// Print a field-by-field breakdown of an `UPDATE` packet header.
fn annotate_update(wire: &[u8]) {
    match Message::decode(wire) {
        Ok(msg) => {
            println!(
                "  header           id={:#06x} opcode={} zocount={} prcount={} upcount={} adcount={}",
                msg.header.id,
                msg.header.flags.opcode,
                msg.header.zocount(),
                msg.header.prcount(),
                msg.header.upcount(),
                msg.header.adcount()
            );
            for q in msg.zone() {
                println!("  zone             {} {} {}", q.name, q.qclass, q.qtype);
            }
            for rr in msg.updates() {
                println!(
                    "  update           {} {} {} ttl={} rdlength={}",
                    rr.name,
                    rr.class,
                    rr.rtype,
                    rr.ttl,
                    rr.rdata.len()
                );
            }
        }
        Err(e) => println!("  (decode failed: {e})"),
    }
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

fn cmd_run(args: &Args) -> Result<ExitCode, String> {
    let cfg = Config::from_process_env().map_err(|e| e.to_string())?;
    let rt = build_tokio_runtime(&cfg.runtime).map_err(|e| e.to_string())?;

    let (input_path, output_path) = resolve_run_paths(args)?;

    rt.block_on(async move {
        let executor = Executor::new(cfg).map_err(|e| e.to_string())?;

        // Buffer the *reader* only. Every task frame is two reads — a 93-byte
        // header and then the payload — and on `tokio::fs`/`stdin` each of those
        // is a `spawn_blocking` round trip. Reading through a `BufReader` turns
        // the pair into one syscall per buffer-full and measurably halves the
        // per-task cost.
        //
        // The writer is deliberately *not* buffered: a supervisor blocking on a
        // result must not wait for a buffer to fill, so `dispatch_loop` flushes
        // after every frame. That is one write syscall per task, by design.
        let count = match (input_path, output_path) {
            (None, None) => {
                let mut input = buffered(tokio::io::stdin());
                let mut stdout = tokio::io::stdout();
                dispatch_loop(&mut input, &mut stdout, &executor).await
            }
            (Some(path), None) => {
                let mut input = buffered(open_input(&path).await?);
                let mut stdout = tokio::io::stdout();
                dispatch_loop(&mut input, &mut stdout, &executor).await
            }
            (None, Some(path)) => {
                let mut input = buffered(tokio::io::stdin());
                let mut file = create_output(&path).await?;
                dispatch_loop(&mut input, &mut file, &executor).await
            }
            (Some(inp), Some(outp)) => {
                let mut input = buffered(open_input(&inp).await?);
                let mut file = create_output(&outp).await?;
                dispatch_loop(&mut input, &mut file, &executor).await
            }
        }
        .map_err(|e| e.to_string())?;
        eprintln!("ion: dispatched {count} task(s)");
        Ok(ExitCode::SUCCESS)
    })
}

/// Work out where `ion run` should read from and write to.
///
/// `ion run <file>` is accepted as shorthand for `--input <file>`. That is not
/// sugar, it closes a silent-failure hole: a stray positional used to be dropped,
/// so `ion run task.bin` read an *empty stdin*, dispatched zero tasks, and exited
/// 0. A typo therefore looked like success — and worse, a deliberately corrupted
/// frame handed to it looked *accepted*, because nothing was ever read to reject
/// it. An unknown `--flag` was already an error; an unknown positional should not
/// be more forgiving.
///
/// Split out from [`cmd_run`] so it can be tested without a tokio runtime or a
/// filesystem.
fn resolve_run_paths(args: &Args) -> Result<(Option<String>, Option<String>), String> {
    let output_path = args.flag("output").map(str::to_owned);
    let input_path = match (args.flag("input"), args.positional_at(1)) {
        (Some(flag), Some(pos)) if flag != pos => {
            return Err(format!(
                "conflicting inputs: --input {flag:?} and positional {pos:?}; pass one"
            ));
        }
        (Some(flag), _) => Some(flag.to_owned()),
        (None, Some(pos)) => Some(pos.to_owned()),
        (None, None) => None,
    };
    if let Some(extra) = args.positional_at(2) {
        return Err(format!(
            "unexpected argument {extra:?}; `ion run` takes at most one input path"
        ));
    }
    Ok((input_path, output_path))
}

/// Frame-reader buffer. Sized to hold many small task frames per syscall while
/// staying far below the memory budget.
const INPUT_BUFFER: usize = 64 * 1024;

fn buffered<R: tokio::io::AsyncRead>(inner: R) -> tokio::io::BufReader<R> {
    tokio::io::BufReader::with_capacity(INPUT_BUFFER, inner)
}

async fn open_input(path: &str) -> Result<tokio::fs::File, String> {
    tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("cannot open {path}: {e}"))
}

async fn create_output(path: &str) -> Result<tokio::fs::File, String> {
    tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("cannot create {path}: {e}"))
}

// ---------------------------------------------------------------------------
// scrape
// ---------------------------------------------------------------------------

fn cmd_scrape(args: &Args) -> Result<ExitCode, String> {
    let url = args
        .positional_at(1)
        .ok_or("scrape requires a URL: `ion scrape https://example.com`")?
        .to_owned();

    let mut cfg = Config::from_process_env().map_err(|e| e.to_string())?;
    if let Some(ms) = args.u64_flag("timeout-ms")? {
        cfg.http.timeout = std::time::Duration::from_millis(ms.max(1));
    }
    if let Some(bytes) = args.u64_flag("max-bytes")? {
        cfg.http.max_body_bytes = bytes.max(1);
    }

    let want_links = args.has("links");
    let as_json = args.has("json");
    let selector = args.flag("select").map(str::to_owned);
    let mode = Extract::parse(args.flag("mode").unwrap_or("text")).map_err(|e| e.to_string())?;

    let rt = build_tokio_runtime(&cfg.runtime).map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let scraper = Scraper::new(&cfg.http).map_err(|e| e.to_string())?;
        let page = scraper.fetch(&url).await.map_err(|e| e.to_string())?;
        let text = page.text();

        let extracted = if want_links {
            links(&text, Some(&page.final_url)).map_err(|e| e.to_string())?
        } else if let Some(css) = &selector {
            select(&text, css, &mode).map_err(|e| e.to_string())?
        } else {
            Vec::new()
        };

        if as_json {
            let report = serde_json::json!({
                "url": page.url,
                "final_url": page.final_url,
                "status": page.status,
                "version": page.version,
                "content_type": page.content_type,
                "bytes": page.body.len(),
                "truncated": page.truncated,
                "elapsed_ms": page.elapsed_ms,
                "title": title(&text),
                "extracted": extracted,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
        } else {
            println!("{} {} {}", page.status, page.version, page.final_url);
            if let Some(ct) = &page.content_type {
                println!("content-type: {ct}");
            }
            println!(
                "{} bytes in {}ms{}",
                page.body.len(),
                page.elapsed_ms,
                if page.truncated { " (truncated)" } else { "" }
            );
            if let Some(t) = title(&text) {
                println!("title: {t}");
            }
            for item in &extracted {
                println!("{item}");
            }
        }

        if page.is_success() {
            Ok(ExitCode::SUCCESS)
        } else {
            Ok(ExitCode::from(2))
        }
    })
}

// ---------------------------------------------------------------------------
// dns
// ---------------------------------------------------------------------------

fn cmd_dns(args: &Args) -> Result<ExitCode, String> {
    let action = args
        .positional_at(1)
        .ok_or("dns requires an action: `ion dns register` or `ion dns delete`")?;
    if action != "register" && action != "delete" {
        return Err(format!(
            "unknown dns action {action:?} (expected \"register\" or \"delete\")"
        ));
    }

    let mut cfg = Config::from_process_env().map_err(|e| e.to_string())?;
    if let Some(server) = args.flag("server") {
        cfg.dns.server = parse_server_addr("--server", server).map_err(|e| e.to_string())?;
    }
    if let Some(zone) = args.flag("zone") {
        cfg.dns.zone = zone.to_owned();
        cfg.dns.base_domain = zone.to_owned();
    }
    if let Some(ttl) = args.u64_flag("ttl")? {
        cfg.dns.ttl = u32::try_from(ttl).map_err(|_| "--ttl is too large".to_owned())?;
    }
    apply_tsig_flags(args, &mut cfg)?;

    let explicit_name = args.flag("name").map(str::to_owned);
    let explicit_ip = match args.flag("ip") {
        Some(raw) => Some(
            raw.parse::<std::net::IpAddr>()
                .map_err(|_| format!("--ip must be a literal address, got {raw:?}"))?,
        ),
        None => None,
    };
    let dry_run = args.has("dry-run");
    let whole_rrset = args.has("rrset");
    let register = action == "register";

    let rt = build_tokio_runtime(&cfg.runtime).map_err(|e| e.to_string())?;
    rt.block_on(async move {
        // Resolve the address first: the registrar needs it, and if the operator
        // did not supply one we discover it by probing the route to the server.
        let address = match explicit_ip {
            Some(ip) => ip,
            None => ion::registrar::detect_local_ip(cfg.dns.server)
                .await
                .map_err(|e| e.to_string())?,
        };

        // A caller-supplied --name overrides the derived one. Both are validated.
        let fqdn = match &explicit_name {
            Some(raw) => Name::from_ascii(raw).map_err(|e| e.to_string())?,
            None => endpoint_name(cfg.task_id, &cfg.tenant_id, &cfg.dns.base_domain)
                .map_err(|e| e.to_string())?,
        };

        if whole_rrset && !register {
            return dns_delete_rrset(&cfg, &fqdn, dry_run).await;
        }

        let reg = Registrar::with_address(&cfg.dns, cfg.task_id, &cfg.tenant_id, address)
            .map_err(|e| e.to_string())?;

        // When --name was given we must not use the derived registrar name, so
        // build the packet from the explicit name via the builder instead.
        let id = random_id();
        let (packet, request_mac) = if explicit_name.is_some() {
            build_explicit_packet(&cfg, &fqdn, address, register, id)?
        } else if register {
            reg.build_register_packet(id, now_unix())
                .map_err(|e| e.to_string())?
        } else {
            reg.build_delete_packet(id, now_unix())
                .map_err(|e| e.to_string())?
        };

        println!("name    {fqdn}");
        println!(
            "owner   {} (relative to the zone)",
            strip_zone_suffix(&fqdn, &cfg.dns.zone)
        );
        println!("address {address}");
        println!("zone    {}", cfg.dns.zone);
        println!("server  {}", cfg.dns.server);
        println!(
            "signed  {}",
            if request_mac.is_empty() { "no" } else { "yes" }
        );
        println!("packet  {} bytes", packet.len());
        println!("        {}", to_hex(&packet));

        if dry_run {
            println!("dry-run: nothing sent");
            return Ok(ExitCode::SUCCESS);
        }

        let raw = send_update(cfg.dns.server, &packet, cfg.dns.timeout, cfg.dns.retries)
            .await
            .map_err(|e| e.to_string())?;
        let response = Message::decode(&raw).map_err(|e| e.to_string())?;
        println!(
            "response {} id={:#06x} {} bytes",
            response.rcode(),
            response.header.id,
            raw.len()
        );
        if response.rcode().is_error() {
            Ok(ExitCode::from(3))
        } else {
            Ok(ExitCode::SUCCESS)
        }
    })
}

/// Build an add/delete packet for an operator-supplied `--name`.
fn build_explicit_packet(
    cfg: &Config,
    fqdn: &Name,
    address: std::net::IpAddr,
    register: bool,
    id: u16,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let zone = Name::from_ascii(&cfg.dns.zone).map_err(|e| e.to_string())?;
    let mut b = UpdateBuilder::with_id(zone, id);
    if register {
        b.add_address(fqdn, cfg.dns.ttl, address)
            .map_err(|e| e.to_string())?;
    } else {
        b.delete_address(fqdn, address).map_err(|e| e.to_string())?;
    }
    let mut msg = b.message().map_err(|e| e.to_string())?;
    match &cfg.dns.tsig {
        Some(settings) => {
            let key =
                TsigKey::from_base64(&settings.key_name, settings.algorithm, &settings.secret_b64)
                    .map_err(|e| e.to_string())?;
            sign_and_encode(&mut msg, &key, now_unix(), settings.fudge).map_err(|e| e.to_string())
        }
        None => Ok((msg.encode().map_err(|e| e.to_string())?, Vec::new())),
    }
}

/// `dns delete --rrset`: remove every address record at the name.
async fn dns_delete_rrset(cfg: &Config, fqdn: &Name, dry_run: bool) -> Result<ExitCode, String> {
    let zone = Name::from_ascii(&cfg.dns.zone).map_err(|e| e.to_string())?;
    let mut b = UpdateBuilder::with_id(zone, random_id());
    b.delete_all_rrsets(fqdn).map_err(|e| e.to_string())?;
    let mut msg = b.message().map_err(|e| e.to_string())?;

    let (packet, _mac) = match &cfg.dns.tsig {
        Some(settings) => {
            let key =
                TsigKey::from_base64(&settings.key_name, settings.algorithm, &settings.secret_b64)
                    .map_err(|e| e.to_string())?;
            sign_and_encode(&mut msg, &key, now_unix(), settings.fudge)
                .map_err(|e| e.to_string())?
        }
        None => (msg.encode().map_err(|e| e.to_string())?, Vec::new()),
    };

    println!("name    {fqdn}");
    println!("zone    {}", cfg.dns.zone);
    println!("action  delete every RRset at the name (TYPE=ANY CLASS=ANY)");
    println!("packet  {} bytes", packet.len());
    println!("        {}", to_hex(&packet));
    if dry_run {
        println!("dry-run: nothing sent");
        return Ok(ExitCode::SUCCESS);
    }

    let raw = send_update(cfg.dns.server, &packet, cfg.dns.timeout, cfg.dns.retries)
        .await
        .map_err(|e| e.to_string())?;
    let response = Message::decode(&raw).map_err(|e| e.to_string())?;
    println!("response {}", response.rcode());
    if response.rcode().is_error() {
        Ok(ExitCode::from(3))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

/// Fold TSIG-related flags into the configuration.
///
/// Passing a secret on the command line is supported but discouraged: `/proc`
/// makes process arguments readable to any process with the same uid, so
/// `VX_TSIG_SECRET` is the safer channel.
fn apply_tsig_flags(args: &Args, cfg: &mut Config) -> Result<(), String> {
    let key_name = args.flag("key-name").map(str::to_owned);
    let secret = args.flag("key-secret").map(str::to_owned);
    let algorithm = match args.flag("algorithm") {
        Some(raw) => Some(TsigAlgorithm::from_name(raw).map_err(|e| e.to_string())?),
        None => None,
    };

    // Nothing configured yet: the two halves of a key must arrive together.
    if cfg.dns.tsig.is_none() {
        match (&key_name, &secret) {
            (Some(name), Some(sec)) => {
                cfg.dns.tsig = Some(TsigSettings {
                    key_name: name.clone(),
                    secret_b64: sec.clone(),
                    algorithm: algorithm.unwrap_or_default(),
                    fudge: ion::dns::tsig::DEFAULT_FUDGE,
                });
            }
            (Some(_), None) => {
                return Err(
                    "--key-name was given without a secret; set VX_TSIG_SECRET or pass \
                     --key-secret"
                        .to_owned(),
                );
            }
            (None, Some(_)) => {
                return Err("--key-secret was given without --key-name".to_owned());
            }
            (None, None) => {}
        }
        return Ok(());
    }

    // Already configured from the environment: flags override individual fields.
    let Some(existing) = cfg.dns.tsig.as_mut() else {
        return Ok(());
    };
    if let Some(n) = key_name {
        existing.key_name = n;
    }
    if let Some(s) = secret {
        existing.secret_b64 = s;
    }
    if let Some(a) = algorithm {
        existing.algorithm = a;
    }
    Ok(())
}

/// The part of `fqdn` that precedes `zone`, used only for display.
fn strip_zone_suffix(fqdn: &Name, zone: &str) -> String {
    let rendered = fqdn.to_string();
    let zone_normalised = if zone.ends_with('.') {
        zone.to_owned()
    } else {
        format!("{zone}.")
    };
    rendered
        .strip_suffix(&zone_normalised)
        .map_or(rendered.clone(), |head| {
            head.trim_end_matches('.').to_owned()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn flags_switches_and_positionals_are_separated() {
        let a = Args::parse(
            argv(&["scrape", "https://x", "--select", "h1", "--json"]),
            SWITCHES,
        )
        .unwrap();
        assert_eq!(a.positional_at(0), Some("scrape"));
        assert_eq!(a.positional_at(1), Some("https://x"));
        assert_eq!(a.flag("select"), Some("h1"));
        assert!(a.has("json"));
        assert!(!a.has("links"));
    }

    #[test]
    fn key_equals_value_form_is_accepted() {
        let a = Args::parse(argv(&["dns", "register", "--zone=example.com."]), SWITCHES).unwrap();
        assert_eq!(a.flag("zone"), Some("example.com."));
    }

    #[test]
    fn short_options_map_to_switches() {
        assert!(Args::parse(argv(&["-V"]), SWITCHES).unwrap().has("version"));
        assert!(Args::parse(argv(&["-h"]), SWITCHES).unwrap().has("help"));
        assert!(Args::parse(argv(&["-x"]), SWITCHES).is_err());
    }

    #[test]
    fn a_flag_without_a_value_is_an_error() {
        assert!(Args::parse(argv(&["scrape", "https://x", "--select"]), SWITCHES).is_err());
    }

    #[test]
    fn double_dash_ends_option_parsing() {
        let a = Args::parse(argv(&["run", "--", "--not-a-flag"]), SWITCHES).unwrap();
        assert_eq!(a.positional_at(1), Some("--not-a-flag"));
        assert!(a.flag("not-a-flag").is_none());
    }

    #[test]
    fn numeric_flags_are_validated() {
        let a = Args::parse(argv(&["scrape", "u", "--timeout-ms", "500"]), SWITCHES).unwrap();
        assert_eq!(a.u64_flag("timeout-ms").unwrap(), Some(500));
        let bad = Args::parse(argv(&["scrape", "u", "--timeout-ms", "soon"]), SWITCHES).unwrap();
        assert!(bad.u64_flag("timeout-ms").is_err());
    }

    #[test]
    fn zone_suffix_stripping_is_display_only() {
        let n = Name::from_ascii("7.acme.vxcloud.io.").unwrap();
        assert_eq!(strip_zone_suffix(&n, "vxcloud.io."), "7.acme");
        assert_eq!(strip_zone_suffix(&n, "vxcloud.io"), "7.acme");
        assert_eq!(strip_zone_suffix(&n, "example.org."), "7.acme.vxcloud.io.");
    }

    #[test]
    fn tsig_flags_require_both_halves() {
        let mut cfg = Config::default();
        let only_name =
            Args::parse(argv(&["dns", "register", "--key-name", "k."]), SWITCHES).unwrap();
        assert!(apply_tsig_flags(&only_name, &mut cfg).is_err());

        let both = Args::parse(
            argv(&[
                "dns",
                "register",
                "--key-name",
                "k.",
                "--key-secret",
                "c2VjcmV0",
            ]),
            SWITCHES,
        )
        .unwrap();
        let mut cfg2 = Config::default();
        apply_tsig_flags(&both, &mut cfg2).unwrap();
        let tsig = cfg2.dns.tsig.expect("configured");
        assert_eq!(tsig.key_name, "k.");
        assert_eq!(tsig.algorithm, TsigAlgorithm::HmacSha256);
    }

    #[test]
    fn run_accepts_a_positional_input_path() {
        // The shorthand.
        let a = Args::parse(argv(&["run", "task.bin"]), SWITCHES).unwrap();
        assert_eq!(
            resolve_run_paths(&a).unwrap(),
            (Some("task.bin".to_owned()), None)
        );

        // The explicit flag.
        let a = Args::parse(argv(&["run", "--input", "task.bin"]), SWITCHES).unwrap();
        assert_eq!(
            resolve_run_paths(&a).unwrap(),
            (Some("task.bin".to_owned()), None)
        );

        // Both, agreeing, is fine.
        let a = Args::parse(argv(&["run", "task.bin", "--input", "task.bin"]), SWITCHES).unwrap();
        assert_eq!(
            resolve_run_paths(&a).unwrap(),
            (Some("task.bin".to_owned()), None)
        );

        // Neither means stdin/stdout.
        let a = Args::parse(argv(&["run"]), SWITCHES).unwrap();
        assert_eq!(resolve_run_paths(&a).unwrap(), (None, None));

        // Output is independent.
        let a = Args::parse(argv(&["run", "in.bin", "--output", "out.bin"]), SWITCHES).unwrap();
        assert_eq!(
            resolve_run_paths(&a).unwrap(),
            (Some("in.bin".to_owned()), Some("out.bin".to_owned()))
        );
    }

    #[test]
    fn run_refuses_ambiguous_or_surplus_inputs() {
        // Two different inputs is a mistake, not a precedence puzzle.
        let a = Args::parse(argv(&["run", "a.bin", "--input", "b.bin"]), SWITCHES).unwrap();
        let err = resolve_run_paths(&a).unwrap_err();
        assert!(err.contains("conflicting inputs"), "{err}");

        // A surplus positional is an error rather than silently ignored, which is
        // the whole point: a dropped argument used to read empty stdin and exit 0.
        let a = Args::parse(argv(&["run", "a.bin", "b.bin"]), SWITCHES).unwrap();
        let err = resolve_run_paths(&a).unwrap_err();
        assert!(err.contains("unexpected argument"), "{err}");
    }

    #[test]
    fn usage_text_documents_every_command() {
        for cmd in ["run", "scrape", "dns register", "dns delete", "selftest"] {
            assert!(USAGE.contains(cmd), "usage should mention {cmd}");
        }
    }
}
