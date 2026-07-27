//! # ion — the VxCloud micro-worker
//!
//! `ion` is the light half of the VxCloud two-engine worker fleet (`ENGINE_ION`
//! in [`worker_abi.h`]). It is designed to be dropped into any substrate that
//! can execute a static Linux binary — AWS Lambda, a scratch micro-container, a
//! Firecracker/ephemeral VM, a Kubernetes sidecar — and start doing useful work
//! before a JVM would have finished reading its own classpath.
//!
//! ## What it does
//!
//! 1. **Speaks the frozen VxCloud ABI** ([`abi`]). The host `vxnode` runtime
//!    hands `ion` a packed 93-byte [`abi::TaskHeader`] followed by an opaque
//!    payload; `ion` answers with a packed 29-byte [`abi::ResultHeader`]. The
//!    codec is zero-copy on the payload, offset-exact, and returns typed errors
//!    instead of panicking on malformed input.
//!
//! 2. **Registers its own DNS endpoint** ([`dns`], [`registrar`]). Every worker
//!    is addressable at `<task_id>.<tenant>.<base-domain>` the moment it boots.
//!    `ion` does this by hand-encoding [RFC 2136] dynamic `UPDATE` packets in
//!    binary and pushing them over UDP/53, optionally signed with [RFC 8945]
//!    TSIG HMAC-SHA256. There is no `nsupdate`, no `dig`, no subprocess, and no
//!    third-party DNS crate anywhere in the path.
//!
//! 3. **Executes HTTP / scrape tasks** ([`scrape`], [`runtime`]). A tokio HTTP
//!    client that negotiates HTTP/1.1 or HTTP/2 over rustls (no OpenSSL, no
//!    system TLS dependency), with hard timeouts, redirect caps, response-size
//!    caps, CSS-selector extraction, and bounded-concurrency fan-out.
//!
//! ## Module map
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`abi`] | packed `vx_task_header_t` / `vx_result_header_t` codec |
//! | [`config`] | `VX_*` environment configuration, no panics on bad input |
//! | [`dns::name`] | RFC 1035 label encoding, validation, decompression |
//! | [`dns::message`] | DNS header/section encoder + decoder |
//! | [`dns::update`] | RFC 2136 `UPDATE` builder (add / delete / prerequisites) |
//! | [`dns::tsig`] | RFC 8945 TSIG HMAC-SHA256 signing and verification |
//! | [`registrar`] | boot-time `A` record registration, `SIGTERM` de-registration |
//! | [`scrape`] | async HTTP/1.1 + HTTP/2 fetch and HTML extraction |
//! | [`runtime`] | task dispatch loop, wall-clock timing, result emission |
//!
//! ## Example: build a signed UPDATE packet without touching the network
//!
//! ```
//! use ion::dns::{name::Name, update::UpdateBuilder};
//! use std::net::Ipv4Addr;
//!
//! let mut b = UpdateBuilder::with_id("example.com.".parse::<Name>().unwrap(), 0x1234);
//! b.add_a(&"host.example.com.".parse::<Name>().unwrap(), 60, Ipv4Addr::new(192, 0, 2, 7))
//!     .unwrap();
//! let wire = b.encode().unwrap();
//!
//! // opcode 5 (UPDATE) lives in the top nibble-and-a-bit of the flags word
//! assert_eq!(wire[2] >> 3 & 0x0f, 5);
//! assert_eq!(&wire[..2], &[0x12, 0x34]); // message id
//! ```
//!
//! [`worker_abi.h`]: https://github.com/prodxcloud/ion
//! [RFC 2136]: https://www.rfc-editor.org/rfc/rfc2136
//! [RFC 8945]: https://www.rfc-editor.org/rfc/rfc8945

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod abi;
pub mod config;
pub mod dns;
pub mod registrar;
pub mod runtime;
pub mod scrape;

/// Crate version, taken from `Cargo.toml` at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Short build banner printed by `ion --version`.
///
/// ```
/// assert!(ion::banner().starts_with("ion "));
/// ```
#[must_use]
pub fn banner() -> String {
    format!(
        "ion {VERSION} (vx-abi v{abi}, engine {engine:#04x})",
        abi = abi::VX_ABI_VERSION,
        engine = abi::Engine::Ion as u8
    )
}
