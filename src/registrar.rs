//! Boot-time DNS registration and `SIGTERM` de-registration.
//!
//! The contract with the rest of VxCloud is simple: from the moment a worker is
//! running, `<task_id>.<tenant>.<base-domain>` resolves to it, and from the
//! moment it is asked to stop, that name is gone. Nothing else in the fleet has
//! to be told where the worker landed.
//!
//! ## Lifecycle
//!
//! ```text
//!   boot ──► detect local IP ──► UPDATE add A ──► serve ──┐
//!                                                          │ SIGTERM / SIGINT
//!   exit ◄── UPDATE delete A ◄── graceful_shutdown ◄───────┘
//! ```
//!
//! ## Local address detection
//!
//! Finding "my own address" is done with the classic UDP-connect trick: create
//! an unbound UDP socket, `connect()` it to the DNS server, and read back the
//! source address the kernel's routing table chose. `connect()` on a datagram
//! socket sends nothing — it only fixes the peer — so this costs one syscall,
//! reaches no third party, and requires no STUN/metadata/`checkip` service. That
//! matters on a sealed VPC where those services are unreachable, and it matters
//! for cold start, where an HTTP round trip to a metadata endpoint would cost
//! more than everything else `ion` does combined.
//!
//! ## Testability
//!
//! Registration and de-registration are ordinary `async fn`s taking a
//! [`Registrar`], and packet construction is split out into
//! [`Registrar::build_register_packet`] / [`Registrar::build_delete_packet`],
//! which are deterministic given a message id. The signal wait is
//! [`wait_for_termination`], separate from [`graceful_shutdown`], so the shutdown
//! path can be exercised by a test without raising a real signal.

use core::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::config::DnsConfig;
use crate::dns::DnsError;
use crate::dns::message::{Message, Rcode, RecordType, random_id};
use crate::dns::name::Name;
use crate::dns::tsig::{TsigKey, now_unix, sign_and_encode, verify_response};
use crate::dns::update::UpdateBuilder;

/// Largest response we will read. A signed `UPDATE` reply with a SHA-512 MAC and
/// a bulky key name still fits comfortably; anything larger is not something we
/// need to parse.
const RESPONSE_BUFFER: usize = 1232;

/// Why registration or de-registration failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrarError {
    /// A name, packet, or signature could not be built or parsed.
    Dns(DnsError),
    /// A socket operation failed.
    Io {
        /// What we were attempting.
        context: &'static str,
        /// The OS error text.
        detail: String,
    },
    /// Every attempt timed out.
    Timeout {
        /// How many attempts were made.
        attempts: u32,
        /// The per-attempt budget.
        per_attempt: Duration,
    },
    /// The server answered, but with a failure code.
    Rejected {
        /// The response code.
        rcode: Rcode,
    },
    /// The response's message id did not match the request's.
    IdMismatch {
        /// The id we sent.
        expected: u16,
        /// The id that came back.
        found: u16,
    },
    /// The peer sent a query where a response was expected.
    NotAResponse,
    /// The tenant slug or task id could not form a legal domain name.
    BadEndpointName {
        /// The name we tried to build.
        attempted: String,
        /// Why it was rejected.
        reason: String,
    },
}

impl From<DnsError> for RegistrarError {
    fn from(e: DnsError) -> Self {
        Self::Dns(e)
    }
}

impl fmt::Display for RegistrarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(e) => write!(f, "dns: {e}"),
            Self::Io { context, detail } => write!(f, "{context}: {detail}"),
            Self::Timeout {
                attempts,
                per_attempt,
            } => write!(
                f,
                "no response after {attempts} attempt(s) of {}ms",
                per_attempt.as_millis()
            ),
            Self::Rejected { rcode } => {
                write!(
                    f,
                    "server rejected the UPDATE with {rcode} ({})",
                    rcode.code()
                )
            }
            Self::IdMismatch { expected, found } => write!(
                f,
                "response id {found:#06x} does not match request id {expected:#06x}"
            ),
            Self::NotAResponse => write!(f, "peer sent a query, not a response"),
            Self::BadEndpointName { attempted, reason } => {
                write!(f, "cannot build endpoint name {attempted:?}: {reason}")
            }
        }
    }
}

impl std::error::Error for RegistrarError {}

/// Which signal ended the worker's life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    /// `SIGTERM` — the supervisor asked politely.
    Sigterm,
    /// `SIGINT` — Ctrl-C, or an interactive operator.
    Sigint,
    /// The signal handler could not be installed; treated as a stop request.
    Unavailable,
}

impl fmt::Display for Termination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sigterm => f.write_str("SIGTERM"),
            Self::Sigint => f.write_str("SIGINT"),
            Self::Unavailable => f.write_str("signal-unavailable"),
        }
    }
}

/// Build the fully-qualified endpoint name for a worker.
///
/// The shape is `<task_id>.<tenant>.<base-domain>`. The tenant slug is folded to
/// lower case and any byte that is not a legal host character becomes `-`, so an
/// arbitrary tenant string cannot produce an illegal name — but a slug that
/// reduces to nothing is an error rather than a silently-empty label.
///
/// # Errors
/// [`RegistrarError::BadEndpointName`] if the result is not a legal domain name,
/// which in practice means the base domain was malformed or the concatenation
/// crossed the 255-byte limit.
pub fn endpoint_name(
    task_id: u64,
    tenant: &str,
    base_domain: &str,
) -> Result<Name, RegistrarError> {
    let slug = sanitise_label(tenant);
    let attempted = format!("{task_id}.{slug}.{base_domain}");
    let base = Name::from_ascii(base_domain).map_err(|e| RegistrarError::BadEndpointName {
        attempted: attempted.clone(),
        reason: e.to_string(),
    })?;
    let task = task_id.to_string();
    Name::prefixed(&base, [task.as_str(), slug.as_str()]).map_err(|e| {
        RegistrarError::BadEndpointName {
            attempted,
            reason: e.to_string(),
        }
    })
}

/// Fold an arbitrary tenant slug into something usable as a single DNS label.
///
/// Keeps `[a-z0-9-]`, lower-cases ASCII letters, maps everything else to `-`,
/// collapses runs of `-`, trims leading/trailing `-`, and truncates to the
/// 63-byte label limit. Falls back to `tenant` when nothing survives.
fn sanitise_label(input: &str) -> String {
    let mut out = String::with_capacity(input.len().min(63));
    let mut last_dash = false;
    for ch in input.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if mapped == '-' {
            if last_dash || out.is_empty() {
                continue;
            }
            last_dash = true;
        } else {
            last_dash = false;
        }
        if out.len() >= 63 {
            break;
        }
        out.push(mapped);
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "tenant".to_owned()
    } else {
        out
    }
}

/// Discover the local address the kernel would use to reach `peer`.
///
/// Sends nothing: `connect()` on a UDP socket only installs a default peer, and
/// `local_addr()` then reports the source address the routing table selected.
///
/// # Errors
/// [`RegistrarError::Io`] if the socket cannot be created, connected, or queried.
pub async fn detect_local_ip(peer: SocketAddr) -> Result<IpAddr, RegistrarError> {
    let bind: SocketAddr = if peer.is_ipv6() {
        SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u8, 0, 0, 0], 0))
    };
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| RegistrarError::Io {
            context: "bind probe socket for local-address detection",
            detail: e.to_string(),
        })?;
    sock.connect(peer).await.map_err(|e| RegistrarError::Io {
        context: "connect probe socket",
        detail: e.to_string(),
    })?;
    let local = sock.local_addr().map_err(|e| RegistrarError::Io {
        context: "read local address of probe socket",
        detail: e.to_string(),
    })?;
    Ok(local.ip())
}

/// Everything needed to register and later withdraw one worker's endpoint.
#[derive(Debug, Clone)]
pub struct Registrar {
    cfg: DnsConfig,
    zone: Name,
    fqdn: Name,
    address: IpAddr,
    key: Option<TsigKey>,
}

impl Registrar {
    /// Build a registrar, detecting the local address by probing `cfg.server`.
    ///
    /// # Errors
    /// - [`RegistrarError::BadEndpointName`] for a malformed zone or endpoint.
    /// - [`RegistrarError::Dns`] for a malformed TSIG key name or secret.
    /// - [`RegistrarError::Io`] if local-address detection fails.
    pub async fn bind(cfg: &DnsConfig, task_id: u64, tenant: &str) -> Result<Self, RegistrarError> {
        let address = detect_local_ip(cfg.server).await?;
        Self::with_address(cfg, task_id, tenant, address)
    }

    /// Build a registrar for a caller-supplied address, skipping detection.
    ///
    /// This is the seam the test suite uses, and it is also the right entry
    /// point when a supervisor already knows the worker's routable address (a
    /// NAT'd container, for instance, where the local address is not the address
    /// peers should use).
    ///
    /// # Errors
    /// As [`Registrar::bind`], minus the I/O cases.
    pub fn with_address(
        cfg: &DnsConfig,
        task_id: u64,
        tenant: &str,
        address: IpAddr,
    ) -> Result<Self, RegistrarError> {
        let zone = Name::from_ascii(&cfg.zone).map_err(|e| RegistrarError::BadEndpointName {
            attempted: cfg.zone.clone(),
            reason: e.to_string(),
        })?;
        let fqdn = endpoint_name(task_id, tenant, &cfg.base_domain)?;
        let key = match &cfg.tsig {
            Some(t) => Some(TsigKey::from_base64(
                &t.key_name,
                t.algorithm,
                &t.secret_b64,
            )?),
            None => None,
        };
        Ok(Self {
            cfg: cfg.clone(),
            zone,
            fqdn,
            address,
            key,
        })
    }

    /// The name this worker registers.
    #[must_use]
    pub const fn fqdn(&self) -> &Name {
        &self.fqdn
    }

    /// The address this worker registers.
    #[must_use]
    pub const fn address(&self) -> IpAddr {
        self.address
    }

    /// The zone being updated.
    #[must_use]
    pub const fn zone(&self) -> &Name {
        &self.zone
    }

    /// The server the `UPDATE` is sent to.
    #[must_use]
    pub const fn server(&self) -> SocketAddr {
        self.cfg.server
    }

    /// Whether TSIG signing is configured.
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.key.is_some()
    }

    /// Build the "add my address" packet for a given message id.
    ///
    /// Deterministic: the same id, config, and address always produce the same
    /// bytes (unless TSIG is configured, in which case `time_signed` also enters
    /// the MAC — pass a fixed `time_signed` to keep it reproducible).
    ///
    /// Returns the wire bytes and, when signed, the request MAC needed to verify
    /// the response.
    ///
    /// # Errors
    /// [`RegistrarError::Dns`] if the packet cannot be built or signed.
    pub fn build_register_packet(
        &self,
        id: u16,
        time_signed: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), RegistrarError> {
        let mut b = UpdateBuilder::with_id(self.zone.clone(), id);
        if self.cfg.require_absent {
            b.require_name_absent(&self.fqdn)?;
        }
        // Replace rather than accumulate: a recycled task id must not inherit a
        // dead worker's address, so clear the RRset first and then add ours.
        b.delete_rrset(&self.fqdn, address_rtype(self.address))?;
        b.add_address(&self.fqdn, self.cfg.ttl, self.address)?;
        self.finish_at(b, time_signed)
    }

    /// Build the "withdraw my address" packet for a given message id.
    ///
    /// Deletes only this worker's own RR (RFC 2136 §2.5.4, `CLASS=NONE`), so a
    /// shared round-robin name keeps its other members.
    ///
    /// # Errors
    /// [`RegistrarError::Dns`] if the packet cannot be built or signed.
    pub fn build_delete_packet(
        &self,
        id: u16,
        time_signed: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), RegistrarError> {
        let mut b = UpdateBuilder::with_id(self.zone.clone(), id);
        b.delete_address(&self.fqdn, self.address)?;
        self.finish_at(b, time_signed)
    }

    fn finish_at(
        &self,
        b: UpdateBuilder,
        time_signed: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), RegistrarError> {
        let mut msg = b.message()?;
        match (&self.key, &self.cfg.tsig) {
            (Some(key), Some(settings)) => {
                let (wire, mac) = sign_and_encode(&mut msg, key, time_signed, settings.fudge)?;
                Ok((wire, mac))
            }
            _ => Ok((msg.encode()?, Vec::new())),
        }
    }

    /// Register this worker's `A`/`AAAA` record.
    ///
    /// # Errors
    /// Anything [`send_update`] can return.
    pub async fn register(&self) -> Result<Rcode, RegistrarError> {
        let id = random_id();
        let (packet, mac) = self.build_register_packet(id, now_unix())?;
        self.exchange(id, &packet, &mac).await
    }

    /// Withdraw this worker's record.
    ///
    /// # Errors
    /// Anything [`send_update`] can return.
    pub async fn deregister(&self) -> Result<Rcode, RegistrarError> {
        let id = random_id();
        let (packet, mac) = self.build_delete_packet(id, now_unix())?;
        self.exchange(id, &packet, &mac).await
    }

    async fn exchange(
        &self,
        id: u16,
        packet: &[u8],
        request_mac: &[u8],
    ) -> Result<Rcode, RegistrarError> {
        let raw = send_update(self.cfg.server, packet, self.cfg.timeout, self.cfg.retries).await?;
        let msg = Message::decode(&raw)?;
        if !msg.header.flags.response {
            return Err(RegistrarError::NotAResponse);
        }
        if msg.header.id != id {
            return Err(RegistrarError::IdMismatch {
                expected: id,
                found: msg.header.id,
            });
        }
        if let Some(key) = &self.key {
            match verify_response(&raw, key, request_mac, now_unix()) {
                Ok(()) => {}
                // Some servers answer an unknown key with a bare NOTAUTH and no
                // TSIG RR at all. Reporting "no TSIG" would hide the actual,
                // actionable diagnosis, so let the RCODE speak in that case.
                Err(DnsError::MissingTsig) if msg.rcode().is_error() => {
                    return Err(RegistrarError::Rejected { rcode: msg.rcode() });
                }
                Err(e) => return Err(RegistrarError::Dns(e)),
            }
        }
        let rcode = msg.rcode();
        if rcode.is_error() {
            return Err(RegistrarError::Rejected { rcode });
        }
        Ok(rcode)
    }
}

/// Which record type carries this address family.
const fn address_rtype(addr: IpAddr) -> RecordType {
    match addr {
        IpAddr::V4(_) => RecordType::A,
        IpAddr::V6(_) => RecordType::Aaaa,
    }
}

/// Send a pre-built `UPDATE` over UDP and return the raw response bytes.
///
/// Retries `attempts` times with a per-attempt timeout. The packet is reused
/// verbatim on every retry, message id included, so a server that already
/// applied the first copy treats the retry as a duplicate rather than a second
/// mutation.
///
/// No EDNS0 `OPT` record is added and no 512-byte ceiling is enforced: the
/// `UPDATE` packets `ion` produces are 60-250 bytes even when TSIG-signed, well
/// inside what every server and every path MTU accepts.
///
/// # Errors
/// - [`RegistrarError::Io`] if the socket cannot be created or written.
/// - [`RegistrarError::Timeout`] if no attempt produced a response.
pub async fn send_update(
    server: SocketAddr,
    packet: &[u8],
    per_attempt: Duration,
    attempts: u32,
) -> Result<Vec<u8>, RegistrarError> {
    let bind: SocketAddr = if server.is_ipv6() {
        SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u8, 0, 0, 0], 0))
    };

    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| RegistrarError::Io {
            context: "bind UDP socket for DNS UPDATE",
            detail: e.to_string(),
        })?;
    sock.connect(server).await.map_err(|e| RegistrarError::Io {
        context: "connect UDP socket to DNS server",
        detail: e.to_string(),
    })?;

    let mut buf = vec![0u8; RESPONSE_BUFFER];
    for _ in 0..attempts.max(1) {
        sock.send(packet).await.map_err(|e| RegistrarError::Io {
            context: "send DNS UPDATE",
            detail: e.to_string(),
        })?;
        match tokio::time::timeout(per_attempt, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Ok(Err(e)) => {
                return Err(RegistrarError::Io {
                    context: "receive DNS response",
                    detail: e.to_string(),
                });
            }
            Err(_elapsed) => {}
        }
    }
    Err(RegistrarError::Timeout {
        attempts: attempts.max(1),
        per_attempt,
    })
}

/// Wait for `SIGTERM` or `SIGINT`.
///
/// Split out from [`graceful_shutdown`] so that the shutdown path is directly
/// callable from a test without raising a real signal at the process.
#[cfg(unix)]
pub async fn wait_for_termination() -> Termination {
    use tokio::signal::unix::{SignalKind, signal};

    let (mut term, mut int) = match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) {
        (Ok(t), Ok(i)) => (t, i),
        _ => return Termination::Unavailable,
    };
    tokio::select! {
        _ = term.recv() => Termination::Sigterm,
        _ = int.recv() => Termination::Sigint,
    }
}

/// Wait for a console interrupt on non-Unix hosts.
#[cfg(not(unix))]
pub async fn wait_for_termination() -> Termination {
    match tokio::signal::ctrl_c().await {
        Ok(()) => Termination::Sigint,
        Err(_) => Termination::Unavailable,
    }
}

/// Withdraw the endpoint. This is the entire shutdown path, as a plain function.
///
/// # Errors
/// Anything [`Registrar::deregister`] can return.
pub async fn graceful_shutdown(reg: &Registrar) -> Result<Rcode, RegistrarError> {
    reg.deregister().await
}

/// Register, wait for a termination signal, then de-register.
///
/// Returns the signal that ended the wait. A de-registration failure is
/// reported, not swallowed — but note that the endpoint will expire on its own
/// after `ttl` seconds regardless, which is why `ttl` defaults to 60.
///
/// # Errors
/// A registration failure aborts before the wait; a de-registration failure is
/// returned after it.
pub async fn serve_until_signal(reg: &Registrar) -> Result<Termination, RegistrarError> {
    reg.register().await?;
    let signal = wait_for_termination().await;
    graceful_shutdown(reg).await?;
    Ok(signal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_names_are_task_tenant_base() {
        let n = endpoint_name(42, "acme", "vxcloud.io.").unwrap();
        assert_eq!(n.to_string(), "42.acme.vxcloud.io.");
    }

    #[test]
    fn tenant_slugs_are_sanitised_into_one_legal_label() {
        assert_eq!(sanitise_label("Acme Corp"), "acme-corp");
        assert_eq!(sanitise_label("  ..  "), "tenant");
        assert_eq!(sanitise_label("a__b"), "a-b");
        assert_eq!(sanitise_label("-lead-and-trail-"), "lead-and-trail");
        assert_eq!(sanitise_label(&"x".repeat(200)).len(), 63);
        // Non-ASCII is not silently transliterated: each such byte becomes one
        // separator, which is lossy but always produces a legal label.
        assert_eq!(sanitise_label("Ünïcodé"), "n-cod");
    }

    #[test]
    fn sanitised_tenants_still_produce_valid_names() {
        let n = endpoint_name(7, "Big Customer, Inc.", "vxcloud.io.").unwrap();
        assert_eq!(n.to_string(), "7.big-customer-inc.vxcloud.io.");
        assert_eq!(n.label_count(), 4);
    }

    #[test]
    fn oversized_names_are_rejected_not_truncated() {
        let long_base = format!("{}.{}.", "b".repeat(63), "c".repeat(63));
        let err = endpoint_name(
            u64::MAX,
            &"t".repeat(63),
            &format!("{long_base}{long_base}"),
        );
        assert!(matches!(err, Err(RegistrarError::BadEndpointName { .. })));
    }

    #[test]
    fn address_rtype_follows_the_family() {
        assert_eq!(
            address_rtype(IpAddr::from([10, 0, 0, 1])),
            crate::dns::message::RecordType::A
        );
        assert_eq!(
            address_rtype(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])),
            crate::dns::message::RecordType::Aaaa
        );
    }
}
