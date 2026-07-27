//! Hand-rolled DNS wire codec, RFC 2136 dynamic `UPDATE`, and RFC 8945 TSIG.
//!
//! Everything here encodes and decodes raw bytes. There is no dependency on a
//! DNS library, no shell-out to `nsupdate`/`dig`/`kdig`, and no subprocess of
//! any kind — `ion` builds the packets itself and writes them to a UDP socket.
//!
//! ## Layer cake
//!
//! - [`name`] — RFC 1035 §3.1 domain-name encoding: length-prefixed labels,
//!   the 63-byte label limit, the 255-byte total-name limit, canonical
//!   (lowercased) form for TSIG, and pointer-following decompression for
//!   responses.
//! - [`message`] — RFC 1035 §4 message framing generalised over opcodes, so the
//!   same [`message::Message`] type serves a query, a response, and an `UPDATE`.
//! - [`update`] — RFC 2136 §2: the `UPDATE` opcode, the Zone/Prerequisite/Update
//!   section re-interpretation of the four `*COUNT` fields, and the specific
//!   `CLASS`/`TTL`/`RDLENGTH` encodings that distinguish *add*, *delete one RR*,
//!   *delete an RRset*, and *delete every RRset at a name*.
//! - [`tsig`] — RFC 8945: HMAC-SHA256 request signing, the canonical digest
//!   over "message ‖ TSIG variables", and response MAC verification.
//!
//! ## RFC 2136 section-count aliasing
//!
//! An `UPDATE` message reuses the four 16-bit counters of a standard DNS header
//! under different names. [`message::Header`] exposes both spellings:
//!
//! | Standard | RFC 2136 | Contents |
//! |---|---|---|
//! | `QDCOUNT` | `ZOCOUNT` | the zone being updated (one `SOA` question) |
//! | `ANCOUNT` | `PRCOUNT` | prerequisites |
//! | `NSCOUNT` | `UPCOUNT` | the updates themselves |
//! | `ARCOUNT` | `ADCOUNT` | additional data, including the TSIG RR |

use core::fmt;

pub mod message;
pub mod name;
pub mod tsig;
pub mod update;

/// The IANA-assigned port for DNS.
pub const DNS_PORT: u16 = 53;

/// Maximum size of a DNS message carried in a single unfragmented UDP datagram
/// without EDNS0 (RFC 1035 §4.2.1).
pub const MAX_UDP_PAYLOAD: usize = 512;

/// Every way the DNS codec can refuse to encode or decode something.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// A label exceeded the RFC 1035 63-byte limit.
    LabelTooLong {
        /// The offending length.
        len: usize,
    },
    /// A label was zero-length somewhere other than the root.
    EmptyLabel {
        /// The name it appeared in.
        name: String,
    },
    /// The encoded name exceeded the RFC 1035 255-byte wire limit.
    NameTooLong {
        /// The offending wire length.
        len: usize,
    },
    /// A name was the empty string (use `"."` for the root).
    EmptyName,
    /// A label held a byte outside the permitted printable-ASCII range.
    InvalidLabelByte {
        /// The offending byte.
        byte: u8,
    },
    /// The buffer ended in the middle of a field.
    Truncated {
        /// Byte offset at which decoding gave up.
        offset: usize,
        /// Bytes required from that offset.
        need: usize,
    },
    /// A compression pointer did not point strictly backwards.
    BadPointer {
        /// The offset the pointer named.
        target: usize,
        /// Where the pointer itself lived.
        at: usize,
    },
    /// Too many compression jumps: the message is malformed or adversarial.
    PointerLoop,
    /// The two high bits of a length octet were `0b10`, which is not defined.
    BadLabelType(u8),
    /// `RDATA` longer than the 16-bit `RDLENGTH` field can describe.
    RdataTooLong {
        /// The offending length.
        len: usize,
    },
    /// A section declared more records than the buffer contained.
    SectionUnderrun {
        /// Which of the four sections underran.
        section: &'static str,
        /// Records the header declared.
        declared: u16,
        /// Records actually decoded.
        decoded: u16,
    },
    /// `RDATA` had the wrong length for its record type.
    BadRdataLength {
        /// The record type involved.
        rtype: u16,
        /// The length that was found.
        len: usize,
    },
    /// The TSIG algorithm name is not one this build supports.
    UnsupportedTsigAlgorithm {
        /// The algorithm name as it appeared.
        name: String,
    },
    /// The TSIG shared secret was not valid base64.
    BadBase64 {
        /// Human-readable reason.
        reason: &'static str,
    },
    /// The expected TSIG RR was absent from the additional section.
    MissingTsig,
    /// The TSIG MAC did not verify against the shared secret.
    TsigVerifyFailed,
    /// The TSIG key name in a response did not match the key we signed with.
    TsigKeyMismatch {
        /// The key we expected.
        expected: String,
        /// The key the peer used.
        found: String,
    },
    /// `time_signed` was outside the fudge window.
    TsigBadTime {
        /// The peer's `time_signed`.
        signed: u64,
        /// Our clock.
        now: u64,
        /// The permitted skew in seconds.
        fudge: u64,
    },
    /// The TSIG RR reported a non-zero error code.
    TsigRemoteError {
        /// The extended RCODE the peer put in the TSIG `error` field.
        code: u16,
    },
    /// An `UPDATE` tried to touch a name outside the zone it names.
    ///
    /// A server would answer `NOTZONE` (RCODE 10); catching it locally saves a
    /// round trip and gives a clearer message.
    NotInZone {
        /// The out-of-zone name.
        name: String,
        /// The zone the `UPDATE` declared.
        zone: String,
    },
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LabelTooLong { len } => write!(
                f,
                "label is {len} bytes, RFC 1035 limit is {}",
                name::MAX_LABEL_LEN
            ),
            Self::EmptyLabel { name } => write!(f, "empty label in name {name:?}"),
            Self::NameTooLong { len } => write!(
                f,
                "encoded name is {len} bytes, RFC 1035 limit is {}",
                name::MAX_NAME_WIRE_LEN
            ),
            Self::EmptyName => write!(f, "empty domain name (use \".\" for the root)"),
            Self::InvalidLabelByte { byte } => {
                write!(f, "byte {byte:#04x} is not permitted in a label")
            }
            Self::Truncated { offset, need } => {
                write!(f, "truncated message: need {need} bytes at offset {offset}")
            }
            Self::BadPointer { target, at } => write!(
                f,
                "compression pointer at {at} targets {target}, which is not strictly earlier"
            ),
            Self::PointerLoop => write!(f, "compression pointer loop"),
            Self::BadLabelType(b) => write!(f, "reserved label type in length octet {b:#04x}"),
            Self::RdataTooLong { len } => {
                write!(f, "rdata is {len} bytes, RDLENGTH is a 16-bit field")
            }
            Self::SectionUnderrun {
                section,
                declared,
                decoded,
            } => write!(
                f,
                "{section} declared {declared} records but only {decoded} decoded"
            ),
            Self::BadRdataLength { rtype, len } => {
                write!(f, "rdata length {len} is invalid for record type {rtype}")
            }
            Self::UnsupportedTsigAlgorithm { name } => {
                write!(f, "unsupported TSIG algorithm {name:?}")
            }
            Self::BadBase64 { reason } => write!(f, "invalid base64 secret: {reason}"),
            Self::MissingTsig => write!(f, "response carried no TSIG RR"),
            Self::TsigVerifyFailed => write!(f, "TSIG MAC verification failed"),
            Self::TsigKeyMismatch { expected, found } => {
                write!(f, "TSIG key mismatch: expected {expected:?}, got {found:?}")
            }
            Self::TsigBadTime { signed, now, fudge } => write!(
                f,
                "TSIG time_signed {signed} is outside +/-{fudge}s of local time {now}"
            ),
            Self::TsigRemoteError { code } => {
                write!(f, "peer rejected our TSIG with error code {code}")
            }
            Self::NotInZone { name, zone } => {
                write!(f, "name {name} is not inside zone {zone}")
            }
        }
    }
}

impl std::error::Error for DnsError {}
