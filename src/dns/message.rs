//! DNS message framing: header, sections, resource records — encode and decode.
//!
//! The [`Message`] type is deliberately opcode-agnostic. RFC 1035 defines four
//! sections (question / answer / authority / additional) and RFC 2136 reuses the
//! same four slots with different names (zone / prerequisite / update /
//! additional). Rather than model two nearly-identical types, this module keeps
//! the RFC 1035 field names as the storage and offers RFC 2136 aliases on top —
//! see [`Message::zone`], [`Message::prerequisites`], [`Message::updates`].
//!
//! ## Header layout (RFC 1035 §4.1.1)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      ID                       |QR| Opcode|AA|TC|RD|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |RA| Z|AD|CD|   RCODE   |            QDCOUNT / ZOCOUNT          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            ANCOUNT / PRCOUNT                  | NSCOUNT/UPCOUNT
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            ARCOUNT / ADCOUNT                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Everything is big-endian ("network byte order"), which is the opposite of the
//! VxCloud ABI in [`crate::abi`] — a detail worth keeping straight.

use core::fmt;

use super::DnsError;
use super::name::Name;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the fixed DNS header in bytes.
pub const HEADER_LEN: usize = 12;

/// `QUERY` opcode (RFC 1035 §4.1.1).
pub const OPCODE_QUERY: u8 = 0;

/// `UPDATE` opcode (RFC 2136 §2).
pub const OPCODE_UPDATE: u8 = 5;

/// `CLASS IN` — the Internet class.
pub const CLASS_IN: u16 = 1;

/// `CLASS NONE` (RFC 2136 §2.4/§2.5) — "this RR must be absent" / "delete this
/// exact RR".
pub const CLASS_NONE: u16 = 254;

/// `CLASS ANY` (RFC 2136 §2.4/§2.5) — "this RRset must exist" / "delete the
/// whole RRset".
pub const CLASS_ANY: u16 = 255;

// ---------------------------------------------------------------------------
// Record types
// ---------------------------------------------------------------------------

/// A DNS `TYPE` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// IPv4 host address.
    A,
    /// Authoritative name server.
    Ns,
    /// Canonical name for an alias.
    Cname,
    /// Start of a zone of authority — the `QTYPE` of an `UPDATE` zone section.
    Soa,
    /// Domain name pointer.
    Ptr,
    /// Mail exchange.
    Mx,
    /// Text strings.
    Txt,
    /// IPv6 host address.
    Aaaa,
    /// Service locator.
    Srv,
    /// EDNS0 pseudo-record.
    Opt,
    /// Transaction signature (RFC 8945).
    Tsig,
    /// `*` — "any type", used by RFC 2136 delete operations.
    Any,
    /// Any other code, carried through verbatim.
    Other(u16),
}

impl RecordType {
    /// The numeric `TYPE` value.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Ptr => 12,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Srv => 33,
            Self::Opt => 41,
            Self::Tsig => 250,
            Self::Any => 255,
            Self::Other(c) => c,
        }
    }

    /// Decode a numeric `TYPE`. Unknown codes become [`RecordType::Other`].
    #[must_use]
    pub const fn from_code(code: u16) -> Self {
        match code {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            12 => Self::Ptr,
            15 => Self::Mx,
            16 => Self::Txt,
            28 => Self::Aaaa,
            33 => Self::Srv,
            41 => Self::Opt,
            250 => Self::Tsig,
            255 => Self::Any,
            other => Self::Other(other),
        }
    }

    /// The mnemonic used in zone files and `dig` output.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Ns => "NS",
            Self::Cname => "CNAME",
            Self::Soa => "SOA",
            Self::Ptr => "PTR",
            Self::Mx => "MX",
            Self::Txt => "TXT",
            Self::Aaaa => "AAAA",
            Self::Srv => "SRV",
            Self::Opt => "OPT",
            Self::Tsig => "TSIG",
            Self::Any => "ANY",
            Self::Other(_) => "TYPE",
        }
    }

    /// Expected `RDLENGTH` for the fixed-width address types.
    #[must_use]
    pub const fn fixed_rdlength(self) -> Option<usize> {
        match self {
            Self::A => Some(4),
            Self::Aaaa => Some(16),
            _ => None,
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(c) => write!(f, "TYPE{c}"),
            other => f.write_str(other.mnemonic()),
        }
    }
}

/// A DNS `CLASS` code, including the RFC 2136 pseudo-classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordClass {
    /// `IN` — the Internet class.
    In,
    /// `NONE` — RFC 2136's "must not exist" / "delete this exact RR".
    None,
    /// `ANY` — RFC 2136's "must exist" / "delete the whole RRset".
    Any,
    /// Any other code, carried through verbatim.
    Other(u16),
}

impl RecordClass {
    /// The numeric `CLASS` value.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::In => CLASS_IN,
            Self::None => CLASS_NONE,
            Self::Any => CLASS_ANY,
            Self::Other(c) => c,
        }
    }

    /// Decode a numeric `CLASS`.
    #[must_use]
    pub const fn from_code(code: u16) -> Self {
        match code {
            CLASS_IN => Self::In,
            CLASS_NONE => Self::None,
            CLASS_ANY => Self::Any,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for RecordClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::In => f.write_str("IN"),
            Self::None => f.write_str("NONE"),
            Self::Any => f.write_str("ANY"),
            Self::Other(c) => write!(f, "CLASS{c}"),
        }
    }
}

// ---------------------------------------------------------------------------
// RCODE
// ---------------------------------------------------------------------------

/// Response codes, including the RFC 2136 additions and the RFC 8945 TSIG
/// extended codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Rcode {
    /// No error.
    #[default]
    NoError,
    /// Format error.
    FormErr,
    /// Server failure.
    ServFail,
    /// Non-existent domain.
    NxDomain,
    /// Not implemented — a server that does not support dynamic update.
    NotImp,
    /// Query refused by policy.
    Refused,
    /// A name exists when it should not (RFC 2136).
    YxDomain,
    /// An RRset exists when it should not (RFC 2136).
    YxRrset,
    /// An RRset that should exist does not (RFC 2136).
    NxRrset,
    /// Server is not authoritative for the zone, or the TSIG key was not
    /// accepted for this operation (RFC 2136 / RFC 8945).
    NotAuth,
    /// A name used in the prerequisite or update section is out of zone.
    NotZone,
    /// TSIG signature failed to verify (RFC 8945).
    BadSig,
    /// Key not recognised (RFC 8945).
    BadKey,
    /// Signature out of time window (RFC 8945).
    BadTime,
    /// Bad TKEY mode.
    BadMode,
    /// Duplicate key name.
    BadName,
    /// Algorithm not supported.
    BadAlg,
    /// Bad truncation.
    BadTrunc,
    /// Any other code.
    Other(u16),
}

impl Rcode {
    /// The numeric value.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
            Self::YxDomain => 6,
            Self::YxRrset => 7,
            Self::NxRrset => 8,
            Self::NotAuth => 9,
            Self::NotZone => 10,
            Self::BadSig => 16,
            Self::BadKey => 17,
            Self::BadTime => 18,
            Self::BadMode => 19,
            Self::BadName => 20,
            Self::BadAlg => 21,
            Self::BadTrunc => 22,
            Self::Other(c) => c,
        }
    }

    /// Decode a numeric response code.
    #[must_use]
    pub const fn from_code(code: u16) -> Self {
        match code {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            6 => Self::YxDomain,
            7 => Self::YxRrset,
            8 => Self::NxRrset,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            16 => Self::BadSig,
            17 => Self::BadKey,
            18 => Self::BadTime,
            19 => Self::BadMode,
            20 => Self::BadName,
            21 => Self::BadAlg,
            22 => Self::BadTrunc,
            other => Self::Other(other),
        }
    }

    /// Whether this code represents a failure.
    #[must_use]
    pub const fn is_error(self) -> bool {
        !matches!(self, Self::NoError)
    }

    /// The standard mnemonic.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::NoError => "NOERROR",
            Self::FormErr => "FORMERR",
            Self::ServFail => "SERVFAIL",
            Self::NxDomain => "NXDOMAIN",
            Self::NotImp => "NOTIMP",
            Self::Refused => "REFUSED",
            Self::YxDomain => "YXDOMAIN",
            Self::YxRrset => "YXRRSET",
            Self::NxRrset => "NXRRSET",
            Self::NotAuth => "NOTAUTH",
            Self::NotZone => "NOTZONE",
            Self::BadSig => "BADSIG",
            Self::BadKey => "BADKEY",
            Self::BadTime => "BADTIME",
            Self::BadMode => "BADMODE",
            Self::BadName => "BADNAME",
            Self::BadAlg => "BADALG",
            Self::BadTrunc => "BADTRUNC",
            Self::Other(_) => "RCODE",
        }
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(c) => write!(f, "RCODE{c}"),
            other => f.write_str(other.mnemonic()),
        }
    }
}

// ---------------------------------------------------------------------------
// Flags and header
// ---------------------------------------------------------------------------

/// The second 16-bit word of a DNS header, unpacked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags {
    /// `QR` — set on a response.
    pub response: bool,
    /// `Opcode` — 0 `QUERY`, 5 `UPDATE`.
    pub opcode: u8,
    /// `AA` — authoritative answer.
    pub authoritative: bool,
    /// `TC` — truncated.
    pub truncated: bool,
    /// `RD` — recursion desired. Meaningless, and normally zero, for `UPDATE`.
    pub recursion_desired: bool,
    /// `RA` — recursion available.
    pub recursion_available: bool,
    /// `Z` — reserved, must be zero.
    pub zero: bool,
    /// `AD` — authentic data (DNSSEC).
    pub authentic_data: bool,
    /// `CD` — checking disabled (DNSSEC).
    pub checking_disabled: bool,
    /// `RCODE` — response code.
    pub rcode: Rcode,
}

impl Flags {
    /// Flags for an outbound RFC 2136 `UPDATE` request: opcode 5, everything
    /// else clear.
    #[must_use]
    pub fn update_request() -> Self {
        Self {
            opcode: OPCODE_UPDATE,
            ..Self::default()
        }
    }

    /// Pack into the on-wire 16-bit word.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        ((self.response as u16) << 15)
            | (((self.opcode as u16) & 0x0f) << 11)
            | ((self.authoritative as u16) << 10)
            | ((self.truncated as u16) << 9)
            | ((self.recursion_desired as u16) << 8)
            | ((self.recursion_available as u16) << 7)
            | ((self.zero as u16) << 6)
            | ((self.authentic_data as u16) << 5)
            | ((self.checking_disabled as u16) << 4)
            | (self.rcode.code() & 0x0f)
    }

    /// Unpack from the on-wire 16-bit word.
    #[must_use]
    pub const fn from_u16(raw: u16) -> Self {
        Self {
            response: raw & 0x8000 != 0,
            opcode: ((raw >> 11) & 0x0f) as u8,
            authoritative: raw & 0x0400 != 0,
            truncated: raw & 0x0200 != 0,
            recursion_desired: raw & 0x0100 != 0,
            recursion_available: raw & 0x0080 != 0,
            zero: raw & 0x0040 != 0,
            authentic_data: raw & 0x0020 != 0,
            checking_disabled: raw & 0x0010 != 0,
            rcode: Rcode::from_code(raw & 0x000f),
        }
    }
}

/// The fixed 12-byte DNS header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Message identifier, echoed by the responder.
    pub id: u16,
    /// The unpacked flags word.
    pub flags: Flags,
    /// The four section counters, in wire order.
    ///
    /// Index 0 is `QDCOUNT`/`ZOCOUNT`, 1 is `ANCOUNT`/`PRCOUNT`, 2 is
    /// `NSCOUNT`/`UPCOUNT`, 3 is `ARCOUNT`/`ADCOUNT`.
    pub counts: [u16; 4],
}

impl Header {
    /// `QDCOUNT` — question count.
    #[must_use]
    pub const fn qdcount(&self) -> u16 {
        self.counts[0]
    }
    /// `ANCOUNT` — answer count.
    #[must_use]
    pub const fn ancount(&self) -> u16 {
        self.counts[1]
    }
    /// `NSCOUNT` — authority count.
    #[must_use]
    pub const fn nscount(&self) -> u16 {
        self.counts[2]
    }
    /// `ARCOUNT` — additional count.
    #[must_use]
    pub const fn arcount(&self) -> u16 {
        self.counts[3]
    }
    /// `ZOCOUNT` — RFC 2136 alias of `QDCOUNT`.
    #[must_use]
    pub const fn zocount(&self) -> u16 {
        self.counts[0]
    }
    /// `PRCOUNT` — RFC 2136 alias of `ANCOUNT`.
    #[must_use]
    pub const fn prcount(&self) -> u16 {
        self.counts[1]
    }
    /// `UPCOUNT` — RFC 2136 alias of `NSCOUNT`.
    #[must_use]
    pub const fn upcount(&self) -> u16 {
        self.counts[2]
    }
    /// `ADCOUNT` — RFC 2136 alias of `ARCOUNT`.
    #[must_use]
    pub const fn adcount(&self) -> u16 {
        self.counts[3]
    }

    /// Append the 12 big-endian header bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_u16().to_be_bytes());
        for c in self.counts {
            out.extend_from_slice(&c.to_be_bytes());
        }
    }

    /// Decode the 12-byte header prefix of `buf`.
    ///
    /// # Errors
    /// [`DnsError::Truncated`] if fewer than 12 bytes are available.
    pub fn decode(buf: &[u8]) -> Result<Self, DnsError> {
        if buf.len() < HEADER_LEN {
            return Err(DnsError::Truncated {
                offset: 0,
                need: HEADER_LEN,
            });
        }
        let mut counts = [0u16; 4];
        for (i, slot) in counts.iter_mut().enumerate() {
            *slot = be_u16(buf, 4 + i * 2)?;
        }
        Ok(Self {
            id: be_u16(buf, 0)?,
            flags: Flags::from_u16(be_u16(buf, 2)?),
            counts,
        })
    }
}

// ---------------------------------------------------------------------------
// Question and resource record
// ---------------------------------------------------------------------------

/// An entry in the question section. In an `UPDATE` this is the zone being
/// modified, with `QTYPE = SOA` and `QCLASS = IN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// `QNAME`.
    pub name: Name,
    /// `QTYPE`.
    pub qtype: RecordType,
    /// `QCLASS`.
    pub qclass: RecordClass,
}

impl Question {
    /// The RFC 2136 §2.3 zone-section entry for `zone`.
    #[must_use]
    pub fn zone(zone: Name) -> Self {
        Self {
            name: zone,
            qtype: RecordType::Soa,
            qclass: RecordClass::In,
        }
    }

    /// Append the wire form to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        self.name.encode(out);
        out.extend_from_slice(&self.qtype.code().to_be_bytes());
        out.extend_from_slice(&self.qclass.code().to_be_bytes());
    }

    /// Decode one question at `pos`, returning it and the bytes consumed.
    ///
    /// # Errors
    /// Anything [`Name::read`] can raise, or [`DnsError::Truncated`].
    pub fn read(buf: &[u8], pos: usize) -> Result<(Self, usize), DnsError> {
        let (name, used) = Name::read(buf, pos)?;
        let qtype = be_u16(buf, pos + used)?;
        let qclass = be_u16(buf, pos + used + 2)?;
        Ok((
            Self {
                name,
                qtype: RecordType::from_code(qtype),
                qclass: RecordClass::from_code(qclass),
            },
            used + 4,
        ))
    }
}

/// A resource record. In the update section, `class`, `ttl`, and the length of
/// `rdata` together select add-versus-delete semantics — see
/// [`super::update`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// `NAME`.
    pub name: Name,
    /// `TYPE`.
    pub rtype: RecordType,
    /// `CLASS`.
    pub class: RecordClass,
    /// `TTL`.
    pub ttl: u32,
    /// `RDATA`, verbatim. `RDLENGTH` is derived from this on encode.
    pub rdata: Vec<u8>,
}

impl Record {
    /// Construct a record.
    #[must_use]
    pub fn new(
        name: Name,
        rtype: RecordType,
        class: RecordClass,
        ttl: u32,
        rdata: Vec<u8>,
    ) -> Self {
        Self {
            name,
            rtype,
            class,
            ttl,
            rdata,
        }
    }

    /// Append the wire form to `out`.
    ///
    /// # Errors
    /// [`DnsError::RdataTooLong`] if `rdata` will not fit a 16-bit `RDLENGTH`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), DnsError> {
        let rdlength = u16::try_from(self.rdata.len()).map_err(|_| DnsError::RdataTooLong {
            len: self.rdata.len(),
        })?;
        self.name.encode(out);
        out.extend_from_slice(&self.rtype.code().to_be_bytes());
        out.extend_from_slice(&self.class.code().to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        out.extend_from_slice(&rdlength.to_be_bytes());
        out.extend_from_slice(&self.rdata);
        Ok(())
    }

    /// Decode one record at `pos`, returning it and the bytes consumed.
    ///
    /// # Errors
    /// Anything [`Name::read`] can raise, or [`DnsError::Truncated`] if the
    /// declared `RDLENGTH` runs past the end of the buffer.
    pub fn read(buf: &[u8], pos: usize) -> Result<(Self, usize), DnsError> {
        let (name, used) = Name::read(buf, pos)?;
        let mut off = pos + used;
        let rtype = be_u16(buf, off)?;
        let class = be_u16(buf, off + 2)?;
        let ttl = be_u32(buf, off + 4)?;
        let rdlength = usize::from(be_u16(buf, off + 8)?);
        off += 10;
        let rdata = buf
            .get(off..off + rdlength)
            .ok_or(DnsError::Truncated {
                offset: off,
                need: rdlength,
            })?
            .to_vec();
        Ok((
            Self {
                name,
                rtype: RecordType::from_code(rtype),
                class: RecordClass::from_code(class),
                ttl,
                rdata,
            },
            used + 10 + rdlength,
        ))
    }

    /// Interpret `rdata` as an IPv4 address.
    ///
    /// # Errors
    /// [`DnsError::BadRdataLength`] unless `rdata` is exactly 4 bytes.
    pub fn as_ipv4(&self) -> Result<std::net::Ipv4Addr, DnsError> {
        let octets: [u8; 4] =
            self.rdata
                .as_slice()
                .try_into()
                .map_err(|_| DnsError::BadRdataLength {
                    rtype: self.rtype.code(),
                    len: self.rdata.len(),
                })?;
        Ok(std::net::Ipv4Addr::from(octets))
    }

    /// Interpret `rdata` as an IPv6 address.
    ///
    /// # Errors
    /// [`DnsError::BadRdataLength`] unless `rdata` is exactly 16 bytes.
    pub fn as_ipv6(&self) -> Result<std::net::Ipv6Addr, DnsError> {
        let octets: [u8; 16] =
            self.rdata
                .as_slice()
                .try_into()
                .map_err(|_| DnsError::BadRdataLength {
                    rtype: self.rtype.code(),
                    len: self.rdata.len(),
                })?;
        Ok(std::net::Ipv6Addr::from(octets))
    }
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

/// A complete DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The fixed header. Section counts are recomputed by [`Message::encode`],
    /// so callers never have to keep them in sync by hand.
    pub header: Header,
    /// Question section — the *zone* section of an `UPDATE`.
    pub questions: Vec<Question>,
    /// Answer section — the *prerequisite* section of an `UPDATE`.
    pub answers: Vec<Record>,
    /// Authority section — the *update* section of an `UPDATE`.
    pub authority: Vec<Record>,
    /// Additional section — where the TSIG RR lives.
    pub additional: Vec<Record>,
}

impl Message {
    /// An empty message with the given id and flags.
    #[must_use]
    pub fn new(id: u16, flags: Flags) -> Self {
        Self {
            header: Header {
                id,
                flags,
                counts: [0; 4],
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// RFC 2136 alias for the question section.
    #[must_use]
    pub fn zone(&self) -> &[Question] {
        &self.questions
    }
    /// RFC 2136 alias for the answer section.
    #[must_use]
    pub fn prerequisites(&self) -> &[Record] {
        &self.answers
    }
    /// RFC 2136 alias for the authority section.
    #[must_use]
    pub fn updates(&self) -> &[Record] {
        &self.authority
    }

    /// The response code carried in the header.
    #[must_use]
    pub const fn rcode(&self) -> Rcode {
        self.header.flags.rcode
    }

    /// Serialise the whole message, deriving the four section counts from the
    /// section vectors.
    ///
    /// Names are never compressed, so the output is a deterministic function of
    /// the message — the property TSIG signing depends on.
    ///
    /// # Errors
    /// [`DnsError::RdataTooLong`] from any record whose `rdata` overflows
    /// `RDLENGTH`.
    pub fn encode(&self) -> Result<Vec<u8>, DnsError> {
        let mut header = self.header;
        header.counts = [
            u16::try_from(self.questions.len()).unwrap_or(u16::MAX),
            u16::try_from(self.answers.len()).unwrap_or(u16::MAX),
            u16::try_from(self.authority.len()).unwrap_or(u16::MAX),
            u16::try_from(self.additional.len()).unwrap_or(u16::MAX),
        ];

        let mut out = Vec::with_capacity(HEADER_LEN + 64);
        header.encode(&mut out);
        for q in &self.questions {
            q.encode(&mut out);
        }
        for section in [&self.answers, &self.authority, &self.additional] {
            for rr in section {
                rr.encode(&mut out)?;
            }
        }
        Ok(out)
    }

    /// Parse a message off the wire.
    ///
    /// # Errors
    /// Any [`DnsError`] the name or record decoders can raise, plus
    /// [`DnsError::SectionUnderrun`] when a declared count cannot be satisfied.
    pub fn decode(buf: &[u8]) -> Result<Self, DnsError> {
        Self::decode_traced(buf).map(|(msg, _)| msg)
    }

    /// Like [`Message::decode`], but also returns the byte offset at which each
    /// additional-section record began.
    ///
    /// TSIG verification needs this: RFC 8945 digests the response *exactly as
    /// received* up to the start of the TSIG RR, and a re-encode would lose any
    /// name compression the peer used. Returning the offsets lets the verifier
    /// slice the original bytes instead of trusting a round-trip.
    ///
    /// # Errors
    /// As [`Message::decode`].
    pub fn decode_traced(buf: &[u8]) -> Result<(Self, Vec<usize>), DnsError> {
        let header = Header::decode(buf)?;
        let mut pos = HEADER_LEN;

        let mut questions = Vec::with_capacity(usize::from(header.qdcount()).min(16));
        for i in 0..header.qdcount() {
            let (q, used) = Question::read(buf, pos)
                .map_err(|e| underrun("question", header.qdcount(), i, e))?;
            questions.push(q);
            pos += used;
        }

        let mut sections: [Vec<Record>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        let labels = ["answer", "authority", "additional"];
        let mut additional_offsets = Vec::new();

        for (idx, section) in sections.iter_mut().enumerate() {
            let declared = header.counts[idx + 1];
            section.reserve(usize::from(declared).min(16));
            for i in 0..declared {
                if idx == 2 {
                    additional_offsets.push(pos);
                }
                let (rr, used) =
                    Record::read(buf, pos).map_err(|e| underrun(labels[idx], declared, i, e))?;
                section.push(rr);
                pos += used;
            }
        }

        let [answers, authority, additional] = sections;
        Ok((
            Self {
                header,
                questions,
                answers,
                authority,
                additional,
            },
            additional_offsets,
        ))
    }

    /// Find the first record of a given type in the additional section.
    #[must_use]
    pub fn find_additional(&self, rtype: RecordType) -> Option<&Record> {
        self.additional.iter().find(|r| r.rtype == rtype)
    }
}

/// Turn a mid-section decode failure into a `SectionUnderrun`, preserving the
/// underlying cause for `Truncated`-style errors that are not really underruns.
fn underrun(section: &'static str, declared: u16, decoded: u16, cause: DnsError) -> DnsError {
    match cause {
        DnsError::Truncated { .. } => DnsError::SectionUnderrun {
            section,
            declared,
            decoded,
        },
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Big-endian scalar readers
// ---------------------------------------------------------------------------

/// Read a big-endian `u16` at `off`.
///
/// # Errors
/// [`DnsError::Truncated`] if the two bytes are not both present.
pub fn be_u16(buf: &[u8], off: usize) -> Result<u16, DnsError> {
    let raw = buf.get(off..off + 2).ok_or(DnsError::Truncated {
        offset: off,
        need: 2,
    })?;
    let mut a = [0u8; 2];
    a.copy_from_slice(raw);
    Ok(u16::from_be_bytes(a))
}

/// Read a big-endian `u32` at `off`.
///
/// # Errors
/// [`DnsError::Truncated`] if the four bytes are not all present.
pub fn be_u32(buf: &[u8], off: usize) -> Result<u32, DnsError> {
    let raw = buf.get(off..off + 4).ok_or(DnsError::Truncated {
        offset: off,
        need: 4,
    })?;
    let mut a = [0u8; 4];
    a.copy_from_slice(raw);
    Ok(u32::from_be_bytes(a))
}

/// Read a big-endian 48-bit unsigned integer at `off`, widened to `u64`.
///
/// Used for the TSIG `time_signed` field, which RFC 8945 defines as 48 bits so
/// it will not wrap in 2038.
///
/// # Errors
/// [`DnsError::Truncated`] if the six bytes are not all present.
pub fn be_u48(buf: &[u8], off: usize) -> Result<u64, DnsError> {
    let raw = buf.get(off..off + 6).ok_or(DnsError::Truncated {
        offset: off,
        need: 6,
    })?;
    let mut acc = 0u64;
    for &b in raw {
        acc = (acc << 8) | u64::from(b);
    }
    Ok(acc)
}

/// Encode the low 48 bits of `value` big-endian and append them to `out`.
pub fn push_u48(out: &mut Vec<u8>, value: u64) {
    let be = value.to_be_bytes();
    out.extend_from_slice(be.get(2..8).unwrap_or(&[]));
}

/// A 16-bit message identifier drawn from the kernel CSPRNG.
///
/// Falls back to a clock-derived value if `/dev/urandom` is unavailable, which
/// only degrades off-path spoofing resistance; TSIG signing, when configured, is
/// what actually authenticates the exchange.
#[must_use]
pub fn random_id() -> u16 {
    use std::io::Read as _;

    let mut buf = [0u8; 2];
    let seeded = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok();
    if seeded {
        return u16::from_be_bytes(buf);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| d.as_nanos() as u64);
    let mixed = nanos ^ (nanos >> 17) ^ (u64::from(std::process::id()) << 7);
    (mixed & 0xffff) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_flags_pack_to_opcode_five() {
        let f = Flags::update_request();
        assert_eq!(f.to_u16(), 0x2800, "QR=0, opcode=5<<11, rest clear");
        assert_eq!(Flags::from_u16(0x2800), f);
    }

    #[test]
    fn flags_round_trip_every_bit() {
        for raw in [0x0000u16, 0x2800, 0x8400, 0xffff, 0x8503] {
            let round = Flags::from_u16(raw).to_u16();
            // Bits 4..6 of the low byte are AD/CD/Z which we model exactly, so
            // the only lossy part is a >4-bit rcode, which cannot occur here.
            assert_eq!(round, raw, "flags {raw:#06x} must round-trip");
        }
    }

    #[test]
    fn header_encodes_twelve_big_endian_bytes() {
        let h = Header {
            id: 0x1234,
            flags: Flags::update_request(),
            counts: [1, 0, 1, 0],
        };
        let mut out = Vec::new();
        h.encode(&mut out);
        assert_eq!(
            out,
            vec![
                0x12, 0x34, 0x28, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
            ]
        );
        assert_eq!(Header::decode(&out).unwrap(), h);
    }

    #[test]
    fn rcode_names_cover_rfc2136_and_tsig() {
        assert_eq!(Rcode::from_code(9), Rcode::NotAuth);
        assert_eq!(Rcode::from_code(8).mnemonic(), "NXRRSET");
        assert_eq!(Rcode::from_code(16).mnemonic(), "BADSIG");
        assert!(Rcode::NxRrset.is_error());
        assert!(!Rcode::NoError.is_error());
        assert_eq!(Rcode::Other(4095).to_string(), "RCODE4095");
    }

    #[test]
    fn u48_round_trips() {
        let mut out = Vec::new();
        push_u48(&mut out, 0x0000_1234_5678_9abc);
        assert_eq!(out, vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
        assert_eq!(be_u48(&out, 0).unwrap(), 0x0000_1234_5678_9abc);
    }

    #[test]
    fn truncated_reads_are_errors_not_panics() {
        assert!(be_u16(&[0x01], 0).is_err());
        assert!(be_u32(&[0x01, 0x02], 0).is_err());
        assert!(be_u48(&[0x01, 0x02, 0x03], 0).is_err());
        assert!(Header::decode(&[0u8; 11]).is_err());
        assert!(Message::decode(&[]).is_err());
    }
}
