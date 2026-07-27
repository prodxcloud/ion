//! RFC 8945 TSIG — HMAC-SHA256 transaction signatures for DNS.
//!
//! TSIG authenticates a *transaction*, not a zone: the requester and the server
//! share a symmetric key, and each message carries an HMAC over the message plus
//! a set of "TSIG variables". This is what an RFC 2136 `UPDATE` normally uses to
//! prove it is allowed to mutate a zone.
//!
//! ## The TSIG RR
//!
//! The signature travels as the **last** record of the additional section:
//!
//! ```text
//! NAME      the key name (e.g. "vxcloud-registrar.")
//! TYPE      TSIG (250)
//! CLASS     ANY (255)
//! TTL       0
//! RDLENGTH  length of the RDATA below
//! RDATA
//!   Algorithm Name  domain name, e.g. "hmac-sha256."
//!   Time Signed     48-bit seconds since the UNIX epoch
//!   Fudge           16-bit permitted clock skew, seconds
//!   MAC Size        16-bit
//!   MAC             MAC Size bytes
//!   Original ID     16-bit copy of the message ID
//!   Error           16-bit extended RCODE
//!   Other Len       16-bit
//!   Other Data      Other Len bytes (a server clock, when Error == BADTIME)
//! ```
//!
//! ## What gets hashed (RFC 8945 §5.3.2)
//!
//! For a **request** the digest input is the concatenation of:
//!
//! 1. the complete DNS message *before* the TSIG RR is appended, i.e. with
//!    `ARCOUNT` **not** counting the TSIG; then
//! 2. the *TSIG variables*: the key name in canonical form, `CLASS` (`ANY`),
//!    `TTL` (0), the algorithm name in canonical form, `Time Signed`, `Fudge`,
//!    `Error`, `Other Len`, and `Other Data`.
//!
//! Note what is **absent** from that list: `MAC Size`, `MAC`, and `Original ID`
//! are not hashed. Getting this wrong is the classic TSIG bug, and it is why
//! this module builds the digest buffer explicitly instead of re-serialising the
//! finished record.
//!
//! For a **response** the digest is prefixed with the request's MAC, itself
//! prefixed by a 16-bit length:
//!
//! ```text
//! digest = u16(len(request_mac)) ‖ request_mac ‖ response_message ‖ tsig_variables
//! ```
//!
//! ## Security note
//!
//! [`TsigKey`] implements [`Debug`](core::fmt::Debug) by hand so a key can never
//! be spilled into a log line. The secret is only ever read from the process
//! environment or an explicitly-passed argument — never from a file inside this
//! repository.

use core::fmt;

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

use super::DnsError;
use super::message::{
    CLASS_ANY, Message, Record, RecordClass, RecordType, be_u16, be_u48, push_u48,
};
use super::name::Name;

/// Default fudge in seconds: the clock skew a signer asks the verifier to
/// tolerate. RFC 8945 §5.2.1 recommends 300.
pub const DEFAULT_FUDGE: u16 = 300;

/// Fixed size of the non-variable-length tail of TSIG `RDATA`:
/// `time_signed(6) + fudge(2) + mac_size(2) + original_id(2) + error(2) + other_len(2)`.
const RDATA_FIXED_TAIL: usize = 16;

// ---------------------------------------------------------------------------
// Algorithms
// ---------------------------------------------------------------------------

/// The TSIG MAC algorithms this build supports.
///
/// The truncated and MD5/SHA1 variants are deliberately omitted: `hmac-md5` is
/// broken, and a micro-worker has no reason to negotiate downwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TsigAlgorithm {
    /// `hmac-sha256.` — RFC 8945's mandatory-to-implement algorithm.
    #[default]
    HmacSha256,
    /// `hmac-sha512.`
    HmacSha512,
}

impl TsigAlgorithm {
    /// The algorithm's domain name as it appears in `RDATA`.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::HmacSha256 => "hmac-sha256.",
            Self::HmacSha512 => "hmac-sha512.",
        }
    }

    /// Length of the MAC this algorithm produces, in bytes.
    #[must_use]
    pub const fn mac_len(self) -> usize {
        match self {
            Self::HmacSha256 => 32,
            Self::HmacSha512 => 64,
        }
    }

    /// Parse an algorithm name, with or without the trailing dot, case
    /// insensitively.
    ///
    /// # Errors
    /// [`DnsError::UnsupportedTsigAlgorithm`] for anything else.
    pub fn from_name(name: &str) -> Result<Self, DnsError> {
        let normalised = name.trim_end_matches('.').to_ascii_lowercase();
        match normalised.as_str() {
            "hmac-sha256" => Ok(Self::HmacSha256),
            "hmac-sha512" => Ok(Self::HmacSha512),
            _ => Err(DnsError::UnsupportedTsigAlgorithm {
                name: name.to_owned(),
            }),
        }
    }

    /// Compute the MAC over `data` with `secret`.
    fn mac(self, secret: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            // `new_from_slice` on an HMAC accepts a key of any length — it is
            // the hash-then-pad construction that makes this infallible — so the
            // error branch is unreachable and we fall back to an empty key
            // rather than panicking.
            Self::HmacSha256 => match Hmac::<Sha256>::new_from_slice(secret) {
                Ok(mut m) => {
                    m.update(data);
                    m.finalize().into_bytes().to_vec()
                }
                Err(_) => Vec::new(),
            },
            Self::HmacSha512 => match Hmac::<Sha512>::new_from_slice(secret) {
                Ok(mut m) => {
                    m.update(data);
                    m.finalize().into_bytes().to_vec()
                }
                Err(_) => Vec::new(),
            },
        }
    }
}

impl fmt::Display for TsigAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

// ---------------------------------------------------------------------------
// Key
// ---------------------------------------------------------------------------

/// A TSIG shared secret plus the key name and algorithm it is bound to.
#[derive(Clone)]
pub struct TsigKey {
    name: Name,
    algorithm: TsigAlgorithm,
    secret: Vec<u8>,
}

impl TsigKey {
    /// Build a key from raw secret bytes.
    ///
    /// # Errors
    /// Anything [`Name::from_ascii`] can raise for `name`.
    pub fn new(name: &str, algorithm: TsigAlgorithm, secret: Vec<u8>) -> Result<Self, DnsError> {
        Ok(Self {
            name: Name::from_ascii(name)?,
            algorithm,
            secret,
        })
    }

    /// Build a key from a base64 secret, the form `named.conf` and `tsig-keygen`
    /// emit.
    ///
    /// # Errors
    /// [`DnsError::BadBase64`] for a malformed secret, or a name error.
    pub fn from_base64(
        name: &str,
        algorithm: TsigAlgorithm,
        secret_b64: &str,
    ) -> Result<Self, DnsError> {
        Self::new(name, algorithm, decode_base64(secret_b64)?)
    }

    /// The key name.
    #[must_use]
    pub const fn name(&self) -> &Name {
        &self.name
    }

    /// The MAC algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> TsigAlgorithm {
        self.algorithm
    }
}

impl fmt::Debug for TsigKey {
    /// Redacts the secret. A TSIG key is a credential; it must never reach a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsigKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("secret", &"<redacted>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// RDATA
// ---------------------------------------------------------------------------

/// The parsed `RDATA` of a TSIG RR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsigRdata {
    /// Algorithm name, e.g. `hmac-sha256.`.
    pub algorithm: Name,
    /// Seconds since the UNIX epoch, 48 bits on the wire.
    pub time_signed: u64,
    /// Permitted clock skew in seconds.
    pub fudge: u16,
    /// The MAC itself.
    pub mac: Vec<u8>,
    /// A copy of the enclosing message's ID.
    pub original_id: u16,
    /// Extended RCODE: 0, or `BADSIG`/`BADKEY`/`BADTIME` from a rejecting peer.
    pub error: u16,
    /// Extra data; carries the server's clock when `error == BADTIME`.
    pub other: Vec<u8>,
}

impl TsigRdata {
    /// Serialise to wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.algorithm.wire_len() + RDATA_FIXED_TAIL + self.mac.len() + self.other.len(),
        );
        self.algorithm.encode(&mut out);
        push_u48(&mut out, self.time_signed);
        out.extend_from_slice(&self.fudge.to_be_bytes());
        let mac_size = u16::try_from(self.mac.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&mac_size.to_be_bytes());
        out.extend_from_slice(&self.mac);
        out.extend_from_slice(&self.original_id.to_be_bytes());
        out.extend_from_slice(&self.error.to_be_bytes());
        let other_len = u16::try_from(self.other.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&other_len.to_be_bytes());
        out.extend_from_slice(&self.other);
        out
    }

    /// Parse TSIG `RDATA`.
    ///
    /// The algorithm name inside `RDATA` is read with the plain name decoder,
    /// which tolerates but does not require compression — RFC 8945 §4.2 forbids
    /// compressing it.
    ///
    /// # Errors
    /// [`DnsError::Truncated`] on a short buffer, or any name-decoding error.
    pub fn decode(rdata: &[u8]) -> Result<Self, DnsError> {
        let (algorithm, used) = Name::read(rdata, 0)?;
        let mut off = used;
        let time_signed = be_u48(rdata, off)?;
        off += 6;
        let fudge = be_u16(rdata, off)?;
        off += 2;
        let mac_size = usize::from(be_u16(rdata, off)?);
        off += 2;
        let mac = rdata
            .get(off..off + mac_size)
            .ok_or(DnsError::Truncated {
                offset: off,
                need: mac_size,
            })?
            .to_vec();
        off += mac_size;
        let original_id = be_u16(rdata, off)?;
        off += 2;
        let error = be_u16(rdata, off)?;
        off += 2;
        let other_len = usize::from(be_u16(rdata, off)?);
        off += 2;
        let other = rdata
            .get(off..off + other_len)
            .ok_or(DnsError::Truncated {
                offset: off,
                need: other_len,
            })?
            .to_vec();
        Ok(Self {
            algorithm,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other,
        })
    }
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Append the RFC 8945 §4.3.3 "TSIG variables" to `out`.
///
/// Deliberately excludes `MAC Size`, `MAC`, and `Original ID` — those are part
/// of the record but not of the digest.
fn push_tsig_variables(
    out: &mut Vec<u8>,
    key_name: &Name,
    algorithm: &Name,
    time_signed: u64,
    fudge: u16,
    error: u16,
    other: &[u8],
) {
    key_name.encode_canonical(out);
    out.extend_from_slice(&CLASS_ANY.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // TTL is always zero
    algorithm.encode_canonical(out);
    push_u48(out, time_signed);
    out.extend_from_slice(&fudge.to_be_bytes());
    out.extend_from_slice(&error.to_be_bytes());
    let other_len = u16::try_from(other.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&other_len.to_be_bytes());
    out.extend_from_slice(other);
}

/// Sign `msg` in place: computes the MAC, appends the TSIG RR to the additional
/// section (which bumps `ADCOUNT` on the next encode), and returns the MAC.
///
/// `time_signed` is seconds since the UNIX epoch. Passing it explicitly rather
/// than reading the clock internally is what makes signing deterministic and
/// therefore testable.
///
/// # Errors
/// [`DnsError::RdataTooLong`] if the message cannot be encoded.
pub fn sign_request(
    msg: &mut Message,
    key: &TsigKey,
    time_signed: u64,
    fudge: u16,
) -> Result<Vec<u8>, DnsError> {
    let algorithm_name = Name::from_ascii(key.algorithm.wire_name())?;

    // Step 1: the message exactly as it stands, with ADCOUNT *not* counting the
    // TSIG RR we are about to add.
    let mut digest_input = msg.encode()?;

    // Step 2: the TSIG variables.
    push_tsig_variables(
        &mut digest_input,
        &key.name,
        &algorithm_name,
        time_signed,
        fudge,
        0,
        &[],
    );

    let mac = key.algorithm.mac(&key.secret, &digest_input);

    let rdata = TsigRdata {
        algorithm: algorithm_name,
        time_signed,
        fudge,
        mac: mac.clone(),
        original_id: msg.header.id,
        error: 0,
        other: Vec::new(),
    };

    msg.additional.push(Record::new(
        key.name.clone(),
        RecordType::Tsig,
        RecordClass::Any,
        0,
        rdata.encode(),
    ));
    // `Message::encode` derives the counts anyway, but keeping the in-memory
    // header consistent means a caller that inspects `adcount()` after signing
    // sees the truth rather than the pre-signing value.
    msg.header.counts[3] = u16::try_from(msg.additional.len()).unwrap_or(u16::MAX);
    Ok(mac)
}

/// Sign and serialise in one step.
///
/// Returns `(wire_bytes, request_mac)`. Keep the MAC: verifying the server's
/// response requires it.
///
/// # Errors
/// As [`sign_request`].
pub fn sign_and_encode(
    msg: &mut Message,
    key: &TsigKey,
    time_signed: u64,
    fudge: u16,
) -> Result<(Vec<u8>, Vec<u8>), DnsError> {
    let mac = sign_request(msg, key, time_signed, fudge)?;
    let wire = msg.encode()?;
    Ok((wire, mac))
}

/// Sign a **response**, whose digest is prefixed with the request's MAC.
///
/// `ion` is a requester and never needs this in production; it exists so that the
/// response-verification path in [`verify_response`] can be exercised against a
/// real signed response rather than a hand-assembled fixture, and so that a
/// caller embedding `ion` on the server side of an internal control plane has the
/// matching half of the pair.
///
/// # Errors
/// [`DnsError::RdataTooLong`] if the message cannot be encoded.
pub fn sign_response(
    msg: &mut Message,
    key: &TsigKey,
    request_mac: &[u8],
    time_signed: u64,
    fudge: u16,
) -> Result<Vec<u8>, DnsError> {
    let algorithm_name = Name::from_ascii(key.algorithm.wire_name())?;

    let mut digest_input = Vec::new();
    let request_mac_len = u16::try_from(request_mac.len()).unwrap_or(u16::MAX);
    digest_input.extend_from_slice(&request_mac_len.to_be_bytes());
    digest_input.extend_from_slice(request_mac);
    digest_input.extend_from_slice(&msg.encode()?);
    push_tsig_variables(
        &mut digest_input,
        &key.name,
        &algorithm_name,
        time_signed,
        fudge,
        0,
        &[],
    );

    let mac = key.algorithm.mac(&key.secret, &digest_input);
    let rdata = TsigRdata {
        algorithm: algorithm_name,
        time_signed,
        fudge,
        mac: mac.clone(),
        original_id: msg.header.id,
        error: 0,
        other: Vec::new(),
    };
    msg.additional.push(Record::new(
        key.name.clone(),
        RecordType::Tsig,
        RecordClass::Any,
        0,
        rdata.encode(),
    ));
    msg.header.counts[3] = u16::try_from(msg.additional.len()).unwrap_or(u16::MAX);
    Ok(mac)
}

/// Seconds since the UNIX epoch, saturating at 0 if the clock is before 1970.
#[must_use]
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify the TSIG on a response, given the MAC of the request it answers.
///
/// `response` must be the bytes **exactly as received**. The digest is taken
/// over a prefix of those bytes rather than a re-encode, because a re-encode
/// would drop any name compression the server used and produce a different hash.
///
/// # Errors
/// - [`DnsError::MissingTsig`] if the response has no TSIG RR.
/// - [`DnsError::TsigKeyMismatch`] if it is signed with a different key.
/// - [`DnsError::TsigRemoteError`] if the peer set the `error` field, e.g.
///   `BADKEY` or `BADTIME`.
/// - [`DnsError::TsigBadTime`] if `time_signed` is outside `fudge` of `now`.
/// - [`DnsError::TsigVerifyFailed`] if the MAC does not match.
pub fn verify_response(
    response: &[u8],
    key: &TsigKey,
    request_mac: &[u8],
    now: u64,
) -> Result<(), DnsError> {
    let (msg, additional_offsets) = Message::decode_traced(response)?;

    // RFC 8945 §5.2: the TSIG RR is the last record of the additional section.
    let idx = msg
        .additional
        .iter()
        .position(|r| r.rtype == RecordType::Tsig)
        .ok_or(DnsError::MissingTsig)?;
    let tsig_rr = msg.additional.get(idx).ok_or(DnsError::MissingTsig)?;
    let tsig_start = *additional_offsets.get(idx).ok_or(DnsError::MissingTsig)?;

    if !tsig_rr
        .name
        .as_wire()
        .eq_ignore_ascii_case(key.name.as_wire())
    {
        return Err(DnsError::TsigKeyMismatch {
            expected: key.name.to_string(),
            found: tsig_rr.name.to_string(),
        });
    }

    let rdata = TsigRdata::decode(&tsig_rr.rdata)?;
    if rdata.error != 0 {
        return Err(DnsError::TsigRemoteError { code: rdata.error });
    }

    let fudge = u64::from(rdata.fudge);
    if now.abs_diff(rdata.time_signed) > fudge {
        return Err(DnsError::TsigBadTime {
            signed: rdata.time_signed,
            now,
            fudge,
        });
    }

    // Rebuild the digest: request MAC, then the response truncated just before
    // the TSIG RR with ARCOUNT decremented, then the response's TSIG variables.
    let mut digest_input = Vec::with_capacity(response.len() + 64);
    let request_mac_len = u16::try_from(request_mac.len()).unwrap_or(u16::MAX);
    digest_input.extend_from_slice(&request_mac_len.to_be_bytes());
    digest_input.extend_from_slice(request_mac);

    let body = response.get(..tsig_start).ok_or(DnsError::Truncated {
        offset: tsig_start,
        need: 0,
    })?;
    digest_input.extend_from_slice(body);
    // Patch ARCOUNT (offset 10..12) down by one so it excludes the TSIG RR.
    let patched = msg.header.arcount().saturating_sub(1).to_be_bytes();
    let arcount_slot = digest_input
        .len()
        .checked_sub(body.len())
        .and_then(|base| base.checked_add(10))
        .ok_or(DnsError::Truncated {
            offset: 10,
            need: 2,
        })?;
    if let Some(slot) = digest_input.get_mut(arcount_slot..arcount_slot + 2) {
        slot.copy_from_slice(&patched);
    }

    push_tsig_variables(
        &mut digest_input,
        &key.name,
        &rdata.algorithm,
        rdata.time_signed,
        rdata.fudge,
        rdata.error,
        &rdata.other,
    );

    let expected = key.algorithm.mac(&key.secret, &digest_input);
    if constant_time_eq(&expected, &rdata.mac) {
        Ok(())
    } else {
        Err(DnsError::TsigVerifyFailed)
    }
}

/// Compare two byte strings without an early exit, so a timing side channel
/// cannot be used to forge a MAC byte by byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// base64
// ---------------------------------------------------------------------------

/// Decode a standard-alphabet, `=`-padded base64 string.
///
/// Implemented here rather than pulled in as a dependency: it is 40 lines, it
/// keeps the footprint down, and a TSIG secret is exactly the sort of input that
/// should not be handed to a crate we have not read.
///
/// Whitespace is ignored so that a secret copy-pasted out of a `named.conf`
/// still works.
///
/// # Errors
/// [`DnsError::BadBase64`] for an invalid character, bad padding, or a length
/// that is not a whole number of 4-character groups.
pub fn decode_base64(input: &str) -> Result<Vec<u8>, DnsError> {
    const INVALID: u8 = 0xff;

    fn value_of(c: u8) -> u8 {
        match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => INVALID,
        }
    }

    let cleaned: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    if cleaned.len() % 4 != 0 {
        return Err(DnsError::BadBase64 {
            reason: "length is not a multiple of 4",
        });
    }

    let padding = cleaned.iter().rev().take_while(|&&b| b == b'=').count();
    if padding > 2 {
        return Err(DnsError::BadBase64 {
            reason: "more than two padding characters",
        });
    }
    let body = cleaned
        .get(..cleaned.len() - padding)
        .ok_or(DnsError::BadBase64 {
            reason: "malformed padding",
        })?;
    if body.contains(&b'=') {
        return Err(DnsError::BadBase64 {
            reason: "padding character in the middle of the input",
        });
    }

    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in body {
        let v = value_of(c);
        if v == INVALID {
            return Err(DnsError::BadBase64 {
                reason: "character outside the standard base64 alphabet",
            });
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Encode bytes as standard-alphabet, `=`-padded base64.
///
/// Only used for diagnostics and tests; kept next to the decoder so the two
/// cannot drift apart.
#[must_use]
pub fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let triple = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for i in 0..4 {
            if i <= chunk.len() {
                let idx = ((triple >> (18 - i * 6)) & 0x3f) as usize;
                out.push(char::from(ALPHABET.get(idx).copied().unwrap_or(b'A')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Render bytes as lower-case hex. Used by `ion selftest` and the test vectors.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let hi = HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'?');
        let lo = HEX.get(usize::from(b & 0x0f)).copied().unwrap_or(b'?');
        s.push(char::from(hi));
        s.push(char::from(lo));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4231_test_case_2_proves_the_hmac_primitive() {
        // RFC 4231 §4.3: key = "Jefe", data = "what do ya want for nothing?"
        let mac = TsigAlgorithm::HmacSha256.mac(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            to_hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn sha512_variant_is_wired_to_a_different_64_byte_mac() {
        // The RFC 4231 vector above proves the HMAC construction and this
        // module's use of it. For the SHA-512 variant we assert the properties
        // that could actually regress: output width, determinism, and that the
        // algorithm selector really does switch hash.
        let a = TsigAlgorithm::HmacSha512.mac(b"Jefe", b"what do ya want for nothing?");
        let b = TsigAlgorithm::HmacSha512.mac(b"Jefe", b"what do ya want for nothing?");
        let s256 = TsigAlgorithm::HmacSha256.mac(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(a.len(), 64);
        assert_eq!(TsigAlgorithm::HmacSha512.mac_len(), 64);
        assert_eq!(a, b, "the MAC must be deterministic");
        assert_ne!(a.get(..32), s256.get(..32));
    }

    #[test]
    fn base64_round_trips() {
        for raw in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0u8, 255, 128, 1, 2, 3][..],
        ] {
            let encoded = encode_base64(raw);
            assert_eq!(
                decode_base64(&encoded).unwrap(),
                raw.to_vec(),
                "round trip failed for {raw:?} -> {encoded}"
            );
        }
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(encode_base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode_base64(b"fo"), "Zm8=");
        assert_eq!(decode_base64("Zm9vYmFy").unwrap(), b"foobar".to_vec());
        assert_eq!(decode_base64("Zm8=").unwrap(), b"fo".to_vec());
    }

    #[test]
    fn base64_rejects_garbage() {
        assert!(decode_base64("Zm9!YmFy").is_err());
        assert!(decode_base64("Zm9vYmF").is_err());
        assert!(decode_base64("Zm==Y===").is_err());
        assert!(decode_base64("Z===").is_err());
    }

    #[test]
    fn key_debug_redacts_the_secret() {
        let key = TsigKey::from_base64(
            "registrar.vxcloud.io.",
            TsigAlgorithm::HmacSha256,
            "c3VwZXItc2VjcmV0LWtleQ==",
        )
        .unwrap();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("super-secret"));
        assert!(!rendered.contains("c3VwZXI"));
    }

    #[test]
    fn algorithm_names_parse_both_ways() {
        assert_eq!(
            TsigAlgorithm::from_name("HMAC-SHA256").unwrap(),
            TsigAlgorithm::HmacSha256
        );
        assert_eq!(
            TsigAlgorithm::from_name("hmac-sha512.").unwrap(),
            TsigAlgorithm::HmacSha512
        );
        assert!(TsigAlgorithm::from_name("hmac-md5.sig-alg.reg.int.").is_err());
    }

    #[test]
    fn constant_time_eq_behaves_like_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
