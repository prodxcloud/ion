//! RFC 1035 §3.1 domain-name encoding, validation, and decompression.
//!
//! A domain name on the wire is a sequence of length-prefixed labels terminated
//! by a zero octet:
//!
//! ```text
//! "host.example.com."
//!  04 68 6f 73 74   07 65 78 61 6d 70 6c 65   03 63 6f 6d   00
//!  |  h  o  s  t    |  e  x  a  m  p  l  e    |  c  o  m    root
//!  len              len                       len
//! ```
//!
//! Two limits are load-bearing and are enforced at construction time, not at
//! send time:
//!
//! - a single label is 1..=63 bytes ([`MAX_LABEL_LEN`]) — the two high bits of
//!   the length octet are reserved for compression pointers, leaving six bits;
//! - the whole encoded name, length octets and root included, is at most 255
//!   bytes ([`MAX_NAME_WIRE_LEN`]).
//!
//! ```
//! use ion::dns::name::Name;
//!
//! let n: Name = "host.example.com.".parse().unwrap();
//! assert_eq!(n.wire_len(), 18);
//! assert_eq!(n.label_count(), 3);
//! assert_eq!(n.to_string(), "host.example.com.");
//!
//! // 63 is the ceiling for one label; 64 is not encodable.
//! assert!("a".repeat(63).parse::<Name>().is_ok());
//! assert!("a".repeat(64).parse::<Name>().is_err());
//! ```

use core::fmt;
use core::str::FromStr;

use super::DnsError;

/// Maximum length of a single label, in bytes (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// Maximum length of a complete encoded name, in bytes (RFC 1035 §2.3.4).
pub const MAX_NAME_WIRE_LEN: usize = 255;

/// Maximum number of compression jumps tolerated while decoding one name.
///
/// A legal message never needs more than a handful; a hostile one uses pointer
/// chains to turn a small packet into unbounded work.
pub const MAX_POINTER_JUMPS: usize = 64;

/// A validated, fully-qualified domain name held in its wire encoding.
///
/// The invariant maintained by every constructor is that [`Name::as_wire`]
/// returns a byte string that is *already* a legal RFC 1035 name: every label is
/// 1..=63 bytes, the whole thing is <= 255 bytes, and it is terminated by a
/// single zero octet. Encoding a `Name` is therefore an infallible memcpy.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Name {
    /// Wire form, including the trailing root octet.
    wire: Vec<u8>,
}

impl Name {
    /// The root name, `"."` — a single zero octet.
    #[must_use]
    pub fn root() -> Self {
        Self { wire: vec![0] }
    }

    /// Parse a presentation-format name.
    ///
    /// A single trailing dot is optional and ignored; `"."` alone is the root.
    /// Labels may hold any printable, non-space ASCII byte other than `.`, which
    /// admits the `_` of `_service` labels and the `*` of wildcards while still
    /// rejecting whitespace, control characters, and raw UTF-8 (encode
    /// internationalised names as A-labels / punycode before calling this).
    ///
    /// # Errors
    /// - [`DnsError::EmptyName`] for `""`.
    /// - [`DnsError::EmptyLabel`] for a doubled or leading dot.
    /// - [`DnsError::LabelTooLong`] past 63 bytes in one label.
    /// - [`DnsError::NameTooLong`] past 255 encoded bytes.
    /// - [`DnsError::InvalidLabelByte`] for a byte outside `0x21..=0x7e`.
    pub fn from_ascii(input: &str) -> Result<Self, DnsError> {
        if input.is_empty() {
            return Err(DnsError::EmptyName);
        }
        if input == "." {
            return Ok(Self::root());
        }
        let trimmed = input.strip_suffix('.').unwrap_or(input);
        if trimmed.is_empty() {
            return Err(DnsError::EmptyName);
        }

        let mut wire = Vec::with_capacity(trimmed.len() + 2);
        for label in trimmed.split('.') {
            push_label(&mut wire, label, input)?;
        }
        wire.push(0);

        if wire.len() > MAX_NAME_WIRE_LEN {
            return Err(DnsError::NameTooLong { len: wire.len() });
        }
        Ok(Self { wire })
    }

    /// Build a name from already-split labels, e.g. `["_http", "_tcp"]` plus a
    /// parent zone.
    ///
    /// # Errors
    /// Same conditions as [`Name::from_ascii`].
    pub fn from_labels<'a, I>(labels: I) -> Result<Self, DnsError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let joined: Vec<&str> = labels.into_iter().collect();
        if joined.is_empty() {
            return Ok(Self::root());
        }
        Self::from_ascii(&joined.join("."))
    }

    /// Prepend `labels` to this name: `Name::prefixed(&zone, ["web", "eu"])`
    /// yields `web.eu.<zone>`.
    ///
    /// # Errors
    /// Same conditions as [`Name::from_ascii`], most importantly
    /// [`DnsError::NameTooLong`] once the concatenation crosses 255 bytes.
    pub fn prefixed<'a, I>(parent: &Self, labels: I) -> Result<Self, DnsError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut wire = Vec::with_capacity(parent.wire.len() + 16);
        for label in labels {
            push_label(&mut wire, label, label)?;
        }
        wire.extend_from_slice(&parent.wire);
        if wire.len() > MAX_NAME_WIRE_LEN {
            return Err(DnsError::NameTooLong { len: wire.len() });
        }
        Ok(Self { wire })
    }

    /// The wire encoding, including the trailing root octet.
    #[must_use]
    pub fn as_wire(&self) -> &[u8] {
        &self.wire
    }

    /// Length of the wire encoding in bytes. The root is 1.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        self.wire.len()
    }

    /// Whether this is the root name.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.wire.len() == 1
    }

    /// Number of labels, excluding the root.
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// Iterate over the labels, excluding the root.
    #[must_use]
    pub fn labels(&self) -> LabelIter<'_> {
        LabelIter {
            wire: &self.wire,
            pos: 0,
        }
    }

    /// Append the wire encoding to `out`.
    ///
    /// Names are written uncompressed. RFC 2136 does not require compression in
    /// `UPDATE` messages, and omitting it keeps every packet we emit
    /// byte-reproducible — which is exactly what TSIG signing needs.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.wire);
    }

    /// Append the *canonical* wire encoding to `out`: identical to
    /// [`Name::encode`] but with ASCII upper-case mapped to lower-case, as
    /// required for the TSIG digest (RFC 8945 §4.3.3, RFC 4034 §6.2).
    pub fn encode_canonical(&self, out: &mut Vec<u8>) {
        let mut pos = 0usize;
        while let Some(&len) = self.wire.get(pos) {
            out.push(len);
            if len == 0 {
                break;
            }
            let start = pos + 1;
            let end = start + len as usize;
            if let Some(label) = self.wire.get(start..end) {
                out.extend(label.iter().map(u8::to_ascii_lowercase));
            }
            pos = end;
        }
    }

    /// Whether `self` is `other` or lives beneath it.
    #[must_use]
    pub fn is_subdomain_of(&self, other: &Self) -> bool {
        if other.is_root() {
            return true;
        }
        if self.wire.len() < other.wire.len() {
            return false;
        }
        // Walk our own label boundaries so we only ever compare at a boundary;
        // a plain suffix match would say "notexample.com" is under "example.com".
        let mut pos = 0usize;
        while let Some(&len) = self.wire.get(pos) {
            if self.wire.len() - pos == other.wire.len() {
                let tail = self.wire.get(pos..).unwrap_or(&[]);
                return tail.eq_ignore_ascii_case(&other.wire);
            }
            if len == 0 {
                return false;
            }
            pos += 1 + len as usize;
        }
        false
    }

    /// Decode one name starting at `start`, following RFC 1035 §4.1.4
    /// compression pointers.
    ///
    /// Returns the name and the number of bytes consumed **at `start`** — a
    /// pointer consumes 2 bytes there no matter how much name it expands to,
    /// which is what a section parser needs in order to advance.
    ///
    /// # Errors
    /// - [`DnsError::Truncated`] if the buffer ends inside the name.
    /// - [`DnsError::BadPointer`] if a pointer does not point strictly backwards
    ///   (the standard defence against decompression loops).
    /// - [`DnsError::PointerLoop`] after [`MAX_POINTER_JUMPS`] indirections.
    /// - [`DnsError::BadLabelType`] for the reserved `0b10` label type.
    /// - [`DnsError::NameTooLong`] if decompression exceeds 255 bytes.
    pub fn read(buf: &[u8], start: usize) -> Result<(Self, usize), DnsError> {
        let mut wire: Vec<u8> = Vec::with_capacity(32);
        let mut pos = start;
        let mut consumed: Option<usize> = None;
        let mut jumps = 0usize;

        loop {
            let len = *buf.get(pos).ok_or(DnsError::Truncated {
                offset: pos,
                need: 1,
            })?;
            match len & 0xc0 {
                0x00 => {
                    if len == 0 {
                        wire.push(0);
                        pos += 1;
                        if consumed.is_none() {
                            consumed = Some(pos - start);
                        }
                        break;
                    }
                    let label_start = pos + 1;
                    let label_end = label_start + len as usize;
                    let label = buf.get(label_start..label_end).ok_or(DnsError::Truncated {
                        offset: label_start,
                        need: len as usize,
                    })?;
                    wire.push(len);
                    wire.extend_from_slice(label);
                    if wire.len() >= MAX_NAME_WIRE_LEN {
                        return Err(DnsError::NameTooLong {
                            len: wire.len() + 1,
                        });
                    }
                    pos = label_end;
                }
                0xc0 => {
                    let lo = *buf.get(pos + 1).ok_or(DnsError::Truncated {
                        offset: pos + 1,
                        need: 1,
                    })?;
                    let target = ((usize::from(len) & 0x3f) << 8) | usize::from(lo);
                    if consumed.is_none() {
                        consumed = Some(pos + 2 - start);
                    }
                    if target >= pos {
                        return Err(DnsError::BadPointer { target, at: pos });
                    }
                    jumps += 1;
                    if jumps > MAX_POINTER_JUMPS {
                        return Err(DnsError::PointerLoop);
                    }
                    pos = target;
                }
                _ => return Err(DnsError::BadLabelType(len)),
            }
        }

        let used = consumed.unwrap_or(pos.saturating_sub(start));
        Ok((Self { wire }, used))
    }
}

/// Validate one presentation-format label and append its wire form to `wire`.
///
/// `context` is only used to build a readable error message.
fn push_label(wire: &mut Vec<u8>, label: &str, context: &str) -> Result<(), DnsError> {
    let bytes = label.as_bytes();
    if bytes.is_empty() {
        return Err(DnsError::EmptyLabel {
            name: context.to_owned(),
        });
    }
    if bytes.len() > MAX_LABEL_LEN {
        return Err(DnsError::LabelTooLong { len: bytes.len() });
    }
    for &b in bytes {
        if !(0x21..=0x7e).contains(&b) {
            return Err(DnsError::InvalidLabelByte { byte: b });
        }
    }
    // `bytes.len() <= MAX_LABEL_LEN` was just checked, so the cast is exact.
    wire.push(bytes.len() as u8);
    wire.extend_from_slice(bytes);
    Ok(())
}

/// Iterator over the labels of a [`Name`], root octet excluded.
#[derive(Debug, Clone)]
pub struct LabelIter<'a> {
    wire: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for LabelIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let len = *self.wire.get(self.pos)?;
        if len == 0 {
            return None;
        }
        let start = self.pos + 1;
        let end = start + len as usize;
        let label = self.wire.get(start..end)?;
        self.pos = end;
        Some(label)
    }
}

impl FromStr for Name {
    type Err = DnsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_ascii(s)
    }
}

impl fmt::Display for Name {
    /// Presentation format, always fully qualified (trailing dot).
    ///
    /// Bytes that are not printable ASCII, and the `.` and `\` characters, are
    /// escaped as RFC 1035 §5.1 requires so that the output can be re-parsed
    /// unambiguously by a human or a zone file.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }
        for label in self.labels() {
            for &b in label {
                match b {
                    b'.' | b'\\' => write!(f, "\\{}", char::from(b))?,
                    0x21..=0x7e => write!(f, "{}", char::from(b))?,
                    other => write!(f, "\\{other:03}")?,
                }
            }
            f.write_str(".")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_documented_example() {
        let n = Name::from_ascii("host.example.com.").unwrap();
        assert_eq!(
            n.as_wire(),
            b"\x04host\x07example\x03com\x00",
            "wire form must be length-prefixed labels plus a root octet"
        );
    }

    #[test]
    fn trailing_dot_is_optional() {
        assert_eq!(
            Name::from_ascii("a.b").unwrap(),
            Name::from_ascii("a.b.").unwrap()
        );
    }

    #[test]
    fn root_is_a_single_zero_octet() {
        let r = Name::root();
        assert!(r.is_root());
        assert_eq!(r.as_wire(), &[0]);
        assert_eq!(r.to_string(), ".");
        assert_eq!(Name::from_ascii(".").unwrap(), r);
    }

    #[test]
    fn rejects_structurally_invalid_names() {
        assert!(matches!(Name::from_ascii(""), Err(DnsError::EmptyName)));
        assert!(matches!(
            Name::from_ascii("a..b"),
            Err(DnsError::EmptyLabel { .. })
        ));
        assert!(matches!(
            Name::from_ascii(".a"),
            Err(DnsError::EmptyLabel { .. })
        ));
        assert!(matches!(
            Name::from_ascii("a b.com"),
            Err(DnsError::InvalidLabelByte { byte: b' ' })
        ));
    }

    #[test]
    fn canonical_form_lowercases() {
        let n = Name::from_ascii("HOST.Example.COM.").unwrap();
        let mut out = Vec::new();
        n.encode_canonical(&mut out);
        assert_eq!(out, b"\x04host\x07example\x03com\x00");
        // The stored form is preserved verbatim; only the digest form folds case.
        assert_eq!(n.as_wire(), b"\x04HOST\x07Example\x03COM\x00");
    }

    #[test]
    fn subdomain_check_respects_label_boundaries() {
        let zone = Name::from_ascii("example.com.").unwrap();
        assert!(
            Name::from_ascii("a.example.com.")
                .unwrap()
                .is_subdomain_of(&zone)
        );
        assert!(
            Name::from_ascii("example.com.")
                .unwrap()
                .is_subdomain_of(&zone)
        );
        assert!(
            !Name::from_ascii("notexample.com.")
                .unwrap()
                .is_subdomain_of(&zone)
        );
        assert!(
            !Name::from_ascii("example.org.")
                .unwrap()
                .is_subdomain_of(&zone)
        );
    }

    #[test]
    fn prefixed_builds_child_names() {
        let zone = Name::from_ascii("vxcloud.io.").unwrap();
        let child = Name::prefixed(&zone, ["42", "acme"]).unwrap();
        assert_eq!(child.to_string(), "42.acme.vxcloud.io.");
    }
}
