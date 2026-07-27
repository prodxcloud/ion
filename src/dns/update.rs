//! RFC 2136 dynamic `UPDATE` construction.
//!
//! An `UPDATE` is a DNS message with opcode **5** whose four sections mean
//! something different from a query:
//!
//! ```text
//! ZOCOUNT  the zone to modify, as one question with QTYPE=SOA, QCLASS=IN
//! PRCOUNT  prerequisites the server must satisfy before applying anything
//! UPCOUNT  the mutations themselves
//! ADCOUNT  additional data — this is where the TSIG RR goes
//! ```
//!
//! The mutation *verb* is not a separate field. It is encoded in the
//! combination of `CLASS`, `TTL`, and `RDLENGTH` of each record in the update
//! section (RFC 2136 §2.5), and in `CLASS`/`TYPE` for prerequisites (§2.4):
//!
//! | Intent | `TYPE` | `CLASS` | `TTL` | `RDLENGTH` |
//! |---|---|---|---|---|
//! | add an RR to an RRset (§2.5.1) | the type | `IN` (1) | as given | as given |
//! | delete one specific RR (§2.5.4) | the type | `NONE` (254) | 0 | as given |
//! | delete an entire RRset (§2.5.2) | the type | `ANY` (255) | 0 | 0 |
//! | delete every RRset at a name (§2.5.3) | `ANY` (255) | `ANY` (255) | 0 | 0 |
//! | prereq: name is in use (§2.4.4) | `ANY` (255) | `ANY` (255) | 0 | 0 |
//! | prereq: name is **not** in use (§2.4.5) | `ANY` (255) | `NONE` (254) | 0 | 0 |
//! | prereq: RRset exists (§2.4.1) | the type | `ANY` (255) | 0 | 0 |
//! | prereq: RRset does not exist (§2.4.3) | the type | `NONE` (254) | 0 | 0 |
//!
//! Note that "delete an RRset" and "prereq: RRset exists" have byte-identical
//! encodings; they are distinguished purely by which *section* they appear in.
//! That is why this builder keeps the two operations on separate methods rather
//! than exposing a generic "push record".
//!
//! ```
//! use ion::dns::name::Name;
//! use ion::dns::update::UpdateBuilder;
//! use std::net::Ipv4Addr;
//!
//! let zone: Name = "example.com.".parse().unwrap();
//! let host: Name = "host.example.com.".parse().unwrap();
//!
//! let mut b = UpdateBuilder::with_id(zone, 0x1234);
//! b.require_name_absent(&host).unwrap();
//! b.add_a(&host, 60, Ipv4Addr::new(192, 0, 2, 7)).unwrap();
//!
//! let msg = b.message().unwrap();
//! assert_eq!(msg.header.zocount(), 1);
//! assert_eq!(msg.header.prcount(), 1);
//! assert_eq!(msg.header.upcount(), 1);
//! assert_eq!(msg.header.adcount(), 0);
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::DnsError;
use super::message::{Flags, Message, Question, Record, RecordClass, RecordType, random_id};
use super::name::Name;

/// Builder for an RFC 2136 `UPDATE` message.
///
/// Records accumulate in section order; nothing is encoded until
/// [`UpdateBuilder::message`] or [`UpdateBuilder::encode`] is called, so the
/// same builder can be reused to produce a signed and an unsigned variant.
#[derive(Debug, Clone)]
pub struct UpdateBuilder {
    id: u16,
    zone: Name,
    prerequisites: Vec<Record>,
    updates: Vec<Record>,
}

impl UpdateBuilder {
    /// Start an `UPDATE` for `zone` with a CSPRNG-drawn message id.
    #[must_use]
    pub fn new(zone: Name) -> Self {
        Self::with_id(zone, random_id())
    }

    /// Start an `UPDATE` for `zone` with a caller-chosen message id.
    ///
    /// Used by the test suite to make packets byte-reproducible, and by the
    /// registrar so that a retry reuses the original id.
    #[must_use]
    pub fn with_id(zone: Name, id: u16) -> Self {
        Self {
            id,
            zone,
            prerequisites: Vec::new(),
            updates: Vec::new(),
        }
    }

    /// The message id this builder will stamp on the packet.
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// The zone being updated.
    #[must_use]
    pub const fn zone_name(&self) -> &Name {
        &self.zone
    }

    /// Reject any name that does not live inside the zone we are updating.
    ///
    /// A server would answer `NOTZONE` (RCODE 10); catching it locally turns a
    /// round trip into an immediate, well-labelled error.
    fn check_in_zone(&self, name: &Name) -> Result<(), DnsError> {
        if name.is_subdomain_of(&self.zone) {
            Ok(())
        } else {
            Err(DnsError::NotInZone {
                name: name.to_string(),
                zone: self.zone.to_string(),
            })
        }
    }

    // -- prerequisites (RFC 2136 §2.4) ------------------------------------

    /// §2.4.5 — *name is not in use*: `TYPE=ANY`, `CLASS=NONE`, `TTL=0`,
    /// `RDLENGTH=0`.
    ///
    /// This is the prerequisite that makes registration idempotent-safe: it
    /// turns a racing double-registration into an `YXDOMAIN` refusal rather than
    /// two hosts silently sharing a name.
    ///
    /// # Errors
    /// If `name` is not inside the builder's zone.
    pub fn require_name_absent(&mut self, name: &Name) -> Result<&mut Self, DnsError> {
        self.check_in_zone(name)?;
        self.prerequisites.push(Record::new(
            name.clone(),
            RecordType::Any,
            RecordClass::None,
            0,
            Vec::new(),
        ));
        Ok(self)
    }

    /// §2.4.4 — *name is in use*: `TYPE=ANY`, `CLASS=ANY`, `TTL=0`,
    /// `RDLENGTH=0`.
    ///
    /// # Errors
    /// If `name` is not inside the builder's zone.
    pub fn require_name_present(&mut self, name: &Name) -> Result<&mut Self, DnsError> {
        self.check_in_zone(name)?;
        self.prerequisites.push(Record::new(
            name.clone(),
            RecordType::Any,
            RecordClass::Any,
            0,
            Vec::new(),
        ));
        Ok(self)
    }

    /// §2.4.1 — *RRset exists (value independent)*: `CLASS=ANY`, `TTL=0`,
    /// `RDLENGTH=0`.
    ///
    /// # Errors
    /// If `name` is not inside the builder's zone.
    pub fn require_rrset_present(
        &mut self,
        name: &Name,
        rtype: RecordType,
    ) -> Result<&mut Self, DnsError> {
        self.check_in_zone(name)?;
        self.prerequisites.push(Record::new(
            name.clone(),
            rtype,
            RecordClass::Any,
            0,
            Vec::new(),
        ));
        Ok(self)
    }

    /// §2.4.3 — *RRset does not exist*: `CLASS=NONE`, `TTL=0`, `RDLENGTH=0`.
    ///
    /// # Errors
    /// If `name` is not inside the builder's zone.
    pub fn require_rrset_absent(
        &mut self,
        name: &Name,
        rtype: RecordType,
    ) -> Result<&mut Self, DnsError> {
        self.check_in_zone(name)?;
        self.prerequisites.push(Record::new(
            name.clone(),
            rtype,
            RecordClass::None,
            0,
            Vec::new(),
        ));
        Ok(self)
    }

    // -- additions (RFC 2136 §2.5.1) --------------------------------------

    /// Add an `A` record: `TYPE=A`, `CLASS=IN`, the given `TTL`, `RDLENGTH=4`.
    ///
    /// # Errors
    /// If `name` is not inside the builder's zone.
    pub fn add_a(&mut self, name: &Name, ttl: u32, addr: Ipv4Addr) -> Result<&mut Self, DnsError> {
        self.check_in_zone(name)?;
        self.updates.push(Record::new(
            name.clone(),
            RecordType::A,
            RecordClass::In,
            ttl,
            addr.octets().to_vec(),
        ));
        Ok(self)
    }

    /// Add an `AAAA` record: `TYPE=AAAA`, `CLASS=IN`, the given `TTL`,
    /// `RDLENGTH=16`.
    ///
    /// # Errors
    /// If `name` is not inside the builder's zone.
    pub fn add_aaaa(
        &mut self,
        name: &Name,
        ttl: u32,
        addr: Ipv6Addr,
    ) -> Result<&mut Self, DnsError> {
        self.check_in_zone(name)?;
        self.updates.push(Record::new(
            name.clone(),
            RecordType::Aaaa,
            RecordClass::In,
            ttl,
            addr.octets().to_vec(),
        ));
        Ok(self)
    }

    /// Add an `A` or `AAAA` record according to the address family.
    ///
    /// # Errors
    /// If `name` is not inside the builder's zone.
    pub fn add_address(
        &mut self,
        name: &Name,
        ttl: u32,
        addr: IpAddr,
    ) -> Result<&mut Self, DnsError> {
        match addr {
            IpAddr::V4(v4) => self.add_a(name, ttl, v4),
            IpAddr::V6(v6) => self.add_aaaa(name, ttl, v6),
        }
    }

    /// Add a `CNAME` record. The target is encoded as an uncompressed name, as
    /// RFC 3597 §4 requires for `RDATA` that a server may have to re-serialise.
    ///
    /// # Errors
    /// If `name` is not inside the builder's zone.
    pub fn add_cname(
        &mut self,
        name: &Name,
        ttl: u32,
        target: &Name,
    ) -> Result<&mut Self, DnsError> {
        self.check_in_zone(name)?;
        let mut rdata = Vec::with_capacity(target.wire_len());
        target.encode(&mut rdata);
        self.updates.push(Record::new(
            name.clone(),
            RecordType::Cname,
            RecordClass::In,
            ttl,
            rdata,
        ));
        Ok(self)
    }

    /// Add a `TXT` record. Each string is emitted as one length-prefixed
    /// character-string, so values longer than 255 bytes must be pre-split by
    /// the caller.
    ///
    /// # Errors
    /// If `name` is not inside the builder's zone, or a string exceeds 255
    /// bytes.
    pub fn add_txt(
        &mut self,
        name: &Name,
        ttl: u32,
        strings: &[&str],
    ) -> Result<&mut Self, DnsError> {
        self.check_in_zone(name)?;
        let mut rdata = Vec::new();
        for s in strings {
            let bytes = s.as_bytes();
            let len = u8::try_from(bytes.len())
                .map_err(|_| DnsError::RdataTooLong { len: bytes.len() })?;
            rdata.push(len);
            rdata.extend_from_slice(bytes);
        }
        self.updates.push(Record::new(
            name.clone(),
            RecordType::Txt,
            RecordClass::In,
            ttl,
            rdata,
        ));
        Ok(self)
    }

    // -- deletions (RFC 2136 §2.5.2 / §2.5.3 / §2.5.4) --------------------

    /// §2.5.4 — delete one specific `A` record: `CLASS=NONE`, `TTL=0`,
    /// `RDLENGTH=4` with the address in `RDATA`.
    ///
    /// Other `A` records at the same name survive. This is the right verb for a
    /// worker tearing down *its own* address from a shared round-robin name.
    ///
    /// # Errors
    /// If `name` is not inside the builder's zone.
    pub fn delete_a(&mut self, name: &Name, addr: Ipv4Addr) -> Result<&mut Self, DnsError> {
        self.check_in_zone(name)?;
        self.updates.push(Record::new(
            name.clone(),
            RecordType::A,
            RecordClass::None,
            0,
            addr.octets().to_vec(),
        ));
        Ok(self)
    }

    /// §2.5.4 — delete one specific `AAAA` record.
    ///
    /// # Errors
    /// If `name` is not inside the builder's zone.
    pub fn delete_aaaa(&mut self, name: &Name, addr: Ipv6Addr) -> Result<&mut Self, DnsError> {
        self.check_in_zone(name)?;
        self.updates.push(Record::new(
            name.clone(),
            RecordType::Aaaa,
            RecordClass::None,
            0,
            addr.octets().to_vec(),
        ));
        Ok(self)
    }

    /// §2.5.4 — delete one specific address record, `A` or `AAAA`.
    ///
    /// # Errors
    /// If `name` is not inside the builder's zone.
    pub fn delete_address(&mut self, name: &Name, addr: IpAddr) -> Result<&mut Self, DnsError> {
        match addr {
            IpAddr::V4(v4) => self.delete_a(name, v4),
            IpAddr::V6(v6) => self.delete_aaaa(name, v6),
        }
    }

    /// §2.5.4 — delete one specific `CNAME` record.
    ///
    /// # Errors
    /// If `name` is not inside the builder's zone.
    pub fn delete_cname(&mut self, name: &Name, target: &Name) -> Result<&mut Self, DnsError> {
        self.check_in_zone(name)?;
        let mut rdata = Vec::with_capacity(target.wire_len());
        target.encode(&mut rdata);
        self.updates.push(Record::new(
            name.clone(),
            RecordType::Cname,
            RecordClass::None,
            0,
            rdata,
        ));
        Ok(self)
    }

    /// §2.5.2 — delete an entire RRset: `CLASS=ANY`, `TTL=0`, `RDLENGTH=0`.
    ///
    /// # Errors
    /// If `name` is not inside the builder's zone.
    pub fn delete_rrset(&mut self, name: &Name, rtype: RecordType) -> Result<&mut Self, DnsError> {
        self.check_in_zone(name)?;
        self.updates.push(Record::new(
            name.clone(),
            rtype,
            RecordClass::Any,
            0,
            Vec::new(),
        ));
        Ok(self)
    }

    /// §2.5.3 — delete every RRset at a name: `TYPE=ANY`, `CLASS=ANY`, `TTL=0`,
    /// `RDLENGTH=0`.
    ///
    /// # Errors
    /// If `name` is not inside the builder's zone.
    pub fn delete_all_rrsets(&mut self, name: &Name) -> Result<&mut Self, DnsError> {
        self.check_in_zone(name)?;
        self.updates.push(Record::new(
            name.clone(),
            RecordType::Any,
            RecordClass::Any,
            0,
            Vec::new(),
        ));
        Ok(self)
    }

    // -- output ------------------------------------------------------------

    /// Number of prerequisites queued.
    #[must_use]
    pub fn prerequisite_count(&self) -> usize {
        self.prerequisites.len()
    }

    /// Number of mutations queued.
    #[must_use]
    pub fn update_count(&self) -> usize {
        self.updates.len()
    }

    /// Materialise the [`Message`], with correct opcode, zone section, and
    /// section counts.
    ///
    /// # Errors
    /// Currently infallible in practice; returns `Result` so that future
    /// validation can be added without a breaking change.
    pub fn message(&self) -> Result<Message, DnsError> {
        let mut msg = Message::new(self.id, Flags::update_request());
        msg.questions.push(Question::zone(self.zone.clone()));
        msg.answers = self.prerequisites.clone();
        msg.authority = self.updates.clone();
        msg.header.counts = [
            1,
            u16::try_from(self.prerequisites.len()).unwrap_or(u16::MAX),
            u16::try_from(self.updates.len()).unwrap_or(u16::MAX),
            0,
        ];
        Ok(msg)
    }

    /// Encode the unsigned `UPDATE` packet.
    ///
    /// # Errors
    /// [`DnsError::RdataTooLong`] from any oversized `RDATA`.
    pub fn encode(&self) -> Result<Vec<u8>, DnsError> {
        self.message()?.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone() -> Name {
        Name::from_ascii("example.com.").unwrap()
    }

    fn host() -> Name {
        Name::from_ascii("host.example.com.").unwrap()
    }

    /// The first record of the update section, as a fresh owned value.
    fn first_update(b: &UpdateBuilder) -> Record {
        b.message()
            .expect("message")
            .updates()
            .first()
            .expect("one update record")
            .clone()
    }

    /// The first record of the prerequisite section.
    fn first_prereq(b: &UpdateBuilder) -> Record {
        b.message()
            .expect("message")
            .prerequisites()
            .first()
            .expect("one prerequisite record")
            .clone()
    }

    #[test]
    fn add_uses_class_in_and_keeps_the_ttl() {
        let mut b = UpdateBuilder::with_id(zone(), 1);
        b.add_a(&host(), 300, Ipv4Addr::new(10, 0, 0, 1)).unwrap();
        let rr = first_update(&b);
        assert_eq!(rr.class, RecordClass::In);
        assert_eq!(rr.rtype, RecordType::A);
        assert_eq!(rr.ttl, 300);
        assert_eq!(rr.rdata, vec![10, 0, 0, 1]);
    }

    #[test]
    fn delete_one_rr_uses_class_none_ttl_zero_and_keeps_rdata() {
        let mut b = UpdateBuilder::with_id(zone(), 1);
        b.delete_a(&host(), Ipv4Addr::new(10, 0, 0, 1)).unwrap();
        let rr = first_update(&b);
        assert_eq!(rr.class, RecordClass::None);
        assert_eq!(rr.class.code(), 254);
        assert_eq!(rr.ttl, 0);
        assert_eq!(rr.rdata.len(), 4);
    }

    #[test]
    fn delete_rrset_uses_class_any_and_empty_rdata() {
        let mut b = UpdateBuilder::with_id(zone(), 1);
        b.delete_rrset(&host(), RecordType::A).unwrap();
        let rr = first_update(&b);
        assert_eq!(rr.class.code(), 255);
        assert_eq!(rr.ttl, 0);
        assert!(rr.rdata.is_empty());
    }

    #[test]
    fn delete_all_rrsets_uses_type_any_class_any() {
        let mut b = UpdateBuilder::with_id(zone(), 1);
        b.delete_all_rrsets(&host()).unwrap();
        let rr = first_update(&b);
        assert_eq!(rr.rtype.code(), 255);
        assert_eq!(rr.class.code(), 255);
        assert_eq!(rr.ttl, 0);
        assert!(rr.rdata.is_empty());
    }

    #[test]
    fn name_absent_prereq_is_type_any_class_none() {
        let mut b = UpdateBuilder::with_id(zone(), 1);
        b.require_name_absent(&host()).unwrap();
        let rr = first_prereq(&b);
        assert_eq!(rr.rtype.code(), 255);
        assert_eq!(rr.class.code(), 254);
        assert_eq!(rr.ttl, 0);
        assert!(rr.rdata.is_empty());
    }

    #[test]
    fn out_of_zone_names_are_refused_locally() {
        let mut b = UpdateBuilder::with_id(zone(), 1);
        let elsewhere = Name::from_ascii("host.example.org.").unwrap();
        assert!(b.add_a(&elsewhere, 60, Ipv4Addr::LOCALHOST).is_err());
        assert!(b.delete_all_rrsets(&elsewhere).is_err());
        assert_eq!(b.update_count(), 0);
    }

    #[test]
    fn zone_section_is_one_soa_question() {
        let b = UpdateBuilder::with_id(zone(), 1);
        let msg = b.message().unwrap();
        assert_eq!(msg.zone().len(), 1);
        assert_eq!(msg.zone()[0].qtype, RecordType::Soa);
        assert_eq!(msg.zone()[0].qclass, RecordClass::In);
        assert_eq!(msg.header.flags.opcode, crate::dns::message::OPCODE_UPDATE);
    }

    #[test]
    fn cname_rdata_is_an_uncompressed_name() {
        let mut b = UpdateBuilder::with_id(zone(), 1);
        let target = Name::from_ascii("lb.example.com.").unwrap();
        b.add_cname(&host(), 60, &target).unwrap();
        let rr = first_update(&b);
        assert_eq!(rr.rdata, target.as_wire());
        assert_eq!(rr.rtype.code(), 5);
    }

    #[test]
    fn txt_rdata_is_length_prefixed_character_strings() {
        let mut b = UpdateBuilder::with_id(zone(), 1);
        b.add_txt(&host(), 60, &["ion", "vx"]).unwrap();
        let rr = first_update(&b);
        assert_eq!(rr.rdata, b"\x03ion\x02vx");
    }
}
