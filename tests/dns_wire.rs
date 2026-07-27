//! Wire-format tests for the hand-rolled DNS codec.
//!
//! ## Where the golden vectors come from
//!
//! Every packet asserted here was first derived **by hand** from RFC 1035 §4 and
//! RFC 2136 §2 (count the length octets, look up the `TYPE`/`CLASS` numbers,
//! check `RDLENGTH`), and then independently cross-checked against
//! [dnspython](https://www.dnspython.org/) 2.8.0 — a completely separate
//! implementation — during development:
//!
//! - the header, zone section, and every `TYPE`/`CLASS`/`TTL`/`RDLENGTH`/`RDATA`
//!   field matched dnspython byte for byte;
//! - the only difference was name compression, which dnspython applies and `ion`
//!   deliberately does not (see [`ion::dns::name::Name::encode`]); dnspython
//!   confirmed the two encodings parse to *equal* messages. That compressed
//!   packet is preserved below as [`DNSPYTHON_COMPRESSED_ADD`] and is fed to
//!   `ion`'s decoder as a third-party interop fixture;
//! - the TSIG MAC in [`TSIG_MAC_HEX`] was produced by `ion` and then **validated
//!   by dnspython's own `dns.tsig` verifier** with the clock pinned to the
//!   vector's `time_signed`. A bit-flip in the MAC was rejected by the same
//!   verifier, so the check is discriminating rather than vacuous.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use ion::config::DnsConfig;
use ion::dns::DnsError;
use ion::dns::message::{
    CLASS_ANY, CLASS_IN, CLASS_NONE, Flags, Message, OPCODE_UPDATE, Rcode, RecordType,
};
use ion::dns::name::{MAX_LABEL_LEN, MAX_NAME_WIRE_LEN, Name};
use ion::dns::tsig::{
    TsigAlgorithm, TsigKey, TsigRdata, sign_and_encode, sign_response, to_hex, verify_response,
};
use ion::dns::update::UpdateBuilder;
use ion::registrar::{Registrar, RegistrarError, graceful_shutdown, send_update};

// ---------------------------------------------------------------------------
// Golden vectors
// ---------------------------------------------------------------------------

/// `UPDATE` adding `host.example.com. 60 IN A 192.0.2.7` to zone `example.com.`,
/// message id `0x1234`.
///
/// ```text
/// 1234              ID = 0x1234
/// 2800              QR=0 Opcode=5 (UPDATE) AA=0 TC=0 RD=0 RA=0 Z=0 RCODE=0
/// 0001              ZOCOUNT = 1
/// 0000              PRCOUNT = 0
/// 0001              UPCOUNT = 1
/// 0000              ADCOUNT = 0
/// 07 example 03 com 00   ZONE   QNAME  = example.com.
/// 0006                   ZONE   QTYPE  = SOA
/// 0001                   ZONE   QCLASS = IN
/// 04 host 07 example 03 com 00   UPDATE NAME     = host.example.com.
/// 0001                           UPDATE TYPE     = A
/// 0001                           UPDATE CLASS    = IN      <- "add"
/// 0000003c                       UPDATE TTL      = 60
/// 0004                           UPDATE RDLENGTH = 4
/// c0000207                       UPDATE RDATA    = 192.0.2.7
/// ```
const GOLDEN_ADD_A: &str = concat!(
    "123428000001000000010000",
    "076578616d706c6503636f6d00",
    "00060001",
    "04686f7374076578616d706c6503636f6d00",
    "000100010000003c0004c0000207",
);

/// Same message, but deleting that one specific RR: `CLASS=NONE` (254), `TTL=0`,
/// `RDLENGTH`/`RDATA` retained so the server knows *which* RR to remove
/// (RFC 2136 §2.5.4).
const GOLDEN_DELETE_RR: &str = concat!(
    "123428000001000000010000",
    "076578616d706c6503636f6d00",
    "00060001",
    "04686f7374076578616d706c6503636f6d00",
    "000100fe000000000004c0000207",
);

/// Deleting the whole `A` RRset: `CLASS=ANY` (255), `TTL=0`, `RDLENGTH=0`
/// (RFC 2136 §2.5.2).
const GOLDEN_DELETE_RRSET: &str = concat!(
    "123428000001000000010000",
    "076578616d706c6503636f6d00",
    "00060001",
    "04686f7374076578616d706c6503636f6d00",
    "000100ff000000000000",
);

/// Deleting every RRset at the name: `TYPE=ANY` (255), `CLASS=ANY` (255),
/// `TTL=0`, `RDLENGTH=0` (RFC 2136 §2.5.3).
const GOLDEN_DELETE_ALL: &str = concat!(
    "123428000001000000010000",
    "076578616d706c6503636f6d00",
    "00060001",
    "04686f7374076578616d706c6503636f6d00",
    "00ff00ff000000000000",
);

/// Prerequisite "name is not in use" (`TYPE=ANY`, `CLASS=NONE`, `TTL=0`,
/// `RDLENGTH=0`, RFC 2136 §2.4.5) followed by the add. Note `PRCOUNT` is now 1.
const GOLDEN_PREREQ_AND_ADD: &str = concat!(
    "123428000001000100010000",
    "076578616d706c6503636f6d00",
    "00060001",
    "04686f7374076578616d706c6503636f6d00",
    "00ff00fe000000000000",
    "04686f7374076578616d706c6503636f6d00",
    "000100010000003c0004c0000207",
);

/// `AAAA` add: `TYPE=28` (`001c`), `RDLENGTH=16`.
const GOLDEN_ADD_AAAA: &str = concat!(
    "123428000001000000010000",
    "076578616d706c6503636f6d00",
    "00060001",
    "04686f7374076578616d706c6503636f6d00",
    "001c00010000003c0010",
    "20010db8000000000000000000000007",
);

/// `CNAME` add: `TYPE=5`, `RDATA` is an uncompressed name (`lb.example.com.`),
/// `RDLENGTH=16`.
const GOLDEN_ADD_CNAME: &str = concat!(
    "123428000001000000010000",
    "076578616d706c6503636f6d00",
    "00060001",
    "04686f7374076578616d706c6503636f6d00",
    "000500010000003c0010",
    "026c62076578616d706c6503636f6d00",
);

/// The same "add A" message as [`GOLDEN_ADD_A`], but as **dnspython** emits it:
/// the owner name is `04 host` followed by the compression pointer `c00c`, which
/// points at offset 12 — the start of the zone name in the question section.
///
/// Used to prove `ion`'s decoder follows real third-party compression.
const DNSPYTHON_COMPRESSED_ADD: &str = concat!(
    "123428000001000000010000",
    "076578616d706c6503636f6d00",
    "00060001",
    "04686f7374c00c",
    "000100010000003c0004c0000207",
);

/// TSIG demonstration key. Deliberately worthless and published: it exists only
/// so the vector below is reproducible. Real deployments pass the secret through
/// `VX_TSIG_SECRET`.
const TSIG_KEY_NAME: &str = "selftest.key.";
const TSIG_SECRET_B64: &str = "aWY6eW91LWNhbi1yZWFkLXRoaXMtaXQtaXMtbm90LWEtc2VjcmV0";
const TSIG_TIME_SIGNED: u64 = 1_700_000_000;
const TSIG_FUDGE: u16 = 300;

/// HMAC-SHA256 over [`GOLDEN_ADD_A`] plus the RFC 8945 TSIG variables for the key
/// and timestamp above. Validated by dnspython's verifier — see the module docs.
const TSIG_MAC_HEX: &str = "763ba61aad52bd42bee5f4561061107b49ea49756ddec3641dc8b8c4f9d064b5";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn from_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex literal must have even length");
    let bytes = hex.as_bytes();
    (0..hex.len() / 2)
        .map(|i| (nibble(bytes[i * 2]) << 4) | nibble(bytes[i * 2 + 1]))
        .collect()
}

fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        other => panic!("not a hex digit: {}", char::from(other)),
    }
}

fn zone() -> Name {
    Name::from_ascii("example.com.").expect("zone")
}

fn host() -> Name {
    Name::from_ascii("host.example.com.").expect("host")
}

fn demo_key() -> TsigKey {
    TsigKey::from_base64(TSIG_KEY_NAME, TsigAlgorithm::HmacSha256, TSIG_SECRET_B64)
        .expect("demo key")
}

/// Decode `wire` and hand back the `index`-th record of the update section as an
/// owned value, so callers do not have to keep the whole message alive.
fn decoded_update(wire: &[u8], index: usize) -> ion::dns::message::Record {
    Message::decode(wire)
        .expect("message must decode")
        .updates()
        .get(index)
        .expect("update record at that index")
        .clone()
}

/// Assert that `actual` equals `expected_hex`, printing both as hex on failure so
/// a diff is readable rather than a wall of decimal byte values.
fn assert_wire(actual: &[u8], expected_hex: &str, what: &str) {
    let got = to_hex(actual);
    assert_eq!(
        got, expected_hex,
        "\n{what} mismatch\n  expected: {expected_hex}\n  actual:   {got}\n"
    );
}

// ---------------------------------------------------------------------------
// Golden byte vectors
// ---------------------------------------------------------------------------

#[test]
fn golden_update_add_a_is_byte_exact() {
    let mut b = UpdateBuilder::with_id(zone(), 0x1234);
    b.add_a(&host(), 60, Ipv4Addr::new(192, 0, 2, 7)).unwrap();
    let wire = b.encode().unwrap();
    assert_wire(&wire, GOLDEN_ADD_A, "UPDATE add A");
    assert_eq!(wire.len(), 61);

    // And the individual fields the hex diagram claims.
    assert_eq!(&wire[0..2], &[0x12, 0x34], "message id");
    assert_eq!(
        (u16::from_be_bytes([wire[2], wire[3]]) >> 11) & 0x0f,
        u16::from(OPCODE_UPDATE),
        "opcode must be 5"
    );
    assert_eq!(&wire[4..6], &[0x00, 0x01], "ZOCOUNT");
    assert_eq!(&wire[6..8], &[0x00, 0x00], "PRCOUNT");
    assert_eq!(&wire[8..10], &[0x00, 0x01], "UPCOUNT");
    assert_eq!(&wire[10..12], &[0x00, 0x00], "ADCOUNT");
}

#[test]
fn golden_update_delete_one_rr_is_byte_exact() {
    let mut b = UpdateBuilder::with_id(zone(), 0x1234);
    b.delete_a(&host(), Ipv4Addr::new(192, 0, 2, 7)).unwrap();
    let wire = b.encode().unwrap();
    assert_wire(&wire, GOLDEN_DELETE_RR, "UPDATE delete one RR");

    // The delete verb lives in CLASS=NONE with TTL=0 and RDATA retained.
    let rr = decoded_update(&wire, 0);
    assert_eq!(rr.class.code(), CLASS_NONE);
    assert_eq!(rr.ttl, 0);
    assert_eq!(rr.rdata, vec![192, 0, 2, 7]);
}

#[test]
fn golden_update_delete_rrset_is_byte_exact() {
    let mut b = UpdateBuilder::with_id(zone(), 0x1234);
    b.delete_rrset(&host(), RecordType::A).unwrap();
    let wire = b.encode().unwrap();
    assert_wire(&wire, GOLDEN_DELETE_RRSET, "UPDATE delete RRset");
    assert_eq!(wire.len(), 57, "RDLENGTH 0 makes this four bytes shorter");

    let rr = decoded_update(&wire, 0);
    assert_eq!(rr.class.code(), CLASS_ANY);
    assert_eq!(
        rr.rtype,
        RecordType::A,
        "the type is kept, only CLASS changes"
    );
    assert_eq!(rr.ttl, 0);
    assert!(rr.rdata.is_empty());
}

#[test]
fn golden_update_delete_every_rrset_is_byte_exact() {
    let mut b = UpdateBuilder::with_id(zone(), 0x1234);
    b.delete_all_rrsets(&host()).unwrap();
    assert_wire(
        &b.encode().unwrap(),
        GOLDEN_DELETE_ALL,
        "UPDATE delete every RRset",
    );
}

#[test]
fn golden_prerequisite_plus_add_is_byte_exact() {
    let mut b = UpdateBuilder::with_id(zone(), 0x1234);
    b.require_name_absent(&host()).unwrap();
    b.add_a(&host(), 60, Ipv4Addr::new(192, 0, 2, 7)).unwrap();
    let wire = b.encode().unwrap();
    assert_wire(&wire, GOLDEN_PREREQ_AND_ADD, "prerequisite + add");
    assert_eq!(wire.len(), 89);

    let msg = Message::decode(&wire).unwrap();
    assert_eq!(msg.header.prcount(), 1);
    assert_eq!(msg.header.upcount(), 1);
    let prereq = &msg.prerequisites()[0];
    assert_eq!(prereq.rtype.code(), 255, "TYPE=ANY");
    assert_eq!(prereq.class.code(), CLASS_NONE, "CLASS=NONE");
    assert!(prereq.rdata.is_empty());
}

#[test]
fn golden_add_aaaa_is_byte_exact() {
    let mut b = UpdateBuilder::with_id(zone(), 0x1234);
    b.add_aaaa(
        &host(),
        60,
        "2001:db8::7".parse::<Ipv6Addr>().expect("v6 literal"),
    )
    .unwrap();
    let wire = b.encode().unwrap();
    assert_wire(&wire, GOLDEN_ADD_AAAA, "UPDATE add AAAA");
    let rr = decoded_update(&wire, 0);
    assert_eq!(rr.rtype.code(), 28);
    assert_eq!(rr.rdata.len(), 16);
    assert_eq!(
        rr.as_ipv6().unwrap(),
        "2001:db8::7".parse::<Ipv6Addr>().unwrap()
    );
}

#[test]
fn golden_add_cname_is_byte_exact() {
    let mut b = UpdateBuilder::with_id(zone(), 0x1234);
    let target = Name::from_ascii("lb.example.com.").unwrap();
    b.add_cname(&host(), 60, &target).unwrap();
    let wire = b.encode().unwrap();
    assert_wire(&wire, GOLDEN_ADD_CNAME, "UPDATE add CNAME");
    let rr = decoded_update(&wire, 0);
    assert_eq!(rr.rtype.code(), 5);
    assert_eq!(rr.rdata, target.as_wire(), "CNAME rdata is a bare name");
}

#[test]
fn every_golden_packet_round_trips_through_the_decoder() {
    for (label, hex) in [
        ("add A", GOLDEN_ADD_A),
        ("delete RR", GOLDEN_DELETE_RR),
        ("delete RRset", GOLDEN_DELETE_RRSET),
        ("delete all", GOLDEN_DELETE_ALL),
        ("prereq + add", GOLDEN_PREREQ_AND_ADD),
        ("add AAAA", GOLDEN_ADD_AAAA),
        ("add CNAME", GOLDEN_ADD_CNAME),
    ] {
        let wire = from_hex(hex);
        let msg = Message::decode(&wire).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(msg.header.flags.opcode, OPCODE_UPDATE, "{label}");
        assert_eq!(msg.zone().len(), 1, "{label}");
        assert_eq!(msg.zone()[0].qtype, RecordType::Soa, "{label}");
        assert_eq!(msg.zone()[0].qclass.code(), CLASS_IN, "{label}");
        assert_wire(&msg.encode().unwrap(), hex, label);
    }
}

// ---------------------------------------------------------------------------
// Third-party interop: decode a compressed packet from dnspython
// ---------------------------------------------------------------------------

#[test]
fn decodes_dnspython_name_compression() {
    let wire = from_hex(DNSPYTHON_COMPRESSED_ADD);
    assert_eq!(wire.len(), 50, "compression saves 11 bytes here");
    // Layout: 12-byte header, 13-byte zone name, 4 bytes QTYPE/QCLASS, then the
    // update record's owner name starts at 29 as `04 "host"` (5 bytes) followed by
    // the pointer at 34. 0xc0 0x0c: the two high bits mark a pointer, the
    // remaining 14 bits are the offset -- 12, where the zone name begins.
    assert_eq!(&wire[29..34], b"\x04host");
    assert_eq!(&wire[34..36], &[0xc0, 0x0c]);

    let msg = Message::decode(&wire).expect("ion must follow compression pointers");
    assert_eq!(msg.zone()[0].name.to_string(), "example.com.");
    assert_eq!(
        msg.updates()[0].name.to_string(),
        "host.example.com.",
        "the pointer must be expanded, not stored verbatim"
    );
    assert_eq!(
        msg.updates()[0].as_ipv4().unwrap(),
        Ipv4Addr::new(192, 0, 2, 7)
    );
    assert_eq!(msg.updates()[0].ttl, 60);

    // Re-encoding produces ion's uncompressed form: semantically identical,
    // 11 bytes longer. dnspython confirmed the two parse to equal messages.
    assert_wire(&msg.encode().unwrap(), GOLDEN_ADD_A, "re-encoded");
}

#[test]
fn rejects_hostile_compression() {
    // A pointer to itself.
    let mut selfref = from_hex("123428000001000000000000");
    selfref.extend_from_slice(&[0xc0, 0x0c]);
    assert!(matches!(
        Message::decode(&selfref),
        Err(DnsError::BadPointer { .. })
    ));

    // A forward pointer, the building block of a decompression loop.
    let mut forward = from_hex("123428000001000000000000");
    forward.extend_from_slice(&[0xc0, 0x20, 0, 0, 0, 0]);
    assert!(matches!(
        Message::decode(&forward),
        Err(DnsError::BadPointer { .. })
    ));

    // The reserved 0b01 / 0b10 label types.
    let mut reserved = from_hex("123428000001000000000000");
    reserved.extend_from_slice(&[0x80, 0x01]);
    assert!(matches!(
        Message::decode(&reserved),
        Err(DnsError::BadLabelType(0x80))
    ));
}

// ---------------------------------------------------------------------------
// RFC 1035 name limits
// ---------------------------------------------------------------------------

#[test]
fn label_length_boundary_is_sixty_three() {
    assert_eq!(MAX_LABEL_LEN, 63);

    let ok = "a".repeat(63);
    let name = Name::from_ascii(&ok).expect("a 63-byte label is legal");
    assert_eq!(name.wire_len(), 65, "1 length octet + 63 bytes + root");
    assert_eq!(name.as_wire()[0], 63);

    let too_long = "a".repeat(64);
    assert!(matches!(
        Name::from_ascii(&too_long),
        Err(DnsError::LabelTooLong { len: 64 })
    ));
}

#[test]
fn total_name_length_boundary_is_two_hundred_and_fifty_five() {
    assert_eq!(MAX_NAME_WIRE_LEN, 255);

    let l63 = "a".repeat(63);
    // (1 + 63) * 3 + (1 + 61) + 1 root = 255, exactly at the limit.
    let at_limit = format!("{l63}.{l63}.{l63}.{}", "b".repeat(61));
    let name = Name::from_ascii(&at_limit).expect("255 encoded bytes is legal");
    assert_eq!(name.wire_len(), 255);
    assert_eq!(name.label_count(), 4);

    // One more byte in the final label pushes the encoding to 256.
    let over_limit = format!("{l63}.{l63}.{l63}.{}", "b".repeat(62));
    assert!(matches!(
        Name::from_ascii(&over_limit),
        Err(DnsError::NameTooLong { len: 256 })
    ));
}

#[test]
fn name_syntax_edge_cases() {
    // Root.
    let root = Name::from_ascii(".").unwrap();
    assert!(root.is_root());
    assert_eq!(root.as_wire(), &[0u8]);
    assert_eq!(root.wire_len(), 1);
    assert_eq!(root.label_count(), 0);

    // Empty string is not the root.
    assert!(matches!(Name::from_ascii(""), Err(DnsError::EmptyName)));

    // Doubled, leading dots.
    assert!(matches!(
        Name::from_ascii("a..b.com"),
        Err(DnsError::EmptyLabel { .. })
    ));
    assert!(matches!(
        Name::from_ascii(".a.com"),
        Err(DnsError::EmptyLabel { .. })
    ));

    // Trailing dot optional and idempotent.
    assert_eq!(
        Name::from_ascii("a.b.c").unwrap().as_wire(),
        Name::from_ascii("a.b.c.").unwrap().as_wire()
    );

    // Characters outside printable, non-space ASCII.
    for bad in ["a b.com", "a\tb.com", "hé.com"] {
        assert!(
            matches!(
                Name::from_ascii(bad),
                Err(DnsError::InvalidLabelByte { .. })
            ),
            "{bad:?} must be rejected"
        );
    }

    // Underscore and wildcard labels are legal and used in practice.
    assert!(Name::from_ascii("_dns-sd._udp.example.com.").is_ok());
    assert!(Name::from_ascii("*.example.com.").is_ok());
}

#[test]
fn out_of_zone_updates_are_refused_before_they_reach_the_wire() {
    let mut b = UpdateBuilder::with_id(zone(), 1);
    let elsewhere = Name::from_ascii("host.example.org.").unwrap();
    assert!(matches!(
        b.add_a(&elsewhere, 60, Ipv4Addr::LOCALHOST),
        Err(DnsError::NotInZone { .. })
    ));
    assert_eq!(
        b.update_count(),
        0,
        "the rejected record must not be queued"
    );
}

#[test]
fn truncated_input_never_panics() {
    let full = from_hex(GOLDEN_ADD_A);
    // Every proper prefix must produce an error rather than a panic or a
    // half-decoded message.
    for cut in 0..full.len() {
        let prefix = &full[..cut];
        let outcome = Message::decode(prefix);
        assert!(
            outcome.is_err(),
            "a {cut}-byte prefix must not decode as a whole message"
        );
    }
    assert!(Message::decode(&full).is_ok());
}

// ---------------------------------------------------------------------------
// TSIG
// ---------------------------------------------------------------------------

#[test]
fn tsig_signing_is_deterministic_for_a_fixed_key_and_time() {
    let key = demo_key();

    let mut first = UpdateBuilder::with_id(zone(), 0x1234).message().unwrap();
    first
        .authority
        .push(build_add_record(&host(), 60, Ipv4Addr::new(192, 0, 2, 7)));
    let (wire_a, mac_a) = sign_and_encode(&mut first, &key, TSIG_TIME_SIGNED, TSIG_FUDGE).unwrap();

    let mut second = UpdateBuilder::with_id(zone(), 0x1234).message().unwrap();
    second
        .authority
        .push(build_add_record(&host(), 60, Ipv4Addr::new(192, 0, 2, 7)));
    let (wire_b, mac_b) = sign_and_encode(&mut second, &key, TSIG_TIME_SIGNED, TSIG_FUDGE).unwrap();

    assert_eq!(mac_a, mac_b, "same inputs must produce the same MAC");
    assert_eq!(wire_a, wire_b, "same inputs must produce the same packet");
    assert_eq!(
        to_hex(&mac_a),
        TSIG_MAC_HEX,
        "the MAC must match the dnspython-validated vector"
    );
    assert_eq!(mac_a.len(), 32, "hmac-sha256 is 32 bytes");
}

/// A one-record helper so the deterministic test builds exactly the same message
/// as [`GOLDEN_ADD_A`] without going through the builder twice.
fn build_add_record(name: &Name, ttl: u32, addr: Ipv4Addr) -> ion::dns::message::Record {
    ion::dns::message::Record::new(
        name.clone(),
        RecordType::A,
        ion::dns::message::RecordClass::In,
        ttl,
        addr.octets().to_vec(),
    )
}

#[test]
fn a_changed_secret_changes_the_mac() {
    let mut msg = UpdateBuilder::with_id(zone(), 0x1234).message().unwrap();
    msg.authority
        .push(build_add_record(&host(), 60, Ipv4Addr::new(192, 0, 2, 7)));
    let other = TsigKey::from_base64(
        TSIG_KEY_NAME,
        TsigAlgorithm::HmacSha256,
        "ZGlmZmVyZW50LXNlY3JldC1lbnRpcmVseQ==",
    )
    .unwrap();
    let (_, mac) = sign_and_encode(&mut msg, &other, TSIG_TIME_SIGNED, TSIG_FUDGE).unwrap();
    assert_ne!(to_hex(&mac), TSIG_MAC_HEX);
}

#[test]
fn a_changed_timestamp_changes_the_mac() {
    let mut msg = UpdateBuilder::with_id(zone(), 0x1234).message().unwrap();
    msg.authority
        .push(build_add_record(&host(), 60, Ipv4Addr::new(192, 0, 2, 7)));
    let (_, mac) =
        sign_and_encode(&mut msg, &demo_key(), TSIG_TIME_SIGNED + 1, TSIG_FUDGE).unwrap();
    assert_ne!(
        to_hex(&mac),
        TSIG_MAC_HEX,
        "time_signed is part of the TSIG variables and must affect the MAC"
    );
}

#[test]
fn the_tsig_rr_round_trips_through_the_message_decoder() {
    let mut msg = UpdateBuilder::with_id(zone(), 0x1234).message().unwrap();
    msg.authority
        .push(build_add_record(&host(), 60, Ipv4Addr::new(192, 0, 2, 7)));
    let (wire, mac) = sign_and_encode(&mut msg, &demo_key(), TSIG_TIME_SIGNED, TSIG_FUDGE).unwrap();

    // Signing appends to the additional section and bumps ADCOUNT.
    assert_eq!(msg.header.adcount(), 1);
    assert_eq!(&wire[10..12], &[0x00, 0x01], "ADCOUNT on the wire");

    let decoded = Message::decode(&wire).expect("signed packet must decode");
    assert_eq!(decoded.additional.len(), 1);
    let rr = decoded
        .find_additional(RecordType::Tsig)
        .expect("a TSIG RR in the additional section");
    assert_eq!(rr.rtype.code(), 250, "TYPE = TSIG");
    assert_eq!(rr.class.code(), CLASS_ANY, "CLASS = ANY");
    assert_eq!(rr.ttl, 0, "TTL = 0");
    assert_eq!(rr.name.to_string(), TSIG_KEY_NAME);

    let rdata = TsigRdata::decode(&rr.rdata).expect("TSIG rdata must decode");
    assert_eq!(rdata.algorithm.to_string(), "hmac-sha256.");
    assert_eq!(rdata.time_signed, TSIG_TIME_SIGNED);
    assert_eq!(rdata.fudge, TSIG_FUDGE);
    assert_eq!(rdata.mac, mac);
    assert_eq!(rdata.original_id, 0x1234);
    assert_eq!(rdata.error, 0);
    assert!(rdata.other.is_empty());

    // And the record re-serialises to the same bytes it was parsed from.
    assert_eq!(rdata.encode(), rr.rdata);
    assert_wire(&decoded.encode().unwrap(), &to_hex(&wire), "signed packet");
}

#[test]
fn a_signed_response_verifies_and_tampering_does_not() {
    let key = demo_key();

    // Request.
    let mut request = UpdateBuilder::with_id(zone(), 0x4321).message().unwrap();
    request
        .authority
        .push(build_add_record(&host(), 60, Ipv4Addr::new(192, 0, 2, 7)));
    let (_req_wire, request_mac) =
        sign_and_encode(&mut request, &key, TSIG_TIME_SIGNED, TSIG_FUDGE).unwrap();

    // Response: same id, QR set, zone echoed, TSIG chained off the request MAC.
    let mut response = Message::new(0x4321, {
        let mut f = Flags::update_request();
        f.response = true;
        f
    });
    response.questions.push(request.questions[0].clone());
    sign_response(
        &mut response,
        &key,
        &request_mac,
        TSIG_TIME_SIGNED,
        TSIG_FUDGE,
    )
    .unwrap();
    let response_wire = response.encode().unwrap();

    verify_response(&response_wire, &key, &request_mac, TSIG_TIME_SIGNED)
        .expect("a correctly signed response must verify");

    // Flip one bit of the MAC.
    let mut tampered = response_wire.clone();
    let last = tampered.len() - 7;
    tampered[last] ^= 0x01;
    assert!(matches!(
        verify_response(&tampered, &key, &request_mac, TSIG_TIME_SIGNED),
        Err(DnsError::TsigVerifyFailed)
    ));

    // A different request MAC must not verify: that is the whole point of
    // chaining the response digest off the request.
    assert!(matches!(
        verify_response(
            &response_wire,
            &key,
            b"not the request mac",
            TSIG_TIME_SIGNED
        ),
        Err(DnsError::TsigVerifyFailed)
    ));

    // Outside the fudge window.
    assert!(matches!(
        verify_response(
            &response_wire,
            &key,
            &request_mac,
            TSIG_TIME_SIGNED + u64::from(TSIG_FUDGE) + 1
        ),
        Err(DnsError::TsigBadTime { .. })
    ));

    // An unsigned response cannot masquerade as a signed one.
    let unsigned = Message::new(0x4321, Flags::update_request())
        .encode()
        .unwrap();
    assert!(matches!(
        verify_response(&unsigned, &key, &request_mac, TSIG_TIME_SIGNED),
        Err(DnsError::MissingTsig)
    ));
}

#[test]
fn signing_grows_the_packet_by_exactly_the_tsig_rr() {
    let mut b = UpdateBuilder::with_id(zone(), 0x1234);
    b.add_a(&host(), 60, Ipv4Addr::new(192, 0, 2, 7)).unwrap();
    let unsigned = b.encode().unwrap();

    let mut msg = b.message().unwrap();
    let (signed, _) = sign_and_encode(&mut msg, &demo_key(), TSIG_TIME_SIGNED, TSIG_FUDGE).unwrap();

    // key name (14) + TYPE/CLASS/TTL/RDLENGTH (10) + RDATA (61) = 85.
    assert_eq!(signed.len() - unsigned.len(), 85);
    // The signed packet begins with the unsigned one, except for ADCOUNT.
    assert_eq!(&signed[..10], &unsigned[..10]);
    assert_eq!(&signed[12..unsigned.len()], &unsigned[12..]);
}

// ---------------------------------------------------------------------------
// Live loopback UDP
// ---------------------------------------------------------------------------

/// A one-shot DNS server on the loopback interface.
///
/// Returns the address it is listening on and a handle that yields the exact
/// bytes it received. `rcode` selects the response code so that both the happy
/// path and a refusal can be exercised.
async fn spawn_one_shot_server(rcode: Rcode) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
    let sock = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind loopback server");
    let addr = sock.local_addr().expect("local addr");

    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (n, peer) = sock.recv_from(&mut buf).await.expect("recv");
        let received = buf.get(..n).unwrap_or_default().to_vec();

        if let Ok(request) = Message::decode(&received) {
            // An UPDATE response echoes the header and the zone section.
            let mut response = Message::new(request.header.id, {
                let mut f = Flags::update_request();
                f.response = true;
                f.authoritative = true;
                f.rcode = rcode;
                f
            });
            response.questions = request.questions.clone();
            if let Ok(bytes) = response.encode() {
                let _ = sock.send_to(&bytes, peer).await;
            }
        }
        received
    });

    (addr, handle)
}

fn loopback_dns_config(server: SocketAddr) -> DnsConfig {
    DnsConfig {
        enabled: true,
        server,
        zone: "example.com.".to_owned(),
        base_domain: "example.com.".to_owned(),
        ttl: 60,
        timeout: Duration::from_millis(2_000),
        retries: 2,
        require_absent: false,
        tsig: None,
    }
}

#[tokio::test]
async fn live_loopback_send_update_puts_the_exact_golden_bytes_on_the_wire() {
    let (addr, server) = spawn_one_shot_server(Rcode::NoError).await;
    let packet = from_hex(GOLDEN_ADD_A);

    let raw = send_update(addr, &packet, Duration::from_millis(2_000), 2)
        .await
        .expect("the loopback server must answer");

    let received = server.await.expect("server task");
    assert_wire(
        &received,
        GOLDEN_ADD_A,
        "bytes observed by a real UDP socket",
    );
    assert_eq!(
        received, packet,
        "not one byte may change between build and send"
    );

    let response = Message::decode(&raw).expect("response must decode");
    assert!(response.header.flags.response);
    assert_eq!(response.header.id, 0x1234, "the id must be echoed");
    assert_eq!(response.rcode(), Rcode::NoError);
}

#[tokio::test]
async fn live_loopback_registrar_registers_and_deregisters() {
    // --- register --------------------------------------------------------
    let (addr, server) = spawn_one_shot_server(Rcode::NoError).await;
    let cfg = loopback_dns_config(addr);
    let reg =
        Registrar::with_address(&cfg, 42, "acme", IpAddr::from([10, 1, 2, 3])).expect("registrar");
    assert_eq!(reg.fqdn().to_string(), "42.acme.example.com.");
    assert!(!reg.is_signed());

    let rcode = reg.register().await.expect("register");
    assert_eq!(rcode, Rcode::NoError);

    let received = server.await.expect("server task");
    let sent = Message::decode(&received).expect("what we sent must be a valid message");
    assert_eq!(sent.header.flags.opcode, OPCODE_UPDATE);
    assert_eq!(sent.zone()[0].name.to_string(), "example.com.");
    assert_eq!(sent.header.upcount(), 2, "clear the RRset, then add ours");

    // Update 1: delete the whole A RRset so a recycled task id cannot inherit
    // a dead worker's address.
    assert_eq!(sent.updates()[0].class.code(), CLASS_ANY);
    assert_eq!(sent.updates()[0].rtype, RecordType::A);
    assert!(sent.updates()[0].rdata.is_empty());
    // Update 2: add ours.
    assert_eq!(sent.updates()[1].class.code(), CLASS_IN);
    assert_eq!(sent.updates()[1].ttl, 60);
    assert_eq!(
        sent.updates()[1].as_ipv4().unwrap(),
        Ipv4Addr::new(10, 1, 2, 3)
    );
    assert_eq!(sent.updates()[1].name.to_string(), "42.acme.example.com.");

    // The bytes on the wire are exactly what build_register_packet produces for
    // that message id -- the only non-deterministic input.
    let (expected, _) = reg
        .build_register_packet(sent.header.id, 0)
        .expect("rebuild");
    assert_eq!(received, expected, "byte-exact match after fixing the id");

    // --- graceful shutdown ----------------------------------------------
    let (addr2, server2) = spawn_one_shot_server(Rcode::NoError).await;
    let cfg2 = loopback_dns_config(addr2);
    let reg2 =
        Registrar::with_address(&cfg2, 42, "acme", IpAddr::from([10, 1, 2, 3])).expect("registrar");
    let rcode = graceful_shutdown(&reg2).await.expect("deregister");
    assert_eq!(rcode, Rcode::NoError);

    let withdrawn = Message::decode(&server2.await.expect("server task")).expect("decode");
    assert_eq!(withdrawn.header.upcount(), 1);
    let rr = &withdrawn.updates()[0];
    assert_eq!(
        rr.class.code(),
        CLASS_NONE,
        "delete only our own RR, so a shared name keeps its other members"
    );
    assert_eq!(rr.ttl, 0);
    assert_eq!(rr.as_ipv4().unwrap(), Ipv4Addr::new(10, 1, 2, 3));
}

#[tokio::test]
async fn live_loopback_a_refusal_becomes_a_typed_error() {
    let (addr, server) = spawn_one_shot_server(Rcode::NotAuth).await;
    let cfg = loopback_dns_config(addr);
    let reg = Registrar::with_address(&cfg, 7, "acme", IpAddr::from([10, 0, 0, 9])).unwrap();

    let err = reg.register().await.expect_err("NOTAUTH must be an error");
    assert!(
        matches!(
            err,
            RegistrarError::Rejected {
                rcode: Rcode::NotAuth
            }
        ),
        "got {err:?}"
    );
    assert!(err.to_string().contains("NOTAUTH"), "{err}");
    let _ = server.await;
}

#[tokio::test]
async fn live_loopback_a_silent_server_times_out_after_the_configured_attempts() {
    // Bind a socket and never read from it: the client's datagrams are accepted
    // by the kernel and never answered.
    let sink = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind sink");
    let addr = sink.local_addr().expect("addr");

    let cfg = DnsConfig {
        timeout: Duration::from_millis(60),
        retries: 3,
        ..loopback_dns_config(addr)
    };
    let reg = Registrar::with_address(&cfg, 1, "acme", IpAddr::from([127, 0, 0, 1])).unwrap();

    let started = std::time::Instant::now();
    let err = reg.register().await.expect_err("must time out");
    assert!(
        matches!(err, RegistrarError::Timeout { attempts: 3, .. }),
        "got {err:?}"
    );
    // Three attempts of 60ms each: the retry loop really did retry.
    assert!(
        started.elapsed() >= Duration::from_millis(150),
        "elapsed {:?} suggests the retries were not attempted",
        started.elapsed()
    );
    drop(sink);
}

#[tokio::test]
async fn live_loopback_a_signed_exchange_verifies_end_to_end() {
    let sock = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind");
    let addr = sock.local_addr().expect("addr");

    let server_key = demo_key();
    let server = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (n, peer) = sock.recv_from(&mut buf).await.expect("recv");
        let received = buf.get(..n).unwrap_or_default().to_vec();
        let request = Message::decode(&received).expect("decode request");

        // Pull the request MAC out of its TSIG RR: the response digest chains
        // off it, which is what binds the two halves of the transaction.
        let tsig = request
            .find_additional(RecordType::Tsig)
            .expect("a signed request");
        let request_mac = TsigRdata::decode(&tsig.rdata).expect("tsig rdata").mac;

        let mut response = Message::new(request.header.id, {
            let mut f = Flags::update_request();
            f.response = true;
            f.authoritative = true;
            f
        });
        response.questions = request.questions.clone();
        sign_response(
            &mut response,
            &server_key,
            &request_mac,
            ion::dns::tsig::now_unix(),
            TSIG_FUDGE,
        )
        .expect("sign response");
        let bytes = response.encode().expect("encode response");
        let _ = sock.send_to(&bytes, peer).await;
        received
    });

    let cfg = DnsConfig {
        tsig: Some(ion::config::TsigSettings {
            key_name: TSIG_KEY_NAME.to_owned(),
            secret_b64: TSIG_SECRET_B64.to_owned(),
            algorithm: TsigAlgorithm::HmacSha256,
            fudge: TSIG_FUDGE,
        }),
        ..loopback_dns_config(addr)
    };
    let reg = Registrar::with_address(&cfg, 99, "acme", IpAddr::from([10, 9, 9, 9])).unwrap();
    assert!(reg.is_signed());

    let rcode = reg
        .register()
        .await
        .expect("a signed exchange must complete and the response MAC must verify");
    assert_eq!(rcode, Rcode::NoError);

    // And the request really was signed with the key we configured.
    let received = server.await.expect("server task");
    let sent = Message::decode(&received).expect("decode");
    let tsig = sent.find_additional(RecordType::Tsig).expect("TSIG RR");
    assert_eq!(tsig.name.to_string(), TSIG_KEY_NAME);
    let rdata = TsigRdata::decode(&tsig.rdata).expect("rdata");
    assert_eq!(rdata.algorithm.to_string(), "hmac-sha256.");
    assert_eq!(rdata.mac.len(), 32);
    assert_eq!(rdata.original_id, sent.header.id);
}

#[test]
fn an_ipv6_worker_registers_an_aaaa_record() {
    // The registrar picks the record type from the address family, so an IPv6
    // worker must clear and add AAAA, never A.
    let cfg = loopback_dns_config(SocketAddr::from(([127, 0, 0, 1], 53)));
    let v6: Ipv6Addr = "2001:db8::9".parse().expect("v6 literal");
    let reg = Registrar::with_address(&cfg, 7, "acme", IpAddr::V6(v6)).expect("registrar");

    let (packet, mac) = reg.build_register_packet(0x0abc, 0).expect("build");
    assert!(mac.is_empty(), "this config is unsigned");

    let msg = Message::decode(&packet).expect("decode");
    assert_eq!(msg.header.upcount(), 2);
    assert_eq!(msg.updates()[0].rtype, RecordType::Aaaa);
    assert_eq!(msg.updates()[0].class.code(), CLASS_ANY, "clear the RRset");
    assert_eq!(msg.updates()[1].rtype, RecordType::Aaaa);
    assert_eq!(msg.updates()[1].class.code(), CLASS_IN, "then add ours");
    assert_eq!(msg.updates()[1].rdata.len(), 16);
    assert_eq!(msg.updates()[1].as_ipv6().expect("v6 rdata"), v6);

    // And withdrawal deletes exactly that one AAAA RR.
    let (withdraw, _) = reg.build_delete_packet(0x0abd, 0).expect("build");
    let msg = Message::decode(&withdraw).expect("decode");
    assert_eq!(msg.header.upcount(), 1);
    assert_eq!(msg.updates()[0].rtype, RecordType::Aaaa);
    assert_eq!(msg.updates()[0].class.code(), CLASS_NONE);
    assert_eq!(msg.updates()[0].as_ipv6().expect("v6 rdata"), v6);
}

#[tokio::test]
async fn local_address_detection_sends_nothing_and_finds_a_loopback_source() {
    let peer = SocketAddr::from(([127, 0, 0, 1], 53));
    let ip = ion::registrar::detect_local_ip(peer)
        .await
        .expect("detection must work without any external service");
    assert!(
        ip.is_loopback(),
        "route to 127.0.0.1 must be loopback, got {ip}"
    );
}
