//! Conformance tests for the VxCloud System ABI v1 codec.
//!
//! `worker/include/worker_abi.h` is the normative contract. These tests assert
//! the same things its `_Static_assert`s do — sizes and offsets — plus the
//! runtime behaviour a C header cannot express: that every malformed frame
//! produces a typed error instead of a panic, and that the byte order really is
//! little-endian at every field.
//!
//! The golden header vector below was assembled by hand from the offset table in
//! the header, so a regression in the codec cannot be papered over by a matching
//! regression in the encoder.

use ion::abi::{
    AbiError, Engine, ResultFrame, ResultHeader, Task, TaskHeader, TaskState, VX_ABI_VERSION,
    VX_MAGIC_HEADER, VX_MAX_PAYLOAD_LEN, VX_RESULT_HEADER_SIZE, VX_TASK_HEADER_SIZE,
    VX_TENANT_ID_LEN, VxStatus, peek_magic, peek_payload_len, peek_task_id, peek_tenant_id_raw,
    result_offset, task_offset, tenant_id_str,
};

// ---------------------------------------------------------------------------
// Sizes and offsets — the frozen contract
// ---------------------------------------------------------------------------

#[test]
fn sizes_match_the_c_header() {
    assert_eq!(
        VX_TASK_HEADER_SIZE, 93,
        "vx_task_header_t is 93 packed bytes"
    );
    assert_eq!(
        VX_RESULT_HEADER_SIZE, 29,
        "vx_result_header_t is 29 packed bytes"
    );
    assert_eq!(VX_TENANT_ID_LEN, 64);
    assert_eq!(VX_MAX_PAYLOAD_LEN, 16 * 1024 * 1024);
    assert_eq!(VX_ABI_VERSION, 1);
    assert_eq!(VX_MAGIC_HEADER, 0x5857_5601);
}

#[test]
fn task_offsets_match_the_c_header() {
    // These mirror the `__builtin_offsetof` static assertions verbatim.
    assert_eq!(task_offset::MAGIC, 0);
    assert_eq!(task_offset::TASK_ID, 4);
    assert_eq!(task_offset::TENANT_ID, 12);
    assert_eq!(task_offset::ENGINE, 76);
    assert_eq!(task_offset::MEMORY_LIMIT_MB, 77);
    assert_eq!(task_offset::CPU_QUOTA_US, 81);
    assert_eq!(task_offset::PAYLOAD_LEN, 85);
    assert_eq!(task_offset::PAYLOAD, 93);

    // And the fields tile the struct exactly, with no padding and no overlap.
    let widths = [
        (task_offset::MAGIC, 4),
        (task_offset::TASK_ID, 8),
        (task_offset::TENANT_ID, 64),
        (task_offset::ENGINE, 1),
        (task_offset::MEMORY_LIMIT_MB, 4),
        (task_offset::CPU_QUOTA_US, 4),
        (task_offset::PAYLOAD_LEN, 8),
    ];
    let mut cursor = 0usize;
    for (offset, width) in widths {
        assert_eq!(offset, cursor, "field at {offset} leaves a padding hole");
        cursor += width;
    }
    assert_eq!(cursor, VX_TASK_HEADER_SIZE, "the struct must be packed");
}

#[test]
fn result_offsets_tile_the_struct_exactly() {
    assert_eq!(result_offset::MAGIC, 0);
    assert_eq!(result_offset::TASK_ID, 4);
    assert_eq!(result_offset::STATE, 12);
    assert_eq!(result_offset::EXIT_CODE, 13);
    assert_eq!(result_offset::DURATION_US, 17);
    assert_eq!(result_offset::PAYLOAD_LEN, 25);
    assert_eq!(result_offset::PAYLOAD, 29);

    let widths = [
        (result_offset::MAGIC, 4),
        (result_offset::TASK_ID, 8),
        (result_offset::STATE, 1),
        (result_offset::EXIT_CODE, 4),
        (result_offset::DURATION_US, 8),
        (result_offset::PAYLOAD_LEN, 4),
    ];
    let mut cursor = 0usize;
    for (offset, width) in widths {
        assert_eq!(offset, cursor);
        cursor += width;
    }
    assert_eq!(cursor, VX_RESULT_HEADER_SIZE);
}

#[test]
fn magic_is_vxw_plus_a_version_nibble() {
    // 0x58575601: 'X' 'W' 'V' 0x01 big-endian, i.e. version byte first on a
    // little-endian wire.
    assert_eq!(VX_MAGIC_HEADER.to_be_bytes(), [b'X', b'W', b'V', 0x01]);
    assert_eq!(
        VX_MAGIC_HEADER.to_le_bytes(),
        [0x01, b'V', b'W', b'X'],
        "the low byte carries the ABI version and is what a guest sees first"
    );
}

// ---------------------------------------------------------------------------
// Byte-exact encoding
// ---------------------------------------------------------------------------

/// A header assembled by hand from the offset table:
/// `task_id = 0x0102030405060708`, `tenant = "acme"`, `engine = ION`,
/// `memory_limit_mb = 8`, `cpu_quota_us = 100000 (0x000186a0)`,
/// `payload_len = 13`.
fn golden_header_bytes() -> Vec<u8> {
    let mut out = vec![0u8; VX_TASK_HEADER_SIZE];
    out[0..4].copy_from_slice(&[0x01, 0x56, 0x57, 0x58]); // magic, little-endian
    out[4..12].copy_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]); // task_id LE
    out[12..16].copy_from_slice(b"acme"); // tenant_id, NUL-padded to 64
    out[76] = 0x01; // engine = ENGINE_ION
    out[77..81].copy_from_slice(&[0x08, 0x00, 0x00, 0x00]); // memory_limit_mb = 8
    out[81..85].copy_from_slice(&[0xa0, 0x86, 0x01, 0x00]); // cpu_quota_us = 100000
    out[85..93].copy_from_slice(&[0x0d, 0, 0, 0, 0, 0, 0, 0]); // payload_len = 13
    out
}

#[test]
fn encoding_matches_the_hand_assembled_golden_header() {
    let header = TaskHeader::new(0x0102_0304_0506_0708, "acme", Engine::Ion, 8, 100_000, 13)
        .expect("valid header");
    assert_eq!(
        header.encode().to_vec(),
        golden_header_bytes(),
        "the codec must place every field at its documented offset, little-endian"
    );
}

#[test]
fn every_multi_byte_field_is_little_endian() {
    let bytes = golden_header_bytes();

    // task_id: least-significant byte first.
    assert_eq!(bytes[task_offset::TASK_ID], 0x08);
    assert_eq!(bytes[task_offset::TASK_ID + 7], 0x01);

    // cpu_quota_us = 100_000 = 0x000186a0.
    assert_eq!(
        &bytes[task_offset::CPU_QUOTA_US..task_offset::CPU_QUOTA_US + 4],
        &[0xa0, 0x86, 0x01, 0x00]
    );

    let decoded = TaskHeader::decode(&bytes).expect("decode");
    assert_eq!(decoded.task_id, 0x0102_0304_0506_0708);
    assert_eq!(decoded.cpu_quota_us, 100_000);
    assert_eq!(decoded.memory_limit_mb, 8);
    assert_eq!(decoded.payload_len, 13);
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

#[test]
fn task_header_round_trips_every_field() {
    for (task_id, tenant, engine, mem, cpu, len) in [
        (0u64, "", Engine::Ion, 0u32, 0u32, 0u64),
        (1, "a", Engine::Iron, 1, 1, 1),
        (
            u64::MAX,
            "a-tenant-slug-of-exactly-sixty-four-bytes-0123456789abcdefghijkl",
            Engine::Ion,
            u32::MAX,
            u32::MAX,
            VX_MAX_PAYLOAD_LEN,
        ),
        (42, "acme", Engine::Ion, 8, 100_000, 13),
    ] {
        let header = TaskHeader::new(task_id, tenant, engine, mem, cpu, len)
            .unwrap_or_else(|e| panic!("{tenant:?} should be a valid tenant: {e}"));
        let wire = header.encode();
        assert_eq!(wire.len(), VX_TASK_HEADER_SIZE);

        let back = TaskHeader::decode(&wire).expect("decode");
        assert_eq!(back, header, "round trip changed the header");
        assert_eq!(back.magic, VX_MAGIC_HEADER);
        assert_eq!(back.task_id, task_id);
        assert_eq!(back.tenant().expect("utf8"), tenant);
        assert_eq!(back.engine().expect("engine"), engine);
        assert_eq!(back.memory_limit_mb, mem);
        assert_eq!(back.cpu_quota_us, cpu);
        assert_eq!(back.payload_len, len);
        assert_eq!(back.frame_len(), VX_TASK_HEADER_SIZE as u64 + len);
    }
}

#[test]
fn a_sixty_four_byte_tenant_fits_and_a_sixty_five_byte_one_does_not() {
    let exactly = "t".repeat(64);
    let header = TaskHeader::new(1, &exactly, Engine::Ion, 1, 1, 0).expect("64 bytes fits");
    assert_eq!(header.tenant().expect("utf8"), exactly);
    assert_eq!(
        header.tenant_id.iter().filter(|&&b| b == 0).count(),
        0,
        "a full-width tenant leaves no NUL padding"
    );

    assert!(matches!(
        TaskHeader::new(1, &"t".repeat(65), Engine::Ion, 1, 1, 0),
        Err(AbiError::TenantIdTooLong { len: 65 })
    ));
}

#[test]
fn tenant_padding_is_nul_and_is_stripped_on_read() {
    let header = TaskHeader::new(1, "acme", Engine::Ion, 1, 1, 0).expect("header");
    assert_eq!(&header.tenant_id[..4], b"acme");
    assert!(
        header.tenant_id[4..].iter().all(|&b| b == 0),
        "the remainder must be NUL, not uninitialised or space-padded"
    );
    assert_eq!(header.tenant().expect("utf8"), "acme");

    // Bytes after the first NUL are ignored, as "NUL-padded" implies.
    let mut raw = header.tenant_id;
    raw[10] = b'X';
    assert_eq!(tenant_id_str(&raw).expect("utf8"), "acme");
}

#[test]
fn a_non_utf8_tenant_is_an_error_not_a_lossy_string() {
    let mut wire = golden_header_bytes();
    wire[task_offset::TENANT_ID] = 0xff;
    let header = TaskHeader::decode(&wire).expect("the header itself is still well-formed");
    assert!(matches!(header.tenant(), Err(AbiError::TenantIdNotUtf8)));
}

#[test]
fn task_frame_round_trips_and_borrows_its_payload() {
    let payload = br#"{"op":"scrape","url":"https://example.com"}"#;
    let header = TaskHeader::new(7, "acme", Engine::Ion, 16, 200_000, 0).expect("header");
    let frame = Task::encode(&header, payload).expect("encode");

    assert_eq!(frame.len(), VX_TASK_HEADER_SIZE + payload.len());
    let task = Task::parse(&frame).expect("parse");
    assert_eq!(task.payload, payload);
    assert_eq!(task.task_id(), 7);
    assert_eq!(task.tenant().expect("utf8"), "acme");
    assert_eq!(
        task.header.payload_len,
        payload.len() as u64,
        "encode must overwrite payload_len with the real length"
    );

    // The payload is a borrow into `frame`, not a copy.
    assert!(
        std::ptr::eq(task.payload.as_ptr(), frame[VX_TASK_HEADER_SIZE..].as_ptr()),
        "Task::parse must borrow the payload in place"
    );
}

#[test]
fn trailing_bytes_beyond_payload_len_are_ignored() {
    let header = TaskHeader::new(1, "acme", Engine::Ion, 1, 1, 3).expect("header");
    let mut frame = header.encode().to_vec();
    frame.extend_from_slice(b"abc");
    frame.extend_from_slice(b"and some slack from a larger read buffer");

    let task = Task::parse(&frame).expect("parse");
    assert_eq!(
        task.payload, b"abc",
        "only payload_len bytes belong to the task"
    );
}

#[test]
fn a_zero_length_payload_is_valid() {
    let header = TaskHeader::new(1, "acme", Engine::Ion, 1, 1, 0).expect("header");
    let frame = header.encode().to_vec();
    let task = Task::parse(&frame).expect("a bare header is a complete frame");
    assert!(task.payload.is_empty());
}

#[test]
fn result_frame_round_trips() {
    let frame = ResultFrame::new(
        0x0102_0304_0506_0708,
        TaskState::Completed,
        0,
        1_234_567,
        b"{\"op\":\"noop\"}".to_vec(),
    );
    let wire = frame.encode();
    assert_eq!(wire.len(), VX_RESULT_HEADER_SIZE + 13);

    let back = ResultFrame::decode(&wire).expect("decode");
    assert_eq!(back, frame);
    assert_eq!(back.header.magic, VX_MAGIC_HEADER);
    assert_eq!(back.header.task_id, 0x0102_0304_0506_0708);
    assert_eq!(back.header.state().expect("state"), TaskState::Completed);
    assert_eq!(back.header.exit_code, 0);
    assert_eq!(back.header.duration_us, 1_234_567);
    assert_eq!(back.header.payload_len, 13);
}

#[test]
fn a_negative_exit_code_survives_the_round_trip() {
    // exit_code is int32_t, and the VxStatus codes are all negative.
    for status in [
        VxStatus::BadMagic,
        VxStatus::PayloadTooLarge,
        VxStatus::Timeout,
        VxStatus::Unsupported,
    ] {
        let frame = ResultFrame::new(1, TaskState::Failed, status.code(), 0, Vec::new());
        let back = ResultFrame::decode(&frame.encode()).expect("decode");
        assert_eq!(back.header.exit_code, status.code());
        assert!(back.header.exit_code < 0);
    }

    let header = ResultHeader::new(1, TaskState::Failed, i32::MIN, 0, 0);
    let back = ResultHeader::decode(&header.encode()).expect("decode");
    assert_eq!(back.exit_code, i32::MIN);
}

// ---------------------------------------------------------------------------
// Rejection paths — every one of them, and never a panic
// ---------------------------------------------------------------------------

#[test]
fn a_short_header_is_rejected() {
    let full = golden_header_bytes();
    for cut in 0..VX_TASK_HEADER_SIZE {
        let outcome = TaskHeader::decode(&full[..cut]);
        assert!(
            matches!(
                outcome,
                Err(AbiError::ShortHeader {
                    need: VX_TASK_HEADER_SIZE,
                    ..
                })
            ),
            "a {cut}-byte buffer must be rejected, got {outcome:?}"
        );
    }
    assert!(TaskHeader::decode(&full).is_ok());
}

#[test]
fn bad_magic_is_rejected() {
    for corrupt in [0x0000_0000u32, 0xffff_ffff, 0x5857_5602, 0x0156_5758] {
        let mut wire = golden_header_bytes();
        wire[0..4].copy_from_slice(&corrupt.to_le_bytes());
        let outcome = TaskHeader::decode(&wire);
        assert!(
            matches!(outcome, Err(AbiError::BadMagic { found }) if found == corrupt),
            "magic {corrupt:#010x} must be rejected, got {outcome:?}"
        );
    }
}

#[test]
fn an_oversized_payload_len_is_rejected() {
    for oversize in [
        VX_MAX_PAYLOAD_LEN + 1,
        VX_MAX_PAYLOAD_LEN * 2,
        1 << 40,
        u64::MAX,
    ] {
        let mut wire = golden_header_bytes();
        wire[task_offset::PAYLOAD_LEN..task_offset::PAYLOAD]
            .copy_from_slice(&oversize.to_le_bytes());
        let outcome = TaskHeader::decode(&wire);
        assert!(
            matches!(outcome, Err(AbiError::PayloadTooLarge { len }) if len == oversize),
            "payload_len {oversize} must be rejected, got {outcome:?}"
        );
    }

    // The boundary itself is legal.
    let mut wire = golden_header_bytes();
    wire[task_offset::PAYLOAD_LEN..task_offset::PAYLOAD]
        .copy_from_slice(&VX_MAX_PAYLOAD_LEN.to_le_bytes());
    assert!(
        TaskHeader::decode(&wire).is_ok(),
        "exactly 16 MiB is within the limit"
    );
}

#[test]
fn a_truncated_payload_is_rejected() {
    let header = TaskHeader::new(1, "acme", Engine::Ion, 1, 1, 100).expect("header");
    let mut frame = header.encode().to_vec();
    frame.extend_from_slice(&[0u8; 40]); // promised 100, supplied 40

    let outcome = Task::parse(&frame);
    assert!(
        matches!(outcome, Err(AbiError::ShortPayload { need: 100, got: 40 })),
        "got {outcome:?}"
    );
}

#[test]
fn a_lying_payload_len_cannot_cause_an_allocation_or_a_panic() {
    // The pathological host frame: a tiny buffer that claims a gigabyte.
    let mut frame = golden_header_bytes();
    frame[task_offset::PAYLOAD_LEN..task_offset::PAYLOAD]
        .copy_from_slice(&(1u64 << 30).to_le_bytes());
    frame.extend_from_slice(b"five");
    assert!(matches!(
        Task::parse(&frame),
        Err(AbiError::PayloadTooLarge { .. })
    ));

    // And one just inside the cap, which must be an honest ShortPayload.
    let mut frame = golden_header_bytes();
    frame[task_offset::PAYLOAD_LEN..task_offset::PAYLOAD]
        .copy_from_slice(&VX_MAX_PAYLOAD_LEN.to_le_bytes());
    frame.extend_from_slice(b"five");
    assert!(matches!(
        Task::parse(&frame),
        Err(AbiError::ShortPayload { got: 4, .. })
    ));
}

#[test]
fn an_unknown_engine_is_rejected_when_it_is_read() {
    for code in [0x00u8, 0x03, 0x7f, 0xff] {
        let mut wire = golden_header_bytes();
        wire[task_offset::ENGINE] = code;
        // The frame itself is well-formed: the ABI does not make engine a
        // structural field, so decode succeeds and the accessor reports.
        let header = TaskHeader::decode(&wire).expect("structurally valid");
        assert!(matches!(
            header.engine(),
            Err(AbiError::UnknownEngine(found)) if found == code
        ));
        assert!(matches!(
            header.require_ion(),
            Err(AbiError::WrongEngine { .. })
        ));
    }
}

#[test]
fn a_task_routed_to_iron_is_refused_by_ion() {
    let mut wire = golden_header_bytes();
    wire[task_offset::ENGINE] = Engine::Iron.code();
    let header = TaskHeader::decode(&wire).expect("valid");
    assert_eq!(header.engine().expect("engine"), Engine::Iron);
    assert!(matches!(
        header.require_ion(),
        Err(AbiError::WrongEngine {
            found: 0x02,
            expected: 0x01
        })
    ));
}

#[test]
fn an_oversized_result_payload_is_truncated_rather_than_dropped() {
    // payload_len in the result header is only 32 bits. Losing the tail of an
    // enormous diagnostic beats failing to report a result at all.
    let frame = ResultFrame::new(1, TaskState::Failed, -1, 0, vec![b'x'; 1000]);
    assert_eq!(frame.header.payload_len, 1000);
    assert_eq!(frame.payload.len(), 1000);
    let back = ResultFrame::decode(&frame.encode()).expect("decode");
    assert_eq!(back.payload.len(), 1000);
}

#[test]
fn result_rejection_paths() {
    // Short header.
    let good = ResultHeader::new(1, TaskState::Completed, 0, 0, 0).encode();
    for cut in 0..VX_RESULT_HEADER_SIZE {
        assert!(matches!(
            ResultHeader::decode(&good[..cut]),
            Err(AbiError::ShortHeader {
                need: VX_RESULT_HEADER_SIZE,
                ..
            })
        ));
    }

    // Bad magic.
    let mut wrong = good;
    wrong[0] ^= 0xff;
    assert!(matches!(
        ResultHeader::decode(&wrong),
        Err(AbiError::BadMagic { .. })
    ));

    // Short body.
    let mut short = ResultHeader::new(1, TaskState::Completed, 0, 0, 50)
        .encode()
        .to_vec();
    short.extend_from_slice(b"only ten..");
    assert!(matches!(
        ResultFrame::decode(&short),
        Err(AbiError::ShortPayload { need: 50, got: 10 })
    ));

    // Unknown state discriminant.
    let mut odd = ResultHeader::new(1, TaskState::Completed, 0, 0, 0)
        .encode()
        .to_vec();
    odd[result_offset::STATE] = 0x42;
    let header = ResultHeader::decode(&odd).expect("structurally valid");
    assert!(matches!(header.state(), Err(AbiError::UnknownState(0x42))));
}

// ---------------------------------------------------------------------------
// Zero-copy peek helpers
// ---------------------------------------------------------------------------

#[test]
fn peek_helpers_read_fields_without_decoding_the_header() {
    let wire = golden_header_bytes();
    assert_eq!(peek_magic(&wire).expect("magic"), VX_MAGIC_HEADER);
    assert_eq!(peek_task_id(&wire).expect("task_id"), 0x0102_0304_0506_0708);
    assert_eq!(peek_payload_len(&wire).expect("payload_len"), 13);

    let raw = peek_tenant_id_raw(&wire).expect("tenant");
    assert_eq!(raw.len(), VX_TENANT_ID_LEN);
    assert!(
        std::ptr::eq(raw.as_ptr(), wire[task_offset::TENANT_ID..].as_ptr()),
        "the tenant field must be borrowed, not copied"
    );
    assert_eq!(tenant_id_str(raw).expect("utf8"), "acme");

    // Peeks are bounds-checked, not unchecked reads.
    assert!(peek_magic(&wire[..3]).is_err());
    assert!(peek_task_id(&wire[..11]).is_err());
    assert!(peek_payload_len(&wire[..92]).is_err());
    assert!(peek_tenant_id_raw(&wire[..75]).is_err());
    assert!(peek_magic(&[]).is_err());
}

// ---------------------------------------------------------------------------
// Error mapping and enum discriminants
// ---------------------------------------------------------------------------

#[test]
fn errors_map_onto_the_documented_status_codes() {
    assert_eq!(
        AbiError::BadMagic { found: 0 }.status().code(),
        VxStatus::BadMagic.code()
    );
    assert_eq!(AbiError::BadMagic { found: 0 }.status().code(), -2);
    assert_eq!(
        AbiError::PayloadTooLarge { len: 0 }.status().code(),
        -3,
        "VX_ERR_PAYLOAD_TOO_LARGE"
    );
    assert_eq!(
        AbiError::ShortHeader { need: 93, got: 0 }.status().code(),
        -1,
        "VX_ERR_INVALID_ARG"
    );
    assert_eq!(
        AbiError::WrongEngine {
            found: 2,
            expected: 1
        }
        .status()
        .code(),
        -13,
        "VX_ERR_UNSUPPORTED"
    );
}

#[test]
fn status_code_values_match_the_c_enum() {
    for (status, code) in [
        (VxStatus::Ok, 0),
        (VxStatus::InvalidArg, -1),
        (VxStatus::BadMagic, -2),
        (VxStatus::PayloadTooLarge, -3),
        (VxStatus::NoMemory, -4),
        (VxStatus::Shm, -5),
        (VxStatus::RingFull, -6),
        (VxStatus::RingEmpty, -7),
        (VxStatus::Namespace, -8),
        (VxStatus::Cgroup, -9),
        (VxStatus::UidMap, -10),
        (VxStatus::Spawn, -11),
        (VxStatus::Timeout, -12),
        (VxStatus::Unsupported, -13),
    ] {
        assert_eq!(status.code(), code, "{status:?}");
    }
}

#[test]
fn engine_and_state_discriminants_match_the_c_enums() {
    assert_eq!(Engine::Ion.code(), 0x01);
    assert_eq!(Engine::Iron.code(), 0x02);
    assert_eq!(Engine::from_code(0x01).expect("ion"), Engine::Ion);
    assert_eq!(Engine::from_code(0x02).expect("iron"), Engine::Iron);
    assert!(Engine::from_code(0x00).is_err());

    for (state, code) in [
        (TaskState::Pending, 0x00u8),
        (TaskState::Running, 0x01),
        (TaskState::Completed, 0x02),
        (TaskState::Failed, 0x03),
        (TaskState::KilledOom, 0x04),
        (TaskState::KilledTimeout, 0x05),
        (TaskState::KilledSignal, 0x06),
    ] {
        assert_eq!(state.code(), code, "{state:?}");
        assert_eq!(TaskState::from_code(code).expect("state"), state);
    }
    assert!(TaskState::from_code(0x07).is_err());

    assert!(!TaskState::Pending.is_terminal());
    assert!(!TaskState::Running.is_terminal());
    for terminal in [
        TaskState::Completed,
        TaskState::Failed,
        TaskState::KilledOom,
        TaskState::KilledTimeout,
        TaskState::KilledSignal,
    ] {
        assert!(terminal.is_terminal(), "{terminal:?} is terminal");
    }
}

#[test]
fn error_messages_name_the_field_and_the_numbers() {
    let rendered = AbiError::BadMagic { found: 0xdead_beef }.to_string();
    assert!(rendered.contains("0xdeadbeef"), "{rendered}");
    assert!(rendered.contains("0x58575601"), "{rendered}");

    let rendered = AbiError::PayloadTooLarge { len: 1 << 30 }.to_string();
    assert!(rendered.contains("1073741824"), "{rendered}");
    assert!(rendered.contains("16777216"), "{rendered}");

    let rendered = AbiError::ShortPayload { need: 100, got: 40 }.to_string();
    assert!(
        rendered.contains("100") && rendered.contains("40"),
        "{rendered}"
    );
}

// ---------------------------------------------------------------------------
// Fuzz-flavoured sweep: no input may panic
// ---------------------------------------------------------------------------

#[test]
fn no_byte_pattern_can_panic_the_decoder() {
    // A cheap deterministic PRNG (xorshift64*) so the sweep is reproducible.
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };

    for round in 0..4096u32 {
        let len = (next() % 200) as usize;
        let mut buf: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();

        // Half the rounds get valid magic so the deeper paths are reached too.
        if round % 2 == 0 && buf.len() >= 4 {
            buf[0..4].copy_from_slice(&VX_MAGIC_HEADER.to_le_bytes());
        }

        // None of these may panic; any Result is acceptable.
        let _ = TaskHeader::decode(&buf);
        let _ = Task::parse(&buf);
        let _ = ResultHeader::decode(&buf);
        let _ = ResultFrame::decode(&buf);
        let _ = peek_magic(&buf);
        let _ = peek_task_id(&buf);
        let _ = peek_payload_len(&buf);
        if let Ok(raw) = peek_tenant_id_raw(&buf) {
            let _ = tenant_id_str(raw);
        }
    }
}
