//! Zero-copy codec for the **VxCloud immutable System ABI v1**.
//!
//! This module is a hand-mirror of `worker/include/worker_abi.h`. The C header
//! is the normative contract; the constants and offsets below are asserted
//! against it by the test suite. Field order and offsets are *frozen* — see the
//! stability note in the header.
//!
//! ## `vx_task_header_t` — host → guest (93 packed bytes, little-endian)
//!
//! ```text
//! offset  size  field
//! ------  ----  -----------------------------------------------------------
//!      0     4  magic            VX_MAGIC_HEADER (0x58575601)
//!      4     8  task_id          monotonic per-node task identifier
//!     12    64  tenant_id[64]    NUL-padded tenant slug
//!     76     1  engine           vx_engine_type_t (0x01 ion, 0x02 iron)
//!     77     4  memory_limit_mb  cgroup memory.max, MiB
//!     81     4  cpu_quota_us     cgroup cpu.max quota, microseconds
//!     85     8  payload_len      length of payload[] in bytes
//!     93     -  payload[]        flexible array
//! ```
//!
//! ## `vx_result_header_t` — guest → host (29 packed bytes, little-endian)
//!
//! ```text
//! offset  size  field
//! ------  ----  -----------------------------------------------------------
//!      0     4  magic            VX_MAGIC_HEADER
//!      4     8  task_id          echoes vx_task_header_t.task_id
//!     12     1  state            vx_task_state_t
//!     13     4  exit_code        i32, engine/process exit status
//!     17     8  duration_us      wall-clock execution time, microseconds
//!     25     4  payload_len      bytes in payload[]
//!     29     -  payload[]        result body / error text
//! ```
//!
//! ## Safety posture
//!
//! There is no `unsafe` in this module and no `transmute` of host structs.
//! Every multi-byte field is assembled with [`u32::from_le_bytes`] and friends
//! from a bounds-checked slice, so a hostile or truncated frame produces an
//! [`AbiError`] rather than a panic or a torn read.
//!
//! ```
//! use ion::abi::{task_offset, AbiError, Engine, Task, TaskHeader};
//!
//! let hdr = TaskHeader::new(7, "acme", Engine::Ion, 8, 100_000, 5).unwrap();
//! let frame = Task::encode(&hdr, b"hello").unwrap();
//!
//! // The happy path borrows the payload rather than copying it.
//! let task = Task::parse(&frame).unwrap();
//! assert_eq!(task.payload, b"hello");
//! assert_eq!(task.tenant().unwrap(), "acme");
//!
//! // A frame that lies about its own payload size is rejected, not trusted.
//! let mut liar = frame.clone();
//! liar[task_offset::PAYLOAD_LEN..task_offset::PAYLOAD]
//!     .copy_from_slice(&(1u64 << 30).to_le_bytes());
//! assert!(matches!(
//!     Task::parse(&liar),
//!     Err(AbiError::PayloadTooLarge { .. })
//! ));
//!
//! // So is a frame from an incompatible host runtime.
//! let mut wrong_magic = frame.clone();
//! wrong_magic[0] = 0xff;
//! assert!(matches!(
//!     Task::parse(&wrong_magic),
//!     Err(AbiError::BadMagic { .. })
//! ));
//! ```

use core::fmt;

// ---------------------------------------------------------------------------
// Versioning and fixed sizes (mirrors of the `#define`s in worker_abi.h)
// ---------------------------------------------------------------------------

/// `VX_MAGIC_HEADER` — `'V','X','W'` plus the version nibble.
///
/// A guest **must** reject any header whose magic differs; a mismatch means an
/// incompatible host runtime.
pub const VX_MAGIC_HEADER: u32 = 0x5857_5601;

/// `VX_ABI_VERSION`.
pub const VX_ABI_VERSION: u32 = 1;

/// `VX_TENANT_ID_LEN` — width of the NUL-padded tenant slug field.
pub const VX_TENANT_ID_LEN: usize = 64;

/// `VX_TASK_HEADER_SIZE` — packed size of `vx_task_header_t`.
pub const VX_TASK_HEADER_SIZE: usize = 93;

/// `VX_RESULT_HEADER_SIZE` — packed size of `vx_result_header_t`.
pub const VX_RESULT_HEADER_SIZE: usize = 29;

/// `VX_MAX_PAYLOAD_LEN` — 16 MiB. Larger bodies travel by shared-memory handle.
pub const VX_MAX_PAYLOAD_LEN: u64 = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Frozen field offsets — the contract
// ---------------------------------------------------------------------------

/// Byte offsets of every `vx_task_header_t` field.
pub mod task_offset {
    /// `magic` — 4 bytes.
    pub const MAGIC: usize = 0;
    /// `task_id` — 8 bytes.
    pub const TASK_ID: usize = 4;
    /// `tenant_id[64]` — 64 bytes.
    pub const TENANT_ID: usize = 12;
    /// `engine` — 1 byte.
    pub const ENGINE: usize = 76;
    /// `memory_limit_mb` — 4 bytes.
    pub const MEMORY_LIMIT_MB: usize = 77;
    /// `cpu_quota_us` — 4 bytes.
    pub const CPU_QUOTA_US: usize = 81;
    /// `payload_len` — 8 bytes.
    pub const PAYLOAD_LEN: usize = 85;
    /// `payload[]` — flexible array member.
    pub const PAYLOAD: usize = 93;
}

/// Byte offsets of every `vx_result_header_t` field.
pub mod result_offset {
    /// `magic` — 4 bytes.
    pub const MAGIC: usize = 0;
    /// `task_id` — 8 bytes.
    pub const TASK_ID: usize = 4;
    /// `state` — 1 byte.
    pub const STATE: usize = 12;
    /// `exit_code` — 4 bytes, signed.
    pub const EXIT_CODE: usize = 13;
    /// `duration_us` — 8 bytes.
    pub const DURATION_US: usize = 17;
    /// `payload_len` — 4 bytes.
    pub const PAYLOAD_LEN: usize = 25;
    /// `payload[]` — flexible array member.
    pub const PAYLOAD: usize = 29;
}

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/// `vx_engine_type_t` — which guest engine the host selected for this task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Engine {
    /// Micro-worker (this crate): Rust 2024 / tokio, sub-millisecond start.
    Ion = 0x01,
    /// Heavy worker: C++23 / io_uring, durable long-running tasks.
    Iron = 0x02,
}

impl Engine {
    /// Decode the on-wire discriminant.
    ///
    /// # Errors
    /// Returns [`AbiError::UnknownEngine`] for any value outside the enum.
    pub const fn from_code(code: u8) -> Result<Self, AbiError> {
        match code {
            0x01 => Ok(Self::Ion),
            0x02 => Ok(Self::Iron),
            other => Err(AbiError::UnknownEngine(other)),
        }
    }

    /// The on-wire discriminant.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// `vx_task_state_t` — terminal (or in-flight) disposition of a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TaskState {
    /// Accepted, not yet scheduled.
    Pending = 0x00,
    /// Executing.
    Running = 0x01,
    /// Finished successfully.
    Completed = 0x02,
    /// Finished with an application-level error.
    Failed = 0x03,
    /// Reaped after a `cgroup` `memory.max` breach.
    KilledOom = 0x04,
    /// Reaped after exceeding its wall-clock budget.
    KilledTimeout = 0x05,
    /// Reaped by a supervisor signal (`SIGTERM` / `SIGKILL`).
    KilledSignal = 0x06,
}

impl TaskState {
    /// Decode the on-wire discriminant.
    ///
    /// # Errors
    /// Returns [`AbiError::UnknownState`] for any value outside the enum.
    pub const fn from_code(code: u8) -> Result<Self, AbiError> {
        match code {
            0x00 => Ok(Self::Pending),
            0x01 => Ok(Self::Running),
            0x02 => Ok(Self::Completed),
            0x03 => Ok(Self::Failed),
            0x04 => Ok(Self::KilledOom),
            0x05 => Ok(Self::KilledTimeout),
            0x06 => Ok(Self::KilledSignal),
            other => Err(AbiError::UnknownState(other)),
        }
    }

    /// The on-wire discriminant.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Whether this state means "the task will not make further progress".
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending | Self::Running)
    }
}

/// `vx_status_t` — the negative status codes every `vx_*` entry point returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum VxStatus {
    /// Success.
    Ok = 0,
    /// A caller-supplied argument was structurally invalid.
    InvalidArg = -1,
    /// `magic` did not equal [`VX_MAGIC_HEADER`].
    BadMagic = -2,
    /// `payload_len` exceeded [`VX_MAX_PAYLOAD_LEN`].
    PayloadTooLarge = -3,
    /// Allocation failed.
    NoMemory = -4,
    /// `shm_open` / `mmap` / `ftruncate` failed.
    Shm = -5,
    /// Ring producer found no space.
    RingFull = -6,
    /// Ring consumer found no record.
    RingEmpty = -7,
    /// `unshare()` / `clone()` denied.
    Namespace = -8,
    /// cgroup v2 node create or write failed.
    Cgroup = -9,
    /// `uid_map` / `gid_map` write denied.
    UidMap = -10,
    /// `fork` / `exec` failed.
    Spawn = -11,
    /// Deadline exceeded.
    Timeout = -12,
    /// The kernel lacks a required facility.
    Unsupported = -13,
}

impl VxStatus {
    /// The numeric code as it crosses the FFI boundary.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every way an ABI frame can be rejected. No variant is ever a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiError {
    /// The buffer is shorter than the fixed header it claims to be.
    ShortHeader {
        /// Bytes the header requires.
        need: usize,
        /// Bytes actually available.
        got: usize,
    },
    /// `magic` did not equal [`VX_MAGIC_HEADER`].
    BadMagic {
        /// The value that was found instead.
        found: u32,
    },
    /// `payload_len` exceeded [`VX_MAX_PAYLOAD_LEN`].
    PayloadTooLarge {
        /// The declared length.
        len: u64,
    },
    /// `payload_len` promised more bytes than the buffer holds.
    ShortPayload {
        /// Bytes the header promised.
        need: u64,
        /// Bytes actually available after the header.
        got: u64,
    },
    /// `engine` held a value outside [`Engine`].
    UnknownEngine(u8),
    /// `state` held a value outside [`TaskState`].
    UnknownState(u8),
    /// `tenant_id` was not valid UTF-8 once NUL padding was stripped.
    TenantIdNotUtf8,
    /// A tenant slug longer than [`VX_TENANT_ID_LEN`] cannot be encoded.
    TenantIdTooLong {
        /// The offending length in bytes.
        len: usize,
    },
    /// The task was routed to a different engine than this binary implements.
    WrongEngine {
        /// The engine the host asked for.
        found: u8,
        /// The engine this binary implements.
        expected: u8,
    },
}

impl AbiError {
    /// Map this error onto the [`VxStatus`] the host expects to receive.
    #[must_use]
    pub const fn status(&self) -> VxStatus {
        match self {
            Self::BadMagic { .. } => VxStatus::BadMagic,
            Self::PayloadTooLarge { .. } => VxStatus::PayloadTooLarge,
            Self::ShortHeader { .. } | Self::ShortPayload { .. } => VxStatus::InvalidArg,
            Self::UnknownEngine(_)
            | Self::UnknownState(_)
            | Self::TenantIdNotUtf8
            | Self::TenantIdTooLong { .. } => VxStatus::InvalidArg,
            Self::WrongEngine { .. } => VxStatus::Unsupported,
        }
    }
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortHeader { need, got } => {
                write!(f, "truncated header: need {need} bytes, got {got}")
            }
            Self::BadMagic { found } => write!(
                f,
                "bad magic {found:#010x}, expected {VX_MAGIC_HEADER:#010x}"
            ),
            Self::PayloadTooLarge { len } => write!(
                f,
                "payload_len {len} exceeds VX_MAX_PAYLOAD_LEN {VX_MAX_PAYLOAD_LEN}"
            ),
            Self::ShortPayload { need, got } => {
                write!(f, "truncated payload: need {need} bytes, got {got}")
            }
            Self::UnknownEngine(e) => write!(f, "unknown engine discriminant {e:#04x}"),
            Self::UnknownState(s) => write!(f, "unknown task state discriminant {s:#04x}"),
            Self::TenantIdNotUtf8 => write!(f, "tenant_id is not valid UTF-8"),
            Self::TenantIdTooLong { len } => write!(
                f,
                "tenant slug is {len} bytes, maximum is {VX_TENANT_ID_LEN}"
            ),
            Self::WrongEngine { found, expected } => write!(
                f,
                "task routed to engine {found:#04x}, this binary is engine {expected:#04x}"
            ),
        }
    }
}

impl std::error::Error for AbiError {}

// ---------------------------------------------------------------------------
// Bounds-checked little-endian scalar readers
// ---------------------------------------------------------------------------

fn slice_at(buf: &[u8], off: usize, len: usize) -> Result<&[u8], AbiError> {
    let end = off.checked_add(len).ok_or(AbiError::ShortHeader {
        need: usize::MAX,
        got: buf.len(),
    })?;
    buf.get(off..end).ok_or(AbiError::ShortHeader {
        need: end,
        got: buf.len(),
    })
}

fn read_u8(buf: &[u8], off: usize) -> Result<u8, AbiError> {
    slice_at(buf, off, 1).map(|s| s[0])
}

fn read_u32(buf: &[u8], off: usize) -> Result<u32, AbiError> {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(slice_at(buf, off, 4)?);
    Ok(u32::from_le_bytes(raw))
}

fn read_i32(buf: &[u8], off: usize) -> Result<i32, AbiError> {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(slice_at(buf, off, 4)?);
    Ok(i32::from_le_bytes(raw))
}

fn read_u64(buf: &[u8], off: usize) -> Result<u64, AbiError> {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(slice_at(buf, off, 8)?);
    Ok(u64::from_le_bytes(raw))
}

// ---------------------------------------------------------------------------
// Raw "peek" helpers — genuinely zero-copy field access, no struct built
// ---------------------------------------------------------------------------

/// Read `magic` straight out of a frame without decoding anything else.
///
/// # Errors
/// [`AbiError::ShortHeader`] if fewer than 4 bytes are available.
pub fn peek_magic(buf: &[u8]) -> Result<u32, AbiError> {
    read_u32(buf, task_offset::MAGIC)
}

/// Read `task_id` straight out of a frame.
///
/// # Errors
/// [`AbiError::ShortHeader`] if the field is not fully present.
pub fn peek_task_id(buf: &[u8]) -> Result<u64, AbiError> {
    read_u64(buf, task_offset::TASK_ID)
}

/// Read `payload_len` straight out of a frame.
///
/// This is the hot path for a framing reader: it needs `payload_len` to know how
/// many more bytes to pull off the wire, and nothing else.
///
/// # Errors
/// [`AbiError::ShortHeader`] if the field is not fully present.
pub fn peek_payload_len(buf: &[u8]) -> Result<u64, AbiError> {
    read_u64(buf, task_offset::PAYLOAD_LEN)
}

/// Borrow the raw 64-byte `tenant_id` field without copying or validating it.
///
/// # Errors
/// [`AbiError::ShortHeader`] if the field is not fully present.
pub fn peek_tenant_id_raw(buf: &[u8]) -> Result<&[u8], AbiError> {
    slice_at(buf, task_offset::TENANT_ID, VX_TENANT_ID_LEN)
}

/// Strip NUL padding from a raw `tenant_id` field and validate it as UTF-8.
///
/// # Errors
/// [`AbiError::TenantIdNotUtf8`] if the unpadded bytes are not UTF-8.
pub fn tenant_id_str(raw: &[u8]) -> Result<&str, AbiError> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let trimmed = raw.get(..end).unwrap_or(&[]);
    core::str::from_utf8(trimmed).map_err(|_| AbiError::TenantIdNotUtf8)
}

// ---------------------------------------------------------------------------
// TaskHeader
// ---------------------------------------------------------------------------

/// A decoded `vx_task_header_t`.
///
/// This is a plain `Copy` value type occupying the same 93 logical bytes as the
/// C struct; it deliberately does *not* borrow, so a framing reader can decode
/// the header, learn `payload_len`, and only then acquire the payload bytes.
/// The payload itself is never copied — see [`Task`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskHeader {
    /// `magic`. Always [`VX_MAGIC_HEADER`] for a header produced by [`Self::new`].
    pub magic: u32,
    /// `task_id` — monotonic per-node identifier.
    pub task_id: u64,
    /// `tenant_id[64]` verbatim, including NUL padding.
    pub tenant_id: [u8; VX_TENANT_ID_LEN],
    /// `engine` discriminant, undecoded (see [`Self::engine`]).
    pub engine: u8,
    /// `memory_limit_mb` — cgroup `memory.max` in MiB.
    pub memory_limit_mb: u32,
    /// `cpu_quota_us` — cgroup `cpu.max` quota in microseconds.
    pub cpu_quota_us: u32,
    /// `payload_len` — bytes of payload following the header.
    pub payload_len: u64,
}

impl TaskHeader {
    /// Build a well-formed header.
    ///
    /// # Errors
    /// - [`AbiError::TenantIdTooLong`] if `tenant` exceeds [`VX_TENANT_ID_LEN`].
    /// - [`AbiError::PayloadTooLarge`] if `payload_len` exceeds [`VX_MAX_PAYLOAD_LEN`].
    pub fn new(
        task_id: u64,
        tenant: &str,
        engine: Engine,
        memory_limit_mb: u32,
        cpu_quota_us: u32,
        payload_len: u64,
    ) -> Result<Self, AbiError> {
        let bytes = tenant.as_bytes();
        if bytes.len() > VX_TENANT_ID_LEN {
            return Err(AbiError::TenantIdTooLong { len: bytes.len() });
        }
        if payload_len > VX_MAX_PAYLOAD_LEN {
            return Err(AbiError::PayloadTooLarge { len: payload_len });
        }
        let mut tenant_id = [0u8; VX_TENANT_ID_LEN];
        tenant_id
            .get_mut(..bytes.len())
            .ok_or(AbiError::TenantIdTooLong { len: bytes.len() })?
            .copy_from_slice(bytes);
        Ok(Self {
            magic: VX_MAGIC_HEADER,
            task_id,
            tenant_id,
            engine: engine.code(),
            memory_limit_mb,
            cpu_quota_us,
            payload_len,
        })
    }

    /// Decode the fixed 93-byte header prefix of `buf`.
    ///
    /// Only the header is inspected; `buf` may legitimately be exactly
    /// [`VX_TASK_HEADER_SIZE`] bytes long even when `payload_len > 0`, which is
    /// what lets a streaming reader decode-then-read.
    ///
    /// # Errors
    /// - [`AbiError::ShortHeader`] if `buf` is shorter than 93 bytes.
    /// - [`AbiError::BadMagic`] if `magic` is wrong.
    /// - [`AbiError::PayloadTooLarge`] if `payload_len` exceeds 16 MiB.
    pub fn decode(buf: &[u8]) -> Result<Self, AbiError> {
        if buf.len() < VX_TASK_HEADER_SIZE {
            return Err(AbiError::ShortHeader {
                need: VX_TASK_HEADER_SIZE,
                got: buf.len(),
            });
        }
        let magic = read_u32(buf, task_offset::MAGIC)?;
        if magic != VX_MAGIC_HEADER {
            return Err(AbiError::BadMagic { found: magic });
        }
        let payload_len = read_u64(buf, task_offset::PAYLOAD_LEN)?;
        if payload_len > VX_MAX_PAYLOAD_LEN {
            return Err(AbiError::PayloadTooLarge { len: payload_len });
        }
        let mut tenant_id = [0u8; VX_TENANT_ID_LEN];
        tenant_id.copy_from_slice(slice_at(buf, task_offset::TENANT_ID, VX_TENANT_ID_LEN)?);
        Ok(Self {
            magic,
            task_id: read_u64(buf, task_offset::TASK_ID)?,
            tenant_id,
            engine: read_u8(buf, task_offset::ENGINE)?,
            memory_limit_mb: read_u32(buf, task_offset::MEMORY_LIMIT_MB)?,
            cpu_quota_us: read_u32(buf, task_offset::CPU_QUOTA_US)?,
            payload_len,
        })
    }

    /// Serialise to the packed 93-byte little-endian wire form.
    #[must_use]
    pub fn encode(&self) -> [u8; VX_TASK_HEADER_SIZE] {
        let mut out = [0u8; VX_TASK_HEADER_SIZE];
        write_at(&mut out, task_offset::MAGIC, &self.magic.to_le_bytes());
        write_at(&mut out, task_offset::TASK_ID, &self.task_id.to_le_bytes());
        write_at(&mut out, task_offset::TENANT_ID, &self.tenant_id);
        write_at(&mut out, task_offset::ENGINE, &[self.engine]);
        write_at(
            &mut out,
            task_offset::MEMORY_LIMIT_MB,
            &self.memory_limit_mb.to_le_bytes(),
        );
        write_at(
            &mut out,
            task_offset::CPU_QUOTA_US,
            &self.cpu_quota_us.to_le_bytes(),
        );
        write_at(
            &mut out,
            task_offset::PAYLOAD_LEN,
            &self.payload_len.to_le_bytes(),
        );
        out
    }

    /// The tenant slug with NUL padding stripped.
    ///
    /// # Errors
    /// [`AbiError::TenantIdNotUtf8`] if the unpadded bytes are not UTF-8.
    pub fn tenant(&self) -> Result<&str, AbiError> {
        tenant_id_str(&self.tenant_id)
    }

    /// The decoded engine selector.
    ///
    /// # Errors
    /// [`AbiError::UnknownEngine`] for an unrecognised discriminant.
    pub const fn engine(&self) -> Result<Engine, AbiError> {
        Engine::from_code(self.engine)
    }

    /// Assert that this task really was routed to `ion`.
    ///
    /// # Errors
    /// [`AbiError::WrongEngine`] if `engine` is not [`Engine::Ion`].
    pub const fn require_ion(&self) -> Result<(), AbiError> {
        if self.engine == Engine::Ion as u8 {
            Ok(())
        } else {
            Err(AbiError::WrongEngine {
                found: self.engine,
                expected: Engine::Ion as u8,
            })
        }
    }

    /// Total on-wire size of this frame: header plus declared payload.
    #[must_use]
    pub const fn frame_len(&self) -> u64 {
        VX_TASK_HEADER_SIZE as u64 + self.payload_len
    }
}

/// A header paired with a **borrowed** payload: the zero-copy view of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Task<'a> {
    /// The decoded fixed header.
    pub header: TaskHeader,
    /// The payload, borrowed directly out of the caller's buffer.
    pub payload: &'a [u8],
}

impl<'a> Task<'a> {
    /// Decode a complete frame: 93-byte header followed by `payload_len` bytes.
    ///
    /// The payload is *borrowed*, never copied — this is the zero-copy entry
    /// point. Trailing bytes beyond `payload_len` are ignored so that a caller
    /// may hand in a larger read buffer.
    ///
    /// # Errors
    /// Everything [`TaskHeader::decode`] can return, plus
    /// [`AbiError::ShortPayload`] when the buffer is missing payload bytes.
    pub fn parse(buf: &'a [u8]) -> Result<Self, AbiError> {
        let header = TaskHeader::decode(buf)?;
        let available = (buf.len() - VX_TASK_HEADER_SIZE) as u64;
        if available < header.payload_len {
            return Err(AbiError::ShortPayload {
                need: header.payload_len,
                got: available,
            });
        }
        // `payload_len <= VX_MAX_PAYLOAD_LEN` was enforced by `decode`, so this
        // cast cannot wrap on any platform with a 32-bit-or-wider `usize`.
        let len = header.payload_len as usize;
        let payload = slice_at(buf, task_offset::PAYLOAD, len)?;
        Ok(Self { header, payload })
    }

    /// Encode a frame from a header and payload.
    ///
    /// # Errors
    /// [`AbiError::PayloadTooLarge`] if `payload` exceeds [`VX_MAX_PAYLOAD_LEN`].
    pub fn encode(header: &TaskHeader, payload: &[u8]) -> Result<Vec<u8>, AbiError> {
        if payload.len() as u64 > VX_MAX_PAYLOAD_LEN {
            return Err(AbiError::PayloadTooLarge {
                len: payload.len() as u64,
            });
        }
        let mut hdr = *header;
        hdr.payload_len = payload.len() as u64;
        let mut out = Vec::with_capacity(VX_TASK_HEADER_SIZE + payload.len());
        out.extend_from_slice(&hdr.encode());
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// The tenant slug with NUL padding stripped.
    ///
    /// # Errors
    /// [`AbiError::TenantIdNotUtf8`] if the unpadded bytes are not UTF-8.
    pub fn tenant(&self) -> Result<&str, AbiError> {
        self.header.tenant()
    }

    /// The `task_id` this frame carries.
    #[must_use]
    pub const fn task_id(&self) -> u64 {
        self.header.task_id
    }
}

// ---------------------------------------------------------------------------
// ResultHeader
// ---------------------------------------------------------------------------

/// A decoded `vx_result_header_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultHeader {
    /// `magic`. Always [`VX_MAGIC_HEADER`].
    pub magic: u32,
    /// `task_id` — echoes the task this result answers.
    pub task_id: u64,
    /// `state` discriminant, undecoded (see [`Self::state`]).
    pub state: u8,
    /// `exit_code` — engine or process exit status.
    pub exit_code: i32,
    /// `duration_us` — wall-clock execution time in microseconds.
    pub duration_us: u64,
    /// `payload_len` — bytes of result body / error text following the header.
    pub payload_len: u32,
}

impl ResultHeader {
    /// Build a result header.
    #[must_use]
    pub const fn new(
        task_id: u64,
        state: TaskState,
        exit_code: i32,
        duration_us: u64,
        payload_len: u32,
    ) -> Self {
        Self {
            magic: VX_MAGIC_HEADER,
            task_id,
            state: state as u8,
            exit_code,
            duration_us,
            payload_len,
        }
    }

    /// Decode the fixed 29-byte result header prefix of `buf`.
    ///
    /// # Errors
    /// - [`AbiError::ShortHeader`] if `buf` is shorter than 29 bytes.
    /// - [`AbiError::BadMagic`] if `magic` is wrong.
    pub fn decode(buf: &[u8]) -> Result<Self, AbiError> {
        if buf.len() < VX_RESULT_HEADER_SIZE {
            return Err(AbiError::ShortHeader {
                need: VX_RESULT_HEADER_SIZE,
                got: buf.len(),
            });
        }
        let magic = read_u32(buf, result_offset::MAGIC)?;
        if magic != VX_MAGIC_HEADER {
            return Err(AbiError::BadMagic { found: magic });
        }
        Ok(Self {
            magic,
            task_id: read_u64(buf, result_offset::TASK_ID)?,
            state: read_u8(buf, result_offset::STATE)?,
            exit_code: read_i32(buf, result_offset::EXIT_CODE)?,
            duration_us: read_u64(buf, result_offset::DURATION_US)?,
            payload_len: read_u32(buf, result_offset::PAYLOAD_LEN)?,
        })
    }

    /// Serialise to the packed 29-byte little-endian wire form.
    #[must_use]
    pub fn encode(&self) -> [u8; VX_RESULT_HEADER_SIZE] {
        let mut out = [0u8; VX_RESULT_HEADER_SIZE];
        write_at(&mut out, result_offset::MAGIC, &self.magic.to_le_bytes());
        write_at(
            &mut out,
            result_offset::TASK_ID,
            &self.task_id.to_le_bytes(),
        );
        write_at(&mut out, result_offset::STATE, &[self.state]);
        write_at(
            &mut out,
            result_offset::EXIT_CODE,
            &self.exit_code.to_le_bytes(),
        );
        write_at(
            &mut out,
            result_offset::DURATION_US,
            &self.duration_us.to_le_bytes(),
        );
        write_at(
            &mut out,
            result_offset::PAYLOAD_LEN,
            &self.payload_len.to_le_bytes(),
        );
        out
    }

    /// The decoded task state.
    ///
    /// # Errors
    /// [`AbiError::UnknownState`] for an unrecognised discriminant.
    pub const fn state(&self) -> Result<TaskState, AbiError> {
        TaskState::from_code(self.state)
    }
}

/// A result header paired with its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultFrame {
    /// The fixed header.
    pub header: ResultHeader,
    /// The result body: JSON on success, error text on failure.
    pub payload: Vec<u8>,
}

impl ResultFrame {
    /// Assemble a frame, deriving `payload_len` from `payload`.
    ///
    /// A payload longer than `u32::MAX` is truncated rather than rejected: the
    /// header field is only 32 bits wide, and losing the tail of an oversized
    /// diagnostic is strictly better than failing to report a result at all.
    #[must_use]
    pub fn new(
        task_id: u64,
        state: TaskState,
        exit_code: i32,
        duration_us: u64,
        mut payload: Vec<u8>,
    ) -> Self {
        if payload.len() > u32::MAX as usize {
            payload.truncate(u32::MAX as usize);
        }
        let payload_len = payload.len() as u32;
        Self {
            header: ResultHeader::new(task_id, state, exit_code, duration_us, payload_len),
            payload,
        }
    }

    /// Serialise header plus body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(VX_RESULT_HEADER_SIZE + self.payload.len());
        out.extend_from_slice(&self.header.encode());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode a complete result frame.
    ///
    /// # Errors
    /// Everything [`ResultHeader::decode`] returns, plus
    /// [`AbiError::ShortPayload`] when body bytes are missing.
    pub fn decode(buf: &[u8]) -> Result<Self, AbiError> {
        let header = ResultHeader::decode(buf)?;
        let available = (buf.len() - VX_RESULT_HEADER_SIZE) as u64;
        if available < u64::from(header.payload_len) {
            return Err(AbiError::ShortPayload {
                need: u64::from(header.payload_len),
                got: available,
            });
        }
        let payload = slice_at(buf, result_offset::PAYLOAD, header.payload_len as usize)?.to_vec();
        Ok(Self { header, payload })
    }
}

/// Copy `src` into `dst` at `off`. Silently no-ops if the destination is too
/// small, which cannot happen for the fixed-size arrays used above but keeps
/// the function panic-free by construction.
fn write_at(dst: &mut [u8], off: usize, src: &[u8]) {
    if let Some(slot) = dst.get_mut(off..off + src.len()) {
        slot.copy_from_slice(src);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_match_the_c_header() {
        assert_eq!(task_offset::MAGIC, 0);
        assert_eq!(task_offset::TASK_ID, 4);
        assert_eq!(task_offset::TENANT_ID, 12);
        assert_eq!(task_offset::ENGINE, 76);
        assert_eq!(task_offset::MEMORY_LIMIT_MB, 77);
        assert_eq!(task_offset::CPU_QUOTA_US, 81);
        assert_eq!(task_offset::PAYLOAD_LEN, 85);
        assert_eq!(task_offset::PAYLOAD, VX_TASK_HEADER_SIZE);
        assert_eq!(result_offset::PAYLOAD, VX_RESULT_HEADER_SIZE);
    }

    #[test]
    fn magic_spells_vxw_v1() {
        assert_eq!(VX_MAGIC_HEADER.to_be_bytes(), [b'X', b'W', b'V', 0x01]);
    }

    #[test]
    fn status_codes_are_negative_and_distinct() {
        assert_eq!(VxStatus::Ok.code(), 0);
        assert_eq!(VxStatus::BadMagic.code(), -2);
        assert_eq!(VxStatus::Unsupported.code(), -13);
    }
}
