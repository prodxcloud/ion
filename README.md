# ion

**An ultra-light Rust micro-worker for VxCloud.** It speaks the frozen VxCloud
System ABI, registers its own dynamic-DNS endpoint by hand-encoding RFC 2136
`UPDATE` packets over UDP/53, and executes async HTTP/scrape tasks over
HTTP/1.1 or HTTP/2 with rustls.

Measured on the host described below: **2.1–2.6 MiB peak RSS** and a **846 µs
end-to-end process lifetime** for the static build — 26 µs more than `/bin/true`
costs on the same machine.

```
$ ion --version
ion 0.1.0 (vx-abi v1, engine 0x01)
```

---

## Contents

- [Why](#why)
- [Architecture](#architecture)
- [The DNS layer](#the-dns-layer-the-centrepiece)
- [Wire format of an UPDATE packet](#wire-format-of-an-update-packet)
- [TSIG](#tsig-rfc-8945)
- [The ABI](#the-abi)
- [Substrate matrix](#substrate-matrix)
- [Measured performance](#measured-performance)
- [Usage](#usage)
- [Configuration](#configuration)
- [Building](#building)
- [Testing and verification](#testing-and-verification)
- [Security](#security)

---

## Why

VxCloud runs two guest engines behind one ABI. `iron` (C++23 / io_uring) is the
heavy half: durable, long-running, io_uring-backed. `ion` is the light half. It
exists for the case where the work is small and the *overhead* is the problem —
a scrape, a health probe, a webhook fan-out — and where that work has to happen
in a Lambda invocation, a 4 MiB container, or a VM that will be torn down in
ninety seconds.

Three properties follow from that:

1. **Start faster than the scheduler can notice.** No runtime is created for
   subcommands that do not need one; `--version` and `selftest` never touch
   tokio. Measured in-process time from `main` entry to exit: **49 µs** (p50,
   glibc build).

2. **Stay small enough to be free.** Current-thread tokio by default, one idle
   connection per host, a hard response-size cap, and no unbuffered accumulation
   anywhere. Measured peak RSS with a live rustls HTTP client constructed:
   **2.63 MiB** (static build).

3. **Be addressable the moment it is alive.** Every worker publishes
   `<task_id>.<tenant>.<base-domain>` as an `A` record on boot and withdraws it
   on `SIGTERM`. Nothing else in the fleet needs to be told where it landed.

---

## Architecture

```
                        ┌──────────────────────────────────────┐
   vxnode host  ────────▶│ 93-byte vx_task_header_t + payload  │
                        └──────────────────┬───────────────────┘
                                           │
                              ┌────────────▼────────────┐
                              │  abi.rs                 │  zero-copy codec,
                              │  parse / validate       │  typed errors, no panics
                              └────────────┬────────────┘
                                           │
   ┌───────────────────────────────────────▼──────────────────────────────┐
   │ runtime.rs — dispatch loop, wall-clock timing, result emission       │
   └───┬───────────────────────────────────────────────────────┬──────────┘
       │                                                       │
┌──────▼──────────────────┐                       ┌────────────▼───────────────┐
│ scrape.rs               │                       │ registrar.rs               │
│ tokio + hyper + rustls  │                       │ boot: UPDATE add A         │
│ HTTP/1.1 and HTTP/2     │                       │ SIGTERM: UPDATE delete RR  │
│ CSS selectors           │                       └────────────┬───────────────┘
│ bounded fan-out         │                                    │
└─────────────────────────┘               ┌────────────────────▼──────────────┐
                                          │ dns/                              │
                                          │  name.rs     RFC 1035 labels      │
                                          │  message.rs  header + sections    │
                                          │  update.rs   RFC 2136 UPDATE      │
                                          │  tsig.rs     RFC 8945 HMAC-SHA256 │
                                          └────────────────────┬──────────────┘
                                                               │ UDP/53
                                          ┌────────────────────▼──────────────┐
                                          │ authoritative server (BIND, Knot, │
                                          │ PowerDNS, Route 53 via a relay)   │
                                          └───────────────────────────────────┘
       │
┌──────▼───────────────────────────────────────────────────────────────────────┐
│ 29-byte vx_result_header_t + result body  ────────────────▶  vxnode host     │
└──────────────────────────────────────────────────────────────────────────────┘
```

| File | Lines of responsibility |
|---|---|
| `src/abi.rs` | packed `vx_task_header_t` / `vx_result_header_t` codec, offset-exact |
| `src/config.rs` | `VX_*` environment configuration, no panics on operator input |
| `src/dns/name.rs` | RFC 1035 label encoding, the 63/255 limits, decompression |
| `src/dns/message.rs` | DNS header + four sections, encoder and decoder |
| `src/dns/update.rs` | RFC 2136 `UPDATE` builder: add, three deletes, four prerequisites |
| `src/dns/tsig.rs` | RFC 8945 signing and verification, hand-rolled base64 |
| `src/registrar.rs` | lifecycle, local-address detection, retry, graceful shutdown |
| `src/scrape.rs` | async fetch, three caps, CSS extraction, bounded fan-out |
| `src/runtime.rs` | frame dispatch loop, timing, result emission |
| `src/main.rs` | hand-rolled CLI, no `clap` |

There is **no `unsafe`** anywhere: `src/lib.rs` carries `#![forbid(unsafe_code)]`.

---

## The DNS layer (the centrepiece)

`ion` does not shell out. There is no `nsupdate`, no `dig`, no `Command::new`,
and no third-party DNS crate in the dependency graph. It builds the bytes.

What is implemented:

| RFC | Feature |
|---|---|
| 1035 §3.1 | length-prefixed label encoding, 63-byte label limit, 255-byte name limit |
| 1035 §4.1.1 | 12-byte header, flags word, four section counters |
| 1035 §4.1.4 | compression-pointer *decoding*, with backward-only and loop guards |
| 2136 §2 | opcode 5, and the `ZOCOUNT`/`PRCOUNT`/`UPCOUNT`/`ADCOUNT` re-reading of the counters |
| 2136 §2.3 | zone section: one question, `QTYPE=SOA`, `QCLASS=IN` |
| 2136 §2.4.1 | prerequisite: RRset exists (value independent) — `CLASS=ANY` |
| 2136 §2.4.3 | prerequisite: RRset does not exist — `CLASS=NONE` |
| 2136 §2.4.4 | prerequisite: name is in use — `TYPE=ANY`, `CLASS=ANY` |
| 2136 §2.4.5 | prerequisite: name is **not** in use — `TYPE=ANY`, `CLASS=NONE` |
| 2136 §2.5.1 | add an RR — `CLASS=IN`, TTL as given |
| 2136 §2.5.2 | delete an entire RRset — `CLASS=ANY`, `TTL=0`, `RDLENGTH=0` |
| 2136 §2.5.3 | delete every RRset at a name — `TYPE=ANY`, `CLASS=ANY`, `TTL=0`, `RDLENGTH=0` |
| 2136 §2.5.4 | delete one specific RR — `CLASS=NONE`, `TTL=0`, `RDATA` retained |
| 8945 | TSIG HMAC-SHA256 request signing and response verification |
| — | record types `A`, `AAAA`, `CNAME`, `TXT`, `SOA`, `ANY`, `TSIG` |
| — | response decoding with typed `RCODE` reporting, including the RFC 2136 additions (`YXDOMAIN`, `YXRRSET`, `NXRRSET`, `NOTAUTH`, `NOTZONE`) and the RFC 8945 extended codes (`BADSIG`, `BADKEY`, `BADTIME`) |

Two deliberate choices worth stating:

**Names are never compressed on output.** Compression is optional in RFC 1035
§4.1.4 and not required by RFC 2136. Emitting uncompressed names makes every
packet a deterministic function of the message, which is precisely what TSIG
signing needs, and it sidesteps the class of bugs RFC 3597 §4 warns about when
`RDATA` containing names is re-serialised by an intermediary. It costs 11 bytes
on a typical registration. Compression is fully supported on *input* — see the
interop note below.

**Out-of-zone names are rejected locally.** A server would answer `NOTZONE`;
catching it in the builder turns a round trip into an immediate typed error.

---

## Wire format of an UPDATE packet

This is a real packet, byte for byte, as `ion selftest` prints it. It adds
`host.example.com. 60 IN A 192.0.2.7` to the zone `example.com.`

```
123428000001000000010000076578616d706c6503636f6d000006000104686f
7374076578616d706c6503636f6d00000100010000003c0004c0000207
```

Annotated:

```
offset  bytes                             meaning
------  --------------------------------  ----------------------------------------
                                          ── HEADER (RFC 1035 §4.1.1) ────────────
  0     12 34                             ID = 0x1234
  2     28 00                             flags: QR=0 Opcode=5(UPDATE) AA=0 TC=0
                                                 RD=0 RA=0 Z=0 AD=0 CD=0 RCODE=0
                                            0x2800 = 0b0010_1000_0000_0000
                                                       ^^^^ opcode, bits 11..14
  4     00 01                             ZOCOUNT = 1   (aliases QDCOUNT)
  6     00 00                             PRCOUNT = 0   (aliases ANCOUNT)
  8     00 01                             UPCOUNT = 1   (aliases NSCOUNT)
 10     00 00                             ADCOUNT = 0   (aliases ARCOUNT)

                                          ── ZONE SECTION (RFC 2136 §2.3) ────────
 12     07 65 78 61 6d 70 6c 65           len=7 "example"
 20     03 63 6f 6d                       len=3 "com"
 24     00                                root label, name ends
 25     00 06                             QTYPE  = 6   (SOA — always, for a zone)
 27     00 01                             QCLASS = 1   (IN)

                                          ── UPDATE SECTION (RFC 2136 §2.5.1) ────
 29     04 68 6f 73 74                    len=4 "host"
 34     07 65 78 61 6d 70 6c 65           len=7 "example"   (uncompressed)
 42     03 63 6f 6d                       len=3 "com"
 46     00                                root label
 47     00 01                             TYPE     = 1    (A)
 49     00 01                             CLASS    = 1    (IN)  <- this means ADD
 51     00 00 00 3c                       TTL      = 60
 55     00 04                             RDLENGTH = 4
 57     c0 00 02 07                       RDATA    = 192.0.2.7
                                          ────────────────────────────── 61 bytes
```

The same message with the verb changed. Only `CLASS`, `TTL`, and `RDLENGTH`
move — there is no "operation" field in RFC 2136:

```
add one RR              ... 00 01  00 01  00 00 00 3c  00 04  c0 00 02 07   61 bytes
delete that exact RR    ... 00 01  00 fe  00 00 00 00  00 04  c0 00 02 07   61 bytes
delete the A RRset      ... 00 01  00 ff  00 00 00 00  00 00                57 bytes
delete every RRset      ... 00 ff  00 ff  00 00 00 00  00 00                57 bytes
prereq: name unused     ... 00 ff  00 fe  00 00 00 00  00 00                57 bytes
                            ^type  ^class ^ttl         ^rdlength
```

`0x00fe` = 254 = `CLASS NONE`. `0x00ff` = 255 = `CLASS ANY` / `TYPE ANY`.

### Third-party interop

The packets above were derived by hand from the RFCs and then cross-checked
against [dnspython](https://www.dnspython.org/) 2.8.0. Every field matched byte
for byte. The single difference was compression: dnspython emits the update
record's owner name as `04 "host"` followed by the pointer `c0 0c`, giving 50
bytes instead of 61, and confirmed that its parse of `ion`'s uncompressed packet
compares **equal** to its parse of its own. That compressed packet is checked
into `tests/dns_wire.rs` as a fixture and fed to `ion`'s decoder, so pointer
following is tested against bytes a different implementation produced.

---

## TSIG (RFC 8945)

Signing is HMAC-SHA256 (and HMAC-SHA512), pure Rust via `hmac` + `sha2`.

The digest is the part implementations get wrong, so it is worth being explicit.
For a **request** it is the concatenation of:

1. the complete message *before* the TSIG RR is appended — `ARCOUNT` **not**
   counting it; then
2. the *TSIG variables*: key name (canonical, lowercased), `CLASS`(=`ANY`),
   `TTL`(=0), algorithm name (canonical), `Time Signed` (48 bits), `Fudge`,
   `Error`, `Other Len`, `Other Data`.

`MAC Size`, `MAC`, and `Original ID` are part of the record but **not** part of
the digest. For a **response**, the digest is prefixed with
`u16(len(request_mac)) ‖ request_mac`, which is what binds the two halves of a
transaction together.

Response verification digests the received bytes *as received*, truncated at the
offset where the TSIG RR begins and with `ARCOUNT` patched down by one — not a
re-encode, because a re-encode would lose whatever compression the server used
and produce a different hash.

### Verified against dnspython

The signed packet `ion selftest` produces was handed to dnspython's own
`dns.tsig` verifier with the clock pinned to the vector's `time_signed`:

```
ion signed packet 146 bytes, TSIG RR starts at offset 61
>>> from_wire() with keyring succeeded, had_tsig = True
dnspython parsed it. opcode: UPDATE
  zone  : example.com. IN SOA
  update: ['host.example.com. 60 IN A 192.0.2.7']
  tsig  : hmac-sha256. 1700000000 300 32 djumGq1SvUK+5fRWEGEQe0nqSXVt3sNkHci4xPnQZLU= 4660 NOERROR 0
>>> dnspython VALIDATED ion's TSIG MAC (no exception raised)
>>> negative control: tampered MAC correctly rejected
```

The negative control matters: flipping one bit inside the MAC makes the same
verifier raise `BadSignature`, so the positive result is not vacuous. The MAC is
pinned in `tests/dns_wire.rs` as `TSIG_MAC_HEX`.

The HMAC primitive itself is separately checked against **RFC 4231 test case 2**
in `src/dns/tsig.rs`.

---

## The ABI

`worker/include/worker_abi.h` is the normative contract; `src/abi.rs` mirrors it
by hand. Field offsets are frozen and asserted by `tests/abi_roundtrip.rs`
against a header assembled by hand from the offset table, so a regression in the
codec cannot be masked by a matching regression in the encoder.

```
vx_task_header_t — host → guest, 93 packed bytes, little-endian
  0   4  magic            0x58575601
  4   8  task_id
 12  64  tenant_id[64]    NUL-padded
 76   1  engine           0x01 ion, 0x02 iron
 77   4  memory_limit_mb
 81   4  cpu_quota_us
 85   8  payload_len      ≤ 16 MiB
 93   -  payload[]

vx_result_header_t — guest → host, 29 packed bytes, little-endian
  0   4  magic
  4   8  task_id
 12   1  state            0x02 completed, 0x03 failed, …
 13   4  exit_code        int32, negative = vx_status_t
 17   8  duration_us
 25   4  payload_len
 29   -  payload[]
```

Note that the ABI is **little-endian** and DNS is **big-endian**; the two codecs
are deliberately separate and each test suite asserts its own byte order.

The codec's contract:

- **No `unsafe`, no `transmute`.** Every field is assembled with
  `u32::from_le_bytes` and friends from a bounds-checked slice.
- **Zero-copy payload.** `Task::parse` borrows the payload in place; the test
  suite asserts pointer identity, not just equality.
- **Never panics.** Bad magic, an oversized `payload_len`, a truncated buffer, a
  non-UTF-8 tenant, an unknown engine or state discriminant — all typed errors
  mapped onto `vx_status_t`. A 4096-round randomised sweep asserts that no byte
  pattern panics any decoder.
- **A lying header cannot cause a huge allocation.** `payload_len` is validated
  against the 16 MiB cap *before* anything is reserved.

Framing is implicit: a task frame is self-describing, so a stream is just
`[header][payload][header][payload]…`. `dispatch_loop` stops cleanly at EOF on a
frame boundary and errors on a partial frame — silently dropping a truncated
task would lose work.

---

## Substrate matrix

| Substrate | Fit | Notes |
|---|---|---|
| **AWS Lambda** (`provided.al2023`) | strong | 2.1 MiB RSS against a 128 MiB floor; the static build has no dynamic loader work to do. Set `VX_DNS_ENABLED=0` — Lambda's address is ephemeral and not routable. |
| **Micro-container** (`scratch` / `distroless`) | strong | the musl build is `static-pie linked`, so `FROM scratch` + one `COPY` is a complete image. rustls means no CA bundle or OpenSSL to install. |
| **Ephemeral VM** (Firecracker, cloud-init) | strong | this is the design centre: register an `A` record on boot, serve, withdraw on `SIGTERM`. `VX_DNS_TTL=60` bounds the damage if the VM dies without a signal. |
| **Kubernetes sidecar / Job** | good | current-thread runtime keeps the memory `requests` honest. Use a `preStop` hook or plain `SIGTERM`; `serve_until_signal` handles both `SIGTERM` and `SIGINT`. Registration is usually redundant next to a `Service`, so leave `VX_DNS_ENABLED=0` unless you want per-pod names. |
| **systemd unit on a shared host** | good | `Type=simple`, `KillSignal=SIGTERM`. The de-registration path runs before exit. |
| **Windows / macOS** | partial | the DNS, ABI, and scrape layers are portable; the signal wait falls back to `ctrl_c()` off Unix. Only tested on Linux. |

### Dockerfile for the static build

```dockerfile
FROM scratch
COPY ion /ion
ENTRYPOINT ["/ion"]
```

---

## Measured performance

Everything below was measured, not estimated. Where a number misses the target,
it says so.

**Host:** WSL2, kernel 6.6.87.2-microsoft-standard-WSL2, x86_64,
12th Gen Intel Core i5-12450H, 12 cores, glibc 2.39.
**Build:** `--release` with `opt-level="z"`, `lto="fat"`, `codegen-units=1`,
`panic="abort"`, `strip=true`.
**Method:** three full benchmark sessions on the same binaries. Ranges below are
the spread across those sessions — this is a laptop under WSL2, not a quiet
benchmark rig, and pretending a single run's digits are stable would be
dishonest. Every session is reproducible with the commands at the end of this
section.

### Binary size

| Build | Size | Linkage |
|---|---|---|
| `x86_64-unknown-linux-gnu` | 3,430,232 B (3.27 MiB) | dynamic: `libc`, `libm`, `libgcc_s`, `ld-linux` — **no OpenSSL, no system TLS** |
| `x86_64-unknown-linux-musl` | 3,560,432 B (3.40 MiB) | `static-pie linked`, `ldd` reports `statically linked` |

### Peak RSS — target ≤ 8 MiB: **met**

`/usr/bin/time -v`, "Maximum resident set size", worst of 7 runs per session,
range across 3 sessions.

| Workload | glibc dynamic | musl static |
|---|---|---|
| `ion --version` (no tokio runtime created) | 3,968–4,096 KiB — **3.88–4.00 MiB** | 2,176 KiB — **2.13 MiB** |
| `ion selftest` (ABI + 4 DNS packets + TSIG sign + decode) | 4,224–4,352 KiB — **4.13–4.25 MiB** | 2,304–2,432 KiB — **2.25–2.38 MiB** |
| `ion run`, 1 task (current-thread tokio **and** a live rustls HTTP client) | 4,864–4,992 KiB — **4.75–4.88 MiB** | 2,688 KiB — **2.63 MiB** |
| `ion run`, 1,000 tasks streamed | 4,736–4,864 KiB — **4.63–4.75 MiB** | 2,816 KiB — **2.75 MiB** |
| `ion run`, one 1 MiB inline payload | — | 4,480 KiB — **4.38 MiB** |

The static build's worst measured figure across every workload is **2.75 MiB**,
about a third of the budget. Streaming 5,000 tasks does not move it, which is the
point of the streaming reader: memory is bounded by the frame, not the stream.

Two honest caveats:

- **RSS scales with the inline payload**, because the ABI passes payloads inline.
  A 1 MiB payload measured 4.38 MiB peak. The 16 MiB ABI ceiling would therefore
  exceed the 8 MiB target; that is what the header's "pass larger payloads by
  shared-memory handle" note is for.
- **The current-thread default did not measurably beat multi-thread here.**
  Measured on this 12-core host: `run` with `VX_RUNTIME_MULTI_THREAD=1` came out
  at 2,816 KiB (musl) versus 2,688 KiB for current-thread, and *identical* at
  4,864–4,992 KiB for glibc. Thread stacks are lazily faulted, so 11 idle workers
  cost little *resident* memory on a workload this short. Current-thread remains
  the default because it keeps the worker-thread spawn off the startup path and
  the virtual-memory reservation out of the accounting, but the honest RSS win is
  about 128 KiB, not the dramatic figure the design note might imply.

### Cold start — target < 1 ms

Two measurements, because they answer different questions.

**(a) In-process: `main` entry to process exit**, reported by `ion --timing`.
This is `ion`'s own cost, excluding the kernel's `execve` and the dynamic
loader. 60 runs per session, p50 quoted; the min/p95/max columns are from the
best-behaved session.

| | p50 across sessions | min | p95 | max |
|---|---|---|---|---|
| glibc `--version` | **49 – 79 µs** | 39 µs | 79–90 µs | 202 µs |
| glibc `selftest` | **96 – 145 µs** | 85 µs | 141–147 µs | 193 µs |
| musl `--version` | **86 – 123 µs** | 73 µs | 129–198 µs | 267 µs |
| musl `selftest` | **141 – 199 µs** | 119 µs | 216–326 µs | 676 µs |

**Target met with an order of magnitude in hand** — the worst p50 anywhere is
199 µs, and `selftest` is doing real work: an ABI encode/decode round trip, four
`UPDATE` packets, a TSIG signature, and a full message decode.

**(b) Full process: `fork` + `execve` + loader + run + exit**, wall clock,
500 iterations per session. The reference row is the floor this host can achieve
at all, and it moved between sessions, so both it and the results are ranges.

| | per process | verdict |
|---|---|---|
| shell loop, no `exec` | 7 µs | harness overhead |
| `/bin/true` (26 KiB, dynamic) | **715 – 833 µs** | the fork+exec floor on this host |
| **musl static `ion --version`** | **825 – 846 µs** | **target met** — 26–110 µs above the floor |
| musl static `ion selftest` | 906 – 1,244 µs | borderline, doing real work |
| glibc dynamic `ion --version` | 1,288 – 1,713 µs | **target missed** |
| glibc dynamic `ion selftest` | 1,322 – 1,861 µs | **target missed** |

The honest reading: **the static build meets < 1 ms end to end**, and does so by
adding 26–110 µs to what this operating system charges for creating *any* process.
The glibc build misses it, and the reason is not `ion` — it is `ld.so` resolving
`libc`/`libm`/`libgcc_s`, which costs 500–900 µs here. Ship the static build where
cold start matters.

WSL2 process creation is unusually expensive; on bare-metal Linux the `/bin/true`
floor is typically 200–400 µs and every row above would shift down with it. The
in-process figures in (a) are the ones that reflect `ion` rather than the host.

### Per-task dispatch cost

1,000 `{"op":"noop"}` frames through `ion run`, in-process time:

| Build | per task |
|---|---|
| glibc | **39 – 45 µs** |
| musl | **35 – 65 µs** |

This is a *measured optimisation*, not a design assumption. The first
implementation cost **170–280 µs per task**. Profiling by substitution — file
output versus `/dev/null` versus a real pipe changed almost nothing — showed the
cost was not I/O bandwidth but the *number* of `spawn_blocking` round trips: two
reads (93-byte header, then payload) plus a write plus a flush, each one a thread
handoff. Reading through a `BufReader` collapsed the two reads into one buffered
syscall and took the cost to 35–65 µs, a 3–5× improvement:

```
before:  1000 tasks, File in + File out  : 170.5 us/task
after :  1000 tasks, File in + File out  :  62.3 us/task
         5000 tasks, File in + File out  :  51.5 us/task
```

The writer is deliberately **not** buffered. `dispatch_loop` flushes after every
result frame, which is one write syscall per task, because a supervisor blocking
on a result must not wait for a buffer to fill.

### Reproducing these numbers

```bash
cargo build --release
/usr/bin/time -v ./target/release/ion run --input tasks.bin --output out.bin
./target/release/ion selftest --timing        # in-process time to stderr
for i in $(seq 500); do ./target/release/ion --version >/dev/null; done   # wall clock
```

---

## Usage

All output below is real, captured from the static build.

### `ion --version`

```
$ ion --version
ion 0.1.0 (vx-abi v1, engine 0x01)
```

### `ion selftest` — encode every packet type, print hex, touch no network

```
$ ion selftest
ion 0.1.0 (vx-abi v1, engine 0x01)

ABI task frame     106 bytes
  header           01565758 0807060504030201 61636d65<56 NUL bytes> 01 08000000
                   a0860100 0d00000000000000
  task_id          0x0102030405060708
  tenant_id        "acme"
  payload_len      13
ABI result frame   31 bytes
  header           0156575808070605040302010200000000d20400000000000002000000

RFC 2136 UPDATE add A  61 bytes
  123428000001000000010000076578616d706c6503636f6d000006000104686f7374076578
  616d706c6503636f6d00000100010000003c0004c0000207
  header           id=0x1234 opcode=5 zocount=1 prcount=0 upcount=1 adcount=0
  zone             example.com. IN SOA
  update           host.example.com. IN A ttl=60 rdlength=4

RFC 2136 UPDATE delete RR (CLASS NONE)  61 bytes
  123428000001000000010000076578616d706c6503636f6d000006000104686f7374076578
  616d706c6503636f6d00000100fe000000000004c0000207

RFC 2136 UPDATE delete RRset (CLASS ANY)  57 bytes
  123428000001000000010000076578616d706c6503636f6d000006000104686f7374076578
  616d706c6503636f6d00000100ff000000000000

TSIG hmac-sha256 signed UPDATE  146 bytes
  wire             123428000001000000010001...  (see the TSIG section)
  mac              763ba61aad52bd42bee5f4561061107b49ea49756ddec3641dc8b8c4f9d064b5
  key name         selftest.key.
  time signed      1700000000 fudge 300
  additional count 1
  round-trip       1 additional record(s), last is TSIG

RFC 1035 limits
  63-byte label    accepted
  64-byte label    rejected
selftest ok
```

The hex above is wrapped for this page and the 56-byte NUL run of the `tenant_id`
field is elided; `ion` prints every packet as one unbroken line of hex.

### `ion scrape` — HTTP/2 negotiated over ALPN, CSS extraction

```
$ ion scrape https://example.com --select h1
200 HTTP/2.0 https://example.com/
content-type: text/html
559 bytes in 161ms
title: Example Domain
Example Domain
```

```
$ ion scrape https://www.rust-lang.org --select 'a.button-download' --json
{
  "bytes": 18594,
  "content_type": "text/html; charset=utf-8",
  "elapsed_ms": 601,
  "extracted": [
    "Get Started"
  ],
  "final_url": "https://rust-lang.org/",
  "status": 200,
  "title": "Rust Programming Language",
  "truncated": false,
  "url": "https://www.rust-lang.org",
  "version": "HTTP/2.0"
}
```

HTTP/1.1 when that is what the server offers — same binary, same code path:

```
$ ion scrape http://example.com --json | grep version
  "version": "HTTP/1.1",
```

The response-size cap is enforced on bytes actually read, not on a
`Content-Length` the server might be lying about:

```
$ ion scrape https://example.com --max-bytes 200 --json
  "bytes": 200,
  "truncated": true,
```

The redirect cap is a real refusal, not a silent follow:

```
$ VX_HTTP_MAX_REDIRECTS=0 ion scrape https://www.rust-lang.org
301 HTTP/2.0 https://www.rust-lang.org/
content-type: text/html
162 bytes in 36ms
title: 301 Moved Permanently
$ echo $?
2
```

Links, resolved absolutely against the post-redirect URL:

```
$ ion scrape https://example.com --links
200 HTTP/2.0 https://example.com/
content-type: text/html
559 bytes in 191ms
title: Example Domain
https://iana.org/domains/example
```

### `ion dns register` / `ion dns delete`

`--dry-run` builds the packet and prints it without sending:

```
$ VX_TENANT_ID=acme VX_TASK_ID=4711 ion dns register \
    --zone example.com. --name w1.example.com. --ip 192.0.2.55 \
    --server 127.0.0.1:53 --ttl 30 --dry-run
name    w1.example.com.
owner   w1 (relative to the zone)
address 192.0.2.55
zone    example.com.
server  127.0.0.1:53
signed  no
packet  59 bytes
        3d4428000001000000010000076578616d706c6503636f6d0000060001027731076578
        616d706c6503636f6d00000100010000001e0004c0000237
dry-run: nothing sent
```

The delete differs in exactly two bytes of `CLASS` and four of `TTL`:

```
$ ... ion dns delete --zone example.com. --name w1.example.com. --ip 192.0.2.55 --dry-run
packet  59 bytes
        475828000001000000010000076578616d706c6503636f6d0000060001027731076578
        616d706c6503636f6d00000100fe000000000004c0000237
                                  ^^^^ CLASS NONE
```

With TSIG configured from the environment the packet grows by the signature RR:

```
$ VX_TSIG_KEY_NAME=registrar.example.com. VX_TSIG_SECRET=... ion dns register ... --dry-run
signed  yes
packet  153 bytes
        b49428000001000000010001...09726567697374726172076578616d706c6503636f6d
        0000fa00ff00000000003d0b686d61632d7368613235360000006a678823012c002058c5
        a2f48c0a41568542dc5ce2ac6689ff967d53c76effd391706a7212971109b49400000000
```

Drop `--dry-run` to send it for real. With no `--name`, the endpoint name is
derived as `<task_id>.<tenant>.<base-domain>`, and the packet carries **two**
updates: clear the `A` RRset, then add ours, so a recycled task id cannot inherit
a dead worker's address. Against a server rigged to answer `NOTAUTH`:

```
$ VX_TENANT_ID=acme VX_TASK_ID=4711 ion dns register \
    --zone example.com. --server 127.0.0.1:5354 --ip 192.0.2.55 --ttl 30
name    4711.acme.example.com.
owner   4711.acme (relative to the zone)
address 192.0.2.55
zone    example.com.
server  127.0.0.1:5354
signed  no
packet  99 bytes
        626c28000001000000020000076578616d706c6503636f6d0000060001043437313104
        61636d65076578616d706c6503636f6d00000100ff0000000000000434373131046163
        6d65076578616d706c6503636f6d00000100010000001e0004c0000237
response NOTAUTH id=0x626c 29 bytes
$ echo $?
3
```

`00 01 00 ff … 00 00` is the RRset clear, `00 01 00 01 00 00 00 1e 00 04` the add
with TTL 30. `UPCOUNT` is `00 02` at offset 8.

A closed port fails fast rather than burning the timeout budget, because the
socket is `connect()`ed and Linux surfaces the ICMP unreachable as `ECONNREFUSED`:

```
$ ion dns register --zone example.com. --server 127.0.0.1:5399 --ip 192.0.2.55
...
ion: receive DNS response: Connection refused (os error 111)
$ echo $?
1
```

The `Timeout` path — `VX_DNS_RETRIES` attempts of `VX_DNS_TIMEOUT_MS` each — is
what a *bound but silent* server produces, and is covered by
`live_loopback_a_silent_server_times_out_after_the_configured_attempts`.

### `ion run` — the ABI path

Frames arrive on stdin by default; `ion run <file>` is shorthand for
`--input <file>`. A surplus or conflicting path is a hard error rather than a
silent fallback to an empty stdin, because "dispatched 0 tasks, exit 0" is the
worst possible answer to a mistyped filename.

A real scrape task, in and out over the ABI:

```
$ ion run --input scrape-task.bin --output scrape-result.bin
ion: dispatched 1 task(s)

$ decode scrape-result.bin
result header: magic=0x58575601 task_id=99 state=2 exit_code=0
               duration_us=173371 payload_len=227
payload: {
  "op": "scrape",
  "pages": [
    {
      "url": "https://example.com",
      "final_url": "https://example.com/",
      "status": 200,
      "version": "HTTP/2.0",
      "bytes": 559,
      "truncated": false,
      "elapsed_ms": 173,
      "title": "Example Domain"
    }
  ],
  "extracted": [ "Example Domain" ]
}
```

Bounded fan-out — three URLs, `VX_HTTP_CONCURRENCY=2`:

```
$ VX_HTTP_CONCURRENCY=2 ion run --input many-task.bin --output many-result.bin
ion: dispatched 1 task(s)

result: task_id=100 state=2 duration_us=222135
{
  "op": "fetch_many",
  "pages": [
    { "url": "https://example.com",       "status": 200, "version": "HTTP/2.0",
      "bytes": 559,   "elapsed_ms": 218, "title": "Example Domain" },
    { "url": "https://www.rust-lang.org", "status": 200, "version": "HTTP/2.0",
      "bytes": 18594, "elapsed_ms": 60,  "title": "Rust Programming Language" },
    { "url": "https://doc.rust-lang.org", "status": 200, "version": "HTTP/2.0",
      "bytes": 10730, "elapsed_ms": 32,  "title": "Rust Documentation" }
  ],
  "extracted": [
    "Example Domain", "Rust Programming Language", "Rust Documentation"
  ]
}
```

A failing task still produces a result frame — the host is never left waiting:

```
$ ion run --input bad-task.bin --output bad-result.bin
ion: dispatched 1 task(s)

result: task_id=101 state=3 (0x03 = VX_STATE_FAILED)
        exit_code=-1 (VX_ERR_INVALID_ARG)
payload: bad task payload: expected ident at line 1 column 2
```

### Task payload schema

```json
{"op": "noop"}
{"op": "scrape",     "url": "https://…", "select": "h1", "mode": "text"}
{"op": "fetch_many", "urls": ["https://a", "https://b"], "select": "title"}
{"op": "links",      "url": "https://…"}
{"op": "dns_encode", "zone": "example.com.", "name": "h.example.com.",
                     "ip": "192.0.2.7", "ttl": 60, "action": "add"}
```

`mode` is `text` (default), `html`, or `attr:<name>`. `action` is `add`,
`delete`, or `delete_rrset`. `dns_encode` performs no network I/O; it returns the
packet as hex, which makes it useful as a control-plane pre-flight check.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | usage error, configuration error, or a failed request |
| 2 | the page was fetched but the status was not 2xx |
| 3 | the DNS server answered with a failure `RCODE` |

---

## Configuration

Every knob is a `VX_*` environment variable, because that is the lowest common
denominator across Lambda, `docker run -e`, a cgroup supervisor, and a
Kubernetes `ConfigMap`. CLI flags override the environment.

| Variable | Default | Meaning |
|---|---|---|
| `VX_TENANT_ID` | `default` | tenant slug, ≤ 64 bytes |
| `VX_TASK_ID` | `0` | task id used when the CLI synthesises a header |
| `VX_DNS_ENABLED` | `0` | register an `A` record on boot |
| `VX_DNS_SERVER` | `127.0.0.1:53` | authoritative server, literal `IP` or `IP:port` |
| `VX_DNS_ZONE` | `vxcloud.io.` | zone named in the `UPDATE` zone section |
| `VX_DNS_BASE_DOMAIN` | value of `VX_DNS_ZONE` | suffix for the worker's own name |
| `VX_DNS_TTL` | `60` | `A` record TTL, seconds |
| `VX_DNS_TIMEOUT_MS` | `2000` | per-attempt UDP timeout |
| `VX_DNS_RETRIES` | `3` | total attempts |
| `VX_DNS_REQUIRE_ABSENT` | `0` | add the §2.4.5 "name not in use" prerequisite |
| `VX_TSIG_KEY_NAME` | unset | TSIG key name; signing needs this **and** a secret |
| `VX_TSIG_SECRET` | unset | base64 shared secret |
| `VX_TSIG_ALGORITHM` | `hmac-sha256` | `hmac-sha256` or `hmac-sha512` |
| `VX_TSIG_FUDGE` | `300` | permitted clock skew, seconds |
| `VX_HTTP_TIMEOUT_MS` | `10000` | per-request deadline |
| `VX_HTTP_MAX_REDIRECTS` | `5` | redirect cap; `0` refuses to follow |
| `VX_HTTP_MAX_BODY_BYTES` | `2097152` | response-size cap (2 MiB) |
| `VX_HTTP_CONCURRENCY` | `8` | fan-out semaphore permits |
| `VX_HTTP_USER_AGENT` | `ion/<version>` | `User-Agent` header |
| `VX_RUNTIME_MULTI_THREAD` | `0` | opt in to the multi-thread scheduler |
| `VX_RUNTIME_WORKER_THREADS` | unset | worker threads when multi-threaded |

`VX_DNS_SERVER` must be a literal address. Accepting a hostname would mean
resolving it through the very resolver the setting names.

A blank value is treated as absent, because Lambda and Kubernetes both happily
project an empty string for an unset key. Every malformed value is a startup
error naming the variable and the value — nothing is silently coerced, and
nothing panics.

---

## Building

```bash
cargo build --release                       # dynamic, glibc
cargo test --all                            # 139 tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Static build for `scratch` containers and Lambda:

```bash
rustup target add x86_64-unknown-linux-musl
RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build --release --target x86_64-unknown-linux-musl
```

If you do not have a musl cross-compiler, `ring` (via rustls) still builds by
pointing `cc-rs` at the system compiler — rustc supplies the self-contained musl
CRT objects itself:

```bash
CC_x86_64_unknown_linux_musl=gcc \
AR_x86_64_unknown_linux_musl=ar \
RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=yes" \
  cargo build --release --target x86_64-unknown-linux-musl
```

### Dependencies, and why each one is there

| Crate | Why | Could it be dropped? |
|---|---|---|
| `tokio` | the async runtime; `default-features = false`, current-thread by default | no |
| `reqwest` | HTTP/1.1 + HTTP/2 over rustls; `default-features = false` keeps OpenSSL out entirely | replaceable with raw `hyper` for a smaller image |
| `scraper` | real CSS selector engine (servo's `selectors` + `html5ever`) | only by writing a worse selector parser |
| `hmac`, `sha2` | RFC 8945 MACs, pure Rust | no |
| `serde`, `serde_json` | task payload and result codec | no |

Deliberately **not** dependencies: any DNS crate (the point of the exercise),
`clap` (hand-rolled parsing, ~300 KiB saved), a base64 crate (40 lines in
`tsig.rs` — a TSIG secret is the last input to hand to unread code), `rand`
(`/dev/urandom` with a clock fallback), OpenSSL or any system TLS library.

---

## Testing and verification

```
$ cargo test --all
   Doc-tests ion

test result: ok. 65 passed; 0 failed  (unit tests, src/)
test result: ok. 11 passed; 0 failed  (CLI parser, src/main.rs)
test result: ok. 30 passed; 0 failed  (tests/abi_roundtrip.rs)
test result: ok. 28 passed; 0 failed  (tests/dns_wire.rs)
test result: ok.  5 passed; 0 failed  (doc-tests)
```

**139 tests, 0 failures.** `cargo clippy --all-targets -- -D warnings`,
`cargo fmt --check`, and `cargo doc` with `RUSTDOCFLAGS=-D warnings` are all clean.

What is actually verified, as opposed to merely exercised:

- **Golden byte vectors.** Seven complete `UPDATE` packets asserted byte for
  byte — add `A`, delete one RR, delete an RRset, delete every RRset,
  prerequisite + add, add `AAAA`, add `CNAME` — each derived by hand from the
  RFCs and cross-checked against dnspython.
- **Third-party wire interop.** dnspython's *compressed* packet is decoded by
  `ion` and must expand to `host.example.com.`
- **Hostile input.** Self-referential pointers, forward pointers, and reserved
  label types are rejected with typed errors. Every proper prefix of a valid
  packet — all 61 of them — must fail to decode rather than half-decode.
- **RFC 1035 boundaries.** 63-byte label accepted, 64 rejected; a name encoding
  to exactly 255 bytes accepted, 256 rejected; empty, doubled-dot, leading-dot,
  and non-ASCII labels rejected.
- **TSIG.** RFC 4231 vector for the HMAC primitive; a pinned MAC validated by
  dnspython's verifier with a bit-flip negative control; determinism across two
  independent builds of the same message; the TSIG RR round-tripping through the
  decoder field by field; response verification accepting a correct signature and
  rejecting a tampered MAC, a wrong request MAC, an out-of-window timestamp, and
  a missing TSIG.
- **Live UDP.** Six tests bind a real ephemeral loopback socket. One asserts the
  bytes a real `sendto` delivered are byte-identical to the golden vector. Others
  drive a full `Registrar::register()` / `graceful_shutdown()` round trip and
  assert the received packet's `UPCOUNT`, classes, and TTLs; check that a
  `NOTAUTH` becomes a typed `Rejected` error; verify a signed exchange end to end
  including response-MAC verification; and confirm that a silent server produces
  a `Timeout` after the configured attempts, with the elapsed time proving the
  retries really happened.
- **ABI.** Offsets asserted against a hand-assembled header; fields proved to
  tile the struct with no padding; every rejection path; a 4,096-round randomised
  sweep asserting no byte pattern panics any decoder.

---

## Security

- **No credential, key, token, or private address from any local file appears in
  this repository.** Test and example addresses are RFC 5737 documentation
  ranges (`192.0.2.0/24`), RFC 3849 (`2001:db8::/32`), loopback, or RFC 1918
  literals invented for the tests.
- The TSIG key in `selftest` and the test suite is a published demonstration
  key. Its base64 decodes to `if:you-can-read-this-it-is-not-a-secret`, which is
  the point: the vectors are reproducible and the key is worthless.
- `TsigKey` and `TsigSettings` implement `Debug` **by hand** to redact the
  secret, so a key cannot reach a log through a stray `{:?}`. Two tests assert
  the redaction.
- Real secrets belong in `VX_TSIG_SECRET`. `--key-secret` exists for symmetry
  and the help text says why you should not use it: `/proc/<pid>/cmdline` is
  readable by any process with the same uid.
- Response MAC comparison is constant-time.
- Compression-pointer decoding is bounded — backward-only targets, a jump limit,
  and a 255-byte output ceiling — so a decompression bomb is a typed error.
- `#![forbid(unsafe_code)]`.
- TLS is rustls with bundled webpki roots. No OpenSSL, no `native-tls`, no
  system certificate store, nothing to CVE-patch in the base image.

---

## License

Apache-2.0. See [LICENSE](LICENSE).
