# ion — Phase 2 requirements

Status of every item in the Phase 2 specification. A box is ticked only if the
behaviour is implemented **and** covered by a test that would fail if it broke.
Unticked boxes are honest gaps, each with a note on why.

Verified on WSL2 (kernel 6.6.87.2, x86_64, 12th Gen Intel Core i5-12450H,
12 cores, glibc 2.39) with Rust 1.97.1.

```
cargo test --all                             145 passed, 0 failed
cargo clippy --all-targets -- -D warnings    clean
cargo fmt --check                            clean
cargo doc --no-deps  (RUSTDOCFLAGS=-D …)     clean
```

---

## 1. Crate layout

- [x] `Cargo.toml` with `[package] name="ion" edition="2024" rust-version="1.85"`
- [x] `src/main.rs` — thin CLI binary
- [x] `src/lib.rs` — `pub mod` re-exports plus crate docs
- [x] `src/abi.rs` — zero-copy `vx_task_header_t` / `vx_result_header_t` codec
- [x] `src/config.rs` — env-driven config (`VX_*`), no `unwrap` on user input
- [x] `src/dns/mod.rs`
- [x] `src/dns/name.rs` — RFC 1035 label encoding and validation
- [x] `src/dns/message.rs` — header/section encoder **and** decoder
- [x] `src/dns/update.rs` — RFC 2136 `UPDATE` builder
- [x] `src/dns/tsig.rs` — RFC 8945 TSIG HMAC-SHA256 signing
- [x] `src/registrar.rs` — register on boot, delete on `SIGTERM`
- [x] `src/scrape.rs` — tokio HTTP/1.1 + HTTP/2 fetch and HTML extraction
- [x] `src/runtime.rs` — task dispatch loop, timing, result emission
- [x] `tests/dns_wire.rs` — golden byte-vector tests
- [x] `tests/abi_roundtrip.rs`
- [x] `README.md`
- [x] `REQUIREMENTS.md`
- [x] `LICENSE`
- [x] `.gitignore`
- [x] `.github/workflows/ci.yml`

No files were added beyond this list. The MSRV declaration is real and was
checked, not assumed: the code avoids let-chains (Rust 1.88) and `is_multiple_of`
(1.87), and `cargo +1.85.0 check --lib --bins` compiles cleanly against
`rustc 1.85.0 (4d91de4e4 2025-02-17)` even though the toolchain used for
development is 1.97.1. CI enforces it in the `msrv` job.

---

## 2. ABI codec (`abi.rs`)

- [x] Parse and emit the 93-byte packed `vx_task_header_t`
- [x] Exact documented offsets: `magic@0`, `task_id@4`, `tenant_id[64]@12`,
      `engine@76`, `memory_limit_mb@77`, `cpu_quota_us@81`, `payload_len@85`,
      `payload@93` — asserted individually, and asserted to tile the struct with
      no padding hole (`task_offsets_match_the_c_header`)
- [x] Little-endian, proved against a hand-assembled golden header
      (`encoding_matches_the_hand_assembled_golden_header`,
      `every_multi_byte_field_is_little_endian`)
- [x] Reject bad magic (`0x58575601`) — `bad_magic_is_rejected`, four corrupt
      values including the byte-swapped one
- [x] Reject oversized payload (> 16 MiB) — `an_oversized_payload_len_is_rejected`,
      including that exactly 16 MiB is *accepted*
- [x] Reject truncated buffers — `a_short_header_is_rejected` sweeps all 93
      prefixes; `a_truncated_payload_is_rejected`
- [x] Typed errors, never a panic — `AbiError` with 9 variants, each mapped onto
      `vx_status_t` by `AbiError::status()`; `no_byte_pattern_can_panic_the_decoder`
      runs 4,096 randomised buffers through all six decode entry points
- [x] Emit the 29-byte `vx_result_header_t` — `result_frame_round_trips`,
      `result_offsets_tile_the_struct_exactly`, and `exit_code` proved to survive
      as a signed `i32` down to `i32::MIN`
- [x] No `unsafe` transmutes — `#![forbid(unsafe_code)]` at the crate root
- [x] `u32::from_le_bytes` on bounds-checked slices — `slice_at` returns
      `Result`, so no indexing operation in the module can panic

Zero-copy is real, not nominal: `Task::parse` borrows the payload, and
`task_frame_round_trips_and_borrows_its_payload` asserts *pointer identity* with
`std::ptr::eq` rather than byte equality. `peek_magic` / `peek_task_id` /
`peek_payload_len` / `peek_tenant_id_raw` read individual fields at their offsets
with no struct built at all.

---

## 3. DNS encoder

- [x] **No subprocess.** No `nsupdate`, no `dig`, no `std::process::Command`
      anywhere in the crate; no third-party DNS crate in the dependency graph
- [x] Header: id, flags, opcode **5 (UPDATE)**
- [x] RFC 2136 section counts `ZOCOUNT`/`PRCOUNT`/`UPCOUNT`/`ADCOUNT`, exposed
      under both spellings on `Header`
- [x] Zone section: `QNAME`=zone, `QTYPE`=**SOA (6)**, `QCLASS`=IN (1)
- [x] Add `A`: name / A(1) / IN(1) / ttl / rdlength=4 / 4-byte rdata
- [x] Delete one RR: class **NONE (254)**, ttl 0, rdlength 4 + rdata
- [x] Delete an entire RRset: class **ANY (255)**, ttl 0, rdlength 0
- [x] Prerequisite "name is not in use": class NONE, type ANY(255), ttl 0, rdlen 0
- [x] `AAAA` (28) and `CNAME` (5)
- [x] RFC 1035 limits: label ≤ 63, name ≤ 255, empty and oversized labels rejected
- [x] Response decoder reading the `RCODE` and reporting a typed error

Beyond the required set, also implemented and tested:

- [x] Delete **every** RRset at a name (§2.5.3): `TYPE=ANY`, `CLASS=ANY`
- [x] The other three prerequisites: name in use (§2.4.4), RRset exists (§2.4.1),
      RRset does not exist (§2.4.3)
- [x] `TXT` records with length-prefixed character strings
- [x] Compression-pointer **decoding** with backward-only enforcement, a 64-jump
      limit, and a 255-byte expansion ceiling
- [x] `RCODE` coverage for the RFC 2136 additions (`YXDOMAIN`, `YXRRSET`,
      `NXRRSET`, `NOTAUTH`, `NOTZONE`) and the RFC 8945 extended codes
      (`BADSIG`, `BADKEY`, `BADTIME`, …)
- [x] Out-of-zone names refused in the builder rather than round-tripped to a
      `NOTZONE`

**Deliberately not implemented:** compression on *output*. RFC 1035 §4.1.4 makes
it optional and RFC 2136 does not require it; omitting it makes every packet a
deterministic function of the message, which is what TSIG signing needs, and
avoids the RFC 3597 §4 hazard around names inside `RDATA`. Cost: 11 bytes on a
typical registration. Cross-checked with dnspython, which *does* compress, and
which confirmed the two encodings parse to equal messages.

**Also not implemented:** EDNS0 `OPT`. `ion`'s largest packet is 153 bytes
signed, far inside the 512-byte floor, so there is nothing to negotiate.

---

## 4. TSIG (`tsig.rs`)

- [x] Sign `UPDATE` requests with HMAC-SHA256 per RFC 8945
- [x] Canonical digest over the request **plus** the TSIG variables: algorithm
      name, time-signed, fudge, error, other-len — with `MAC Size`, `MAC`, and
      `Original ID` correctly **excluded**
- [x] Append the TSIG RR to the additional section and bump `ADCOUNT`
- [x] Uses the `hmac` + `sha2` crates
- [x] Test that signing is deterministic for a fixed key and time
      (`tsig_signing_is_deterministic_for_a_fixed_key_and_time`)
- [x] Test that the TSIG RR round-trips through the message decoder
      (`the_tsig_rr_round_trips_through_the_message_decoder`, field by field)

Beyond the required set:

- [x] **Verified against dnspython 2.8.0.** `ion`'s signed packet was accepted
      and its MAC validated by dnspython's own `dns.tsig` verifier, with a
      bit-flip negative control confirming the check is discriminating
- [x] RFC 4231 test case 2 pins the HMAC primitive itself
- [x] HMAC-SHA512 as a second algorithm
- [x] Response MAC verification, chained off the request MAC, digesting the
      received bytes *as received* with `ARCOUNT` patched down — not a re-encode,
      so server-side name compression cannot break it
- [x] Fudge-window enforcement and `TsigRemoteError` for a peer-set error code
- [x] Constant-time MAC comparison
- [x] `sign_response`, so the verification path is testable end to end
- [x] Hand-rolled base64 with round-trip and malformed-input tests
- [x] `TsigKey` / `TsigSettings` redact the secret in `Debug`, with tests

---

## 5. Registrar lifecycle (`registrar.rs`)

- [x] Detect the local IP by `connect()`ing a UDP socket to the resolver and
      reading back `local_addr()` — **no external service call**, no packet sent
      (`local_address_detection_sends_nothing_and_finds_a_loopback_source`)
- [x] Build `<task_id>.<tenant>.vxcloud.io` → `A` record (base domain
      configurable via `VX_DNS_BASE_DOMAIN`, default `vxcloud.io.`)
- [x] Send to the CloudDNS server over `tokio::net::UdpSocket`
- [x] Retry with a per-attempt timeout
- [x] On `SIGTERM` / `SIGINT` via `tokio::signal::unix`, send the DELETE and exit
- [x] The graceful-shutdown path is a testable function — `graceful_shutdown(&Registrar)`,
      with `wait_for_termination()` split out so no test has to raise a signal

Beyond the required set:

- [x] Registration clears the address RRset before adding, so a recycled task id
      cannot inherit a dead worker's address
- [x] De-registration deletes only *this* worker's RR (`CLASS=NONE`), so a shared
      round-robin name keeps its other members
- [x] Tenant slugs are folded into one legal DNS label (lower-cased, non-LDH
      mapped to `-`, runs collapsed, trimmed, truncated at 63) so an arbitrary
      tenant string cannot produce an illegal name
- [x] `Registrar::with_address` skips detection, for NAT'd containers where the
      local address is not the address peers should use
- [x] Response id echo and QR-bit checked before the `RCODE` is trusted
- [x] A bare `NOTAUTH` with no TSIG RR reports the `RCODE` rather than a
      misleading "no TSIG"
- [x] IPv6: `AAAA` registration and an IPv6 server address both work

---

## 6. Footprint

- [x] `[profile.release]` with `opt-level="z"`, `lto="fat"`, `codegen-units=1`,
      `panic="abort"`, `strip=true`
- [x] Current-thread tokio by default; multi-thread opt-in via
      `VX_RUNTIME_MULTI_THREAD`
- [x] Cold start and peak RSS **actually measured** in WSL and reported in the
      README with the real numbers

Ranges below are the spread across three full benchmark sessions on the same
binaries. This is a laptop under WSL2, so single-run digits are not stable and are
not presented as if they were.

### Peak RSS — target ≤ 8 MiB: **MET**

Worst of 7 runs per session, `/usr/bin/time -v`:

| Workload | glibc dynamic | musl static |
|---|---|---|
| `--version` | 3.88–4.00 MiB | **2.13 MiB** |
| `selftest` | 4.13–4.25 MiB | **2.25–2.38 MiB** |
| `run`, 1 task (tokio + live rustls client) | 4.75–4.88 MiB | **2.63 MiB** |
| `run`, 1,000 tasks streamed | 4.63–4.75 MiB | **2.75 MiB** |
| `run`, 5,000 tasks streamed | — | **2.75 MiB** (unchanged: bounded by the frame) |

Worst figure anywhere for the static build on the streaming workloads:
**2.75 MiB**, roughly a third of the budget.

Honestly reported caveats:

- The current-thread default did **not** measurably beat multi-thread on this
  12-core host: 2,688 KiB versus 2,816 KiB (musl), and identical at 4,864–4,992
  KiB (glibc). Thread stacks are lazily faulted, so 11 idle workers cost little
  resident memory on a workload this short. Current-thread stays the default for
  startup latency, but the honest RSS win is ~128 KiB, not dramatic.

### The inline-payload ceiling — the ABI/budget composition hole, now closed

- [x] RSS scales with the inline payload, so the ABI's 16 MiB `payload_len`
      cap and the 8 MiB RSS budget do not compose. `ion` now enforces
      `VX_MAX_INLINE_PAYLOAD_BYTES` (default **1 MiB**, clamped to the ABI cap
      — a larger value is a startup `ConfigError`, not a licence to exceed the
      ABI) at dispatch time, *before* the payload is allocated
- [x] An over-ceiling frame is answered with a typed `VX_STATE_FAILED` /
      `VX_ERR_PAYLOAD_TOO_LARGE` result naming both the actual size and the
      limit; its bytes are drained through a fixed 64 KiB scratch buffer —
      never allocated — and the stream **continues**, because the header was
      valid ABI so the framing is intact, and aborting would forfeit every
      task queued behind the oversized one
      (`one_byte_over_the_ceiling_is_rejected_and_the_stream_continues`,
      `a_payload_exactly_at_the_ceiling_is_accepted`,
      `a_rejected_payload_larger_than_the_drain_buffer_is_fully_skipped`,
      `an_over_ceiling_frame_truncated_mid_payload_is_still_a_stream_error`,
      `execute_rejects_an_over_ceiling_payload_without_running_it`,
      `inline_payload_ceiling_overrides_and_refuses_to_exceed_the_abi_cap`)

Measured (one padded-noop task, `/usr/bin/time -v`, worst of 7 runs; "accepted"
= ceiling raised to the ABI max so the payload is really read and parsed,
"rejected" = the same frame against the default 1 MiB ceiling):

| Payload | accepted glibc | accepted musl | rejected glibc | rejected musl |
|---|---|---|---|---|
| 13 B | 4.88 MiB | 2.50 MiB | — | — |
| 4 KiB | 4.75 MiB | 2.50 MiB | — | — |
| 256 KiB | 5.01 MiB | 3.00 MiB | — | — |
| 1 MiB | **6.50 MiB** | **4.50 MiB** | at the limit: accepted | at the limit: accepted |
| 2 MiB | 8.63 MiB | 6.50 MiB | 5.00 MiB | 2.63 MiB |
| 4 MiB | 10.50 MiB | 8.63 MiB | 5.00 MiB | 2.63 MiB |
| 8 MiB | 14.50 MiB | 12.63 MiB | 4.88 MiB | 2.63 MiB |
| 16 MiB | 22.50 MiB | 20.63 MiB | 4.88 MiB | 2.63 MiB |

The relationship is **piecewise linear, not linear**: ~2 MiB of RSS per 1 MiB
of payload up to 2 MiB (payload buffer + `tokio::fs`'s blocking-pool copy,
whose buffer grows with the read until its own 2 MiB cap), settling to
~1× + 2 MiB beyond. The default is 1 MiB because that is the largest
power-of-two at which the *worst* build stays inside the budget: 6.50 MiB at
1 MiB, 8.63 MiB — a breach — at 2 MiB. Rejection is flat: a 16 MiB frame
against the default ceiling costs baseline + the 64 KiB drain buffer
(2.63 MiB musl), so the budget now holds regardless of what arrives on the
wire.

### Cold start — target < 1 ms: **MET by the static build; MISSED by the dynamic build**

In-process (`main` entry → exit, via `ion --timing`, 60 runs per session, p50):

| | p50 across sessions |
|---|---|
| glibc `--version` | **49–79 µs** |
| glibc `selftest` | **96–145 µs** |
| musl `--version` | **86–123 µs** |
| musl `selftest` | **141–199 µs** |

Worst p50 anywhere: 199 µs, five times inside the target, on the workload that
does the most real work.

Full process (`fork` + `execve` + loader + run + exit, 500 iterations per session):

| | per process | verdict |
|---|---|---|
| `/bin/true` (reference floor on this host) | 715–833 µs | — |
| musl static `ion --version` | **825–846 µs** | **MET**, 26–110 µs above the floor |
| musl static `ion selftest` | 906–1,244 µs | borderline, doing real work |
| glibc dynamic `ion --version` | 1,288–1,713 µs | **MISSED** |
| glibc dynamic `ion selftest` | 1,322–1,861 µs | **MISSED** |

The dynamic build misses the target because `ld.so` resolution of
`libc`/`libm`/`libgcc_s` costs 500–900 µs on this WSL2 host, not because of
anything `ion` does. Ship the static build where cold start matters. WSL2 process
creation is unusually expensive; the same rows on bare metal would shift down with
the `/bin/true` floor, typically 200–400 µs.

### Per-task dispatch

Measured, then optimised, then re-measured: 170–280 µs/task initially, **35–65
µs/task** after collapsing the two blocking reads per frame into one buffered
read. Method and the before/after figures are in the README.

---

## 7. CLI (`main.rs`)

- [x] `ion run` — read a task header from stdin or a file, execute, write the
      result (`--input` / `--output`, any combination, plus `ion run <file>` as
      shorthand; a conflicting or surplus path is a hard error rather than a
      silent fallback to an empty stdin)
- [x] `ion scrape <url> [--select CSS]` — plus `--mode`, `--links`,
      `--timeout-ms`, `--max-bytes`, `--json`
- [x] `ion dns register|delete` with flags for zone / name / ip / server / key
      (`--zone --name --ip --server --ttl --key-name --key-secret --algorithm
      --rrset --dry-run`)
- [x] `ion selftest` — encodes packets and prints hex, no network
- [x] `ion --version`
- [x] Lean: argument parsing is hand-rolled, ~90 lines, no `clap`, 9 unit tests

Also present: `ion help`, `-h`, `-V`, `--key=value` form, `--` terminator, and
`--timing` (prints `ion`'s own main-entry-to-exit time, which is how the
cold-start figure above is measured).

---

## 8. Tests

- [x] `cargo test --all` green — **145 passed, 0 failed**
- [x] Golden hex vectors for a full `UPDATE` add and delete, asserting exact bytes
      — and five more: delete-RRset, delete-every-RRset, prerequisite+add,
      `AAAA`, `CNAME`
- [x] Name-encoding edge cases: 63-byte label OK, 64 rejected, 255-byte name
      boundary OK, 256 rejected, plus empty / doubled-dot / leading-dot /
      non-ASCII / root / underscore / wildcard
- [x] ABI round trip **and every rejection path**
- [x] TSIG determinism
- [x] **A live loopback UDP test** that binds an ephemeral socket, sends a real
      `UPDATE`, and asserts the server side received the exact expected bytes
      (`live_loopback_send_update_puts_the_exact_golden_bytes_on_the_wire`)

Six live-UDP tests in total: exact-bytes-on-the-wire, a full register +
graceful-shutdown round trip with byte-exact packet comparison, a `NOTAUTH`
refusal becoming a typed error, a signed exchange verified end to end including
the response MAC, a silent server producing `Timeout` after the configured
attempts with elapsed time proving the retries happened, and local-address
detection.

Test count by target:

| Target | Tests |
|---|---|
| `src/` unit tests | 71 |
| `src/main.rs` CLI parser and path resolution | 11 |
| `tests/abi_roundtrip.rs` | 30 |
| `tests/dns_wire.rs` | 28 |
| doc-tests | 5 |
| **total** | **145** |

---

## 9. Lints

- [x] `cargo clippy --all-targets -- -D warnings` clean
- [x] `cargo fmt --check` clean

---

## 10. Docs

- [x] `README.md` with architecture
- [x] Substrate matrix (Lambda / ephemeral VM / K8s, plus micro-container and
      systemd)
- [x] Real measured benchmarks, including the two that miss their target
- [x] Usage examples with real captured output — every code block in the usage
      section is copied from an actual run against the built binary
- [x] Wire-format hex diagram of an `UPDATE` packet, annotated offset by offset
- [x] `REQUIREMENTS.md` restating the spec with honest checkboxes

---

## 11. CI

- [x] `.github/workflows/ci.yml` on `ubuntu-latest` with stable Rust
- [x] `cargo build --release`
- [x] `cargo test`
- [x] `cargo clippy`
- [x] `cargo fmt`

The workflow also builds the static musl target and runs the doc-tests, since
both are load-bearing claims in the README.

---

## 12. Security

- [x] No credential, API key, token, password, or private IP from any local file
      appears in this repository
- [x] Environment variables and placeholders only

Addresses used in tests and examples are RFC 5737 documentation ranges
(`192.0.2.0/24`), RFC 3849 (`2001:db8::/32`), loopback, or RFC 1918 literals
invented for the tests. The TSIG key in `selftest` and the test suite is a
published demonstration key whose base64 decodes to
`if:you-can-read-this-it-is-not-a-secret`.

Additional hardening, none of it required by the spec:

- [x] `TsigKey` and `TsigSettings` hand-write `Debug` to redact the secret, so a
      key cannot escape through a stray `{:?}`; two tests assert it
- [x] Constant-time MAC comparison
- [x] Bounded compression-pointer decoding (backward-only, jump limit, output
      ceiling) so a decompression bomb is a typed error
- [x] `#![forbid(unsafe_code)]`
- [x] rustls with bundled webpki roots — no OpenSSL, no `native-tls`, no system
      certificate store in the image
- [x] The help text explains why `--key-secret` is worse than `VX_TSIG_SECRET`
      (`/proc/<pid>/cmdline`)

---

## Known gaps

Things a reader might reasonably expect that are **not** here:

1. **DNS name compression on output.** Deliberate; see item 3.
2. **EDNS0 / `OPT`.** Not needed at 153 bytes; would be required for DNSSEC or
   larger payloads.
3. **TCP fallback for DNS.** `UPDATE` over TCP (RFC 2136 §6) is unimplemented.
   Only relevant for a packet over the UDP limit, which `ion` cannot produce.
4. **TSIG multi-message / TKEY / GSS-TSIG.** Single-message signing only.
5. **Payloads above the inline ceiling are refused, not processed.** The
   budget hole this used to be — RSS scales with the inline payload, so a
   legal 16 MiB frame breached the 8 MiB target — is closed: frames above
   `VX_MAX_INLINE_PAYLOAD_BYTES` (default 1 MiB, measured justification in
   item 6) now get a typed `VX_STATE_FAILED` result and are drained without
   allocation. What remains true is that `ion` cannot *execute* a payload
   bigger than the ceiling: the shared-memory handle path the ABI header
   alludes to for large bodies is not in the v1 header, so raising the ceiling
   (at most to the 16 MiB ABI cap, trading budget for capacity) is the only
   inline option.
6. **Windows and macOS are unverified.** The code compiles conditionally for
   non-Unix (signal handling falls back to `ctrl_c()`), but nothing was run there.
7. **No benchmark harness in-tree.** The numbers above were produced by shell
   scripts using `/usr/bin/time -v` and `date +%s%N`, plus `ion --timing`, and
   are reproducible with the commands given in the README, but there is no
   `criterion` suite committed.
8. **`scraper` is a heavy dependency** (`html5ever` + servo's `selectors`). It is
   the reason the binary is 3.4 MiB rather than well under 1 MiB. The trade was
   made knowingly: a real CSS selector engine beats a hand-rolled approximation.
