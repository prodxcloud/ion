//! Environment-driven configuration.
//!
//! Every knob is a `VX_*` environment variable, because that is the lowest
//! common denominator across the substrates `ion` runs on: Lambda passes
//! configuration as environment, a `docker run` passes `-e`, a cgroup-managed
//! ephemeral VM inherits it from the supervisor, and Kubernetes projects
//! `ConfigMap`/`Secret` keys into it.
//!
//! ## Rules this module follows
//!
//! - **Nothing panics on operator input.** A malformed value produces a
//!   [`ConfigError`] naming the variable and the value, so a misconfigured
//!   deployment fails loudly at startup with an actionable message instead of
//!   dying later inside a parser.
//! - **Secrets are never printed.** [`TsigSettings`] has a hand-written
//!   [`Debug`](core::fmt::Debug) that redacts the shared secret; the secret is
//!   read from the environment only, never from a file in the repository.
//! - **No DNS to find DNS.** `VX_DNS_SERVER` must be a literal IP (optionally
//!   with `:port`). Resolving a hostname would require the very resolver we are
//!   trying to talk to.
//!
//! ## Variables
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `VX_TENANT_ID` | `default` | tenant slug, <= 64 bytes |
//! | `VX_TASK_ID` | `0` | task id used when the CLI synthesises a header |
//! | `VX_DNS_ENABLED` | `0` | register an `A` record on boot |
//! | `VX_DNS_SERVER` | `127.0.0.1:53` | authoritative server to `UPDATE` |
//! | `VX_DNS_ZONE` | `vxcloud.io.` | zone named in the `UPDATE` zone section |
//! | `VX_DNS_BASE_DOMAIN` | value of `VX_DNS_ZONE` | suffix for the worker's own name |
//! | `VX_DNS_TTL` | `60` | `A` record TTL, seconds |
//! | `VX_DNS_TIMEOUT_MS` | `2000` | per-attempt UDP timeout |
//! | `VX_DNS_RETRIES` | `3` | total attempts before giving up |
//! | `VX_DNS_REQUIRE_ABSENT` | `0` | add the §2.4.5 "name not in use" prerequisite |
//! | `VX_TSIG_KEY_NAME` | unset | TSIG key name; enables signing when set with a secret |
//! | `VX_TSIG_SECRET` | unset | base64 shared secret |
//! | `VX_TSIG_ALGORITHM` | `hmac-sha256` | `hmac-sha256` or `hmac-sha512` |
//! | `VX_TSIG_FUDGE` | `300` | permitted clock skew, seconds |
//! | `VX_HTTP_TIMEOUT_MS` | `10000` | per-request deadline |
//! | `VX_HTTP_MAX_REDIRECTS` | `5` | redirect cap |
//! | `VX_HTTP_MAX_BODY_BYTES` | `2097152` | response-size cap (2 MiB) |
//! | `VX_HTTP_CONCURRENCY` | `8` | fan-out semaphore permits |
//! | `VX_HTTP_USER_AGENT` | `ion/<version>` | `User-Agent` header |
//! | `VX_RUNTIME_MULTI_THREAD` | `0` | opt in to the multi-thread scheduler |
//! | `VX_RUNTIME_WORKER_THREADS` | unset | worker threads when multi-threaded |

use core::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::abi::VX_TENANT_ID_LEN;
use crate::dns::DNS_PORT;
use crate::dns::tsig::{DEFAULT_FUDGE, TsigAlgorithm};

/// Why configuration could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A numeric variable did not parse.
    NotAnInteger {
        /// The variable name.
        var: &'static str,
        /// The value as supplied.
        value: String,
    },
    /// A boolean variable was neither truthy nor falsy.
    NotABoolean {
        /// The variable name.
        var: &'static str,
        /// The value as supplied.
        value: String,
    },
    /// A numeric variable parsed but fell outside the usable range.
    OutOfRange {
        /// The variable name.
        var: &'static str,
        /// The value as supplied.
        value: String,
        /// Inclusive lower bound.
        min: u64,
        /// Inclusive upper bound.
        max: u64,
    },
    /// `VX_DNS_SERVER` was not a literal `IP` or `IP:port`.
    NotAnAddress {
        /// The variable name.
        var: &'static str,
        /// The value as supplied.
        value: String,
    },
    /// A variable that must be non-empty was empty.
    Empty {
        /// The variable name.
        var: &'static str,
    },
    /// `VX_TENANT_ID` exceeded the 64-byte ABI field.
    TenantTooLong {
        /// The offending length.
        len: usize,
    },
    /// A DNS-related variable held a malformed name, zone, or secret.
    Dns {
        /// The variable name.
        var: &'static str,
        /// The underlying reason.
        reason: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnInteger { var, value } => {
                write!(f, "{var}={value:?} is not an integer")
            }
            Self::NotABoolean { var, value } => write!(
                f,
                "{var}={value:?} is not a boolean (use 1/0, true/false, yes/no, on/off)"
            ),
            Self::OutOfRange {
                var,
                value,
                min,
                max,
            } => write!(f, "{var}={value:?} is outside the range {min}..={max}"),
            Self::NotAnAddress { var, value } => write!(
                f,
                "{var}={value:?} is not a literal IP address or IP:port \
                 (a hostname cannot be used: resolving it would need the very resolver \
                 this setting names)"
            ),
            Self::Empty { var } => write!(f, "{var} must not be empty"),
            Self::TenantTooLong { len } => write!(
                f,
                "VX_TENANT_ID is {len} bytes, the ABI field is {VX_TENANT_ID_LEN}"
            ),
            Self::Dns { var, reason } => write!(f, "{var}: {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {}

// ---------------------------------------------------------------------------
// Primitive readers
// ---------------------------------------------------------------------------

/// A source of configuration values. Abstracted over so tests can supply a map
/// instead of mutating the real process environment, which is a global that
/// makes parallel tests flaky.
pub trait EnvSource {
    /// Look up one variable.
    fn get(&self, key: &str) -> Option<String>;
}

/// Reads from the real process environment.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

impl EnvSource for std::collections::HashMap<String, String> {
    fn get(&self, key: &str) -> Option<String> {
        // Spelled out to make it unambiguous that this is the inherent
        // `HashMap::get` and not a recursive call into the trait method.
        std::collections::HashMap::get(self, key).cloned()
    }
}

fn read_string<E: EnvSource + ?Sized>(env: &E, var: &'static str) -> Option<String> {
    env.get(var)
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn read_u64<E: EnvSource + ?Sized>(
    env: &E,
    var: &'static str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, ConfigError> {
    let Some(raw) = read_string(env, var) else {
        return Ok(default);
    };
    let parsed = raw.parse::<u64>().map_err(|_| ConfigError::NotAnInteger {
        var,
        value: raw.clone(),
    })?;
    if parsed < min || parsed > max {
        return Err(ConfigError::OutOfRange {
            var,
            value: raw,
            min,
            max,
        });
    }
    Ok(parsed)
}

fn read_bool<E: EnvSource + ?Sized>(
    env: &E,
    var: &'static str,
    default: bool,
) -> Result<bool, ConfigError> {
    let Some(raw) = read_string(env, var) else {
        return Ok(default);
    };
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" | "y" => Ok(true),
        "0" | "false" | "no" | "off" | "n" => Ok(false),
        _ => Err(ConfigError::NotABoolean { var, value: raw }),
    }
}

/// Parse `IP` or `IP:port` into a [`SocketAddr`], defaulting the port to 53.
///
/// Bare IPv6 literals may be written either plain (`::1`) or bracketed
/// (`[::1]`); a port always requires brackets, as in `[::1]:5353`.
///
/// # Errors
/// [`ConfigError::NotAnAddress`] for anything that is not a literal address.
pub fn parse_server_addr(var: &'static str, raw: &str) -> Result<SocketAddr, ConfigError> {
    let trimmed = raw.trim();
    let fail = || ConfigError::NotAnAddress {
        var,
        value: raw.to_owned(),
    };

    if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        return Ok(sock);
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, DNS_PORT));
    }
    // "[::1]" with no port.
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(fail)?;
    let ip = unbracketed.parse::<IpAddr>().map_err(|_| fail())?;
    Ok(SocketAddr::new(ip, DNS_PORT))
}

// ---------------------------------------------------------------------------
// Sub-configurations
// ---------------------------------------------------------------------------

/// TSIG signing settings. Present only when both a key name and a secret were
/// supplied.
#[derive(Clone, PartialEq, Eq)]
pub struct TsigSettings {
    /// Key name, e.g. `registrar.vxcloud.io.`.
    pub key_name: String,
    /// Base64 shared secret. Never logged.
    pub secret_b64: String,
    /// MAC algorithm.
    pub algorithm: TsigAlgorithm,
    /// Permitted clock skew, seconds.
    pub fudge: u16,
}

impl fmt::Debug for TsigSettings {
    /// Redacts the secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsigSettings")
            .field("key_name", &self.key_name)
            .field("secret_b64", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("fudge", &self.fudge)
            .finish()
    }
}

/// Dynamic-DNS registration settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    /// Whether to register on boot and de-register on `SIGTERM`.
    pub enabled: bool,
    /// The authoritative server to send `UPDATE` to.
    pub server: SocketAddr,
    /// The zone named in the `UPDATE` zone section.
    pub zone: String,
    /// The suffix appended to `<task_id>.<tenant>` to form the worker's name.
    pub base_domain: String,
    /// `A` record TTL in seconds.
    pub ttl: u32,
    /// Per-attempt UDP timeout.
    pub timeout: Duration,
    /// Total attempts, including the first.
    pub retries: u32,
    /// Add the RFC 2136 §2.4.5 "name is not in use" prerequisite.
    pub require_absent: bool,
    /// TSIG settings, when signing is configured.
    pub tsig: Option<TsigSettings>,
}

impl DnsConfig {
    /// Load from an environment source.
    ///
    /// # Errors
    /// Any [`ConfigError`] arising from a malformed variable.
    pub fn from_env<E: EnvSource + ?Sized>(env: &E) -> Result<Self, ConfigError> {
        let server_raw =
            read_string(env, "VX_DNS_SERVER").unwrap_or_else(|| "127.0.0.1:53".to_owned());
        let server = parse_server_addr("VX_DNS_SERVER", &server_raw)?;

        let zone = read_string(env, "VX_DNS_ZONE").unwrap_or_else(|| "vxcloud.io.".to_owned());
        let base_domain = read_string(env, "VX_DNS_BASE_DOMAIN").unwrap_or_else(|| zone.clone());

        let ttl = read_u64(env, "VX_DNS_TTL", 60, 1, u64::from(u32::MAX))? as u32;
        let timeout = Duration::from_millis(read_u64(env, "VX_DNS_TIMEOUT_MS", 2_000, 1, 600_000)?);
        let retries = read_u64(env, "VX_DNS_RETRIES", 3, 1, 32)? as u32;

        let tsig = match (
            read_string(env, "VX_TSIG_KEY_NAME"),
            read_string(env, "VX_TSIG_SECRET"),
        ) {
            (Some(key_name), Some(secret_b64)) => {
                let algorithm_raw = read_string(env, "VX_TSIG_ALGORITHM")
                    .unwrap_or_else(|| "hmac-sha256".to_owned());
                let algorithm =
                    TsigAlgorithm::from_name(&algorithm_raw).map_err(|e| ConfigError::Dns {
                        var: "VX_TSIG_ALGORITHM",
                        reason: e.to_string(),
                    })?;
                let fudge =
                    read_u64(env, "VX_TSIG_FUDGE", u64::from(DEFAULT_FUDGE), 1, 65_535)? as u16;
                Some(TsigSettings {
                    key_name,
                    secret_b64,
                    algorithm,
                    fudge,
                })
            }
            _ => None,
        };

        Ok(Self {
            enabled: read_bool(env, "VX_DNS_ENABLED", false)?,
            server,
            zone,
            base_domain,
            ttl,
            timeout,
            retries,
            require_absent: read_bool(env, "VX_DNS_REQUIRE_ABSENT", false)?,
            tsig,
        })
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: SocketAddr::from(([127, 0, 0, 1], DNS_PORT)),
            zone: "vxcloud.io.".to_owned(),
            base_domain: "vxcloud.io.".to_owned(),
            ttl: 60,
            timeout: Duration::from_millis(2_000),
            retries: 3,
            require_absent: false,
            tsig: None,
        }
    }
}

/// HTTP client settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConfig {
    /// Per-request deadline, covering connect, TLS, and body.
    pub timeout: Duration,
    /// Maximum redirects to follow before erroring.
    pub max_redirects: usize,
    /// Hard cap on response body bytes retained.
    pub max_body_bytes: u64,
    /// Maximum simultaneous in-flight requests during fan-out.
    pub concurrency: usize,
    /// `User-Agent` header value.
    pub user_agent: String,
}

impl HttpConfig {
    /// Load from an environment source.
    ///
    /// # Errors
    /// Any [`ConfigError`] arising from a malformed variable.
    pub fn from_env<E: EnvSource + ?Sized>(env: &E) -> Result<Self, ConfigError> {
        Ok(Self {
            timeout: Duration::from_millis(read_u64(
                env,
                "VX_HTTP_TIMEOUT_MS",
                10_000,
                1,
                600_000,
            )?),
            max_redirects: read_u64(env, "VX_HTTP_MAX_REDIRECTS", 5, 0, 64)? as usize,
            max_body_bytes: read_u64(
                env,
                "VX_HTTP_MAX_BODY_BYTES",
                2 * 1024 * 1024,
                1,
                1024 * 1024 * 1024,
            )?,
            concurrency: read_u64(env, "VX_HTTP_CONCURRENCY", 8, 1, 1024)? as usize,
            user_agent: read_string(env, "VX_HTTP_USER_AGENT")
                .unwrap_or_else(|| format!("ion/{}", crate::VERSION)),
        })
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(10_000),
            max_redirects: 5,
            max_body_bytes: 2 * 1024 * 1024,
            concurrency: 8,
            user_agent: format!("ion/{}", crate::VERSION),
        }
    }
}

/// Tokio scheduler settings.
///
/// The default is the **current-thread** scheduler. That is the whole point of
/// `ion`: a multi-thread runtime pre-spawns one worker per core, each with its
/// own stack and its own share of the allocator's arenas, and that alone can
/// double idle RSS on a 16-core host for a worker that is going to make three
/// HTTP requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RuntimeConfig {
    /// Opt in to the multi-thread scheduler.
    pub multi_thread: bool,
    /// Worker-thread count when multi-threaded. `None` means "one per core".
    pub worker_threads: Option<usize>,
}

impl RuntimeConfig {
    /// Load from an environment source.
    ///
    /// # Errors
    /// Any [`ConfigError`] arising from a malformed variable.
    pub fn from_env<E: EnvSource + ?Sized>(env: &E) -> Result<Self, ConfigError> {
        let multi_thread = read_bool(env, "VX_RUNTIME_MULTI_THREAD", false)?;
        let worker_threads = if read_string(env, "VX_RUNTIME_WORKER_THREADS").is_some() {
            Some(read_u64(env, "VX_RUNTIME_WORKER_THREADS", 1, 1, 256)? as usize)
        } else {
            None
        };
        Ok(Self {
            multi_thread,
            worker_threads,
        })
    }
}

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

/// The complete worker configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Tenant slug, at most [`VX_TENANT_ID_LEN`] bytes.
    pub tenant_id: String,
    /// Task id used when the CLI has to synthesise an ABI header.
    pub task_id: u64,
    /// Dynamic-DNS settings.
    pub dns: DnsConfig,
    /// HTTP client settings.
    pub http: HttpConfig,
    /// Scheduler settings.
    pub runtime: RuntimeConfig,
}

impl Config {
    /// Load everything from the real process environment.
    ///
    /// # Errors
    /// Any [`ConfigError`] arising from a malformed variable.
    pub fn from_process_env() -> Result<Self, ConfigError> {
        Self::from_env(&ProcessEnv)
    }

    /// Load everything from an arbitrary environment source.
    ///
    /// # Errors
    /// Any [`ConfigError`] arising from a malformed variable.
    pub fn from_env<E: EnvSource + ?Sized>(env: &E) -> Result<Self, ConfigError> {
        let tenant_id = read_string(env, "VX_TENANT_ID").unwrap_or_else(|| "default".to_owned());
        if tenant_id.len() > VX_TENANT_ID_LEN {
            return Err(ConfigError::TenantTooLong {
                len: tenant_id.len(),
            });
        }
        Ok(Self {
            tenant_id,
            task_id: read_u64(env, "VX_TASK_ID", 0, 0, u64::MAX)?,
            dns: DnsConfig::from_env(env)?,
            http: HttpConfig::from_env(env)?,
            runtime: RuntimeConfig::from_env(env)?,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tenant_id: "default".to_owned(),
            task_id: 0,
            dns: DnsConfig::default(),
            http: HttpConfig::default(),
            runtime: RuntimeConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn defaults_are_sane_with_an_empty_environment() {
        let cfg = Config::from_env(&env(&[])).unwrap();
        assert_eq!(cfg.tenant_id, "default");
        assert_eq!(cfg.task_id, 0);
        assert!(!cfg.dns.enabled);
        assert_eq!(cfg.dns.server.port(), 53);
        assert_eq!(cfg.dns.ttl, 60);
        assert_eq!(cfg.dns.retries, 3);
        assert!(cfg.dns.tsig.is_none());
        assert_eq!(cfg.http.max_redirects, 5);
        assert_eq!(cfg.http.concurrency, 8);
        assert!(!cfg.runtime.multi_thread);
        assert_eq!(cfg.runtime.worker_threads, None);
    }

    #[test]
    fn bad_input_is_an_error_not_a_panic() {
        assert!(matches!(
            Config::from_env(&env(&[("VX_DNS_TTL", "sixty")])),
            Err(ConfigError::NotAnInteger { .. })
        ));
        assert!(matches!(
            Config::from_env(&env(&[("VX_DNS_ENABLED", "maybe")])),
            Err(ConfigError::NotABoolean { .. })
        ));
        assert!(matches!(
            Config::from_env(&env(&[("VX_HTTP_CONCURRENCY", "0")])),
            Err(ConfigError::OutOfRange { .. })
        ));
        assert!(matches!(
            Config::from_env(&env(&[("VX_DNS_SERVER", "ns1.example.com")])),
            Err(ConfigError::NotAnAddress { .. })
        ));
        assert!(matches!(
            Config::from_env(&env(&[("VX_TENANT_ID", &"t".repeat(65))])),
            Err(ConfigError::TenantTooLong { len: 65 })
        ));
        assert!(matches!(
            Config::from_env(&env(&[
                ("VX_TSIG_KEY_NAME", "k."),
                ("VX_TSIG_SECRET", "AAAA"),
                ("VX_TSIG_ALGORITHM", "hmac-md5"),
            ])),
            Err(ConfigError::Dns { .. })
        ));
    }

    #[test]
    fn server_addresses_parse_in_every_accepted_shape() {
        for (raw, expect_port) in [
            ("10.0.0.1", 53u16),
            ("10.0.0.1:5353", 5353),
            ("::1", 53),
            ("[::1]", 53),
            ("[::1]:5353", 5353),
        ] {
            let got = parse_server_addr("VX_DNS_SERVER", raw)
                .unwrap_or_else(|e| panic!("{raw} should parse: {e}"));
            assert_eq!(got.port(), expect_port, "port for {raw}");
        }
        assert!(parse_server_addr("VX_DNS_SERVER", "not an ip").is_err());
        assert!(parse_server_addr("VX_DNS_SERVER", "").is_err());
    }

    #[test]
    fn tsig_needs_both_a_name_and_a_secret() {
        let only_name = Config::from_env(&env(&[("VX_TSIG_KEY_NAME", "k.")])).unwrap();
        assert!(only_name.dns.tsig.is_none());

        let both = Config::from_env(&env(&[
            ("VX_TSIG_KEY_NAME", "registrar.vxcloud.io."),
            ("VX_TSIG_SECRET", "c2VjcmV0"),
            ("VX_TSIG_ALGORITHM", "hmac-sha512"),
            ("VX_TSIG_FUDGE", "120"),
        ]))
        .unwrap();
        let tsig = both.dns.tsig.expect("tsig should be configured");
        assert_eq!(tsig.algorithm, TsigAlgorithm::HmacSha512);
        assert_eq!(tsig.fudge, 120);
    }

    #[test]
    fn tsig_debug_redacts_the_secret() {
        let cfg = Config::from_env(&env(&[
            ("VX_TSIG_KEY_NAME", "k."),
            ("VX_TSIG_SECRET", "c3VwZXItc2VjcmV0"),
        ]))
        .unwrap();
        let rendered = format!("{:?}", cfg.dns);
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("c3VwZXItc2VjcmV0"));
    }

    #[test]
    fn base_domain_defaults_to_the_zone() {
        let cfg = Config::from_env(&env(&[("VX_DNS_ZONE", "internal.example.")])).unwrap();
        assert_eq!(cfg.dns.base_domain, "internal.example.");
    }

    #[test]
    fn blank_values_fall_through_to_defaults() {
        // Lambda and Kubernetes both love to project an empty string for an
        // unset key; treating "" as "absent" avoids a useless hard failure.
        let cfg = Config::from_env(&env(&[("VX_DNS_ZONE", "   "), ("VX_TENANT_ID", "")])).unwrap();
        assert_eq!(cfg.dns.zone, "vxcloud.io.");
        assert_eq!(cfg.tenant_id, "default");
    }
}
