//! Environment-driven configuration for `pii-server`.
//!
//! Every value is read from environment variables at startup. Invalid or
//! missing required values fail fast with a descriptive message and a
//! non-zero exit code.

use pii_core::TokenFormat;
use std::net::SocketAddr;

/// Resolved startup configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Socket address to bind (e.g. `0.0.0.0:8080` in Kubernetes,
    /// `127.0.0.1:8080` as a localhost sidecar).
    pub bind_addr: SocketAddr,
    /// Token format: stateless-sealed (self-contained tokens) or redis.
    pub token_format: TokenFormat,
    /// 32-byte session key for `stateless-sealed` mode.
    pub seal_key: Option<zeroize::Zeroizing<[u8; 32]>>,
    /// Redis connection URL, required when `token_format` is `redis`.
    pub redis_url: Option<String>,
    /// Maximum accepted HTTP request body size in bytes.
    pub max_body_bytes: usize,
    /// Log output format: `json` (default) or `pretty`.
    pub log_format: LogFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

/// What went wrong while reading configuration.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "configuration error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Reads configuration from the process environment, failing fast.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = parse_bind_addr(env_opt("PII_BIND_ADDR")?, "0.0.0.0:8080")?;

        let token_format_raw =
            env_opt("PII_TOKEN_FORMAT")?.unwrap_or_else(|| "stateless-sealed".into());
        let token_format = match token_format_raw.as_str() {
            "stateless-sealed" => TokenFormat::StatelessSealed,
            "redis" => TokenFormat::CompactHash,
            other => {
                return Err(ConfigError(format!(
                    "PII_TOKEN_FORMAT: unknown value '{other}' (expected 'stateless-sealed' or 'redis')"
                )))
            }
        };

        let seal_key = parse_seal_key(env_opt("PII_SEAL_KEY")?, token_format_raw.as_str())?;
        let redis_url = match token_format_raw.as_str() {
            "redis" => Some(env_required("PII_REDIS_URL")?),
            _ => None,
        };

        let max_body_bytes = match env_opt("PII_MAX_BODY_BYTES")? {
            Some(v) => v
                .parse::<usize>()
                .map_err(|_| ConfigError("PII_MAX_BODY_BYTES: not a valid usize".into()))?,
            None => 1_048_576,
        };

        let log_format = match env_opt("PII_LOG_FORMAT")?
            .unwrap_or_else(|| "json".into())
            .as_str()
        {
            "json" => LogFormat::Json,
            "pretty" => LogFormat::Pretty,
            other => {
                return Err(ConfigError(format!(
                    "PII_LOG_FORMAT: unknown value '{other}' (expected 'json' or 'pretty')"
                )))
            }
        };

        Ok(Config {
            bind_addr,
            token_format,
            seal_key,
            redis_url,
            max_body_bytes,
            log_format,
        })
    }
}

/// `Ok(None)` when unset or empty; error when not valid UTF-8.
fn env_opt(name: &str) -> Result<Option<String>, ConfigError> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Ok(Some(v.trim().to_string())),
        Ok(_) => Ok(None),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(ConfigError(format!("{name}: value is not valid UTF-8")))
        }
    }
}

fn env_required(name: &str) -> Result<String, ConfigError> {
    env_opt(name)?.ok_or_else(|| ConfigError(format!("{name} is required but not set")))
}

fn parse_bind_addr(raw: Option<String>, default: &str) -> Result<SocketAddr, ConfigError> {
    let value = raw.unwrap_or_else(|| default.to_string());
    value
        .parse::<SocketAddr>()
        .map_err(|_| ConfigError(format!("PII_BIND_ADDR: invalid socket address '{value}'")))
}

/// Parses `PII_SEAL_KEY` as 32 raw bytes encoded as hex (64 chars), base64
/// (44 chars), or a raw 32-byte string. Always required: the redis store also
/// seals vault entries with this key.
fn parse_seal_key(
    raw: Option<String>,
    _token_format: &str,
) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>, ConfigError> {
    let key_bytes: Vec<u8> = match raw {
        Some(value) => {
            if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
                hex::decode(&value).map_err(|_| ConfigError("PII_SEAL_KEY: invalid hex".into()))?
            } else if value.len() == 44 && value.ends_with('=') {
                base64_decode(&value)
                    .map_err(|_| ConfigError("PII_SEAL_KEY: invalid base64".into()))?
            } else if value.len() == 32 {
                value.into_bytes()
            } else {
                return Err(ConfigError(
                    "PII_SEAL_KEY: expected 64-char hex, base64 (44 chars), or 32 raw bytes \
                     encoding a 32-byte key"
                        .into(),
                ));
            }
        }
        None => Vec::new(),
    };

    if key_bytes.is_empty() {
        return Err(ConfigError("PII_SEAL_KEY is required but not set".into()));
    }

    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| ConfigError("PII_SEAL_KEY: key must be exactly 32 bytes".into()))?;

    if key.iter().all(|b| *b == 0) {
        return Err(ConfigError(
            "PII_SEAL_KEY: all-zero key is not allowed".into(),
        ));
    }

    Ok(Some(zeroize::Zeroizing::new(key)))
}

/// Minimal std-alphabet base64 decoder (avoids pulling a new dependency).
fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in input.as_bytes() {
        if b == b'=' {
            break;
        }
        let v = ALPHABET.iter().position(|&a| a == b).ok_or(())?;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX_KEY: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

    #[test]
    fn defaults() {
        let cfg = Config {
            bind_addr: parse_bind_addr(None, "0.0.0.0:8080").unwrap(),
            token_format: TokenFormat::StatelessSealed,
            seal_key: parse_seal_key(Some(HEX_KEY.into()), "stateless-sealed").unwrap(),
            redis_url: None,
            max_body_bytes: 1_048_576,
            log_format: LogFormat::Json,
        };
        assert_eq!(cfg.bind_addr.to_string(), "0.0.0.0:8080");
        assert!(cfg.redis_url.is_none());
        assert_eq!(cfg.seal_key.unwrap().as_ref(), &[0xa1u8; 32]);
    }

    #[test]
    fn hex_seal_key() {
        let key = parse_seal_key(Some(HEX_KEY.into()), "stateless-sealed")
            .unwrap()
            .unwrap();
        assert_eq!(key.as_ref(), &[0xa1u8; 32]);
    }

    #[test]
    fn base64_seal_key() {
        let value = base64::encode(&[0xa1u8; 32]);
        let key = parse_seal_key(Some(value), "stateless-sealed")
            .unwrap()
            .unwrap();
        assert_eq!(key.as_ref(), &[0xa1u8; 32]);
    }

    #[test]
    fn missing_key_errors_in_both_modes() {
        let err = parse_seal_key(None, "stateless-sealed").unwrap_err();
        assert!(err.0.contains("required"));
        assert!(parse_seal_key(None, "redis").is_err());
    }

    #[test]
    fn rejects_all_zero_key() {
        let err = parse_seal_key(Some("00".repeat(32)), "redis").unwrap_err();
        assert!(err.0.contains("all-zero"));
    }

    #[test]
    fn rejects_bad_bind_addr() {
        let err = parse_bind_addr(Some("not-an-addr".into()), "0.0.0.0:8080").unwrap_err();
        assert!(err.0.contains("PII_BIND_ADDR"));
    }

    #[test]
    fn base64_roundtrip_matches_hex() {
        let bytes = base64_decode(&base64::encode(&[0xa1u8; 32])).unwrap();
        assert_eq!(bytes, vec![0xa1u8; 32]);
    }

    /// Local base64 encoder for the tests above (std alphabet).
    mod base64 {
        pub fn encode(data: &[u8]) -> String {
            const ALPHABET: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for chunk in data.chunks(3) {
                let b = [
                    chunk[0],
                    chunk.get(1).copied().unwrap_or(0),
                    chunk.get(2).copied().unwrap_or(0),
                ];
                let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
                out.push(ALPHABET[(n >> 18) as usize & 63] as char);
                out.push(ALPHABET[(n >> 12) as usize & 63] as char);
                out.push(if chunk.len() > 1 {
                    ALPHABET[(n >> 6) as usize & 63] as char
                } else {
                    '='
                });
                out.push(if chunk.len() > 2 {
                    ALPHABET[n as usize & 63] as char
                } else {
                    '='
                });
            }
            out
        }
    }
}
