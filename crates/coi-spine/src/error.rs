//! Product error surface. Distinct refusal kinds are explicit so callers and
//! tests can assert on them; nothing is silently coerced into another kind.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoiError {
    /// A JSON document failed schema validation (certificate or config).
    Schema(String),
    /// The typed certificate failed sanity validation after schema parsing.
    MalformedCertificate(String),
    /// The requirements matrix failed sanity validation after schema parsing.
    InvalidConfig(String),
    /// A governance or lifecycle refusal (already-signed pack, blocked lock).
    Refused(String),
    /// CLI-argument-level failure (bad date, missing signoff fields).
    Usage(String),
    /// Filesystem failure reading or writing a document.
    Io(String),
}

impl fmt::Display for CoiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoiError::Schema(m) => write!(f, "schema violation: {m}"),
            CoiError::MalformedCertificate(m) => write!(f, "malformed certificate: {m}"),
            CoiError::InvalidConfig(m) => write!(f, "invalid requirements config: {m}"),
            CoiError::Refused(m) => write!(f, "refused: {m}"),
            CoiError::Usage(m) => write!(f, "usage: {m}"),
            CoiError::Io(m) => write!(f, "io: {m}"),
        }
    }
}

impl std::error::Error for CoiError {}
