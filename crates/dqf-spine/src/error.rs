//! Engine errors. Every variant is an input-integrity refusal: the engine
//! fails closed on malformed records or configs instead of guessing.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DqfError {
    /// JSON failed the schema (unknown field, wrong type, missing field).
    Schema { file: &'static str, detail: String },
    /// Driver record failed shape validation.
    MalformedDriver { driver_id: String, detail: String },
    /// Document failed shape validation for its kind.
    MalformedDocument { doc_id: String, detail: String },
    /// Config table failed semantic validation.
    InvalidConfig { detail: String },
    /// A validity-window computation overflowed the representable date range.
    DateOverflow { detail: String },
}

impl fmt::Display for DqfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DqfError::Schema { file, detail } => {
                write!(f, "schema violation in {file}: {detail}")
            }
            DqfError::MalformedDriver { driver_id, detail } => {
                write!(f, "malformed driver {driver_id:?}: {detail}")
            }
            DqfError::MalformedDocument { doc_id, detail } => {
                write!(f, "malformed document {doc_id:?}: {detail}")
            }
            DqfError::InvalidConfig { detail } => write!(f, "invalid config: {detail}"),
            DqfError::DateOverflow { detail } => write!(f, "date overflow: {detail}"),
        }
    }
}

impl std::error::Error for DqfError {}
