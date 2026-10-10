use core::fmt;

/// Error returned when a file is not a PE image we can process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Placeholder while the feature is being developed.
    Unimplemented,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unimplemented => f.write_str("not implemented"),
        }
    }
}

impl std::error::Error for Error {}
