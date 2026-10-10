use core::fmt;

/// Error returned when a file is not a PE image we can process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The file ends before a header or structure it announces.
    Truncated,
    /// The file does not start with `MZ`.
    BadDosSignature,
    /// The `PE\0\0` signature is missing at `e_lfanew`.
    BadPeSignature,
    /// The optional header is neither PE32 (`0x10b`) nor PE32+ (`0x20b`).
    UnknownOptionalHeaderMagic,
    /// `NumberOfRvaAndSizes` is below 5: the Certificate Table entry does not exist.
    MissingCertificateDirectory,
    /// `SizeOfHeaders` is inconsistent with the headers or the file.
    InvalidSizeOfHeaders,
    /// A section's raw data lies outside the file.
    SectionOutOfBounds,
    /// The certificate table lies outside the file or overlaps the hashed data.
    InvalidCertificateTable,
    /// Placeholder while the feature is being developed.
    Unimplemented,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Truncated => "file is truncated",
            Error::BadDosSignature => "missing MZ signature",
            Error::BadPeSignature => "missing PE signature",
            Error::UnknownOptionalHeaderMagic => "unknown optional header magic",
            Error::MissingCertificateDirectory => "no Certificate Table data directory entry",
            Error::InvalidSizeOfHeaders => "invalid SizeOfHeaders",
            Error::SectionOutOfBounds => "section raw data outside of the file",
            Error::InvalidCertificateTable => "invalid certificate table",
            Error::Unimplemented => "not implemented",
        })
    }
}

impl std::error::Error for Error {}
