use crate::pe::Error;
use core::ops::Range;

/// One entry of the section table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    /// `PointerToRawData`.
    pub raw_offset: u32,
    /// `SizeOfRawData`.
    pub raw_size: u32,
}

/// Offsets of the structures of a PE file that signing needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeFile<'a> {
    /// The whole file.
    pub data: &'a [u8],
    /// Offset of the 4-byte `CheckSum` field.
    pub checksum_offset: usize,
    /// Offset of the 8-byte Certificate Table data directory entry.
    pub certificate_entry_offset: usize,
    /// `SizeOfHeaders`.
    pub size_of_headers: usize,
    /// Section table, in table order.
    pub sections: Vec<Section>,
    /// Certificate table (file offset and size), if the file is signed.
    pub certificate_table: Option<Range<usize>>,
}

impl<'a> PeFile<'a> {
    /// Parses the headers of a PE32 or PE32+ file.
    pub fn parse(_data: &'a [u8]) -> Result<Self, Error> {
        Err(Error::Unimplemented)
    }
}
