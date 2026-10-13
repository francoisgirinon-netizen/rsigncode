use crate::pe::Error;
use core::ops::Range;

const DOS_E_LFANEW: usize = 0x3c;
const COFF_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;
const OPT_SECTION_ALIGNMENT: usize = 32;
const OPT_SIZE_OF_HEADERS: usize = 60;
const OPT_CHECKSUM: usize = 64;
const MAGIC_PE32: u16 = 0x10b;
const MAGIC_PE32_PLUS: u16 = 0x20b;
/// Index of the Certificate Table in the data directories.
const CERTIFICATE_DIRECTORY: usize = 4;

/// One entry of the section table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    /// `PointerToRawData`.
    pub raw_offset: u32,
    /// `SizeOfRawData`.
    pub raw_size: u32,
}

/// Offsets of the structures of a PE file that signing needs.
///
/// Parsing checks only what is needed to locate them; section data is validated when the
/// digest ranges are computed. Offsets are file offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeFile<'a> {
    /// The whole file.
    pub data: &'a [u8],
    /// `true` for PE32+ (64-bit), `false` for PE32.
    pub is_pe32_plus: bool,
    /// Offset of the 4-byte `CheckSum` field.
    pub checksum_offset: usize,
    /// Offset of the 8-byte Certificate Table data directory entry.
    pub certificate_entry_offset: usize,
    /// `SizeOfHeaders`.
    pub size_of_headers: usize,
    /// `SectionAlignment` (the page size of page hashes).
    pub section_alignment: u32,
    /// Section table, in table order.
    pub sections: Vec<Section>,
    /// Certificate table (file offset and size), if the file is signed.
    pub certificate_table: Option<Range<usize>>,
}

/// What to feed to the hash for the Authenticode digest, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashedRanges {
    /// Byte ranges of the file.
    pub ranges: Vec<Range<usize>>,
    /// Number of zero bytes hashed after the ranges (padding that signing inserts before
    /// the certificate table of a file that has none).
    pub padding: usize,
}

fn read_u16(data: &[u8], at: usize) -> Result<u16, Error> {
    let b = data.get(at..).and_then(|rest| rest.first_chunk::<2>());
    b.map(|b| u16::from_le_bytes(*b)).ok_or(Error::Truncated)
}

fn read_u32(data: &[u8], at: usize) -> Result<u32, Error> {
    let b = data.get(at..).and_then(|rest| rest.first_chunk::<4>());
    b.map(|b| u32::from_le_bytes(*b)).ok_or(Error::Truncated)
}

/// Reads a field that `parse` has already checked to be inside the file.
fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

impl<'a> PeFile<'a> {
    /// Parses the headers of a PE32 or PE32+ file.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.get(..2).ok_or(Error::Truncated)? != b"MZ" {
            return Err(Error::BadDosSignature);
        }
        let pe = read_u32(data, DOS_E_LFANEW)? as usize;
        let signature = data.get(pe..).and_then(|rest| rest.first_chunk::<4>());
        if signature.ok_or(Error::Truncated)? != b"PE\0\0" {
            return Err(Error::BadPeSignature);
        }
        let coff = pe + 4;
        let section_count = read_u16(data, coff + 2)? as usize;
        let opt_size = read_u16(data, coff + 16)? as usize;
        let opt = coff + COFF_HEADER_SIZE;
        let is_pe32_plus = match read_u16(data, opt)? {
            MAGIC_PE32 => false,
            MAGIC_PE32_PLUS => true,
            _ => return Err(Error::UnknownOptionalHeaderMagic),
        };
        let (count_offset, dirs_offset) = if is_pe32_plus { (108, 112) } else { (92, 96) };
        let size_of_headers = read_u32(data, opt + OPT_SIZE_OF_HEADERS)? as usize;
        let directory_count = read_u32(data, opt + count_offset)? as usize;
        let entry = dirs_offset + 8 * CERTIFICATE_DIRECTORY;
        if directory_count <= CERTIFICATE_DIRECTORY || opt_size < entry + 8 {
            return Err(Error::MissingCertificateDirectory);
        }
        let checksum_offset = opt + OPT_CHECKSUM;
        let certificate_entry_offset = opt + entry;
        if size_of_headers > data.len() {
            return Err(Error::Truncated);
        }
        if size_of_headers < certificate_entry_offset + 8 {
            return Err(Error::InvalidSizeOfHeaders);
        }

        let table = opt + opt_size;
        let table_end = table.saturating_add(section_count * SECTION_HEADER_SIZE);
        if table_end > data.len() {
            return Err(Error::Truncated);
        }
        let sections = (0..section_count)
            .map(|i| {
                let at = table + i * SECTION_HEADER_SIZE;
                Section {
                    raw_size: u32_at(data, at + 16),
                    raw_offset: u32_at(data, at + 20),
                }
            })
            .collect();

        let cert_offset = u32_at(data, certificate_entry_offset) as usize;
        let cert_size = u32_at(data, certificate_entry_offset + 4) as usize;
        let certificate_table = if cert_size == 0 {
            None
        } else {
            let end = cert_offset
                .checked_add(cert_size)
                .filter(|&e| e <= data.len() && cert_offset >= size_of_headers)
                .ok_or(Error::InvalidCertificateTable)?;
            Some(cert_offset..end)
        };

        Ok(PeFile {
            data,
            is_pe32_plus,
            checksum_offset,
            certificate_entry_offset,
            size_of_headers,
            section_alignment: u32_at(data, opt + OPT_SECTION_ALIGNMENT),
            sections,
            certificate_table,
        })
    }

    /// The parts of the file covered by the Authenticode digest, as described by the
    /// "Windows Authenticode Portable Executable Signature Format" specification.
    pub fn hashed_ranges(&self) -> Result<HashedRanges, Error> {
        let len = self.data.len();
        let mut ranges = vec![
            0..self.checksum_offset,
            self.checksum_offset + 4..self.certificate_entry_offset,
            self.certificate_entry_offset + 8..self.size_of_headers,
        ];
        let mut hashed = self.size_of_headers;

        let mut sorted: Vec<&Section> = self.sections.iter().filter(|s| s.raw_size > 0).collect();
        sorted.sort_by_key(|s| s.raw_offset);
        for s in sorted {
            let start = s.raw_offset as usize;
            let end = start.checked_add(s.raw_size as usize);
            let end = end.filter(|&e| e <= len).ok_or(Error::SectionOutOfBounds)?;
            ranges.push(start..end);
            hashed += s.raw_size as usize;
        }

        let end = self.certificate_table.as_ref().map_or(len, |c| c.start);
        if end > hashed {
            ranges.push(hashed..end);
        } else if self.certificate_table.is_some() && end < hashed {
            return Err(Error::InvalidCertificateTable);
        }
        // SignTool and osslsigncode pad the file to a multiple of 8 bytes before the
        // certificate table; an unsigned file is hashed as if it were already padded.
        let padding = if self.certificate_table.is_none() {
            (8 - len % 8) % 8
        } else {
            0
        };
        Ok(HashedRanges { ranges, padding })
    }
}
