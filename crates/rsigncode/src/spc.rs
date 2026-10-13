//! DER encoding of the Authenticode structures (`SPC_*`) that go into a PE signature.
//!
//! The encodings are those of SignTool and osslsigncode, checked byte for byte against
//! the signatures of the real files in `tests/data`.

/// Why a structure could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {}

const TAG_BIT_STRING: u8 = 0x03;
const TAG_SEQUENCE: u8 = 0x30;

/// Appends the DER length of `len`.
fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// `tag length content`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    push_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// The `flags` of a `SpcPeImageData`: a `BIT STRING` whose bit 0 is the most significant
/// bit of the first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeImageFlags(u8);

impl PeImageFlags {
    /// No flag set: what SignTool writes.
    pub const NONE: PeImageFlags = PeImageFlags(0);
    /// `includeResources` (bit 0): what osslsigncode writes.
    pub const INCLUDE_RESOURCES: PeImageFlags = PeImageFlags(0x80);

    /// DER of the bit string: trailing zero bits are removed (X.690 11.2.2).
    fn der(self) -> Vec<u8> {
        if self.0 == 0 {
            return tlv(TAG_BIT_STRING, &[0]);
        }
        tlv(TAG_BIT_STRING, &[self.0.trailing_zeros() as u8, self.0])
    }
}

/// `<<<Obsolete>>>` as `SpcLink.file`: `[0] { [2] { [0] BMPString } }`.
fn obsolete_file_link() -> Vec<u8> {
    let name: Vec<u8> = "<<<Obsolete>>>"
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect();
    tlv(0xa0, &tlv(0xa2, &tlv(0x80, &name)))
}

/// Encodes a `SpcPeImageData` whose `file` is the `<<<Obsolete>>>` link, the value of the
/// `SPC_PE_IMAGE_DATA_OBJID` (1.3.6.1.4.1.311.2.1.15) attribute.
pub fn pe_image_data(flags: PeImageFlags) -> Vec<u8> {
    let mut content = flags.der();
    content.extend_from_slice(&obsolete_file_link());
    tlv(TAG_SEQUENCE, &content)
}
