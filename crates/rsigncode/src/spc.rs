//! DER encoding of the Authenticode structures (`SPC_*`) that go into a PE signature.
//!
//! The encodings are those of SignTool and osslsigncode, checked byte for byte against
//! the signatures of the real files in `tests/data`.

use crate::hash::HashAlgorithm;

/// Why a structure could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The digest is not as long as the algorithm says.
    DigestLength,
    /// The program name has a character outside the Basic Multilingual Plane.
    ProgramNameNotBmp,
    /// The URL is not ASCII (`IA5String`).
    UrlNotAscii,
}

/// The `-comm` choice: who the signed code is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementType {
    /// Individual code signing (the default).
    Individual,
    /// Commercial code signing (`-comm`).
    Commercial,
}

/// Encodes the `SPC_STATEMENT_TYPE` attribute.
///
/// `SEQUENCE { 1.3.6.1.4.1.311.2.1.11, SET { SEQUENCE { 1.3.6.1.4.1.311.2.1.21 or .22 } } }`.
pub fn statement_type_attribute(statement: StatementType) -> Vec<u8> {
    let last = match statement {
        StatementType::Individual => 0x15,
        StatementType::Commercial => 0x16,
    };
    let mut oid = OID_SPC_MS_BASE.to_vec();
    oid.push(last);
    attribute(
        OID_SPC_STATEMENT_TYPE,
        &tlv(TAG_SEQUENCE, &tlv(TAG_OID, &oid)),
    )
}

/// `SEQUENCE { oid, SET { value } }`, a CMS `Attribute` with one value.
fn attribute(oid: &[u8], value: &[u8]) -> Vec<u8> {
    let mut content = tlv(TAG_OID, oid);
    content.extend_from_slice(&tlv(TAG_SET, value));
    tlv(TAG_SEQUENCE, &content)
}

/// Encodes a `SpcSpOpusInfo`, the value of the `SPC_SP_OPUS_INFO_OBJID` attribute:
/// `programName [0] EXPLICIT SpcString` (`-n`) and `moreInfo [1] EXPLICIT SpcLink` (`-i`),
/// both optional. The name is a `[0] BMPString` (UTF-16BE), the link a `[0] IA5String` URL.
pub fn opus_info(program_name: Option<&str>, more_info: Option<&str>) -> Result<Vec<u8>, Error> {
    let mut content = Vec::new();
    if let Some(name) = program_name {
        let mut bmp = Vec::with_capacity(name.len() * 2);
        for c in name.chars() {
            let unit = u16::try_from(u32::from(c)).map_err(|_| Error::ProgramNameNotBmp)?;
            bmp.extend_from_slice(&unit.to_be_bytes());
        }
        content.extend_from_slice(&tlv(0xa0, &tlv(0x80, &bmp)));
    }
    if let Some(url) = more_info {
        if !url.is_ascii() {
            return Err(Error::UrlNotAscii);
        }
        content.extend_from_slice(&tlv(0xa1, &tlv(0x80, url.as_bytes())));
    }
    Ok(tlv(TAG_SEQUENCE, &content))
}

/// Encodes the `SPC_SP_OPUS_INFO` attribute (1.3.6.1.4.1.311.2.1.12) around
/// [`opus_info`].
pub fn opus_info_attribute(
    program_name: Option<&str>,
    more_info: Option<&str>,
) -> Result<Vec<u8>, Error> {
    Ok(attribute(
        OID_SPC_SP_OPUS_INFO,
        &opus_info(program_name, more_info)?,
    ))
}

/// Encodes a `SpcIndirectDataContent`.
pub fn indirect_data_content(
    image_data: &[u8],
    algorithm: HashAlgorithm,
    digest: &[u8],
) -> Result<Vec<u8>, Error> {
    if digest.len() != algorithm.output_len() {
        return Err(Error::DigestLength);
    }
    let mut data = tlv(TAG_OID, OID_SPC_PE_IMAGE_DATA);
    data.extend_from_slice(image_data);
    let mut content = tlv(TAG_SEQUENCE, &data);
    content.extend_from_slice(&digest_info(algorithm, digest));
    Ok(tlv(TAG_SEQUENCE, &content))
}

/// `DigestInfo { AlgorithmIdentifier { oid, NULL }, OCTET STRING }`.
fn digest_info(algorithm: HashAlgorithm, digest: &[u8]) -> Vec<u8> {
    let oid: &[u8] = match algorithm {
        HashAlgorithm::Sha1 => &[0x2b, 0x0e, 0x03, 0x02, 0x1a],
        HashAlgorithm::Sha256 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
        HashAlgorithm::Sha384 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
        HashAlgorithm::Sha512 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
    };
    let mut id = tlv(TAG_OID, oid);
    id.extend_from_slice(&[TAG_NULL, 0]);
    let mut info = tlv(TAG_SEQUENCE, &id);
    info.extend_from_slice(&tlv(TAG_OCTET_STRING, digest));
    tlv(TAG_SEQUENCE, &info)
}

const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;

/// 1.3.6.1.4.1.311.2.1.15, `SPC_PE_IMAGE_DATA_OBJID`.
const OID_SPC_PE_IMAGE_DATA: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0f];
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;

/// 1.3.6.1.4.1.311.2.1, the arcs the `SPC_*` object identifiers share (without the last).
const OID_SPC_MS_BASE: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01];
/// 1.3.6.1.4.1.311.2.1.11, `SPC_STATEMENT_TYPE_OBJID`.
const OID_SPC_STATEMENT_TYPE: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0b];
/// 1.3.6.1.4.1.311.2.1.12, `SPC_SP_OPUS_INFO_OBJID`.
const OID_SPC_SP_OPUS_INFO: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0c];

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
