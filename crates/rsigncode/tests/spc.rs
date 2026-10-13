use rsigncode::spc::{PeImageFlags, pe_image_data};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `<<<Obsolete>>>` as the `file` link: `[0] { [2] { [0] BMPString } }`.
const OBSOLETE_LINK: &str = "a020a21e801c003c003c003c004f00620073006f006c006500740065003e003e003e";

/// Spec: SPC-1
/// `SpcPeImageData` = flags + obsolete file link, as found in the `SpcIndirectDataContent`
/// of `tiny64.signed.efi` (SignTool, no flag) and `pe32_extra_3.signed.exe` (osslsigncode,
/// `includeResources`), cut out of their PKCS#7.
#[test]
fn pe_image_data_matches_real_signatures() {
    assert_eq!(
        hex(&pe_image_data(PeImageFlags::NONE)),
        format!("3025030100{OBSOLETE_LINK}")
    );
    assert_eq!(
        hex(&pe_image_data(PeImageFlags::INCLUDE_RESOURCES)),
        format!("302603020780{OBSOLETE_LINK}")
    );
}
