# Specification coverage

Each requirement has a stable ID. Tests name the IDs they check in a `/// Spec:` doc
comment, so `grep -rn "AUTH-PE-7" crates/` finds them. Scope: the `hash` and `pe` modules (hashing backend, parsing, page hashes, single pass,
Authenticode digest, checksum). Status: covered, not covered (with the reason), out of
scope for this branch.

Sources:

- AUTH: [Windows Authenticode Portable Executable Signature Format](https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx),
  section "Calculating the PE Image Hash" (steps paraphrased).
- PECOFF: [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
- SIGNTOOL: observed on real SignTool 10.0.26100.0 (and osslsigncode), **not in the
  specification**.
- ROBUST: our own requirement (hostile input), not from a specification.

Oracles: osslsigncode (`extract-data`, `verify`, `remove-signature`), real SignTool values
(authenticode-rs test data), and the structure of the PE format. Never rsigncode itself.

Test names are in `crates/rsigncode/tests/`: `pe_digest.rs` (D), `pe_parser.rs` (P),
`pe_checksum.rs` (C).

## Authenticode, "Calculating the PE Image Hash"

| ID | Requirement | Source | Tests | Status |
|---|---|---|---|---|
| AUTH-PE-1 | Load the image header into memory | Authenticode PE, step 1 | D `sha256_of_every_fixture_matches_osslsigncode`, D `tiny_efi_images_match_osslsigncode`, P `offsets_of_real_images` | covered |
| AUTH-PE-2 | Initialise a hash context (SHA-1, SHA-256, SHA-384, SHA-512) | step 2 | D `all_four_algorithms_match_osslsigncode`, D `sha256_of_every_fixture_matches_osslsigncode` | covered |
| AUTH-PE-3 | Hash the image header from its base up to the CheckSum field | step 3 | D `checksum_field_is_not_hashed`, D `header_bytes_around_the_excluded_fields_are_hashed`, D `sha256_of_every_fixture_matches_osslsigncode` | covered |
| AUTH-PE-4 | Skip the 4-byte CheckSum field | step 4 | D `checksum_field_is_not_hashed`, D `sha256_of_every_fixture_matches_osslsigncode` | covered |
| AUTH-PE-5 | Hash from the end of CheckSum up to the Certificate Table entry | step 5 | D `header_bytes_around_the_excluded_fields_are_hashed`, D `sha256_of_every_fixture_matches_osslsigncode` | covered |
| AUTH-PE-6 | Get the Attribute Certificate Table address and size from the entry | step 6 | P `certificate_table_of_signed_files`, D `certificate_table_and_its_entry_are_not_hashed`, D `certificate_table_outside_the_file_is_an_error`, D `files_signed_by_osslsigncode_have_the_digest_of_the_unsigned_file`, D `file_signed_by_signtool_has_the_digest_of_the_unsigned_file` | covered |
| AUTH-PE-7 | Exclude the 8-byte Certificate Table entry; hash the rest of the headers, section table included | step 7 | D `header_bytes_around_the_excluded_fields_are_hashed`, D `certificate_table_and_its_entry_are_not_hashed`, D `sha256_of_every_fixture_matches_osslsigncode`, D `files_signed_by_osslsigncode_have_the_digest_of_the_unsigned_file` | covered |
| AUTH-PE-8 | SUM_OF_BYTES_HASHED starts at SizeOfHeaders | step 8 | D `extra_data_range_follows_the_sum_of_bytes_hashed`, P `offsets_of_real_images` | covered |
| AUTH-PE-9 | Table of section headers (NumberOfSections), leaving out those with SizeOfRawData = 0 | step 9 | D `sections_with_no_raw_data_are_ignored`, D `sha256_of_every_fixture_matches_osslsigncode` | covered |
| AUTH-PE-10 | Sort that table by PointerToRawData, ascending | step 10 | D `sha256_of_every_fixture_matches_osslsigncode` (`pe32_reversed`, `pe64_reversed`), D `all_four_algorithms_match_osslsigncode` (`pe64_reversed`) | covered |
| AUTH-PE-11 | Hash each section's raw data (SizeOfRawData bytes), in that order | step 11 | D `sha256_of_every_fixture_matches_osslsigncode`, D `section_beyond_the_end_of_the_file_is_an_error` | covered |
| AUTH-PE-12 | Add each SizeOfRawData to SUM_OF_BYTES_HASHED | step 12 | D `extra_data_range_follows_the_sum_of_bytes_hashed` | covered |
| AUTH-PE-13 | Repeat 11 and 12 for all sections of the sorted table | step 13 | D `extra_data_range_follows_the_sum_of_bytes_hashed` (two sections), D `sha256_of_every_fixture_matches_osslsigncode` (up to three) | covered |
| AUTH-PE-14 | FILE_SIZE larger than SUM_OF_BYTES_HASHED: hash the extra data, without the certificate table | step 14 | D `overlay_bytes_are_hashed`, D `extra_data_range_follows_the_sum_of_bytes_hashed`, D `certificate_table_and_its_entry_are_not_hashed`, D `sha256_of_every_fixture_matches_osslsigncode` (`*_overlay_*`, `*_extra_*`), D `files_signed_by_osslsigncode_have_the_digest_of_the_unsigned_file` | covered |
| AUTH-PE-15 | Finalise the hash context | step 15 | D `digest_lengths`, D `all_four_algorithms_match_osslsigncode`, all oracle tests | covered |
| AUTH-PE-14b | Step 14 computes the extra data length as FILE_SIZE - (CertDirectory.Size + SUM_OF_BYTES_HASHED); we hash up to the certificate table offset, which is the same when the table is the last thing in the file | step 14 | none | not covered: no real signed file with data after the certificate table to use as oracle |

## PE/COFF

| ID | Requirement | Source | Tests | Status |
|---|---|---|---|---|
| PECOFF-1 | DOS header: `MZ`, `e_lfanew` (offset 0x3c) points to the `PE\0\0` signature | PE Format, MS-DOS stub and PE signature | D `bad_signatures_and_magic_are_reported`, P `offsets_of_real_images`, P `offsets_of_pe32` | covered |
| PECOFF-2 | Optional header magic `0x10b` (PE32) or `0x20b` (PE32+); optional header follows the 20-byte COFF header | Optional header | D `bad_signatures_and_magic_are_reported`, P `offsets_of_pe32`, P `offsets_of_pe32_plus`, P `offsets_of_real_images` | covered |
| PECOFF-3 | CheckSum field at offset 64 of the optional header (both formats) | Optional header, Windows-specific fields | P `offsets_of_pe32`, P `offsets_of_pe32_plus`, P `offsets_of_real_images`, D `checksum_field_is_not_hashed`, C `checksum_ignores_the_checksum_field` | covered |
| PECOFF-4 | Data directories start at +96 (PE32) or +112 (PE32+); `NumberOfRvaAndSizes` at +92 / +108 | Optional header, data directories | P `offsets_of_pe32`, P `offsets_of_pe32_plus`, P `offsets_of_real_images`, D `fewer_than_five_data_directories_is_an_error` | covered |
| PECOFF-5 | Certificate Table is data directory index 4; its address is a **file offset**, not an RVA | Optional header data directories; Attribute Certificate Table | P `offsets_of_pe32`, P `offsets_of_pe32_plus`, P `offsets_of_real_images`, P `certificate_table_of_signed_files`, D `certificate_table_outside_the_file_is_an_error`, D `file_signed_by_signtool_has_the_digest_of_the_unsigned_file` | covered |
| PECOFF-6 | SizeOfHeaders at offset 60 of the optional header | Optional header, Windows-specific fields | P `offsets_of_pe32`, P `offsets_of_real_images`, D `extra_data_range_follows_the_sum_of_bytes_hashed` | covered |
| PECOFF-7 | Section table follows the optional header (SizeOfOptionalHeader); 40-byte entries, SizeOfRawData at +16, PointerToRawData at +20 | Section table | P `offsets_of_pe32`, D `section_beyond_the_end_of_the_file_is_an_error`, D `sha256_of_every_fixture_matches_osslsigncode` | covered |
| PECOFF-8 | Attribute certificate table: quadword (8-byte) aligned, preceded by zero padding, extends to the end of the file | Attribute Certificate Table (Image Only) | P `certificate_table_of_signed_files` (osslsigncode and SignTool files), D `files_signed_by_osslsigncode_have_the_digest_of_the_unsigned_file` | covered |
| PECOFF-9 | Image checksum: 16-bit one's complement sum of the little-endian words with the CheckSum field as zero, folded, plus the file length (CheckSumMappedFile) | Optional header, CheckSum | C `checksum_of_signed_files_matches_the_tools`, C `checksum_of_unsigned_file_matches_osslsigncode`, C `checksum_ignores_the_checksum_field`, C `checksum_of_odd_length_file_counts_the_last_byte_as_low_byte` | covered |
| PECOFF-10 | Checksum of files of 4 GiB or more (length wraps in 32 bits) | CheckSumMappedFile | none | not covered: needs a multi-GiB file; the code uses wrapping addition |
| PECOFF-11 | Content of the certificate table (`WIN_CERTIFICATE`, `bCertificateType`, several certificates) | Attribute Certificate Table | P `certificate_table_of_signed_files` (only `dwLength`) | out of scope for this branch (signature insertion and extraction) |

## SignTool behaviour (observed, not in the specification)

| ID | Requirement | Source | Tests | Status |
|---|---|---|---|---|
| SIGNTOOL-1 | For a file **without** certificate table whose size is not a multiple of 8, `(8 - size % 8) % 8` zero bytes are appended to the hashed data (the padding signing inserts before the certificate table). Observed: SignTool 10.0.26100.0 SHA-256 `17b7398a...` for `tiny64.efi` + `01 02 03` (2051 bytes); without the padding it would be `2a9e8c97...`. Same with osslsigncode | observed, not in spec | D `unsigned_file_with_odd_size_is_padded_like_signtool`, D `sha256_of_every_fixture_matches_osslsigncode` (`*_extra_1..7`), D `files_signed_by_osslsigncode_have_the_digest_of_the_unsigned_file`, P `certificate_table_of_signed_files` | covered |
| SIGNTOOL-2 | A signed file is hashed up to its certificate table with no extra padding, so it has the digest of the unsigned file | observed, not in spec | D `file_signed_by_signtool_has_the_digest_of_the_unsigned_file`, D `files_signed_by_osslsigncode_have_the_digest_of_the_unsigned_file`, D `extra_data_range_follows_the_sum_of_bytes_hashed` | covered |

## Robustness

| ID | Requirement | Source | Tests | Status |
|---|---|---|---|---|
| ROBUST-1 | Never panic or index out of bounds on hostile input | project rule | D `random_corruption_never_panics`, D `every_truncation_inside_the_headers_or_sections_is_an_error` | covered |
| ROBUST-2 | Malformed input is reported as an `Error` (truncation at any byte, bad signatures, sections or certificate table outside the file, missing directory) | project rule | D `every_truncation_inside_the_headers_or_sections_is_an_error`, D `bad_signatures_and_magic_are_reported`, D `section_beyond_the_end_of_the_file_is_an_error`, D `certificate_table_outside_the_file_is_an_error`, D `fewer_than_five_data_directories_is_an_error`, C `checksum_of_malformed_file_is_an_error` | covered |
| ROBUST-3 | Never allocate or loop from header values: bounds of every section are checked before the table is sized; the table is bounded by the file (sum of section sizes <= file size, `SectionAlignment` <= 1 MiB, page >= headers). osslsigncode had a bug of that kind | project rule | PH `section_bounds_outside_the_file_are_an_error`, PH `table_size_is_bounded_by_the_file`, PH `hostile_alignment_and_overlapping_sections_are_an_error` | covered |

## Page hashes (observed on osslsigncode, not in the specification)

The Authenticode document only names the page hash attribute (`SpcPeImageData`); the table
layout below was determined from the tables osslsigncode embeds when signing with `-ph`
(built from the local checkout, `tests/data/page_hashes.sh`), 17 fixtures x SHA-1 and
SHA-256. Data: `tests/data/page_hashes.txt`. Tests: `pe_page_hashes.rs` (PH). **Not verified
against real SignTool**, so the behaviours marked "quirk" (OSSL-PH-5) may differ from SignTool.

| ID | Requirement | Source | Tests | Status |
|---|---|---|---|---|
| OSSL-PH-1 | The table is a sequence of entries (u32 LE file offset, digest): 24 bytes for SHA-1, 36 for SHA-256 (4 + digest length for any algorithm); last entry: offset of the end of the last section, zero digest | osslsigncode `-ph` | PH `page_hash_tables_match_osslsigncode`, PH `entry_size_follows_the_algorithm` | covered (SHA-384/512 not produced by the oracle: the attribute OIDs exist only for SHA-1 and SHA-256) |
| OSSL-PH-2 | Page size = `SectionAlignment` (0x200, 0x300, 0x1000, 0x2000 observed; not necessarily a power of two) | osslsigncode `-ph` | PH `page_hash_tables_match_osslsigncode` (`ph_pe32_align200`, `ph_pe32_align300`, `ph_pe64_align2000`) | covered |
| OSSL-PH-3 | First page = the headers (`SizeOfHeaders` bytes at file offset 0) without the CheckSum field and the Certificate Table entry (cut out, not zeroed), then zeros up to `SectionAlignment - SizeOfHeaders` bytes, i.e. the page is hashed as a zero-padded page with the excluded fields removed | osslsigncode `-ph` | PH `page_hash_tables_match_osslsigncode` (all, incl. `tiny32`, `tiny64`: 0x400 headers in a 0x1000 page) | covered |
| OSSL-PH-4 | Each section with raw data starts on a new page, at its `PointerToRawData`, and is cut every page size; the last page of a section is hashed zero-padded to the page size; its table offset is the file offset of the page start | osslsigncode `-ph` | PH `page_hash_tables_match_osslsigncode` (`ph_pe32_multi`, `ph_pe64_multi`, `ph_pe64_align2000`, `ph_pe32_align300`) | covered |
| OSSL-PH-5 | Sections are processed in section table order, **not** sorted by file offset (quirk: with raw data in reverse order the pages are not in ascending offset order and the last entry holds the end of the last section of the table). Sections with `SizeOfRawData` = 0 are skipped (also a last one with `PointerToRawData` = 0); the last entry's offset is the end of the last section that has raw data, 0 when none has | osslsigncode `-ph` | PH `page_hash_tables_match_osslsigncode` (`ph_pe32_reversed`, `ph_pe64_empty_*`, `ph_pe64_bss_last`, `ph_pe32_all_empty`) | covered |
| OSSL-PH-6 | Data not in a section (overlay, certificate table) is not covered | osslsigncode `-ph` | PH `page_hash_tables_match_osslsigncode` (`ph_pe64_overlay`, `pe32_extra_3`) | covered |
| OSSL-PH-7 | SHA-1 and SHA-256 tables of PE32 and PE32+ files | osslsigncode `-ph -h sha1|sha256` | PH `page_hash_tables_match_osslsigncode` | covered |
| OSSL-PH-8 | A signed input file: page hashes of a file that already carries a certificate table | not observed | none | not covered: osslsigncode signs a clean file; by construction the certificate table is outside every section |
| OSSL-PH-9 | The oracle refuses `SectionAlignment` = 0 ("Corrupted page size"), `SizeOfHeaders` > `SectionAlignment` ("Page size is smaller than header size") and a file with no section; we return `InvalidPageSize` / `NoSections` | osslsigncode `-ph` | PH `files_that_osslsigncode_refuses_are_an_error` | covered |

## Single pass (project requirements)

| ID | Requirement | Source | Tests | Status |
|---|---|---|---|---|
| PAR-1 | `pe::digests` gives, byte for byte, the results of `authenticode_digest` and `page_hashes` (multi-page, empty and reversed sections, real images, 1.2 MiB with 300 pages split between threads) | project rule; the sequential functions are checked against the oracles | `pe_digests.rs` `single_pass_equals_the_sequential_functions*` | covered |
| PAR-2 | File digests come back in the order of the requested algorithms (SHA-1 + SHA-256 dual signing, all four) | project rule | `pe_digests.rs` `single_pass_equals_the_sequential_functions` | covered |
| PAR-3 | File digests and page hashes are both optional | project rule | `pe_digests.rs` `page_hashes_and_file_digests_are_optional` | covered |
| PAR-4 | Same errors as the sequential functions (page hash errors only when page hashes are requested) | project rule | `pe_digests.rs` `errors_are_reported_like_the_sequential_functions` | covered |

## Hash backend

| ID | Requirement | Source | Tests | Status |
|---|---|---|---|---|
| HASH-1 | SHA-1, SHA-256, SHA-384 and SHA-512 give the NIST FIPS 180-4 values ("abc", empty message, 448-bit message) whatever the backend (`aws-lc` or `pure-rust`) | NIST FIPS 180-4 examples, `openssl dgst` | `hash.rs` `nist_fips_180_vectors` | covered |
| HASH-2 | A hasher is `Send` (can move to a worker thread) | project rule | `hash.rs` `hasher_is_send` | covered |

## Authenticode structures (`spc.rs`)

Sources: Microsoft Authenticode PE specification and the `SPC_*` definitions (`wintrust.h`, as laid out in osslsigncode's ASN.1 templates). The encodings of SPC-1..5 are compared byte for byte with those embedded in `tiny64.signed.efi` (SignTool) and `pe32_extra_3.signed.exe` (osslsigncode); the PKCS#7 was parsed with `openssl asn1parse`.

| ID | Requirement | Source | Tests | Status |
|---|---|---|---|---|
| SPC-1 | `SpcPeImageData`: flags `BIT STRING` (none = `03 01 00`, `includeResources` = `03 02 07 80`) and `file` = `<<<Obsolete>>>` link (`[0] { [2] { [0] BMPString } }`) | Authenticode PE, real signatures | `spc.rs` `pe_image_data_matches_real_signatures` | covered |
| SPC-2 | `SpcIndirectDataContent` (1.3.6.1.4.1.311.2.1.15 + image data, `DigestInfo`) equals the one in real signatures for the same digest | Authenticode PE, real signatures | `spc.rs` `indirect_data_content_matches_real_signatures` | covered |
| SPC-3 | Digest algorithm identifiers SHA-1/256/384/512 with NULL parameters | RFC 3279 / RFC 8017 OIDs | `spc.rs` `indirect_data_content_algorithm_identifiers` | covered |
| SPC-4 | A digest of the wrong length is refused | project rule | `spc.rs` `indirect_data_content_checks_the_digest_length` | covered |
| SPC-5 | `SPC_STATEMENT_TYPE` attribute: individual (...2.1.21), commercial (...2.1.22) | real signature (individual), spec (commercial) | `spc.rs` `statement_type_attribute_matches_osslsigncode` | covered |
| SPC-6 | `SpcSpOpusInfo` (`-n` BMPString `[0]`, `-i` IA5String link `[1]`, both optional) and its attribute (...2.1.12). **Not compared with a real file** (none of the files in `tests/data` has one) | osslsigncode templates | `spc.rs` `opus_info_layout` | covered |
| SPC-7 | UTF-16BE program name; long length form | X.690 | `spc.rs` `opus_info_encodings` | covered |
| SPC-8 | Characters outside the BMP and non-ASCII URLs are refused | project rule | `spc.rs` `opus_info_rejects_unencodable_text` | covered |
| SPC-9 | `SpcPeImageData` with SHA-1 page hashes: moniker `SpcSerializedObject` (class id A6B586D5-...), `SET { SEQUENCE { 1.3.6.1.4.1.311.2.3.1, SET { OCTET STRING } } }`. **Not compared with a real file** (none has page hashes) | osslsigncode templates | `spc.rs` `pe_image_data_with_sha1_page_hashes_layout` | covered |
| SPC-10 | SHA-256 page hashes use 1.3.6.1.4.1.311.2.3.2 | osslsigncode templates | `spc.rs` `pe_image_data_with_sha256_page_hashes_uses_v2` | covered |
| SPC-11 | Page hashes only for SHA-1/SHA-256, table of whole entries | project rule | `spc.rs` `page_hash_arguments_are_checked` | covered |

## CMS `SignedData` (`cms.rs`)

Sources: RFC 5652 and the Authenticode PE specification. The signatures are checked in Rust (CMS-4) and with `openssl smime -verify -noverify` (the PKCS#7 API, which accepts the Authenticode content that is not an `OCTET STRING`); the OpenSSL checks run only when the installed OpenSSL verifies the signature of SignTool (the control). That needs OpenSSL 3.5: 3.0, 3.1 and 3.3 refuse SignTool's own signature. The `openssl` job of the CI installs a recent one with Homebrew and makes the checks mandatory (`RSIGNCODE_REQUIRE_OPENSSL`). **Not compared byte for byte with a real signature**: the signatures change with the key.

| ID | Requirement | Source | Tests | Status |
|---|---|---|---|---|
| CMS-1 | The `SignedData` (content type, `messageDigest` of the content without tag and length, signed attributes as `[0]`, certificates, `SignerInfo`) verifies with OpenSSL for RSA 2048, ECDSA P-256 and P-384, with SHA-1, SHA-256, SHA-384 and SHA-512 | RFC 5652, Authenticode PE | `cms.rs` `signatures_verify_with_openssl` | covered |
| CMS-2 | A changed signature does not verify | project rule | `cms.rs` `a_modified_signature_does_not_verify` | covered |
| CMS-3 | No certificate, an invalid certificate, an unsupported key or an indirect data that is not a `SEQUENCE` are errors | project rule | `cms.rs` `bad_input_is_an_error` | covered |
| CMS-4 | Without OpenSSL: the signature value of every key type and digest algorithm verifies, with the RSA and ECDSA crates, against the hash of the signed attributes as a `SET` | RFC 5652 5.4, RFC 8017, RFC 5753 | `cms.rs` `signatures_verify_in_rust` | covered |
| SIGNTOOL-CMS-1 | Given the `SpcIndirectDataContent` that SignTool signed, the `SignedData` equals SignTool's apart from certificate, signer identifier and signature value: version, digest algorithms, encapsulated content, signed attributes (empty `SpcSpOpusInfo`, content type, individual statement type, message digest; DER order; no signing time), `rsaEncryption` signature algorithm, signature length. SignTool 4.00, SHA-1/256/384/512 | real SignTool output (`signtool_<alg>.p7`) | `cms.rs` `signed_data_matches_signtool` | covered |
| SIGNTOOL-CMS-2 | The Windows cryptographic API (`SignedCms.CheckSignature`) accepts the signatures of rsigncode for RSA 2048, P-256 and P-384 with SHA-1/256/384/512, accepts SignTool's own (control) and refuses a changed one. Runs in the `signtool-oracle` workflow only | Windows CryptoAPI | `ci/verify_cms.ps1`, `examples/cms.rs` | covered (CI) |

## Summary

| | covered | not covered | out of scope |
|---|---|---|---|
| AUTH-PE-1..15 | 15 | 0 | 0 |
| AUTH-PE-14b | 0 | 1 | 0 |
| PECOFF-1..11 | 9 | 1 (PECOFF-10) | 1 (PECOFF-11) |
| SIGNTOOL-1..2 | 2 | 0 | 0 |
| ROBUST-1..3 | 3 | 0 | 0 |
| OSSL-PH-1..9 | 8 | 1 (OSSL-PH-8) | 0 |
| PAR-1..4 | 4 | 0 | 0 |
| HASH-1..2 | 2 | 0 | 0 |
| SPC-1..11 | 11 | 0 | 0 |
| CMS-1..4 | 4 | 0 | 0 |
| SIGNTOOL-CMS-1..2 | 2 | 0 | 0 |
| **Total (64)** | **60** | **3** | **1** |
