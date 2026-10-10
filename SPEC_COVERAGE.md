# Specification coverage

Each requirement has a stable ID. Tests name the IDs they check in a `/// Spec:` doc
comment, so `grep -rn "AUTH-PE-7" crates/` finds them. Scope: the `pe` module (parsing,
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

## Summary

| | covered | not covered | out of scope |
|---|---|---|---|
| AUTH-PE-1..15 | 15 | 0 | 0 |
| AUTH-PE-14b | 0 | 1 | 0 |
| PECOFF-1..11 | 9 | 1 (PECOFF-10) | 1 (PECOFF-11) |
| SIGNTOOL-1..2 | 2 | 0 | 0 |
| ROBUST-1..2 | 2 | 0 | 0 |
| **Total (31)** | **28** | **2** | **1** |
