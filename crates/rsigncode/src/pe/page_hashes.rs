use crate::hash::{HashAlgorithm, Hasher};
use crate::pe::{Error, PeFile};
use core::ops::Range;

/// Largest `SectionAlignment` accepted. Every page is hashed as if it had this size
/// (zero-padded), so the cost of a hostile value must stay small. Real images use 4 KiB or
/// 64 KiB.
const MAX_PAGE_SIZE: usize = 1 << 20;

const ZEROS: [u8; 4096] = [0; 4096];

/// One page of the table.
struct Page {
    /// File offset of the page (the first field of its table entry).
    offset: u32,
    /// File bytes of the page (for the header page: all of `SizeOfHeaders`, the excluded
    /// fields are cut out when hashing).
    range: Range<usize>,
    header: bool,
}

/// Raw data of one section, cut into pages.
struct Run {
    range: Range<usize>,
    /// Index (in the table) of the first page of the run.
    first_page: usize,
}

/// Which pages the table has, without materialising them.
pub(crate) struct PagePlan {
    page_size: usize,
    runs: Vec<Run>,
    pages: usize,
    /// File offset of the terminating entry.
    end: u32,
}

impl PagePlan {
    /// Number of pages, the header page included (the terminating entry is not a page).
    pub(crate) fn len(&self) -> usize {
        self.pages
    }

    fn page(&self, pe: &PeFile<'_>, index: usize) -> Page {
        if index == 0 {
            return Page {
                // Validated by `plan`: the headers fit in the file and in a page.
                offset: 0,
                range: 0..pe.size_of_headers,
                header: true,
            };
        }
        let r = self.runs.partition_point(|r| r.first_page <= index) - 1;
        let run = &self.runs[r];
        let start = run.range.start + (index - run.first_page) * self.page_size;
        let end = run.range.end.min(start.saturating_add(self.page_size));
        Page {
            // Validated by `plan`: every run ends below 4 GiB.
            offset: start as u32,
            range: start..end,
            header: false,
        }
    }
}

/// Lays out the pages of the file, after checking everything that can be checked from the
/// headers. Nothing is allocated from header values before the checks: the table is bounded
/// by the size of the file.
pub(crate) fn plan(pe: &PeFile<'_>) -> Result<PagePlan, Error> {
    let page_size = pe.section_alignment as usize;
    if page_size == 0 || page_size > MAX_PAGE_SIZE || pe.size_of_headers > page_size {
        return Err(Error::InvalidPageSize);
    }
    if pe.sections.is_empty() {
        return Err(Error::NoSections);
    }
    let len = pe.data.len();
    let mut total = 0usize;
    // Sections in table order, those without raw data left out.
    let mut valid = Vec::with_capacity(pe.sections.len());
    for s in pe.sections.iter().filter(|s| s.raw_size > 0) {
        let start = s.raw_offset as usize;
        let end = start.saturating_add(s.raw_size as usize);
        total = total.saturating_add(s.raw_size as usize);
        // Overlapping sections would make the table larger than the file.
        if end > len || end > u32::MAX as usize || total > len {
            return Err(Error::SectionOutOfBounds);
        }
        valid.push(start..end);
    }
    let end = valid.last().map_or(0, |r| r.end);
    let mut pages = 1;
    let mut runs = Vec::with_capacity(valid.len());
    for range in valid {
        let count = range.len().div_ceil(page_size);
        runs.push(Run {
            range,
            first_page: pages,
        });
        pages += count;
    }
    Ok(PagePlan {
        page_size,
        runs,
        pages,
        end: end as u32,
    })
}

/// Entries `first..last` of the table (the terminating entry is not included).
pub(crate) fn hash_pages(
    pe: &PeFile<'_>,
    plan: &PagePlan,
    algorithm: HashAlgorithm,
    pages: Range<usize>,
) -> Vec<u8> {
    let entry = 4 + algorithm.output_len();
    let mut out = Vec::with_capacity(pages.len() * entry);
    for index in pages {
        let page = plan.page(pe, index);
        let mut hasher = Hasher::new(algorithm);
        let hashed = if page.header {
            let (ck, ce) = (pe.checksum_offset, pe.certificate_entry_offset);
            for r in [0..ck, ck + 4..ce, ce + 8..page.range.end] {
                hasher.update(&pe.data[r]);
            }
            page.range.end
        } else {
            hasher.update(&pe.data[page.range.clone()]);
            page.range.len()
        };
        // The page is zero-padded to its size. For the header page the excluded fields do
        // not count as hashed bytes, so the padding is the page size minus SizeOfHeaders.
        let mut pad = plan.page_size - hashed;
        while pad > 0 {
            let n = pad.min(ZEROS.len());
            hasher.update(&ZEROS[..n]);
            pad -= n;
        }
        out.extend_from_slice(&page.offset.to_le_bytes());
        out.extend_from_slice(&hasher.finalize());
    }
    out
}

/// The terminating entry: the file offset where the last section ends and a zero digest.
pub(crate) fn terminator(plan: &PagePlan, algorithm: HashAlgorithm) -> Vec<u8> {
    let mut out = plan.end.to_le_bytes().to_vec();
    out.resize(4 + algorithm.output_len(), 0);
    out
}

/// Computes the page hash table of a PE file, the content of the `SpcPeImageData` page
/// hash attribute (`-ph` of osslsigncode, `/ph` of SignTool).
///
/// The table has one entry per page: the file offset (`u32`, little-endian) and the digest
/// of the page. The pages are, in order, the headers (`SizeOfHeaders` bytes without the
/// CheckSum field and the Certificate Table entry) and then the raw data of each section
/// that has some, in section table order, cut every `SectionAlignment` bytes from the start
/// of the section. Each page is hashed as if zero-padded to `SectionAlignment` bytes. A last
/// entry holds the file offset of the end of the last section and a zero digest.
pub fn page_hashes(data: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>, Error> {
    let pe = PeFile::parse(data)?;
    let plan = plan(&pe)?;
    let mut table = hash_pages(&pe, &plan, algorithm, 0..plan.len());
    table.extend_from_slice(&terminator(&plan, algorithm));
    Ok(table)
}
