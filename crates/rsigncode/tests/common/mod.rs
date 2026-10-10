//! Builder of small, valid PE32 / PE32+ files for tests and benchmarks.
//!
//! Also included by `examples/` through `#[path]`, hence the `allow(dead_code)`.
#![allow(dead_code)]

const DOS_SIZE: usize = 0x80; // e_lfanew
const FILE_ALIGNMENT: usize = 0x200;

pub struct PeBuilder {
    pub pe32plus: bool,
    /// Declared raw size of each section (a multiple of 0x200), in section table order.
    pub section_sizes: Vec<usize>,
    /// Place the raw data of the sections in the reverse of table order.
    pub reverse_raw_order: bool,
    /// Bytes after the last section (not covered by any section).
    pub overlay: Vec<u8>,
    /// Value of the CheckSum field.
    pub checksum_field: u32,
    /// Value of the SectionAlignment field.
    pub section_alignment: u32,
}

impl PeBuilder {
    pub fn new(pe32plus: bool) -> Self {
        PeBuilder {
            pe32plus,
            section_sizes: vec![0x200],
            reverse_raw_order: false,
            overlay: Vec::new(),
            checksum_field: 0xDEAD_BEEF,
            section_alignment: 0x1000,
        }
    }

    pub fn alignment(mut self, section_alignment: u32) -> Self {
        self.section_alignment = section_alignment;
        self
    }

    pub fn sections(mut self, sizes: &[usize]) -> Self {
        self.section_sizes = sizes.to_vec();
        self
    }

    pub fn reversed(mut self) -> Self {
        self.reverse_raw_order = true;
        self
    }

    pub fn overlay_len(mut self, n: usize) -> Self {
        self.overlay = pattern(n, 0x0BAD_CAFE);
        self
    }

    fn opt_size(&self) -> usize {
        if self.pe32plus { 240 } else { 224 }
    }

    fn headers_size(&self) -> usize {
        let raw = DOS_SIZE + 4 + 20 + self.opt_size() + 40 * self.section_sizes.len();
        raw.div_ceil(FILE_ALIGNMENT) * FILE_ALIGNMENT
    }

    /// Headers (padded to `SizeOfHeaders`) and the file offset of each section.
    fn layout(&self) -> (Vec<u8>, Vec<usize>) {
        let hsize = self.headers_size();
        let n = self.section_sizes.len();
        let mut offsets = vec![0usize; n];
        let mut pos = hsize;
        let order: Vec<usize> = if self.reverse_raw_order {
            (0..n).rev().collect()
        } else {
            (0..n).collect()
        };
        for i in order {
            offsets[i] = pos;
            pos += self.section_sizes[i];
        }
        let mut h = vec![0u8; hsize];
        h[0..2].copy_from_slice(b"MZ");
        h[0x3c..0x40].copy_from_slice(&(DOS_SIZE as u32).to_le_bytes());
        let mut p = DOS_SIZE;
        h[p..p + 4].copy_from_slice(b"PE\0\0");
        p += 4;
        put16(&mut h, p, if self.pe32plus { 0x8664 } else { 0x014c });
        put16(&mut h, p + 2, n as u16);
        put16(&mut h, p + 16, self.opt_size() as u16);
        put16(&mut h, p + 18, 0x0022);
        p += 20;
        let image_size = 0x1000 + n * 0x1000;
        put16(&mut h, p, if self.pe32plus { 0x20b } else { 0x10b });
        put32(&mut h, p + 16, 0x1000); // AddressOfEntryPoint
        let (img_base, dirs) = if self.pe32plus { (24, 112) } else { (28, 96) };
        if self.pe32plus {
            h[p + img_base..p + img_base + 8].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        } else {
            put32(&mut h, p + img_base, 0x40_0000);
        }
        put32(&mut h, p + 32, self.section_alignment); // SectionAlignment
        put32(&mut h, p + 36, FILE_ALIGNMENT as u32);
        put16(&mut h, p + 48, 6); // MajorSubsystemVersion
        put32(&mut h, p + 56, image_size as u32);
        put32(&mut h, p + 60, hsize as u32);
        put32(&mut h, p + 64, self.checksum_field);
        put16(&mut h, p + 68, 3); // Subsystem
        put32(&mut h, p + dirs - 4, 16); // NumberOfRvaAndSizes
        // Data directories: a few non-zero entries, Certificate Table (index 4) left empty.
        put32(&mut h, p + dirs, 0x1000);
        put32(&mut h, p + dirs + 4, 0x40);
        p += self.opt_size();
        for (i, size) in self.section_sizes.iter().enumerate() {
            let s = p + 40 * i;
            let name = format!(".s{i}");
            h[s..s + name.len()].copy_from_slice(name.as_bytes());
            put32(&mut h, s + 8, *size as u32); // VirtualSize
            put32(&mut h, s + 12, self.section_alignment * (i as u32 + 1));
            put32(&mut h, s + 16, *size as u32);
            put32(&mut h, s + 20, offsets[i] as u32);
            put32(&mut h, s + 36, 0x6000_0020);
        }
        (h, offsets)
    }

    /// Complete file.
    pub fn build(&self) -> Vec<u8> {
        let (mut file, offsets) = self.layout();
        file.resize(
            self.headers_size() + self.section_sizes.iter().sum::<usize>(),
            0,
        );
        for (i, size) in self.section_sizes.iter().enumerate() {
            let d = pattern(*size, 0x1000 + i as u32);
            file[offsets[i]..offsets[i] + size].copy_from_slice(&d);
        }
        file.extend_from_slice(&self.overlay);
        file
    }

    /// Headers only and total file size; the rest is meant to be a sparse hole.
    pub fn build_sparse(&self) -> (Vec<u8>, u64) {
        let (h, _) = self.layout();
        let total = (self.headers_size()
            + self.section_sizes.iter().sum::<usize>()
            + self.overlay.len()) as u64;
        (h, total)
    }
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// Deterministic pseudo-random bytes (xorshift32).
pub fn pattern(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 8) as u8
        })
        .collect()
}

/// Named fixtures shared by the tests and by the oracle script (`examples/fixtures.rs`).
pub fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    let mut v = vec![
        (
            "pe32_aligned",
            PeBuilder::new(false).sections(&[0x400, 0x200]).build(),
        ),
        (
            "pe64_aligned",
            PeBuilder::new(true).sections(&[0x400, 0x200]).build(),
        ),
        (
            "pe32_overlay_1000",
            PeBuilder::new(false).overlay_len(1000).build(),
        ),
        (
            "pe64_overlay_8",
            PeBuilder::new(true)
                .sections(&[0x200, 0x200])
                .overlay_len(8)
                .build(),
        ),
        (
            "pe32_reversed",
            PeBuilder::new(false)
                .sections(&[0x200, 0x400, 0x200])
                .reversed()
                .build(),
        ),
        (
            "pe64_reversed",
            PeBuilder::new(true)
                .sections(&[0x400, 0x200, 0x200])
                .reversed()
                .overlay_len(5)
                .build(),
        ),
    ];
    for extra in 1..8 {
        let name: &'static str = Box::leak(format!("pe32_extra_{extra}").into_boxed_str());
        v.push((name, PeBuilder::new(false).overlay_len(extra).build()));
        let name: &'static str = Box::leak(format!("pe64_extra_{extra}").into_boxed_str());
        v.push((name, PeBuilder::new(true).overlay_len(extra).build()));
    }
    v
}

/// Fixtures for the page hash tests (multi-page sections, other section alignments, large
/// headers, overlay, reversed and empty sections). The oracle data is produced by
/// `tests/data/page_hashes.sh`.
pub fn page_fixtures() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "ph_pe32_multi",
            PeBuilder::new(false).sections(&[0x2400, 0x200]).build(),
        ),
        (
            "ph_pe64_multi",
            PeBuilder::new(true)
                .sections(&[0x1000, 0x1800, 0x200])
                .build(),
        ),
        (
            "ph_pe32_align200",
            PeBuilder::new(false)
                .alignment(0x200)
                .sections(&[0x600, 0x400])
                .build(),
        ),
        (
            "ph_pe64_align2000",
            PeBuilder::new(true)
                .alignment(0x2000)
                .sections(&[0x2400, 0x2000])
                .build(),
        ),
        (
            "ph_pe32_many_sections",
            PeBuilder::new(false).sections(&[0x200; 100]).build(),
        ),
        (
            "ph_pe64_overlay",
            PeBuilder::new(true)
                .sections(&[0x1200])
                .overlay_len(1000)
                .build(),
        ),
        (
            "ph_pe32_reversed",
            PeBuilder::new(false)
                .sections(&[0x1200, 0x400, 0x200])
                .reversed()
                .build(),
        ),
        (
            "ph_pe32_no_sections",
            PeBuilder::new(false).sections(&[]).build(),
        ),
        (
            "ph_pe32_all_empty",
            PeBuilder::new(false).sections(&[0, 0]).build(),
        ),
        (
            "ph_pe32_align0",
            PeBuilder::new(false)
                .alignment(0)
                .sections(&[0x400, 0x200])
                .build(),
        ),
        (
            "ph_pe32_align300",
            PeBuilder::new(false)
                .alignment(0x300)
                .sections(&[0x600, 0x400])
                .build(),
        ),
        (
            "ph_pe32_align200_big_headers",
            PeBuilder::new(false)
                .alignment(0x200)
                .sections(&[0x200; 20])
                .build(),
        ),
        (
            // Last section like a .bss: no raw data and PointerToRawData = 0.
            "ph_pe64_bss_last",
            {
                let mut f = PeBuilder::new(true).sections(&[0x200, 0x400, 0]).build();
                let raw_offset_of_last = DOS_SIZE + 24 + 240 + 40 * 2 + 20;
                f[raw_offset_of_last..raw_offset_of_last + 4].fill(0);
                f
            },
        ),
        (
            "ph_pe64_empty_first",
            PeBuilder::new(true).sections(&[0, 0x200, 0x400]).build(),
        ),
        (
            "ph_pe64_empty_last",
            PeBuilder::new(true).sections(&[0x200, 0x400, 0]).build(),
        ),
        (
            "ph_pe64_empty_section",
            PeBuilder::new(true).sections(&[0x200, 0, 0x1200]).build(),
        ),
    ]
}
