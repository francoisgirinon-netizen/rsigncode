use crate::pe::{Error, PeFile};

/// Computes the PE image checksum, as `CheckSumMappedFile` does.
///
/// It is the 16-bit one's complement sum of the file read as little-endian 16-bit words
/// (a trailing odd byte counts as a word), with the CheckSum field treated as zero, plus
/// the length of the file.
pub fn checksum(data: &[u8]) -> Result<u32, Error> {
    let pe = PeFile::parse(data)?;
    let field = pe.checksum_offset;
    let mut sum =
        sum_words(&data[..field], false) + sum_words(&data[field + 4..], (field + 4) % 2 == 1);
    // Fold the carries (one's complement addition).
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    Ok((sum as u32).wrapping_add(data.len() as u32))
}

/// Sum of the 16-bit little-endian words of `bytes`, which starts at an odd file offset
/// when `odd_start` (its first byte is then the high byte of a word).
fn sum_words(bytes: &[u8], odd_start: bool) -> u64 {
    let (head, bytes) = match bytes.split_first() {
        Some((&b, rest)) if odd_start => (u64::from(b) << 8, rest),
        _ => (0, bytes),
    };
    let mut words = bytes.chunks_exact(2);
    let mut sum = head;
    for w in &mut words {
        sum += u64::from(u16::from_le_bytes([w[0], w[1]]));
    }
    if let [last] = words.remainder() {
        sum += u64::from(*last);
    }
    sum
}
