//! Hash computation for block-level and file-level checksums.
//!
//! Two modes:
//! - CSUM tree checksums (read from btrfs, already computed by the kernel)
//! - Userspace content hashing (XXH3-128, matching duperemove csum.h:22)

use std::io::Read;

use xxhash_rust::xxh3;

/// Digest size for XXH3-128 (duperemove csum.h:21: DIGEST_LEN = 16).
pub const XXH3_DIGEST_LEN: usize = 16;

/// Compute XXH3-128 hash of a block (duperemove csum.c:43-49).
pub fn hash_block_xxh3(data: &[u8]) -> [u8; XXH3_DIGEST_LEN] {
    let hash = xxh3::xxh3_128(data);
    hash.to_le_bytes()
}

/// Compute a running file-level hash over block hashes.
///
/// This produces a file-level digest by hashing all block digests together,
/// enabling fast (size, file_hash) grouping for whole-file duplicate detection.
/// Matches duperemove's running file checksum (file_scan.c:1060,1130).
pub fn compute_file_hash(block_hashes: &[Vec<u8>]) -> [u8; XXH3_DIGEST_LEN] {
    let mut hasher = xxh3::Xxh3::new();
    for h in block_hashes {
        hasher.update(h);
    }
    hasher.digest128().to_le_bytes()
}

/// Compute file-level hash from block digests by reference (Hickey F20:
/// avoids Vec<Vec<u8>> allocation on the CSUM fast path).
pub fn compute_file_hash_ref(digests: &[&[u8; XXH3_DIGEST_LEN]]) -> [u8; XXH3_DIGEST_LEN] {
    let mut hasher = xxh3::Xxh3::new();
    for h in digests {
        hasher.update(&h[..]);
    }
    hasher.digest128().to_le_bytes()
}

/// Read a file and compute per-block XXH3-128 hashes.
///
/// This is the userspace fallback for files where CSUM tree checksums
/// can't be used (NODATASUM, inline data, cross-compression comparison).
pub fn hash_file_blocks(
    file: &mut std::fs::File,
    block_size: usize,
) -> anyhow::Result<Vec<(u64, [u8; XXH3_DIGEST_LEN])>> {
    let mut buf = vec![0u8; block_size];
    let mut offset = 0u64;
    let mut hashes = Vec::new();

    loop {
        let n = read_full(file, &mut buf)?;
        if n == 0 {
            break;
        }
        let digest = hash_block_xxh3(&buf[..n]);
        hashes.push((offset, digest));
        offset += n as u64;
        if n < buf.len() {
            break;
        }
    }

    Ok(hashes)
}

/// Read into buf, handling partial reads. Returns total bytes read (0 = EOF).
fn read_full(file: &mut std::fs::File, buf: &mut [u8]) -> anyhow::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match file.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_block_deterministic() {
        let data = b"hello world";
        let h1 = hash_block_xxh3(data);
        let h2 = hash_block_xxh3(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_block_different_input() {
        let h1 = hash_block_xxh3(b"hello world");
        let h2 = hash_block_xxh3(b"hello worl!");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_file_hash_matches_for_identical_blocks() {
        let blocks = vec![hash_block_xxh3(b"block1"), hash_block_xxh3(b"block2")];
        let digests: Vec<&[u8; XXH3_DIGEST_LEN]> = blocks.iter().collect();
        let h1 = compute_file_hash_ref(&digests);
        let h2 = compute_file_hash_ref(&digests);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_file_hash_differs_for_different_blocks() {
        let blocks1 = vec![hash_block_xxh3(b"block1"), hash_block_xxh3(b"block2")];
        let blocks2 = vec![hash_block_xxh3(b"block1"), hash_block_xxh3(b"block3")];
        let d1: Vec<&[u8; XXH3_DIGEST_LEN]> = blocks1.iter().collect();
        let d2: Vec<&[u8; XXH3_DIGEST_LEN]> = blocks2.iter().collect();
        let h1 = compute_file_hash_ref(&d1);
        let h2 = compute_file_hash_ref(&d2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_file_blocks_reads_correctly() {
        use std::io::{Seek, Write};
        let data = b"hello world, this is a test file content";
        let mut tmp = tempfile::tempfile().unwrap();
        tmp.write_all(data).unwrap();
        tmp.seek(std::io::SeekFrom::Start(0)).unwrap();
        let hashes = hash_file_blocks(&mut tmp, 16).unwrap();
        // 43 bytes / 16 = 2 full blocks + 1 partial
        assert_eq!(hashes.len(), 3);
        assert_eq!(hashes[0].0, 0);
        assert_eq!(hashes[1].0, 16);
        assert_eq!(hashes[2].0, 32);
    }
}
