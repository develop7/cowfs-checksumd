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
