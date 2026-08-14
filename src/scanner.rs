//! File scanner — walks the filesystem, reads CSUM tree checksums (fast path)
//! or computes userspace hashes (fallback), stores results in SQLite.
//!
//! Two-tier strategy:
//! 1. CSUM tree fast path: for regular, non-compressed, non-NODATASUM extents.
//!    Reads per-sector checksums directly from btrfs CSUM tree via TREE_SEARCH_V2.
//!    40x faster than reading file data (dduper benchmark).
//! 2. Userspace fallback: for NODATASUM files, inline data, or compressed
//!    extents where cross-compression comparison is needed. Reads file data
//!    and computes XXH3-128 hashes.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tracing::{debug, info, warn};

use crate::btrfs::constants;
use crate::btrfs::csum_tree::{FileExtent, read_csums_for_extent, read_file_extents};
use crate::btrfs::fiemap;
use crate::btrfs::ioctl;
use crate::db::{BlockRecord, Db, FileRecord};
use crate::hasher;

/// Block size for hashing (duperemove default: 128K).
const DEFAULT_BLOCK_SIZE: usize = 128 * 1024;

/// File flag: inline data (can't use CSUM tree).
const FILE_INLINED: u32 = 1;

/// Scanner configuration.
pub struct ScannerConfig {
    pub block_size: usize,
    pub sectorsize: u32,
    pub csum_type: u16,
    pub csum_size: u16,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            sectorsize: 4096,
            csum_type: constants::csum_type::CRC32,
            csum_size: 4,
        }
    }
}

/// Scan a single file: read extents, fetch CSUMs, store in DB.
///
/// Returns the file-level digest.
pub fn scan_file(path: &Path, db: &Db, config: &ScannerConfig, scan_epoch: u64) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Ok(());
    }
    let size = metadata.len();
    if size == 0 {
        debug!("skipping empty file: {}", path.display());
        return Ok(());
    }

    let ino = metadata.ino();
    let mtime = metadata.mtime_nsec();

    // Get subvol ID for btrfs (btrfs-util.c:48-63)
    let subvol = {
        let f = File::open(path)?;
        match ioctl::lookup_subvol(f.as_raw_fd()) {
            Ok(subvol) => subvol,
            Err(_) => 0, // non-btrfs, no subvol
        }
    };

    // Check if we can skip (mtime + size unchanged)
    if let Some(existing) = db.get_file(ino, subvol)? {
        if existing.mtime == mtime && existing.size == size {
            debug!("skipping unchanged file: {}", path.display());
            return Ok(());
        }
        // File changed — remove old hashes
        if let Ok(fileid) = db.upsert_file(&FileRecord {
            ino,
            subvol,
            filename: path.to_string_lossy().into(),
            size,
            mtime,
            digest: None,
            scan_epoch,
            flags: 0,
        }) {
            let _ = db.remove_file_hashes(fileid);
        }
    }

    let file = File::open(path).context("opening file for scan")?;
    let fd = file.as_raw_fd();

    // Try CSUM tree fast path, fall back to userspace hashing on any error
    // (FIEMAP not supported, NODATASUM, inline data, non-btrfs, etc.)
    let (block_hashes, file_digest, flags) = match scan_csum_tree(fd, subvol, ino, config) {
        Ok((hashes, digest)) => (hashes, digest, 0u32),
        Err(e) => {
            debug!(
                "CSUM tree path failed ({}), using userspace hashing: {}",
                e,
                path.display()
            );
            scan_userspace(path, config)?
        }
    };

    // Store file record
    let fileid = db.upsert_file(&FileRecord {
        ino,
        subvol,
        filename: path.to_string_lossy().into(),
        size,
        mtime,
        digest: Some(file_digest.to_vec()),
        scan_epoch,
        flags,
    })?;

    // Store block hashes
    let block_records: Vec<BlockRecord> = block_hashes
        .iter()
        .map(|(offset, digest)| BlockRecord {
            digest: digest.to_vec(),
            fileid,
            loff: *offset,
        })
        .collect();

    if !block_records.is_empty() {
        db.store_block_hashes(fileid, &block_records)?;
    }

    debug!(
        "scanned {}: {} blocks, {} bytes",
        path.display(),
        block_hashes.len(),
        size
    );
    Ok(())
}

/// CSUM tree fast path: read per-sector checksums from btrfs CSUM tree.
///
/// Returns (block_hashes, file_digest).
/// block_hashes: (offset, 16-byte XXH3-128 digest computed over sector checksums in block).
fn scan_csum_tree(
    fd: std::os::fd::RawFd,
    subvol: u64,
    ino: u64,
    config: &ScannerConfig,
) -> Result<(
    Vec<(u64, [u8; hasher::XXH3_DIGEST_LEN])>,
    [u8; hasher::XXH3_DIGEST_LEN],
)> {
    // Read file extent items from the subvolume tree
    let extents = read_file_extents(fd, subvol, ino)?;

    if extents.is_empty() {
        bail!("no file extents found");
    }

    let mut block_hashes: Vec<(u64, [u8; hasher::XXH3_DIGEST_LEN])> = Vec::new();
    let mut all_csums: Vec<u8> = Vec::new();

    for ext in &extents {
        if !ext.is_regular() {
            bail!("non-regular extent type {}", ext.extent_type);
        }

        // Read CSUM tree entries for this extent
        let csums = read_csums_for_extent(
            fd,
            ext.disk_bytenr,
            ext.disk_num_bytes,
            config.sectorsize,
            config.csum_size,
        )?;

        // Collect raw csum bytes for block-level hashing
        for csum in &csums {
            all_csums.extend_from_slice(&csum.csum);
        }

        // Group sector checksums into blocks
        let sectors_per_block = config.block_size / config.sectorsize as usize;
        let csum_size = config.csum_size as usize;

        for (i, chunk) in csums.chunks(sectors_per_block).enumerate() {
            let mut block_csum_data = Vec::with_capacity(chunk.len() * csum_size);
            for c in chunk {
                block_csum_data.extend_from_slice(&c.csum);
            }
            let block_offset = ext.file_offset + (i as u64 * config.block_size as u64);
            let block_digest = hasher::hash_block_xxh3(&block_csum_data);
            block_hashes.push((block_offset, block_digest));
        }
    }

    // Compute file-level hash from all block hashes
    let block_digest_vec: Vec<Vec<u8>> = block_hashes.iter().map(|(_, d)| d.to_vec()).collect();
    let file_digest = hasher::compute_file_hash(&block_digest_vec);

    Ok((block_hashes, file_digest))
}

/// Userspace fallback: read file data and compute XXH3-128 hashes.
///
/// Returns (block_hashes, file_digest, flags).
fn scan_userspace(
    path: &Path,
    config: &ScannerConfig,
) -> Result<(
    Vec<(u64, [u8; hasher::XXH3_DIGEST_LEN])>,
    [u8; hasher::XXH3_DIGEST_LEN],
    u32,
)> {
    let mut file = File::open(path)?;
    let block_hashes = hasher::hash_file_blocks(&mut file, config.block_size)?;

    let block_digest_vec: Vec<Vec<u8>> = block_hashes.iter().map(|(_, d)| d.to_vec()).collect();
    let file_digest = hasher::compute_file_hash(&block_digest_vec);

    let flags = if block_hashes.is_empty() {
        FILE_INLINED
    } else {
        0
    };

    Ok((block_hashes, file_digest, flags))
}

/// Walk a directory tree and scan all files.
pub fn scan_directory(
    root: &Path,
    db: &Db,
    config: &ScannerConfig,
    scan_epoch: u64,
) -> Result<usize> {
    let mut count = 0;
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        match scan_file(path, db, config, scan_epoch) {
            Ok(()) => count += 1,
            Err(e) => warn!("failed to scan {}: {}", path.display(), e),
        }
    }
    info!("scanned {} files", count);
    Ok(count)
}
