//! Deduplication via FIDEDUPERANGE ioctl.
//!
//! The kernel verifies byte-by-byte before sharing (fs.h:310).
//! Requires write access to destination files, NOT CAP_SYS_ADMIN (Hickey F4).
//!
//! Reference: duperemove dedupe.c, btrfs-extent-same.c.

use std::fs::File;
use std::os::fd::AsRawFd;

use anyhow::{Result, bail};
use tracing::{info, warn};

use crate::btrfs::constants;
use crate::btrfs::ioctl::{FileDedupeRangeInfo, fideduperange};

/// Deduplicate a range from src to a single dest file.
///
/// Returns bytes deduped.
pub fn dedupe_range(
    src: &File,
    src_offset: u64,
    length: u64,
    dest: &File,
    dest_offset: u64,
) -> Result<u64> {
    let mut info = FileDedupeRangeInfo {
        dest_fd: dest.as_raw_fd() as i64,
        dest_offset,
        bytes_deduped: 0,
        status: 0,
        _reserved: 0,
    };

    fideduperange(
        src.as_raw_fd(),
        src_offset,
        length,
        std::slice::from_mut(&mut info),
    )?;

    match info.status {
        constants::FILE_DEDUPE_RANGE_SAME => {
            info!(
                "deduped {} bytes at offset {}",
                info.bytes_deduped, src_offset
            );
            Ok(info.bytes_deduped)
        }
        constants::FILE_DEDUPE_RANGE_DIFFERS => {
            warn!("data differs at offset {}, not deduped", src_offset);
            Ok(0)
        }
        status if status < 0 => {
            bail!("dedupe failed at offset {}: error {}", src_offset, status)
        }
        _ => {
            warn!(
                "unexpected dedupe status {} at offset {}",
                info.status, src_offset
            );
            Ok(info.bytes_deduped)
        }
    }
}

/// Deduplicate two whole files.
///
/// Iterates in block_size chunks (duperemove pattern).
pub fn dedupe_files(src_path: &str, dest_path: &str, block_size: usize) -> Result<u64> {
    let src = File::open(src_path)?;
    let dest = File::open(dest_path)?;

    let src_meta = src.metadata()?;
    let dest_meta = dest.metadata()?;

    if src_meta.len() != dest_meta.len() {
        bail!(
            "files have different sizes: {} vs {}",
            src_meta.len(),
            dest_meta.len()
        );
    }

    let total = src_meta.len();
    let mut deduped = 0u64;
    let mut offset = 0u64;

    while offset < total {
        let len = (total - offset).min(block_size as u64);
        match dedupe_range(&src, offset, len, &dest, offset) {
            Ok(bytes) => deduped += bytes,
            Err(e) => warn!("dedupe error at offset {}: {}", offset, e),
        }
        offset += len;
    }

    info!("total bytes deduped: {} / {}", deduped, total);
    Ok(deduped)
}
