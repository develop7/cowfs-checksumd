//! FIEMAP helpers — thin wrappers over ioctl::fiemap for scanning logic.

use std::os::fd::RawFd;

use anyhow::Result;

use super::constants;
use super::ioctl::{FiemapExtent, fiemap};

/// Get file extents, filtering out inline and unwritten extents
/// (duperemove file_flags.h:5 skip set).
pub fn get_scanable_extents(fd: RawFd) -> Result<Vec<FiemapExtent>> {
    let all = fiemap(fd)?;
    Ok(all
        .into_iter()
        .filter(|e| {
            let skip_flags =
                constants::FIEMAP_EXTENT_DATA_INLINE | constants::FIEMAP_EXTENT_UNWRITTEN;
            (e.fe_flags & skip_flags) == 0
        })
        .collect())
}

/// Count shared bytes in a file range (duperemove fiemap.c:101-135).
pub fn count_shared(fd: RawFd, start: u64, end: u64) -> Result<u64> {
    let extents = fiemap(fd)?;
    let mut shared = 0u64;

    for ext in &extents {
        let ext_end = ext.fe_logical + ext.fe_length;
        let ext_start = ext.fe_logical;

        if start <= ext_end && end >= ext_start {
            if (ext.fe_flags & constants::FIEMAP_EXTENT_DELALLOC) == 0
                && (ext.fe_flags & constants::FIEMAP_EXTENT_SHARED) != 0
            {
                let lo = ext_start.max(start);
                let hi = ext_end.min(end);
                shared += hi.saturating_sub(lo);
            }
        }
    }

    Ok(shared)
}
