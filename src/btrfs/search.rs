//! Btrfs TREE_SEARCH_V2 incremental scanning via min_transid.
//!
//! Reference: bees docs/how-it-works.md:
//!   "Once a filesystem scan has been completed, bees uses the min_transid
//!   parameter of the TREE_SEARCH_V2 ioctl to avoid rescanning old data."
//!
//! This module finds inodes whose file extent items have been modified
//! since a given transaction ID, enabling incremental rescans.

use std::os::fd::RawFd;

use anyhow::Result;

use super::constants;
use super::ioctl::{BtrfsIoctlSearchKey, tree_search_v2};

/// Find all inodes in a subvolume tree that have EXTENT_DATA items
/// with transid > min_transid.
///
/// Returns a set of (inode, transid) pairs for changed files.
pub fn find_changed_inodes(fd: RawFd, tree_id: u64, min_transid: u64) -> Result<Vec<(u64, u64)>> {
    let mut key = BtrfsIoctlSearchKey {
        tree_id,
        min_objectid: 0,
        max_objectid: u64::MAX,
        min_type: constants::BTRFS_EXTENT_DATA_KEY,
        max_type: constants::BTRFS_EXTENT_DATA_KEY,
        min_offset: 0,
        max_offset: u64::MAX,
        min_transid,
        max_transid: u64::MAX,
        nr_items: 0,
        ..Default::default()
    };

    let items = tree_search_v2(fd, &mut key)?;

    let mut inodes = Vec::new();
    let mut last_inode = None;

    for (header, _payload) in &items {
        if header.ty != constants::BTRFS_EXTENT_DATA_KEY {
            continue;
        }
        // Deduplicate consecutive entries for the same inode
        if Some(header.objectid) != last_inode {
            inodes.push((header.objectid, header.transid));
            last_inode = Some(header.objectid);
        }
    }

    Ok(inodes)
}
