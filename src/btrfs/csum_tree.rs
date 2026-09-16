//! CSUM tree reading via TREE_SEARCH_V2.
//!
//! Reads per-sector checksums from the btrfs CSUM tree (tree 7).
//! Keyed by logical disk address (BTRFS_EXTENT_CSUM_OBJECTID, BTRFS_EXTENT_CSUM_KEY).
//!
//! Reference: dduper patch inspect-dump-csum.c:91-182 (btrfs_lookup_csums).
//! Reference: btrd definitions.rs:1242-1250 (btrfs_csum_item struct).

use std::os::fd::RawFd;

use anyhow::{Result, bail};

use super::constants;
use super::ioctl::{BtrfsIoctlSearchKey, tree_search_v2};

/// A checksum read from the CSUM tree, with its logical disk offset.
#[derive(Clone, Debug)]
pub struct CsumEntry {
    /// Logical disk offset of the sector this checksum covers.
    pub logical: u64,
    /// The raw checksum bytes (size depends on csum_type: 4/8/32 bytes).
    pub csum: Vec<u8>,
}

/// Read all checksums for a logical extent range [disk_bytenr, disk_bytenr + num_bytes).
///
/// This searches the CSUM tree (tree_id = BTRFS_CSUM_TREE_OBJECTID = 7)
/// for BTRFS_EXTENT_CSUM_KEY items covering the given logical address range.
///
/// Each CSUM tree item is keyed by (BTRFS_EXTENT_CSUM_OBJECTID, BTRFS_EXTENT_CSUM_KEY, logical_bytenr)
/// and contains N consecutive sector checksums packed as raw bytes.
///
/// `sectorsize` is typically 4096. `csum_size` is the per-sector digest size
/// (4 for CRC32C, 8 for XXHASH, 32 for SHA256/BLAKE2).
pub fn read_csums_for_extent(
    fd: RawFd,
    disk_bytenr: u64,
    num_bytes: u64,
    sectorsize: u32,
    csum_size: u16,
    nodesize: u32,
) -> Result<Vec<CsumEntry>> {
    let num_sectors = (num_bytes / sectorsize as u64) as usize;
    let mut result = Vec::with_capacity(num_sectors);
    let mut current_bytenr = disk_bytenr;
    let mut remaining = num_sectors;

    // btrfs merges checksum items across adjacent data extents, so the
    // item covering our position can start earlier — up to one leaf's
    // worth of checksums back. TREE_SEARCH_V2 only searches forward, so
    // widen min_offset by that window and pick the covering item. This
    // mirrors the kernel's btrfs_lookup_csums step-back.
    let csums_per_leaf = (nodesize as u64 / csum_size as u64).max(1);
    let window = csums_per_leaf * sectorsize as u64;

    while remaining > 0 {
        let mut key = BtrfsIoctlSearchKey {
            tree_id: constants::BTRFS_CSUM_TREE_OBJECTID,
            min_objectid: constants::BTRFS_EXTENT_CSUM_OBJECTID,
            max_objectid: constants::BTRFS_EXTENT_CSUM_OBJECTID,
            min_type: constants::BTRFS_EXTENT_CSUM_KEY,
            max_type: constants::BTRFS_EXTENT_CSUM_KEY,
            min_offset: current_bytenr.saturating_sub(window),
            max_offset: u64::MAX,
            min_transid: 0,
            max_transid: u64::MAX,
            nr_items: 0,
            ..Default::default()
        };

        let items = tree_search_v2(fd, &mut key)?;

        if items.is_empty() {
            break;
        }

        // Sectors consumed this pass; a pass that consumes nothing means
        // no item covers current_bytenr — stop instead of looping.
        let mut consumed = 0usize;

        for (header, payload) in &items {
            if header.ty != constants::BTRFS_EXTENT_CSUM_KEY {
                continue;
            }

            // Items are returned in key order; once past our position no
            // later item can cover it.
            let item_start = header.offset;
            if item_start > current_bytenr {
                break;
            }

            // The item starts at header.offset (logical bytenr) and contains
            // (payload.len() / csum_size) consecutive sector checksums.
            let csums_in_item = payload.len() / csum_size as usize;

            // How many sectors into this item is our current position?
            let sector_offset = ((current_bytenr - item_start) / sectorsize as u64) as usize;

            // An earlier item whose csums don't reach current_bytenr.
            if sector_offset >= csums_in_item {
                continue;
            }

            let available = csums_in_item - sector_offset;
            let to_read = remaining.min(available);

            for i in 0..to_read {
                let byte_offset = (sector_offset + i) * csum_size as usize;
                let csum = payload[byte_offset..byte_offset + csum_size as usize].to_vec();
                let logical = item_start + (sector_offset + i) as u64 * sectorsize as u64;
                result.push(CsumEntry { logical, csum });
            }

            remaining -= to_read;
            consumed += to_read;
            current_bytenr += to_read as u64 * sectorsize as u64;
        }

        if consumed == 0 {
            break;
        }
    }

    if result.len() < num_sectors {
        bail!(
            "expected {} csums for extent at bytenr {}, got {}",
            num_sectors,
            disk_bytenr,
            result.len()
        );
    }

    Ok(result)
}

/// Read the file extent items for a given inode in a subvolume tree.
///
/// Returns vec of (file_offset, disk_bytenr, disk_num_bytes, num_bytes, compression, extent_type).
///
/// extent_type: 0=inline, 1=regular, 2=prealloc (btrfs_tree.h via btrd definitions.rs:29-31).
/// compression: 0=none, 1=zlib, 2=lzo, 3=zstd (btrfs_tree.h:1095).
pub fn read_file_extents(fd: RawFd, tree_id: u64, inode: u64) -> Result<Vec<FileExtent>> {
    let mut key = BtrfsIoctlSearchKey {
        tree_id,
        min_objectid: inode,
        max_objectid: inode,
        min_type: constants::BTRFS_EXTENT_DATA_KEY,
        max_type: constants::BTRFS_EXTENT_DATA_KEY,
        min_offset: 0,
        max_offset: u64::MAX,
        min_transid: 0,
        max_transid: u64::MAX,
        nr_items: 0,
        ..Default::default()
    };

    let items = tree_search_v2(fd, &mut key)?;
    let mut extents = Vec::with_capacity(items.len());

    for (header, payload) in &items {
        if header.ty != constants::BTRFS_EXTENT_DATA_KEY {
            continue;
        }

        // btrfs_file_extent_item (btrfs_tree.h:1074-1124):
        //   generation: u64 (8)
        //   ram_bytes: u64 (8)
        //   compression: u8 (1)
        //   encryption: u8 (1)
        //   other_encoding: u16 (2)
        //   type: u8 (1)
        //   --- if type == REG or PREALLOC ---
        //   disk_bytenr: u64 (8)
        //   disk_num_bytes: u64 (8)
        //   offset: u64 (8)
        //   num_bytes: u64 (8)
        let static_header_len = 21;

        if payload.len() < static_header_len {
            bail!("file extent item too short: {} bytes", payload.len());
        }

        let compression = payload[16];
        let extent_type = payload[20];

        if extent_type == constants::BTRFS_FILE_EXTENT_REG
            || extent_type == constants::BTRFS_FILE_EXTENT_INLINE
        {
            if extent_type == constants::BTRFS_FILE_EXTENT_REG
                && payload.len() >= static_header_len + 32
            {
                let disk_bytenr = u64::from_le_bytes(payload[21..29].try_into().unwrap());
                let disk_num_bytes = u64::from_le_bytes(payload[29..37].try_into().unwrap());
                let _offset = u64::from_le_bytes(payload[37..45].try_into().unwrap());
                let num_bytes = u64::from_le_bytes(payload[45..53].try_into().unwrap());

                extents.push(FileExtent {
                    file_offset: header.offset,
                    disk_bytenr,
                    disk_num_bytes,
                    num_bytes,
                    compression,
                    extent_type,
                });
            }
            // Inline extents have no disk_bytenr — skip for CSUM tree reading
        }
    }

    Ok(extents)
}

/// A file extent mapping.
#[derive(Clone, Debug)]
pub struct FileExtent {
    /// Logical offset within the file.
    pub file_offset: u64,
    /// Physical disk address of the extent.
    pub disk_bytenr: u64,
    /// Size on disk (may differ from num_bytes if compressed).
    pub disk_num_bytes: u64,
    /// Size in the file (uncompressed).
    pub num_bytes: u64,
    /// Compression type (0=none, 1=zlib, 2=lzo, 3=zstd).
    pub compression: u8,
    /// Extent type (0=inline, 1=regular, 2=prealloc).
    pub extent_type: u8,
}

impl FileExtent {
    pub fn is_compressed(&self) -> bool {
        self.compression != 0
    }

    pub fn is_regular(&self) -> bool {
        self.extent_type == constants::BTRFS_FILE_EXTENT_REG
    }
}
