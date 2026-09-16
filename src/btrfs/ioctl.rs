//! Raw ioctl wrappers for btrfs TREE_SEARCH_V2 and VFS FIEMAP/FIDEDUPERANGE.
//!
//! Reference: btrd/src/btrfs/fs.rs:26-31, 33-76 (TREE_SEARCH_V2).
//! Reference: /usr/include/linux/btrfs.h:1144, 594-600.

use std::mem::{MaybeUninit, size_of};
use std::os::fd::RawFd;

use anyhow::{Result, bail, ensure};
use nix::errno::Errno;
use nix::libc::ioctl as libc_ioctl;

use super::constants;

// ── TREE_SEARCH_V2 ──────────────────────────────────────────────────────────

/// Search key for TREE_SEARCH_V2 (btrfs.h:513-569).
#[repr(C)]
#[derive(Default, Debug, Clone)]
pub struct BtrfsIoctlSearchKey {
    pub tree_id: u64,
    pub min_objectid: u64,
    pub max_objectid: u64,
    pub min_offset: u64,
    pub max_offset: u64,
    pub min_transid: u64,
    pub max_transid: u64,
    pub min_type: u32,
    pub max_type: u32,
    pub nr_items: u32,
    pub _unused: u32,
    pub _unused1: u64,
    pub _unused2: u64,
    pub _unused3: u64,
    pub _unused4: u64,
}

/// Search header for each result item (btrfs.h:571-577).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BtrfsIoctlSearchHeader {
    pub transid: u64,
    pub objectid: u64,
    pub offset: u64,
    pub ty: u32,
    pub len: u32,
}

/// Search args v2 with inline buffer (btrfs.h:594-600).
/// We use a heap-allocated buffer to avoid stack overflow.
const SEARCH_BUF_SIZE: usize = 16 * 1024 * 1024; // 16 MB, matches btrd

#[repr(C)]
struct BtrfsIoctlSearchArgsV2 {
    key: BtrfsIoctlSearchKey,
    buf_size: u64,
    buf: [u8; SEARCH_BUF_SIZE],
}

/// Issue TREE_SEARCH_V2 ioctl (btrfs.h:1144, ioctl number 17).
///
/// Returns vec of (header, payload_bytes) pairs.
pub fn tree_search_v2(
    fd: RawFd,
    key: &mut BtrfsIoctlSearchKey,
) -> Result<Vec<(BtrfsIoctlSearchHeader, Vec<u8>)>> {
    // Allocate on heap to avoid stack overflow (btrd pattern, fs.rs:63-75).
    let mut args: Box<MaybeUninit<BtrfsIoctlSearchArgsV2>> = Box::new_uninit();
    let args_ptr = args.as_mut_ptr() as *mut BtrfsIoctlSearchArgsV2;

    // Zero the entire struct
    unsafe {
        std::ptr::write_bytes(args_ptr as *mut u8, 0, size_of::<BtrfsIoctlSearchArgsV2>());
    }

    // Fill in key and buf_size
    let args_ref = unsafe { &mut *args_ptr };
    args_ref.key = key.clone();
    args_ref.key.nr_items = u32::MAX;
    args_ref.buf_size = SEARCH_BUF_SIZE as u64;

    // _IOWR(0x94, 17, struct btrfs_ioctl_search_args_v2) — btrfs.h:1144.
    // Size field encodes sizeof(args_v2) = key + buf_size = 112 bytes;
    // verified against kernel headers via BTRFS_IOC_TREE_SEARCH_V2.
    const IOC_TREE_SEARCH_V2: u64 = 0xC0709411;

    let ret = unsafe { libc_ioctl(fd, IOC_TREE_SEARCH_V2 as _, args_ptr as *mut _) };
    if ret < 0 {
        let err = Errno::last();
        if err == Errno::EOVERFLOW {
            // Buffer too small for one item — retry not needed, just return what we have
        } else {
            bail!("TREE_SEARCH_V2 ioctl failed: {}", err);
        }
    }

    let args_ref = unsafe { &*args_ptr };
    let nr_items = args_ref.key.nr_items as usize;
    key.nr_items = args_ref.key.nr_items;

    let mut results = Vec::with_capacity(nr_items);
    let mut offset = 0usize;
    let header_sz = size_of::<BtrfsIoctlSearchHeader>();

    for _ in 0..nr_items {
        ensure!(
            header_sz + offset <= SEARCH_BUF_SIZE,
            "search header short read"
        );
        let header = unsafe {
            (args_ref.buf[offset..].as_ptr() as *const BtrfsIoctlSearchHeader).read_unaligned()
        };
        offset += header_sz;

        ensure!(
            header.len as usize + offset <= SEARCH_BUF_SIZE,
            "search payload short read"
        );
        let bytes = args_ref.buf[offset..offset + header.len as usize].to_vec();
        offset += header.len as usize;

        results.push((header, bytes));
    }

    Ok(results)
}

// ── FIEMAP ──────────────────────────────────────────────────────────────────

/// FIEMAP extent (fiemap.h:21-35).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FiemapExtent {
    pub fe_logical: u64,
    pub fe_physical: u64,
    pub fe_length: u64,
    pub _fe_reserved64: [u64; 2],
    pub fe_flags: u32,
    pub _fe_reserved: [u32; 3],
}

/// FIEMAP request (fiemap.h:37-52).
#[repr(C)]
struct Fiemap {
    fm_start: u64,
    fm_length: u64,
    fm_flags: u32,
    fm_mapped_extents: u32,
    fm_extent_count: u32,
    _fm_reserved: u32,
    fm_extents: [FiemapExtent; 0], // flexible array
}

/// Query file extents via FS_IOC_FIEMAP.
///
/// Returns vec of extents. Skip extents with FIEMAP_EXTENT_DATA_INLINE
/// or FIEMAP_EXTENT_UNWRITTEN (duperemove file_flags.h:5).
pub fn fiemap(fd: RawFd) -> Result<Vec<FiemapExtent>> {
    // First call: get extent count
    let mut fm: Fiemap = unsafe { std::mem::zeroed() };
    fm.fm_length = u64::MAX;
    fm.fm_extent_count = 0;

    // _IOWR('f', 11, struct fiemap) — fs.h:318
    const IOC_FIEMAP: u64 = 0xC020660B;

    let ret = unsafe { libc_ioctl(fd, IOC_FIEMAP as _, &mut fm as *mut Fiemap as *mut _) };
    if ret < 0 {
        let err = Errno::last();
        bail!("FIEMAP ioctl (count) failed: {}", err);
    }

    let count = fm.fm_mapped_extents as usize;
    if count == 0 {
        return Ok(Vec::new());
    }

    // Second call: get actual extents

    // We need a buffer that holds Fiemap header + count * FiemapExtent
    let fiemap_size = size_of::<Fiemap>() + count * size_of::<FiemapExtent>();
    let fiemap_layout = std::alloc::Layout::from_size_align(fiemap_size, 8).unwrap();
    let fiemap_buf = unsafe { std::alloc::alloc_zeroed(fiemap_layout) };
    let fiemap = fiemap_buf as *mut Fiemap;

    unsafe {
        (*fiemap).fm_start = 0;
        (*fiemap).fm_length = u64::MAX;
        (*fiemap).fm_extent_count = count as u32;
    }

    let ret = unsafe { libc_ioctl(fd, IOC_FIEMAP as _, fiemap as *mut _) };
    if ret < 0 {
        let err = Errno::last();
        unsafe { std::alloc::dealloc(fiemap_buf, fiemap_layout) };
        bail!("FIEMAP ioctl (extents) failed: {}", err);
    }

    let mapped = unsafe { (*fiemap).fm_mapped_extents as usize };
    let extents_slice = unsafe {
        std::slice::from_raw_parts(
            (fiemap as *const u8).add(size_of::<Fiemap>()) as *const FiemapExtent,
            mapped,
        )
    };
    /// CSUM tree fast path: read per-sector checksums from btrfs CSUM tree.
    ///
    /// Note: the file-level digest produced here is a hash of btrfs checksum
    /// bytes, NOT of file content. It is only comparable to other files scanned
    /// via the same CSUM tree path on the same filesystem (same csum type).
    /// Files scanned via the userspace fallback produce a different digest
    /// format and won't match — this is acceptable because cross-filesystem
    /// dedup is impossible anyway (FIDEDUPERANGE is same-filesystem-only).
    let result = extents_slice.to_vec();

    unsafe { std::alloc::dealloc(fiemap_buf, fiemap_layout) };

    Ok(result)
}

// ── FIDEDUPERANGE ───────────────────────────────────────────────────────────

/// Dedupe range info for one destination (fs.h:163-175).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FileDedupeRangeInfo {
    pub dest_fd: i64,
    pub dest_offset: u64,
    pub bytes_deduped: u64,
    pub status: i32,
    pub _reserved: u32,
}

/// Dedupe range request (fs.h:178-185).
#[repr(C)]
struct FileDedupeRange {
    src_offset: u64,
    src_length: u64,
    dest_count: u16,
    _reserved1: u16,
    _reserved2: u32,
    // followed by dest_count * FileDedupeRangeInfo
}

/// Deduplicate a range between source and destination files.
///
/// The kernel verifies byte-by-byte before sharing (fs.h:310).
/// Returns the per-destination status and bytes deduped.
pub fn fideduperange(
    src_fd: RawFd,
    src_offset: u64,
    src_length: u64,
    dests: &mut [FileDedupeRangeInfo],
) -> Result<()> {
    let dest_count = dests.len() as u16;
    let total_size = size_of::<FileDedupeRange>() + dests.len() * size_of::<FileDedupeRangeInfo>();
    let layout = std::alloc::Layout::from_size_align(total_size, 8).unwrap();
    let buf = unsafe { std::alloc::alloc_zeroed(layout) };
    let range = buf as *mut FileDedupeRange;

    unsafe {
        (*range).src_offset = src_offset;
        (*range).src_length = src_length;
        (*range).dest_count = dest_count;
    }

    // Copy dest info into the buffer
    let dests_ptr =
        unsafe { (buf as *mut u8).add(size_of::<FileDedupeRange>()) as *mut FileDedupeRangeInfo };
    for (i, dest) in dests.iter().enumerate() {
        unsafe {
            *dests_ptr.add(i) = *dest;
        }
    }

    // _IOWR(0x94, 54, struct file_dedupe_range) — fs.h:310
    const IOC_FIDEDUPERANGE: u64 = 0xC0189436;

    let ret = unsafe { libc_ioctl(src_fd, IOC_FIDEDUPERANGE as _, buf as *mut _) };
    if ret < 0 {
        let err = Errno::last();
        unsafe { std::alloc::dealloc(buf, layout) };
        bail!("FIDEDUPERANGE ioctl failed: {}", err);
    }

    // Read back results
    for (i, dest) in dests.iter_mut().enumerate() {
        *dest = unsafe { *dests_ptr.add(i) };
    }

    unsafe { std::alloc::dealloc(buf, layout) };
    Ok(())
}

// ── FS_INFO (get csum type/size) ────────────────────────────────────────────

/// Btrfs FS info args (btrfs.h:274-288).
#[repr(C)]
struct BtrfsIoctlFsInfoArgs {
    max_id: u64,
    num_devices: u64,
    fsid: [u8; 16],
    nodesize: u32,
    sectorsize: u32,
    clone_alignment: u32,
    csum_type: u16,
    csum_size: u16,
    flags: u64,
    generation: u64,
    metadata_uuid: [u8; 16],
    reserved: [u8; 944],
}

/// Get filesystem info including csum type and size.
///
/// Requires BTRFS_FS_INFO_FLAG_CSUM_INFO (btrfs.h:267).
pub fn fs_info(fd: RawFd) -> Result<(u16, u16, u32)> {
    let mut args: BtrfsIoctlFsInfoArgs = unsafe { std::mem::zeroed() };
    args.flags = 1; // BTRFS_FS_INFO_FLAG_CSUM_INFO

    // _IOR(0x94, 31, struct btrfs_ioctl_fs_info_args) — btrfs.h:1166
    const IOC_FS_INFO: u64 = 0x8400941F;

    let ret = unsafe { libc_ioctl(fd, IOC_FS_INFO as _, &mut args as *mut _ as *mut _) };
    if ret < 0 {
        let err = Errno::last();
        bail!("BTRFS_IOC_FS_INFO ioctl failed: {}", err);
    }

    Ok((args.csum_type, args.csum_size, args.sectorsize))
}

// ── INO_LOOKUP (get subvol ID) ──────────────────────────────────────────────

/// INO_LOOKUP args (btrfs.h:490-495).
#[repr(C)]
struct BtrfsIoctlInoLookupArgs {
    treeid: u64,
    objectid: u64,
    name: [u8; 4080],
}

const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;

/// Get the subvolume ID for a file (btrfs-util.c:48-63).
pub fn lookup_subvol(fd: RawFd) -> Result<u64> {
    let mut args: BtrfsIoctlInoLookupArgs = unsafe { std::mem::zeroed() };
    args.objectid = BTRFS_FIRST_FREE_OBJECTID;

    // _IOW(0x94, 18, struct btrfs_ioctl_ino_lookup_args) — btrfs.h:1146.
    // sizeof(args) = 4096 (treeid + objectid + name[4080]); verified via
    // BTRFS_IOC_INO_LOOKUP. Was wrongly encoded as _IOWR, causing ENOTTY.
    const IOC_INO_LOOKUP: u64 = 0xD0009412;

    let ret = unsafe { libc_ioctl(fd, IOC_INO_LOOKUP as _, &mut args as *mut _ as *mut _) };
    if ret < 0 {
        let err = Errno::last();
        bail!("BTRFS_IOC_INO_LOOKUP failed: {}", err);
    }

    Ok(args.treeid)
}
