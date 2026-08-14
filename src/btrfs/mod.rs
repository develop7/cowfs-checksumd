pub mod csum_tree;
pub mod ioctl;

/// Btrfs on-disk constants (from /usr/include/linux/btrfs_tree.h).
/// Verified against kernel headers on disk.
pub mod constants {
    /// CSUM tree object ID (btrfs_tree.h:58).
    pub const BTRFS_CSUM_TREE_OBJECTID: u64 = 7;

    /// EXTENT_CSUM object ID (btrfs_tree.h:100).
    pub const BTRFS_EXTENT_CSUM_OBJECTID: u64 = 0u64.wrapping_sub(10);

    /// EXTENT_CSUM key type (btrfs_tree.h:188).
    pub const BTRFS_EXTENT_CSUM_KEY: u32 = 128;

    /// EXTENT_DATA key type (btrfs_tree.h:182).
    pub const BTRFS_EXTENT_DATA_KEY: u32 = 108;

    /// ROOT_ITEM key type (btrfs_tree.h:194).
    pub const BTRFS_ROOT_ITEM_KEY: u32 = 132;

    /// File extent type: regular (btrfs_tree.h via btrd definitions.rs:30).
    pub const BTRFS_FILE_EXTENT_REG: u8 = 1;

    /// File extent type: inline (btrfs_tree.h via btrd definitions.rs:29).
    pub const BTRFS_FILE_EXTENT_INLINE: u8 = 0;

    /// Max csum size (btrfs_tree.h:379).
    pub const BTRFS_CSUM_SIZE: usize = 32;

    /// CSUM types (btrfs_tree.h:382-386).
    pub mod csum_type {
        pub const CRC32: u16 = 0;
        pub const XXHASH: u16 = 1;
        pub const SHA256: u16 = 2;
        pub const BLAKE2: u16 = 3;
    }

    /// FIEMAP_EXTENT_SHARED flag (fiemap.h:Shared).
    pub const FIEMAP_EXTENT_SHARED: u32 = 0x00002000;

    /// FIEMAP_EXTENT_DATA_INLINE flag (fiemap.h:72).
    pub const FIEMAP_EXTENT_DATA_INLINE: u32 = 0x00000200;

    /// FIEMAP_EXTENT_UNWRITTEN flag (fiemap.h:81).
    pub const FIEMAP_EXTENT_UNWRITTEN: u32 = 0x00000800;

    /// FIEMAP_EXTENT_LAST flag (fiemap.h:67).
    pub const FIEMAP_EXTENT_LAST: u32 = 0x00000001;

    /// FIEMAP_EXTENT_DELALLOC flag (fiemap.h:69).
    pub const FIEMAP_EXTENT_DELALLOC: u32 = 0x00000004;

    /// FILE_DEDUPE_RANGE_SAME (fs.h:159).
    pub const FILE_DEDUPE_RANGE_SAME: i32 = 0;

    /// FILE_DEDUPE_RANGE_DIFFERS (fs.h:160).
    pub const FILE_DEDUPE_RANGE_DIFFERS: i32 = 1;
}

/// Csum type metadata: digest size in bytes.
pub fn csum_digest_size(csum_type: u16) -> usize {
    match csum_type {
        constants::csum_type::CRC32 => 4,
        constants::csum_type::XXHASH => 8,
        constants::csum_type::SHA256 => 32,
        constants::csum_type::BLAKE2 => 32,
        _ => 32, // fallback to max
    }
}

/// Csum type name for display.
pub fn csum_type_name(csum_type: u16) -> &'static str {
    match csum_type {
        constants::csum_type::CRC32 => "crc32c",
        constants::csum_type::XXHASH => "xxhash64",
        constants::csum_type::SHA256 => "sha256",
        constants::csum_type::BLAKE2 => "blake2b",
        _ => "unknown",
    }
}
