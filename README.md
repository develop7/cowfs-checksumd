# cowfs-dupescan

Btrfs duplicate scanner — reads checksums directly from the btrfs CSUM tree
via `TREE_SEARCH_V2` ioctl (dduper-style approach, btrd as reference), detects
duplicate files, and exports results to duperemove-compatible SQLite hashfile
format.

## Why

duperemove and bees compute content hashes by reading file data — slow for
large filesystems. btrfs already stores per-sector checksums in a dedicated
CSUM tree (tree 7). Reading those checksums directly is ~40x faster (dduper
benchmark) because it replaces reading TB of file data with metadata tree
lookups.

## How it works

### Two-tier checksum strategy

1. **CSUM tree fast path**: for regular (`BTRFS_FILE_EXTENT_REG`), non-inline,
   non-`NODATASUM` extents. Reads per-sector checksums from the btrfs CSUM
   tree via `BTRFS_IOC_TREE_SEARCH_V2` ioctl. No file I/O.

2. **Userspace fallback**: for `NODATASUM` files, inline data, non-btrfs
   filesystems, or when FIEMAP is not supported. Reads file data and computes
   XXH3-128 hashes (same algorithm as duperemove).

### Compression handling

btrfs CSUM tree checksums are of **on-disk bytes** (verified from kernel source:
`compression.c:315` → `bio.c:843` → `file-item.c:839` → `inode.c:3483`).
For uncompressed data, this is the file content. For compressed data, it's
the compressed bytes. Two files with identical content but different
compression (e.g., one zstd, one uncompressed) will have different checksums
— a safe false negative. `FIDEDUPERANGE` verifies byte-by-byte in-kernel
before sharing, so false positives can't cause data loss.

### Incremental scanning

Uses `(ino, subvol)` identity (not path) to survive renames and avoid
re-hashing hardlinks/snapshots. Files unchanged since last scan (same
mtime + size) are skipped. On btrfs, `TREE_SEARCH_V2` with `min_transid`
can find only changed inodes (bees approach).

## Usage

```bash
# Scan a directory
cowfs-dupescan scan /mnt/btrfs --db scan.db

# List duplicate files
cowfs-dupescan list --db scan.db

# Export to duperemove-compatible hashfile
cowfs-dupescan export --db scan.db --output hashfile.sqlite

# Then run duperemove to deduplicate
duperemove --read-hashes hashfile.sqlite -d

# Deduplicate two files directly
cowfs-dupescan dedupe /mnt/file1 /mnt/file2
```

## Architecture

```
src/
├── main.rs           — CLI (clap): scan, list, export, dedupe
├── btrfs/
│   ├── mod.rs        — constants, csum type metadata
│   ├── ioctl.rs      — TREE_SEARCH_V2, FIEMAP, FIDEDUPERANGE, FS_INFO, INO_LOOKUP
│   ├── csum_tree.rs  — read CSUM tree entries, read file extent items
│   ├── fiemap.rs     — FIEMAP helpers (scanable extents, shared counting)
│   └── search.rs     — incremental scan via min_transid
├── scanner.rs        — file scanning orchestrator (two-tier: CSUM tree + userspace)
├── hasher.rs         — XXH3-128 block/file hashing
├── db.rs             — SQLite schema (own, independent from duperemove)
├── export.rs         — duperemove hashfile exporter
├── query.rs          — duplicate detection (SQL GROUP BY)
└── dedupe.rs         — FIDEDUPERANGE wrapper
```

## Key design decisions

- **Own schema + exporter** (not duperemove-compatible directly): the daemon's
  schema evolves independently; a separate export command converts to
  duperemove format on demand.
- **No separate Detector component**: duplicate detection is `SELECT ... GROUP
  BY digest, size HAVING count(*) > 1` — a query, not a component.
- **`scan_epoch`**: `FIDEDUPERANGE` doesn't change mtime/size, so mtime-skip
  alone can't detect post-dedup state. The epoch tracks scan rounds.
- **Skip `DATA_INLINE | UNWRITTEN`**, not `DELALLOC`: `FIEMAP_EXTENT_DELALLOC`
  means "dirty, not yet on disk" — skipping it drops real data. (duperemove
  `file_flags.h:5` skip set, verified from `fiemap.h:69`.)

## Tests

Run the ordinary test suite with `cargo test --locked`.

The `btrfs_image` integration test creates a fresh 256 MiB sparse image,
formats and loop-mounts it, writes duplicate, unique, and inline files, then
runs the real `scan` and `list` commands. The same content is also scanned
from a tmpfs directory (which takes the userspace fallback path): the two
file digests must differ, guarding against the CSUM-tree path silently
degrading to fallback. No images are cached or checked in.

This test is ignored by default: it needs Linux, `btrfs-progs`, loop devices,
and mount/`TREE_SEARCH_V2` privileges. Build unprivileged, then execute only
the test binary as root. The canonical recipe lives in the "Locate
btrfs_image test binary" step of `.github/workflows/tests.yml`; for a local
run, adapt it without `GITHUB_ENV`:

```bash
sudo "$(cargo test --locked --test btrfs_image --no-run --message-format=json |
  jq -r 'select(.executable != null and .target.name == "btrfs_image" and (.target.kind | index("test"))) | .executable')" --ignored --nocapture
```
CI runs this on every push and pull request; missing prerequisites fail
rather than silently skip. If unmount fails, the fixture directory is
retained and its path reported for manual cleanup. Killing the test with
SIGKILL also requires manual cleanup.

## References

- btrfs CSUM tree: `/usr/include/linux/btrfs_tree.h:58,188` (on-disk format)
- TREE_SEARCH_V2: `/usr/include/linux/btrfs.h:1144,594-600` (ioctl)
- btrd: `github.com/danobi/btrd` (Rust btrfs debugger, `src/btrfs/fs.rs`)
- dduper: `github.com/Lakshmipathi/dduper` (CSUM tree reading for dedup)
- duperemove: `github.com/markfasheh/duperemove` (hashfile schema, dedup ioctl)
- Compression checksum timing: kernel source `fs/btrfs/compression.c:315`,
  `bio.c:843`, `file-item.c:839`, `inode.c:3483`, `fs.c:44`