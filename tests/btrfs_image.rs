//! Privileged end-to-end test: see the Tests section of README.md.
//!
//! Scanning the same content from a tmpfs directory (userspace fallback) and
//! from a fresh Btrfs disk image (CSUM tree) must produce different file
//! digests — the guard against the ioctl path silently degrading to the
//! fallback.
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::process::{Command, Output};

/// Block size in KB matching the `--block-size` flag pinned in `scan`;
/// the fixture's block-count assertions derive from it.
const BLOCK_SIZE_KB: usize = 128;
const BLOCK_SIZE: usize = BLOCK_SIZE_KB * 1024;

fn run(command: &mut Command) -> Output {
    let output = command.output().expect("start command");
    assert!(
        output.status.success(),
        "{command:?}: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

/// Mounted Btrfs fixture over a temporary directory.
///
/// Unmount failures retain the directory rather than let TempDir recursively
/// delete a still-mounted filesystem. SIGKILL bypasses Drop; that mount and
/// directory need manual cleanup.
struct Image {
    directory: TempDirCell,
    mounted: bool,
}

/// TempDir wrapper whose Drop is the only legal way to move the inner
/// TempDir: Drop-implementing parents cannot move enum payloads out, so the
/// wrapper erases Drop while the parent performs its own unmount bookkeeping.
struct TempDirCell(Option<tempfile::TempDir>);

impl TempDirCell {
    fn path(&self) -> PathBuf {
        self.0
            .as_ref()
            .expect("tempdir present")
            .path()
            .to_path_buf()
    }
}

impl Image {
    /// Path of the mounted Btrfs filesystem.
    fn mount_path(&self) -> PathBuf {
        self.directory.path().join("mount")
    }

    /// Path for files that live outside the mounted filesystem (databases).
    fn outside(&self) -> PathBuf {
        self.directory.path().join("scan.db")
    }

    fn new() -> Self {
        let directory = tempfile::tempdir().expect("create image directory");
        let image = directory.path().join("filesystem.img");
        File::create(&image)
            .expect("create image")
            .set_len(256 * 1024 * 1024)
            .expect("size sparse image");
        run(Command::new("mkfs.btrfs").arg("-f").arg(&image));
        fs::create_dir(directory.path().join("mount")).expect("create mountpoint");
        run(Command::new("mount")
            .args(["-t", "btrfs", "-o", "loop"])
            .arg(&image)
            .arg(directory.path().join("mount")));
        Self {
            directory: TempDirCell(Some(directory)),
            mounted: true,
        }
    }

    /// Explicit unmount at the end of a test. A failed unmount must not
    /// panic — Drop's retain-and-report path handles cleanup — but the
    /// failure is still surfaced as a test failure.
    fn unmount(&mut self) {
        if !self.mounted {
            return;
        }
        let output = Command::new("umount")
            .arg(self.mount_path())
            .output()
            .expect("run umount");
        assert!(
            output.status.success(),
            "umount failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.mounted = false;
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        if self.mounted {
            match Command::new("umount").arg(self.mount_path()).output() {
                Ok(output) if output.status.success() => self.mounted = false,
                result => {
                    // Retain instead of recursing into a live mount.
                    let directory = self.directory.0.take().expect("tempdir present");
                    let retained = directory.keep();
                    eprintln!(
                        "unmount failed ({result:?}); retained {} for manual cleanup",
                        retained.display()
                    );
                }
            }
        }
    }
}

fn write_file(path: &Path, bytes: &[u8]) {
    let mut file = File::create(path).expect("create fixture file");
    file.write_all(bytes).expect("write fixture file");
    file.sync_all().expect("flush fixture file");
}

/// Populate `root` with fixture files; returns the large duplicate content.
fn populate(root: &Path) -> Vec<u8> {
    // Separate writes, not reflinks. Two-block files exercise the CSUM tree
    // path; the small file exercises a partial final block.
    let bytes: Vec<u8> = (0..2 * BLOCK_SIZE).map(|i| (i % 251) as u8).collect();
    write_file(&root.join("first"), &bytes);
    write_file(&root.join("second"), &bytes);
    write_file(&root.join("unique"), &vec![0x7b; bytes.len()]);
    write_file(&root.join("small"), b"tiny inline file, below one block");
    bytes
}

/// Run a real `scan` and return (filename, digest) rows from the database.
fn scan(root: &Path, database: &Path) -> Vec<(String, Vec<u8>)> {
    run(Command::new(env!("CARGO_BIN_EXE_cowfs-dupescan"))
        .args(["scan", "--block-size"])
        .arg(BLOCK_SIZE_KB.to_string())
        .arg(root)
        .args(["--db"])
        .arg(database)
        // Inherit stdio so the scanner's tracing output (fallback warnings,
        // CSUM diagnostics) reaches the test log instead of being captured.
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit()));
    let db = rusqlite::Connection::open(database).expect("open scan database");
    let records: Vec<(String, Vec<u8>)> = db
        .prepare("SELECT filename, digest FROM files ORDER BY filename")
        .expect("query files")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("map rows")
        .collect::<rusqlite::Result<_>>()
        .expect("collect rows");
    drop(db);
    records
}

#[test]
#[ignore = "requires root, loop mounts and btrfs-progs"]
fn scans_duplicate_files_on_fresh_btrfs_image() {
    let mut image = Image::new();
    let root = image.mount_path();
    let bytes = populate(&root);
    let database = image.outside();
    run(Command::new("btrfs")
        .args(["filesystem", "sync"])
        .arg(&root));
    let records = scan(&root, &database);

    assert_eq!(records.len(), 4);
    assert_eq!(records[0].0, root.join("first").to_str().unwrap());
    assert_eq!(records[1].0, root.join("second").to_str().unwrap());
    assert_eq!(records[2].0, root.join("small").to_str().unwrap());
    assert_eq!(records[3].0, root.join("unique").to_str().unwrap());
    // Duplicates share a digest; the same-size unique content does not.
    assert_eq!(records[0].1, records[1].1);
    assert_ne!(records[0].1, records[3].1);
    assert_ne!(records[0].1, records[2].1);

    // Guard against silent CSUM-tree degradation: the same content scanned
    // from a tmpfs directory takes the userspace fallback, whose file digest
    // hashes content — never equal to the CSUM-tree digest hashing checksum
    // bytes. If the ioctl path ever fell back on btrfs, digests converge and
    // this fails.
    let tmpfs = tempfile::tempdir_in("/dev/shm").expect("create tmpfs directory");
    // The database must live outside the scanned root, or the scanner picks
    // up scan.db and its WAL/SHM siblings as scanned files.
    let tmpfs_db = tempfile::tempdir().expect("create tmpfs database directory");
    write_file(&tmpfs.path().join("first"), &bytes);
    let tmpfs_records = scan(tmpfs.path(), &tmpfs_db.path().join("scan.db"));
    assert_eq!(tmpfs_records.len(), 1);
    assert_ne!(records[0].1, tmpfs_records[0].1);

    // Block rows: every file contributes ceil(len / BLOCK_SIZE) rows — the
    // 33-byte small file is a single partial block on the CSUM path too,
    // because btrfs only inlines files below the 2 KiB max_inline default
    // when created via specific paths; a plain write of 33 bytes yields a
    // regular CSUM-backed extent.
    let db = rusqlite::Connection::open(&database).expect("open scan database");
    let blocks_per_file: i64 = (bytes.len() / BLOCK_SIZE) as i64;
    let block_count: i64 = db
        .query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))
        .expect("count blocks");
    assert_eq!(block_count, 3 * blocks_per_file + 1);
    drop(db);

    let output = run(Command::new(env!("CARGO_BIN_EXE_cowfs-dupescan"))
        .args(["list", "--db"])
        .arg(&database));
    let listing = String::from_utf8(output.stdout).expect("list output utf8");
    // Only indented lines are file paths; headers and blank lines are
    // presentation noise.
    let mut listed: Vec<&str> = listing
        .lines()
        .filter_map(|line| line.strip_prefix("  "))
        .collect();
    listed.sort_unstable();
    assert_eq!(listed, vec![records[0].0.as_str(), records[1].0.as_str()]);
    image.unmount();
}
