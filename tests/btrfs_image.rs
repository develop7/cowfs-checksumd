//! Privileged end-to-end test: cargo test --test btrfs_image -- --ignored

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output};

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

// Keep the entire temporary directory if unmount fails: TempDir must never
// recursively delete the contents of a still-mounted filesystem. SIGKILL
// bypasses Drop; its mount and temporary directory need manual cleanup.
struct Image {
    directory: Option<tempfile::TempDir>,
    mounted: bool,
}

impl Image {
    fn mount(&self) -> std::path::PathBuf {
        self.directory.as_ref().unwrap().path().join("mount")
    }

    fn new() -> Self {
        let directory = tempfile::tempdir().expect("create image directory");
        let image = directory.path().join("filesystem.img");
        File::create(&image)
            .expect("create image")
            .set_len(256 * 1024 * 1024)
            .expect("size sparse image");
        run(Command::new("mkfs.btrfs").arg("-f").arg(&image));
        let mut fixture = Self {
            directory: Some(directory),
            mounted: false,
        };
        fs::create_dir(fixture.mount()).expect("create mountpoint");
        run(Command::new("mount")
            .args(["-t", "btrfs", "-o", "loop"])
            .arg(&image)
            .arg(fixture.mount()));
        fixture.mounted = true;
        fixture
    }

    fn unmount(&mut self) {
        run(Command::new("umount").arg(self.mount()));
        self.mounted = false;
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        if self.mounted {
            match Command::new("umount").arg(self.mount()).output() {
                Ok(output) if output.status.success() => {}
                result => {
                    let retained = self.directory.take().unwrap().keep();
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

#[test]
#[ignore = "requires root, loop mounts and btrfs-progs"]
fn scans_duplicate_files_on_fresh_btrfs_image() {
    let mut image = Image::new();
    let root = image.mount();
    let database = image.directory.as_ref().unwrap().path().join("scan.db");
    // Separate writes, not reflinks. Non-inline, full-block data exercises the
    // scanner's Btrfs path; the unique file differs despite having equal size.
    let bytes: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    write_file(&root.join("first"), &bytes);
    write_file(&root.join("second"), &bytes);
    write_file(&root.join("unique"), &vec![0x7b; bytes.len()]);
    run(Command::new("btrfs")
        .args(["filesystem", "sync"])
        .arg(&root));

    run(Command::new(env!("CARGO_BIN_EXE_cowfs-dupescan"))
        .arg("scan")
        .arg(&root)
        .arg("--db")
        .arg(&database));
    let db = rusqlite::Connection::open(&database).expect("open scan database");
    let records: Vec<(String, Vec<u8>)> = db
        .prepare("SELECT filename, digest FROM files ORDER BY filename")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].0, root.join("first").to_str().unwrap());
    assert_eq!(records[1].0, root.join("second").to_str().unwrap());
    assert_eq!(records[2].0, root.join("unique").to_str().unwrap());
    assert_eq!(records[0].1, records[1].1);
    assert_ne!(records[0].1, records[2].1);

    // The Btrfs checksum digest must not equal the userspace fallback digest.
    // Otherwise a broken ioctl path could pass every duplicate assertion.
    let mut fallback = xxhash_rust::xxh3::Xxh3::new();
    for block in bytes.chunks(128 * 1024) {
        fallback.update(&xxhash_rust::xxh3::xxh3_128(block).to_le_bytes());
    }
    assert_ne!(records[0].1, fallback.digest128().to_le_bytes());
    let block_count: i64 = db
        .query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))
        .unwrap();
    assert_eq!(block_count, 6);

    let output = run(Command::new(env!("CARGO_BIN_EXE_cowfs-dupescan"))
        .arg("list")
        .arg("--db")
        .arg(&database));
    let listing = String::from_utf8(output.stdout).unwrap();
    let mut listed: Vec<&str> = listing
        .lines()
        .filter_map(|line| line.strip_prefix("  "))
        .collect();
    listed.sort_unstable();
    assert_eq!(listed, vec![records[0].0.as_str(), records[1].0.as_str()]);
    drop(db);
    image.unmount();
}
