//! Query layer — duplicate detection and reporting.
//!
//! No separate Detector component (Lowy F4, Hickey F1b):
//! duplicate detection is SQL GROUP BY, not a component.

use anyhow::Result;

use crate::db::{Db, DuplicateGroup};

/// List all duplicate file groups.
pub fn list_duplicates(db: &Db) -> Result<Vec<DuplicateGroup>> {
    db.find_duplicate_files()
}

/// Print duplicate groups to stdout.
pub fn print_duplicates(groups: &[DuplicateGroup]) {
    if groups.is_empty() {
        println!("No duplicate files found.");
        return;
    }

    let total_dupes: usize = groups.iter().map(|g| g.count).sum();
    println!(
        "Found {} duplicate file groups ({} files total).\n",
        groups.len(),
        total_dupes
    );

    for (i, group) in groups.iter().enumerate() {
        let digest_hex = hex::encode(&group.digest);
        println!(
            "Group {} ({} files, {} bytes, digest: {}...):",
            i + 1,
            group.count,
            group.size,
            &digest_hex[..8.min(digest_hex.len())]
        );
        for file in &group.files {
            println!("  {}", file);
        }
        println!();
    }
}
