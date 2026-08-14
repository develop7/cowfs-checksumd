//! Query layer — duplicate detection and reporting.
//!
//! No separate Detector component (Lowy F4, Hickey F1b):
//! duplicate detection is SQL GROUP BY, not a component.

use anyhow::Result;
use rusqlite::params;

use crate::db::Db;

/// A group of duplicate files.
#[derive(Clone, Debug)]
pub struct DuplicateGroup {
    pub digest: Vec<u8>,
    pub size: u64,
    pub count: usize,
    pub files: Vec<String>,
}

/// Find duplicate files: groups by (digest, size) with count > 1.
pub fn list_duplicates(db: &Db) -> Result<Vec<DuplicateGroup>> {
    let conn = db.connection();
    let mut stmt = conn.prepare(
        "SELECT digest, size, COUNT(*) as cnt
         FROM files
         WHERE digest IS NOT NULL AND flags & 1 = 0
         GROUP BY digest, size
         HAVING COUNT(*) > 1",
    )?;
    let mut groups = Vec::new();
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let digest: Vec<u8> = row.get(0)?;
        let size: i64 = row.get(1)?;
        let count: i64 = row.get(2)?;

        let mut file_stmt = conn.prepare(
            "SELECT filename FROM files WHERE digest = ?1 AND size = ?2 AND flags & 1 = 0",
        )?;
        let mut file_rows = file_stmt.query(params![digest, size])?;
        let mut files = Vec::new();
        while let Some(frow) = file_rows.next()? {
            files.push(frow.get::<_, String>(0)?);
        }
        groups.push(DuplicateGroup {
            digest,
            size: size as u64,
            count: count as usize,
            files,
        });
    }
    Ok(groups)
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
