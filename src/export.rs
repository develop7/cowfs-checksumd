//! Duperemove hashfile exporter.
//!
//! Converts the daemon's own schema to duperemove-compatible SQLite format
//! so `duperemove --read-hashes <file>` works directly.
//!
//! Duperemove hashfile schema (dbfile.c:137-167):
//!   config: hash_type="XXHASH3 ", block_size, version_major=4, version_minor=1, dedupe_seq, fs_uuid
//!   files:  id, filename, ino, subvol, size, mtime, dedupe_seq, digest, flags
//!   extents: digest, fileid, loff, poff, len
//!   blocks:  digest, fileid, loff

use std::path::Path;

use anyhow::Result;
use rusqlite::{Connection, params};

use crate::db::Db;

/// Duperemove hashfile format constants (dbfile.h:21-22, csum.h:22).
const DB_FILE_MAJOR: i64 = 4;
const DB_FILE_MINOR: i64 = 1;
const HASH_TYPE: &str = "XXHASH3 "; // 8 bytes, csum.h:22

/// Export the daemon's database to a duperemove-compatible hashfile.
pub fn export_duperemove(db: &Db, output: &Path) -> Result<()> {
    let conn = Connection::open(output)?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = OFF;
         PRAGMA foreign_keys = ON;",
    )?;

    create_duperemove_schema(&conn)?;
    write_config(&conn)?;
    export_files(db, &conn)?;
    export_blocks(db, &conn)?;

    Ok(())
}

fn create_duperemove_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS config (
            keyname TEXT PRIMARY KEY NOT NULL,
            keyval BLOB,
            UNIQUE(keyname)
        );

        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY NOT NULL,
            filename TEXT NOT NULL,
            ino INTEGER,
            subvol INTEGER,
            size INTEGER,
            mtime INTEGER,
            dedupe_seq INTEGER,
            digest BLOB,
            flags INTEGER,
            UNIQUE(ino, subvol),
            UNIQUE(filename)
        );

        CREATE TABLE IF NOT EXISTS extents (
            digest BLOB KEY NOT NULL,
            fileid INTEGER,
            loff INTEGER,
            poff INTEGER,
            len INTEGER,
            UNIQUE(fileid, loff, len),
            FOREIGN KEY(fileid) REFERENCES files(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS blocks (
            digest BLOB KEY NOT NULL,
            fileid INTEGER,
            loff INTEGER,
            UNIQUE(fileid, loff),
            FOREIGN KEY(fileid) REFERENCES files(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_blocks_digest ON blocks(digest);
        CREATE INDEX IF NOT EXISTS idx_blocks_fileid ON blocks(fileid);
        CREATE INDEX IF NOT EXISTS idx_extents_digest_len ON extents(digest, len);
        CREATE INDEX IF NOT EXISTS idx_extents_fileid ON extents(fileid);
        CREATE INDEX IF NOT EXISTS idx_files_ino_subvol ON files(ino, subvol);
        CREATE INDEX IF NOT EXISTS idx_files_dedupeseq ON files(dedupe_seq);
        CREATE INDEX IF NOT EXISTS idx_files_digest_size ON files(digest, size);
        "#,
    )?;
    Ok(())
}

fn write_config(conn: &Connection) -> Result<()> {
    // Write config table (dbfile.c:718-767)
    conn.execute(
        "INSERT OR REPLACE INTO config (keyname, keyval) VALUES ('hash_type', ?1)",
        params![HASH_TYPE.as_bytes()],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO config (keyname, keyval) VALUES ('block_size', ?1)",
        params![128 * 1024i64], // default block size
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO config (keyname, keyval) VALUES ('dedupe_sequence', ?1)",
        params![0i64],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO config (keyname, keyval) VALUES ('version_minor', ?1)",
        params![DB_FILE_MINOR],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO config (keyname, keyval) VALUES ('version_major', ?1)",
        params![DB_FILE_MAJOR],
    )?;
    // fs_uuid — empty for now
    conn.execute(
        "INSERT OR REPLACE INTO config (keyname, keyval) VALUES ('fs_uuid', ?1)",
        params!["00000000-0000-0000-0000-000000000000".as_bytes()],
    )?;
    Ok(())
}

fn export_files(db: &Db, conn: &Connection) -> Result<()> {
    let files = db.iter_files()?;
    let tx = conn.unchecked_transaction()?;

    for f in &files {
        tx.execute(
            "INSERT OR REPLACE INTO files (id, filename, ino, subvol, size, mtime, dedupe_seq, digest, flags)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                f.id,
                f.filename,
                f.ino as i64,
                f.subvol as i64,
                f.size as i64,
                f.mtime,
                0i64, // dedupe_seq
                f.digest,
                f.flags as i64,
            ],
        )?;
    }

    tx.commit()?;
    Ok(())
}

fn export_blocks(db: &Db, conn: &Connection) -> Result<()> {
    let blocks = db.iter_blocks()?;
    let tx = conn.unchecked_transaction()?;

    for b in &blocks {
        tx.execute(
            "INSERT OR REPLACE INTO blocks (digest, fileid, loff) VALUES (?1, ?2, ?3)",
            params![b.digest, b.fileid, b.loff as i64],
        )?;
    }

    tx.commit()?;
    Ok(())
}
