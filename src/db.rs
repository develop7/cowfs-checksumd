//! SQLite persistence for scanned file checksums.
//!
//! Own schema, fully independent from duperemove.
//! The exporter (export.rs) converts to duperemove format on demand.

use anyhow::Result;
use rusqlite::{Connection, params};
use std::path::Path;

/// Database handle.
pub struct Db {
    conn: Connection,
}

/// File record for insert/update.
#[derive(Clone, Debug)]
pub struct FileRecord {
    pub ino: u64,
    pub subvol: u64,
    pub filename: String,
    pub size: u64,
    pub mtime: i64,
    pub digest: Option<Vec<u8>>,
    pub scan_epoch: u64,
    pub flags: u32,
}

/// Block checksum record.
#[derive(Clone, Debug)]
pub struct BlockRecord {
    pub digest: Vec<u8>,
    pub fileid: i64,
    pub loff: u64,
}

impl Db {
    /// Open or create the database.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )?;
        Self::create_schema(&conn)?;
        Ok(Self { conn })
    }

    fn create_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS config (
                keyname TEXT PRIMARY KEY NOT NULL,
                keyval BLOB
            );

            CREATE TABLE IF NOT EXISTS files (
                id          INTEGER PRIMARY KEY,
                ino         INTEGER NOT NULL,
                subvol      INTEGER NOT NULL,
                filename    TEXT NOT NULL,
                size        INTEGER NOT NULL,
                mtime       INTEGER NOT NULL,
                digest      BLOB,
                scan_epoch  INTEGER NOT NULL DEFAULT 0,
                flags       INTEGER NOT NULL DEFAULT 0,
                UNIQUE(ino, subvol)
            );

            CREATE TABLE IF NOT EXISTS blocks (
                digest  BLOB NOT NULL,
                fileid  INTEGER NOT NULL,
                loff    INTEGER NOT NULL,
                FOREIGN KEY(fileid) REFERENCES files(id) ON DELETE CASCADE,
                UNIQUE(fileid, loff)
            );

            CREATE INDEX IF NOT EXISTS idx_blocks_digest ON blocks(digest);
            CREATE INDEX IF NOT EXISTS idx_blocks_fileid ON blocks(fileid);
            CREATE INDEX IF NOT EXISTS idx_files_digest_size ON files(digest, size);
            "#,
        )?;
        Ok(())
    }

    /// Set a config key.
    pub fn set_config(&self, key: &str, val: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO config (keyname, keyval) VALUES (?1, ?2)",
            params![key, val],
        )?;
        Ok(())
    }

    /// Set a config integer.
    pub fn set_config_int(&self, key: &str, val: i64) -> Result<()> {
        self.set_config(key, &val.to_le_bytes())
    }

    /// Get a config integer.
    pub fn get_config_int(&self, key: &str) -> Result<Option<i64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT keyval FROM config WHERE keyname = ?1")?;
        let mut rows = stmt.query(params![key])?;
        if let Some(row) = rows.next()? {
            let blob: Vec<u8> = row.get(0)?;
            if blob.len() >= 8 {
                return Ok(Some(i64::from_le_bytes(blob[..8].try_into().unwrap())));
            }
        }
        Ok(None)
    }

    /// Upsert a file record. Returns the file ID.
    pub fn upsert_file(&self, rec: &FileRecord) -> Result<i64> {
        self.conn.execute(
            "INSERT OR REPLACE INTO files (ino, subvol, filename, size, mtime, digest, scan_epoch, flags)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                rec.ino as i64,
                rec.subvol as i64,
                rec.filename,
                rec.size as i64,
                rec.mtime,
                rec.digest,
                rec.scan_epoch as i64,
                rec.flags,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Get file by (ino, subvol).
    pub fn get_file(&self, ino: u64, subvol: u64) -> Result<Option<FileRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ino, subvol, filename, size, mtime, digest, scan_epoch, flags
             FROM files WHERE ino = ?1 AND subvol = ?2",
        )?;
        let mut rows = stmt.query(params![ino as i64, subvol as i64])?;
        if let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let _ = id;
            return Ok(Some(FileRecord {
                ino: row.get::<_, i64>(1)? as u64,
                subvol: row.get::<_, i64>(2)? as u64,
                filename: row.get(3)?,
                size: row.get::<_, i64>(4)? as u64,
                mtime: row.get(5)?,
                digest: row.get(6)?,
                scan_epoch: row.get::<_, i64>(7)? as u64,
                flags: row.get::<_, i64>(8)? as u32,
            }));
        }
        Ok(None)
    }

    /// Remove all block hashes for a file.
    pub fn remove_file_hashes(&self, fileid: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM blocks WHERE fileid = ?1", params![fileid])?;
        Ok(())
    }

    /// Store block hashes for a file in a transaction.
    pub fn store_block_hashes(&self, fileid: i64, blocks: &[BlockRecord]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for b in blocks {
            tx.execute(
                "INSERT OR REPLACE INTO blocks (digest, fileid, loff) VALUES (?1, ?2, ?3)",
                params![b.digest, b.fileid, b.loff as i64],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Get the scan epoch.
    pub fn get_scan_epoch(&self) -> Result<u64> {
        Ok(self.get_config_int("scan_epoch")?.unwrap_or(0) as u64)
    }

    /// Increment and return the scan epoch.
    pub fn bump_scan_epoch(&self) -> Result<u64> {
        let epoch = self.get_scan_epoch()? + 1;
        self.set_config_int("scan_epoch", epoch as i64)?;
        Ok(epoch)
    }

    /// Find duplicate files: groups by (digest, size) with count > 1.
    pub fn find_duplicate_files(&self) -> Result<Vec<DuplicateGroup>> {
        let mut stmt = self.conn.prepare(
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

            // Get filenames for this group
            let mut file_stmt = self.conn.prepare(
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

    /// Get all files with their digests for export.
    pub fn iter_files(&self) -> Result<Vec<ExportFile>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ino, subvol, filename, size, mtime, digest, flags
             FROM files WHERE digest IS NOT NULL",
        )?;
        let mut files = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            files.push(ExportFile {
                id: row.get(0)?,
                ino: row.get::<_, i64>(1)? as u64,
                subvol: row.get::<_, i64>(2)? as u64,
                filename: row.get(3)?,
                size: row.get::<_, i64>(4)? as u64,
                mtime: row.get(5)?,
                digest: row.get(6)?,
                flags: row.get::<_, i64>(7)? as u32,
            });
        }
        Ok(files)
    }

    /// Get all block hashes for export.
    pub fn iter_blocks(&self) -> Result<Vec<ExportBlock>> {
        let mut stmt = self
            .conn
            .prepare("SELECT digest, fileid, loff FROM blocks")?;
        let mut blocks = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            blocks.push(ExportBlock {
                digest: row.get(0)?,
                fileid: row.get(1)?,
                loff: row.get::<_, i64>(2)? as u64,
            });
        }
        Ok(blocks)
    }
}

/// A group of duplicate files.
#[derive(Clone, Debug)]
pub struct DuplicateGroup {
    pub digest: Vec<u8>,
    pub size: u64,
    pub count: usize,
    pub files: Vec<String>,
}

/// File record for export.
#[derive(Clone, Debug)]
pub struct ExportFile {
    pub id: i64,
    pub ino: u64,
    pub subvol: u64,
    pub filename: String,
    pub size: u64,
    pub mtime: i64,
    pub digest: Vec<u8>,
    pub flags: u32,
}

/// Block record for export.
#[derive(Clone, Debug)]
pub struct ExportBlock {
    pub digest: Vec<u8>,
    pub fileid: i64,
    pub loff: u64,
}
