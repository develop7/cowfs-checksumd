use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

mod btrfs;
mod db;
mod dedupe;
mod export;
mod hasher;
mod query;
mod scanner;

/// cowfs-dupescan — Btrfs duplicate scanner.
///
/// Reads checksums directly from the btrfs CSUM tree (40x faster than
/// reading file data), detects duplicate files, and exports results
/// to duperemove-compatible format.
#[derive(Parser)]
#[command(name = "cowfs-dupescan", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory and store checksums in the database.
    Scan {
        /// Directory to scan.
        dir: PathBuf,
        /// Database file path (default: dupescan.db).
        #[arg(short, long, default_value = "dupescan.db")]
        db: PathBuf,
        /// Block size in KB (default: 128).
        #[arg(short, long, default_value_t = 128)]
        block_size: usize,
    },

    /// List duplicate files from the database.
    List {
        /// Database file path.
        #[arg(short, long, default_value = "dupescan.db")]
        db: PathBuf,
    },

    /// Export database to duperemove-compatible hashfile.
    Export {
        /// Database file path.
        #[arg(short, long, default_value = "dupescan.db")]
        db: PathBuf,
        /// Output hashfile path.
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Deduplicate two files using FIDEDUPERANGE.
    Dedupe {
        /// Source file.
        src: String,
        /// Destination file.
        dest: String,
        /// Block size in KB.
        #[arg(short, long, default_value_t = 128)]
        block_size: usize,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            dir,
            db: db_path,
            block_size,
        } => {
            let db = db::Db::open(&db_path)?;
            let scan_epoch = db.bump_scan_epoch()?;

            let config = scanner::ScannerConfig::detect(&dir, block_size);

            db.set_config_int("block_size", (block_size * 1024) as i64)?;
            db.set_config_int("csum_type", config.csum_type as i64)?;
            db.set_config_int("sectorsize", config.sectorsize as i64)?;

            let count = scanner::scan_directory(&dir, &db, &config, scan_epoch)?;
            println!("Scanned {} files.", count);
        }

        Commands::List { db: db_path } => {
            let db = db::Db::open(&db_path)?;
            let groups = query::list_duplicates(&db)?;
            query::print_duplicates(&groups);
        }

        Commands::Export {
            db: db_path,
            output,
        } => {
            let db = db::Db::open(&db_path)?;
            export::export_duperemove(&db, &output)?;
            println!(
                "Exported to {} (duperemove --read-hashes {})",
                output.display(),
                output.display()
            );
        }

        Commands::Dedupe {
            src,
            dest,
            block_size,
        } => {
            let deduped = dedupe::dedupe_files(&src, &dest, block_size * 1024)?;
            println!("Deduped {} bytes.", deduped);
        }
    }

    Ok(())
}
