//! Archive extraction support for compressed log files.
//!
//! Supports `.zip`, `.gz`, `.bz2`, `.tar.gz`, and `.tgz` formats.
//! Gated behind the `archive` feature flag.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Check if a path is a supported archive format.
pub fn is_archive(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Check compound extensions first
    if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        return true;
    }

    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase()
            .as_str(),
        "zip" | "gz" | "bz2"
    )
}

/// Extract an archive to a temporary directory, returning the temp dir handle
/// and a list of extracted file paths.
///
/// The caller must keep the returned `TempDir` alive for as long as the
/// extracted files are needed; dropping it removes the directory.
pub fn extract_to_temp(path: &Path) -> Result<(tempfile::TempDir, Vec<PathBuf>)> {
    let tmp = tempfile::tempdir().context("failed to create temp directory")?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    let files = if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        extract_tar_gz(path, tmp.path())?
    } else {
        match path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase()
            .as_str()
        {
            "zip" => extract_zip(path, tmp.path())?,
            "gz" => extract_single_gz(path, tmp.path())?,
            "bz2" => extract_single_bz2(path, tmp.path())?,
            other => bail!("unsupported archive extension: {}", other),
        }
    };

    Ok((tmp, files))
}

/// Decompress a single `.gz` file entirely into memory.
pub fn decompress_gz(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut decoder = flate2::read::GzDecoder::new(file);
    let mut buf = Vec::new();
    decoder
        .read_to_end(&mut buf)
        .with_context(|| format!("failed to decompress {}", path.display()))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn extract_zip(path: &Path, dest: &Path) -> Result<Vec<PathBuf>> {
    let file = File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("failed to read zip archive {}", path.display()))?;

    let mut extracted = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let entry_path = match entry.enclosed_name() {
            Some(p) => p.to_owned(),
            None => continue, // skip entries with unsafe paths
        };

        let out_path = dest.join(&entry_path);

        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut out_file = File::create(&out_path)?;
            io::copy(&mut entry, &mut out_file)?;
            extracted.push(out_path);
        }
    }

    Ok(extracted)
}

fn extract_tar_gz(path: &Path, dest: &Path) -> Result<Vec<PathBuf>> {
    let file = File::open(path)?;
    let gz = flate2::read::GzDecoder::new(file);
    extract_tar(gz, dest, path)
}

fn extract_tar<R: Read>(reader: R, dest: &Path, source: &Path) -> Result<Vec<PathBuf>> {
    let mut archive = tar::Archive::new(reader);
    let mut extracted = Vec::new();

    for entry in archive
        .entries()
        .with_context(|| format!("failed to read tar entries from {}", source.display()))?
    {
        let mut entry = entry?;
        let entry_path = entry.path()?.to_path_buf();
        let out_path = dest.join(&entry_path);

        if entry.header().entry_type().is_dir() {
            std::fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            entry.unpack(&out_path)?;
            extracted.push(out_path);
        }
    }

    Ok(extracted)
}

fn extract_single_gz(path: &Path, dest: &Path) -> Result<Vec<PathBuf>> {
    let data = decompress_gz(path)?;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("decompressed");
    let out_path = dest.join(stem);
    std::fs::write(&out_path, &data)?;
    Ok(vec![out_path])
}

fn extract_single_bz2(path: &Path, dest: &Path) -> Result<Vec<PathBuf>> {
    let file = File::open(path)?;
    let mut decoder = bzip2::read::BzDecoder::new(file);
    let mut buf = Vec::new();
    decoder
        .read_to_end(&mut buf)
        .with_context(|| format!("failed to decompress {}", path.display()))?;

    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("decompressed");
    let out_path = dest.join(stem);
    std::fs::write(&out_path, &buf)?;
    Ok(vec![out_path])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_archive_zip() {
        assert!(is_archive(Path::new("logs.zip")));
    }

    #[test]
    fn test_is_archive_gz() {
        assert!(is_archive(Path::new("access.log.gz")));
    }

    #[test]
    fn test_is_archive_bz2() {
        assert!(is_archive(Path::new("syslog.bz2")));
    }

    #[test]
    fn test_is_archive_tar_gz() {
        assert!(is_archive(Path::new("logs.tar.gz")));
    }

    #[test]
    fn test_is_archive_tgz() {
        assert!(is_archive(Path::new("bundle.tgz")));
    }

    #[test]
    fn test_is_archive_negative() {
        assert!(!is_archive(Path::new("readme.txt")));
        assert!(!is_archive(Path::new("data.json")));
        assert!(!is_archive(Path::new("events.evtx")));
        assert!(!is_archive(Path::new("no_extension")));
    }

    #[test]
    fn test_is_archive_case_insensitive() {
        assert!(is_archive(Path::new("LOGS.ZIP")));
        assert!(is_archive(Path::new("data.GZ")));
        assert!(is_archive(Path::new("archive.TAR.GZ")));
    }

    #[test]
    fn test_gz_roundtrip() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let original = b"hello world, this is a test log line\n";

        // Compress in memory
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        // Write compressed data to a temp file
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &compressed).unwrap();

        // Decompress and verify
        let decompressed = decompress_gz(tmp.path()).unwrap();
        assert_eq!(decompressed, original);
    }
}
