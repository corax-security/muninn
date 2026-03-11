#[cfg(feature = "archive")]
pub mod archive;

mod auditd;
mod cef;
mod csv_tsv;
mod evtx;
mod flatten;
mod json;
mod leef;
mod macos;
mod syslog;
mod text;
mod w3c;
mod xml;
mod zeek;

use anyhow::{bail, Result};
use log::debug;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::model::{ParseResult, SourceFormat};

pub use flatten::flatten_json;

pub fn detect_format(path: &Path) -> Result<SourceFormat> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "evtx" => return Ok(SourceFormat::Evtx),
        "csv" => return Ok(SourceFormat::Csv),
        "tsv" => return Ok(SourceFormat::Tsv),
        _ => {}
    }

    let mut file = std::fs::File::open(path)?;
    let mut magic = [0u8; 8];
    let n = file.read(&mut magic)?;
    if n >= 7 && &magic[..7] == b"ElfFile" {
        return Ok(SourceFormat::Evtx);
    }

    let sample = std::fs::read_to_string(path)
        .map(|s| s.chars().take(8192).collect::<String>())
        .unwrap_or_default();
    let trimmed = sample.trim();
    let first = trimmed.lines().next().unwrap_or("");

    if first.starts_with("#separator") || first.starts_with("#fields") {
        return Ok(SourceFormat::ZeekTsv);
    }
    if first.starts_with("#Software:")
        || first.starts_with("#Fields:")
        || first.starts_with("#Version:")
    {
        return Ok(SourceFormat::W3cExtended);
    }
    if trimmed.contains("CEF:0|") || trimmed.contains("CEF:1|") {
        return Ok(SourceFormat::Cef);
    }
    if trimmed.contains("LEEF:1.0|") || trimmed.contains("LEEF:2.0|") {
        return Ok(SourceFormat::Leef);
    }
    if trimmed.starts_with('[') {
        if trimmed.contains("\"processImagePath\"") {
            return Ok(SourceFormat::MacosUnifiedLog);
        }
        return Ok(SourceFormat::JsonArray);
    }
    if trimmed.starts_with('{') {
        if trimmed.contains("\"processImagePath\"") || trimmed.contains("\"subsystem\"") {
            return Ok(SourceFormat::MacosUnifiedLog);
        }
        return Ok(SourceFormat::JsonLines);
    }
    if first.starts_with("type=") {
        return Ok(SourceFormat::Auditd);
    }
    if trimmed.contains("<Event>") && trimmed.contains("<EventData>") {
        return Ok(SourceFormat::SysmonLinux);
    }
    if first.starts_with('<') {
        if let Some(close) = first.find('>') {
            if close <= 4 && first[1..close].parse::<u32>().is_ok() {
                return Ok(SourceFormat::Syslog);
            }
        }
    }
    let syslog_re =
        regex::Regex::new(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+").unwrap();
    if syslog_re.is_match(first) {
        return Ok(SourceFormat::Syslog);
    }
    if trimmed.starts_with("<?xml") || (trimmed.starts_with('<') && trimmed.contains("</")) {
        return Ok(SourceFormat::Xml);
    }
    if first.contains(',') && !first.contains('{') && first.matches(',').count() >= 2 {
        return Ok(SourceFormat::Csv);
    }
    if first.contains('\t') && first.matches('\t').count() >= 2 {
        return Ok(SourceFormat::Tsv);
    }

    Ok(SourceFormat::PlainText)
}

pub fn parse_file(path: &Path) -> Result<ParseResult> {
    let format = detect_format(path)?;
    parse_file_as(path, &format)
}

pub fn parse_file_as(path: &Path, format: &SourceFormat) -> Result<ParseResult> {
    let start = Instant::now();
    let path_str = path.display().to_string();

    let events = match format {
        #[cfg(feature = "parser-evtx")]
        SourceFormat::Evtx => evtx::parse(path, &path_str)?,
        #[cfg(not(feature = "parser-evtx"))]
        SourceFormat::Evtx => bail!("EVTX support not compiled (enable feature 'parser-evtx')"),

        SourceFormat::JsonLines => json::parse_jsonl(path, &path_str)?,
        SourceFormat::JsonArray => json::parse_json_array(path, &path_str)?,
        SourceFormat::Csv | SourceFormat::Tsv => csv_tsv::parse(path, &path_str, format)?,
        SourceFormat::Xml | SourceFormat::SysmonLinux => xml::parse(path, &path_str)?,
        SourceFormat::Auditd => auditd::parse(path, &path_str)?,

        #[cfg(feature = "parser-syslog")]
        SourceFormat::Syslog => syslog::parse(path, &path_str)?,
        #[cfg(not(feature = "parser-syslog"))]
        SourceFormat::Syslog => text::parse(path, &path_str)?,

        #[cfg(feature = "parser-cef")]
        SourceFormat::Cef => cef::parse(path, &path_str)?,
        #[cfg(not(feature = "parser-cef"))]
        SourceFormat::Cef => text::parse(path, &path_str)?,

        #[cfg(feature = "parser-leef")]
        SourceFormat::Leef => leef::parse(path, &path_str)?,
        #[cfg(not(feature = "parser-leef"))]
        SourceFormat::Leef => text::parse(path, &path_str)?,

        #[cfg(feature = "parser-w3c")]
        SourceFormat::W3cExtended => w3c::parse(path, &path_str)?,
        #[cfg(not(feature = "parser-w3c"))]
        SourceFormat::W3cExtended => text::parse(path, &path_str)?,

        #[cfg(feature = "parser-zeek")]
        SourceFormat::ZeekTsv => zeek::parse(path, &path_str)?,
        #[cfg(not(feature = "parser-zeek"))]
        SourceFormat::ZeekTsv => text::parse(path, &path_str)?,

        SourceFormat::MacosUnifiedLog => macos::parse(path, &path_str)?,
        SourceFormat::PlainText => text::parse(path, &path_str)?,
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    debug!(
        "Parsed {} events ({}) from {:?} in {}ms",
        events.len(),
        format,
        path,
        duration_ms
    );

    Ok(ParseResult {
        events,
        source_file: path_str,
        source_format: format.clone(),
        parse_errors: 0,
        duration_ms,
    })
}

pub fn discover_files(
    path: &Path,
    select: Option<&str>,
    avoid: Option<&str>,
    recursive: bool,
) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        bail!("{:?} is not a file or directory", path);
    }

    let max_depth = if recursive { usize::MAX } else { 1 };
    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(path)
        .max_depth(max_depth)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();

    if let Some(pat) = select {
        let p = pat.to_lowercase();
        files.retain(|f| {
            f.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.to_lowercase().contains(&p))
                .unwrap_or(false)
        });
    }
    if let Some(pat) = avoid {
        let p = pat.to_lowercase();
        files.retain(|f| {
            f.file_name()
                .and_then(|n| n.to_str())
                .map(|n| !n.to_lowercase().contains(&p))
                .unwrap_or(true)
        });
    }

    files.sort();
    Ok(files)
}

pub fn parse_files_parallel(paths: &[PathBuf]) -> Vec<Result<ParseResult>> {
    use rayon::prelude::*;
    paths.par_iter().map(|p| parse_file(p)).collect()
}
