use std::collections::HashMap;
use std::io::{BufRead, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Tracks file read positions for incremental reading.
pub struct LiveWatcher {
    cursors: HashMap<PathBuf, u64>,
}

impl LiveWatcher {
    pub fn new() -> Self {
        LiveWatcher {
            cursors: HashMap::new(),
        }
    }

    /// Read new content from a file starting at the cursor position.
    /// Returns new lines added since last read.
    pub fn read_new_content(&mut self, path: &Path) -> Result<Vec<String>> {
        let canonical = path
            .canonicalize()
            .unwrap_or_else(|_| path.to_path_buf());

        let cursor = self.cursors.get(&canonical).copied().unwrap_or(0);

        let mut file = std::fs::File::open(&canonical)
            .with_context(|| format!("Failed to open file: {}", canonical.display()))?;

        let metadata = file
            .metadata()
            .with_context(|| format!("Failed to read metadata: {}", canonical.display()))?;
        let file_len = metadata.len();

        // If the file was truncated, reset cursor to 0
        let seek_pos = if cursor > file_len { 0 } else { cursor };

        file.seek(SeekFrom::Start(seek_pos))?;

        let reader = std::io::BufReader::new(&file);
        let mut lines = Vec::new();
        let mut bytes_read = seek_pos;

        for line_result in reader.lines() {
            let line = line_result?;
            // Account for the line content plus the newline character
            bytes_read += line.len() as u64 + 1;
            if !line.is_empty() {
                lines.push(line);
            }
        }

        self.cursors.insert(canonical, bytes_read);
        Ok(lines)
    }

    /// Update cursor for a file to its current size.
    pub fn update_cursor(&mut self, path: &Path) -> Result<()> {
        let canonical = path
            .canonicalize()
            .unwrap_or_else(|_| path.to_path_buf());

        let metadata = std::fs::metadata(&canonical)
            .with_context(|| format!("Failed to read metadata: {}", canonical.display()))?;

        self.cursors.insert(canonical, metadata.len());
        Ok(())
    }

    /// Get the current cursor value for a path (for testing).
    pub fn cursor(&self, path: &Path) -> Option<u64> {
        let canonical = path
            .canonicalize()
            .unwrap_or_else(|_| path.to_path_buf());
        self.cursors.get(&canonical).copied()
    }
}

/// Start watching a directory for changes and process new log lines.
/// This is the main entry point called from CLI.
/// It prints alerts to stdout when new detections are found.
#[cfg(feature = "live")]
pub fn watch_directory(path: &Path, rules_path: &Path) -> Result<()> {
    use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc;

    let rules = crate::sigma::load_rules(rules_path)?;
    if rules.is_empty() {
        anyhow::bail!("No SIGMA rules found at {}", rules_path.display());
    }
    log::info!("Loaded {} SIGMA rules", rules.len());

    // Pre-compile rules into SQL queries
    let compiled: Vec<(String, String)> = rules
        .iter()
        .filter_map(|rule| match crate::sigma::compile(rule) {
            Ok(sql) => Some((rule.title.clone(), sql)),
            Err(e) => {
                log::warn!("Failed to compile rule '{}': {}", rule.title, e);
                None
            }
        })
        .collect();

    if compiled.is_empty() {
        anyhow::bail!("No rules compiled successfully");
    }

    let mut watcher = LiveWatcher::new();

    // Initialize cursors for existing files so we only see new content
    if path.is_dir() {
        for entry in walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let _ = watcher.update_cursor(entry.path());
        }
    } else if path.is_file() {
        watcher.update_cursor(path)?;
    }

    let (tx, rx) = mpsc::channel();

    let mut fs_watcher: RecommendedWatcher =
        RecommendedWatcher::new(tx, Config::default())?;

    let watch_mode = if path.is_dir() {
        RecursiveMode::Recursive
    } else {
        RecursiveMode::NonRecursive
    };

    fs_watcher.watch(path, watch_mode)?;

    println!(
        "[muninn-live] Watching {} for changes ({} rules loaded)",
        path.display(),
        compiled.len()
    );

    for event_result in rx {
        match event_result {
            Ok(event) => {
                if !matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_)
                ) {
                    continue;
                }

                for event_path in &event.paths {
                    if !event_path.is_file() {
                        continue;
                    }

                    match watcher.read_new_content(event_path) {
                        Ok(lines) if lines.is_empty() => continue,
                        Ok(lines) => {
                            if let Err(e) =
                                process_lines(event_path, &lines, &compiled)
                            {
                                log::error!(
                                    "Error processing {}: {}",
                                    event_path.display(),
                                    e
                                );
                            }
                        }
                        Err(e) => {
                            log::error!(
                                "Error reading {}: {}",
                                event_path.display(),
                                e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("Watch error: {}", e);
            }
        }
    }

    Ok(())
}

/// Parse new lines and run SIGMA rules against them, printing any detections.
#[cfg(feature = "live")]
fn process_lines(
    source_path: &Path,
    lines: &[String],
    compiled_rules: &[(String, String)],
) -> Result<()> {
    use crate::model::Event;

    // Build events from lines — treat each line as a JSON log or raw text
    let events: Vec<Event> = lines
        .iter()
        .map(|line| {
            // Try JSON first
            if let Ok(map) = serde_json::from_str::<HashMap<String, serde_json::Value>>(line) {
                let mut fields: HashMap<String, String> = HashMap::new();
                fields.insert("_raw".to_string(), line.clone());
                fields.insert(
                    "_source".to_string(),
                    source_path.display().to_string(),
                );
                for (k, v) in map {
                    match v {
                        serde_json::Value::String(s) => {
                            fields.insert(k, s);
                        }
                        other => {
                            fields.insert(k, other.to_string());
                        }
                    }
                }
                Event {
                    fields,
                    raw: line.clone(),
                    source_file: source_path.display().to_string(),
                    source_format: crate::model::SourceFormat::JsonLines,
                    hash: None,
                }
            } else {
                // Fallback: raw text event
                let mut fields = HashMap::new();
                fields.insert("_raw".to_string(), line.clone());
                fields.insert("message".to_string(), line.clone());
                fields.insert(
                    "_source".to_string(),
                    source_path.display().to_string(),
                );
                Event {
                    fields,
                    raw: line.clone(),
                    source_file: source_path.display().to_string(),
                    source_format: crate::model::SourceFormat::JsonLines,
                    hash: None,
                }
            }
        })
        .collect();

    if events.is_empty() {
        return Ok(());
    }

    // Load into a temporary search engine
    let mut engine = crate::search::SearchEngine::new()?;
    engine.load_events(&events)?;

    // Run each compiled rule
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    for (rule_title, sql) in compiled_rules {
        match engine.query_sql(sql) {
            Ok(result) if result.count > 0 => {
                println!(
                    "[{}] ALERT: {} ({} hit{}) in {}",
                    now,
                    rule_title,
                    result.count,
                    if result.count == 1 { "" } else { "s" },
                    source_path.display()
                );
            }
            Ok(_) => {}
            Err(e) => {
                log::debug!("Rule '{}' query error: {}", rule_title, e);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_cursor_tracking() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.log");
        std::fs::write(&file_path, "line1\nline2\n").unwrap();

        let mut watcher = LiveWatcher::new();

        // Initially no cursor
        assert_eq!(watcher.cursor(&file_path), None);

        // Update cursor to current file size
        watcher.update_cursor(&file_path).unwrap();
        let cursor_val = watcher.cursor(&file_path).unwrap();
        assert_eq!(cursor_val, 12); // "line1\n" (6) + "line2\n" (6) = 12
    }

    #[test]
    fn test_read_new_content() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.log");

        // Write initial content
        {
            let mut f = std::fs::File::create(&file_path).unwrap();
            writeln!(f, "first line").unwrap();
            writeln!(f, "second line").unwrap();
        }

        let mut watcher = LiveWatcher::new();

        // First read should return all content
        let lines = watcher.read_new_content(&file_path).unwrap();
        assert_eq!(lines, vec!["first line", "second line"]);

        // Append more content
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&file_path)
                .unwrap();
            writeln!(f, "third line").unwrap();
        }

        // Second read should return only new content
        let lines = watcher.read_new_content(&file_path).unwrap();
        assert_eq!(lines, vec!["third line"]);

        // Reading again with no new content should return empty
        let lines = watcher.read_new_content(&file_path).unwrap();
        assert!(lines.is_empty());
    }
}
