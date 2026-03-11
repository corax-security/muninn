use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct TimelineEntry {
    pub timestamp: String,
    pub title: String,
    pub level: String,
    pub mitre: Vec<String>,
    pub count: usize,
}

/// Build a sorted timeline from detection results.
/// Each detection's matched events are inspected for timestamp fields.
pub fn build_timeline(
    detections: &[(String, String, Vec<String>, Vec<HashMap<String, String>>)],
    // (title, level, tags, rows)
) -> Vec<TimelineEntry> {
    let timestamp_fields = [
        "SystemTime",
        "timestamp",
        "@timestamp",
        "TimeCreated",
        "UtcTime",
        "date",
        "_time",
        "time",
        "datetime",
        "EventTime",
    ];

    let mut entries = Vec::new();

    for (title, level, tags, rows) in detections {
        let mitre_ids: Vec<String> = crate::mitre::MitreMapper::parse_tags(tags)
            .iter()
            .filter_map(|r| r.technique_id.clone())
            .collect();

        // Group events by timestamp
        let mut ts_counts: HashMap<String, usize> = HashMap::new();
        for row in rows {
            let ts = timestamp_fields
                .iter()
                .find_map(|f| row.get(*f))
                .cloned()
                .unwrap_or_default();
            if !ts.is_empty() {
                *ts_counts.entry(ts).or_default() += 1;
            }
        }

        if ts_counts.is_empty() {
            // No timestamps: single entry with empty timestamp
            entries.push(TimelineEntry {
                timestamp: String::new(),
                title: title.clone(),
                level: level.clone(),
                mitre: mitre_ids,
                count: rows.len(),
            });
        } else {
            // Use earliest timestamp as representative
            let mut timestamps: Vec<_> = ts_counts.into_iter().collect();
            timestamps.sort_by(|a, b| a.0.cmp(&b.0));
            let (first_ts, _) = &timestamps[0];
            entries.push(TimelineEntry {
                timestamp: first_ts.clone(),
                title: title.clone(),
                level: level.clone(),
                mitre: mitre_ids.clone(),
                count: rows.len(),
            });
        }
    }

    entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    entries
}

pub fn render_ascii_timeline(entries: &[TimelineEntry]) -> String {
    if entries.is_empty() {
        return "  No timeline entries.\n".into();
    }

    let mut output = String::new();
    output.push_str("\n  Attack Timeline\n");
    output.push_str(&format!("  {}\n", "═".repeat(80)));

    for entry in entries {
        let ts_display = if entry.timestamp.len() > 19 {
            &entry.timestamp[..19]
        } else if entry.timestamp.is_empty() {
            "  (no timestamp)   "
        } else {
            &entry.timestamp
        };

        let level_marker = match entry.level.as_str() {
            "critical" => "●",
            "high" => "●",
            "medium" => "●",
            "low" => "○",
            _ => "·",
        };

        let mitre_str = if entry.mitre.is_empty() {
            String::new()
        } else {
            format!(" [{}]", entry.mitre.join(", "))
        };

        output.push_str(&format!(
            "  {}  {} {:<8} {}{} ({} events)\n",
            ts_display,
            level_marker,
            entry.level.to_uppercase(),
            entry.title,
            mitre_str,
            entry.count,
        ));
    }

    output.push_str(&format!("  {}\n", "═".repeat(80)));
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_timeline_ordering() {
        let mut row1 = HashMap::new();
        row1.insert("SystemTime".into(), "2024-01-01T10:30:00".into());
        let mut row2 = HashMap::new();
        row2.insert("SystemTime".into(), "2024-01-01T10:00:00".into());

        let detections = vec![
            ("Late Rule".into(), "high".into(), vec![], vec![row1]),
            ("Early Rule".into(), "medium".into(), vec![], vec![row2]),
        ];

        let timeline = build_timeline(&detections);
        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[0].title, "Early Rule");
        assert_eq!(timeline[1].title, "Late Rule");
    }

    #[test]
    fn test_render_ascii() {
        let entries = vec![TimelineEntry {
            timestamp: "2024-01-01T10:00:00".into(),
            title: "Whoami".into(),
            level: "medium".into(),
            mitre: vec!["T1033".into()],
            count: 3,
        }];
        let output = render_ascii_timeline(&entries);
        assert!(output.contains("Whoami"));
        assert!(output.contains("T1033"));
        assert!(output.contains("3 events"));
    }
}
