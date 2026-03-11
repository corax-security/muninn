use anyhow::{bail, Result};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum OutputFormat {
    Splunk,
    Elk,
    Timesketch,
    Csv,
    Sarif,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionData {
    pub title: String,
    pub level: String,
    pub count: usize,
    pub duration_ms: u64,
    pub tags: Vec<String>,
    pub events: Vec<HashMap<String, String>>,
}

impl OutputFormat {
    pub fn from_name(name: &str) -> Result<Self> {
        match name.to_lowercase().as_str() {
            "splunk" => Ok(OutputFormat::Splunk),
            "elk" | "elastic" | "elasticsearch" => Ok(OutputFormat::Elk),
            "timesketch" => Ok(OutputFormat::Timesketch),
            "csv" => Ok(OutputFormat::Csv),
            "sarif" => Ok(OutputFormat::Sarif),
            _ => bail!("Unknown template: '{}'. Available: splunk, elk, timesketch, csv, sarif", name),
        }
    }

    pub fn render(&self, detections: &[DetectionData]) -> Result<String> {
        match self {
            OutputFormat::Splunk => render_splunk(detections),
            OutputFormat::Elk => render_elk(detections),
            OutputFormat::Timesketch => render_timesketch(detections),
            OutputFormat::Csv => render_csv(detections),
            OutputFormat::Sarif => render_sarif(detections),
        }
    }

    pub fn default_extension(&self) -> &str {
        match self {
            OutputFormat::Splunk => "ndjson",
            OutputFormat::Elk => "ndjson",
            OutputFormat::Timesketch => "jsonl",
            OutputFormat::Csv => "csv",
            OutputFormat::Sarif => "sarif.json",
        }
    }
}

fn find_timestamp(event: &HashMap<String, String>) -> String {
    let ts_fields = ["SystemTime", "timestamp", "@timestamp", "TimeCreated", "UtcTime", "date", "_time", "time"];
    for f in &ts_fields {
        if let Some(v) = event.get(*f) {
            if !v.is_empty() {
                return v.clone();
            }
        }
    }
    String::new()
}

fn render_splunk(detections: &[DetectionData]) -> Result<String> {
    let mut lines = Vec::new();
    for det in detections {
        for event in &det.events {
            let ts = find_timestamp(event);
            let mut obj = serde_json::Map::new();
            obj.insert("_time".into(), serde_json::json!(ts));
            obj.insert("source".into(), serde_json::json!("muninn"));
            obj.insert("sourcetype".into(), serde_json::json!(format!("muninn:{}", det.level)));
            obj.insert("rule_title".into(), serde_json::json!(det.title));
            obj.insert("rule_level".into(), serde_json::json!(det.level));
            for (k, v) in event {
                obj.insert(k.clone(), serde_json::json!(v));
            }
            lines.push(serde_json::to_string(&serde_json::Value::Object(obj))?);
        }
    }
    Ok(lines.join("\n"))
}

fn render_elk(detections: &[DetectionData]) -> Result<String> {
    let mut lines = Vec::new();
    for det in detections {
        for event in &det.events {
            let ts = find_timestamp(event);
            let mut obj = serde_json::Map::new();
            obj.insert("@timestamp".into(), serde_json::json!(ts));
            obj.insert("_index".into(), serde_json::json!("muninn-detections"));
            obj.insert("rule.name".into(), serde_json::json!(det.title));
            obj.insert("rule.severity".into(), serde_json::json!(det.level));
            obj.insert("tags".into(), serde_json::json!(det.tags));
            for (k, v) in event {
                obj.insert(k.clone(), serde_json::json!(v));
            }
            lines.push(serde_json::to_string(&serde_json::Value::Object(obj))?);
        }
    }
    Ok(lines.join("\n"))
}

fn render_timesketch(detections: &[DetectionData]) -> Result<String> {
    let mut lines = Vec::new();
    for det in detections {
        for event in &det.events {
            let ts = find_timestamp(event);
            let message = event
                .iter()
                .filter(|(k, _)| *k != "SystemTime" && *k != "timestamp")
                .take(5)
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(" | ");
            let obj = serde_json::json!({
                "datetime": ts,
                "timestamp_desc": "Event Time",
                "message": format!("[{}] {} — {}", det.level.to_uppercase(), det.title, message),
                "tag": det.tags,
                "rule_title": det.title,
                "rule_level": det.level,
            });
            lines.push(serde_json::to_string(&obj)?);
        }
    }
    Ok(lines.join("\n"))
}

fn render_csv(detections: &[DetectionData]) -> Result<String> {
    let mut lines = Vec::new();
    lines.push("rule_title,rule_level,count,tags".into());
    for det in detections {
        let tags_str = det.tags.join(";");
        lines.push(format!(
            "\"{}\",\"{}\",{},\"{}\"",
            det.title.replace('"', "\"\""),
            det.level,
            det.count,
            tags_str.replace('"', "\"\""),
        ));
    }
    Ok(lines.join("\n"))
}

fn render_sarif(detections: &[DetectionData]) -> Result<String> {
    let results: Vec<serde_json::Value> = detections
        .iter()
        .map(|det| {
            serde_json::json!({
                "ruleId": det.title,
                "level": match det.level.as_str() {
                    "critical" | "high" => "error",
                    "medium" => "warning",
                    _ => "note",
                },
                "message": {
                    "text": format!("{} — {} events matched", det.title, det.count)
                },
                "properties": {
                    "severity": det.level,
                    "count": det.count,
                    "tags": det.tags,
                }
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Muninn",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/corax-security/muninn",
                }
            },
            "results": results,
        }]
    });

    Ok(serde_json::to_string_pretty(&sarif)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_detections() -> Vec<DetectionData> {
        let mut event = HashMap::new();
        event.insert("SystemTime".into(), "2024-01-01T10:00:00".into());
        event.insert("CommandLine".into(), "whoami".into());

        vec![DetectionData {
            title: "Whoami Execution".into(),
            level: "medium".into(),
            count: 1,
            duration_ms: 5,
            tags: vec!["attack.discovery".into()],
            events: vec![event],
        }]
    }

    #[test]
    fn test_splunk_format() {
        let dets = sample_detections();
        let output = render_splunk(&dets).unwrap();
        assert!(output.contains("muninn"));
        assert!(output.contains("Whoami"));
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.get("_time").is_some());
    }

    #[test]
    fn test_elk_format() {
        let dets = sample_detections();
        let output = render_elk(&dets).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.get("@timestamp").is_some());
    }

    #[test]
    fn test_csv_format() {
        let dets = sample_detections();
        let output = render_csv(&dets).unwrap();
        assert!(output.contains("rule_title,rule_level"));
        assert!(output.contains("Whoami"));
    }

    #[test]
    fn test_sarif_format() {
        let dets = sample_detections();
        let output = render_sarif(&dets).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
    }

    #[test]
    fn test_timesketch_format() {
        let dets = sample_detections();
        let output = render_timesketch(&dets).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.get("datetime").is_some());
    }

    #[test]
    fn test_from_name() {
        assert!(OutputFormat::from_name("splunk").is_ok());
        assert!(OutputFormat::from_name("elk").is_ok());
        assert!(OutputFormat::from_name("unknown").is_err());
    }
}
