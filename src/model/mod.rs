use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceFormat {
    Evtx,
    JsonLines,
    JsonArray,
    Csv,
    Tsv,
    Xml,
    Auditd,
    SysmonLinux,
    Syslog,
    Cef,
    Leef,
    W3cExtended,
    ZeekTsv,
    MacosUnifiedLog,
    PlainText,
}

impl std::fmt::Display for SourceFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Evtx => write!(f, "EVTX"),
            Self::JsonLines => write!(f, "JSON Lines"),
            Self::JsonArray => write!(f, "JSON Array"),
            Self::Csv => write!(f, "CSV"),
            Self::Tsv => write!(f, "TSV"),
            Self::Xml => write!(f, "XML"),
            Self::Auditd => write!(f, "Auditd"),
            Self::SysmonLinux => write!(f, "Sysmon for Linux"),
            Self::Syslog => write!(f, "Syslog"),
            Self::Cef => write!(f, "CEF"),
            Self::Leef => write!(f, "LEEF"),
            Self::W3cExtended => write!(f, "W3C Extended Log"),
            Self::ZeekTsv => write!(f, "Zeek TSV"),
            Self::MacosUnifiedLog => write!(f, "macOS Unified Log"),
            Self::PlainText => write!(f, "Plain Text"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub fields: HashMap<String, String>,
    pub raw: String,
    pub source_file: String,
    pub source_format: SourceFormat,
    pub hash: Option<u64>,
}

impl Event {
    pub fn new(source_file: &str, source_format: SourceFormat) -> Self {
        Event {
            fields: HashMap::new(),
            raw: String::new(),
            source_file: source_file.to_string(),
            source_format,
            hash: None,
        }
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let v = value.into();
        if !v.is_empty() {
            self.fields.insert(key.into(), v);
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(|s| s.as_str())
    }

    pub fn apply_field_map(&mut self, map: &std::collections::HashMap<String, String>) {
        for (old, new) in map {
            if let Some(val) = self.fields.remove(old) {
                self.fields.insert(new.clone(), val);
            }
        }
    }

    pub fn compute_hash(&mut self) {
        let hash = xxhash_rust::xxh64::xxh64(self.raw.as_bytes(), 0);
        self.hash = Some(hash);
    }

    pub fn from_json_value(
        value: &serde_json::Value,
        source_file: &str,
        source_format: SourceFormat,
    ) -> Self {
        let mut event = Event::new(source_file, source_format);
        event.raw = serde_json::to_string(value).unwrap_or_default();

        if let Some(obj) = value.as_object() {
            for (k, v) in obj {
                let str_val = match v {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Null => continue,
                    other => other.to_string(),
                };
                if !str_val.is_empty() {
                    event.fields.insert(k.clone(), str_val);
                }
            }
        }

        event
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ParseResult {
    pub events: Vec<Event>,
    pub source_file: String,
    pub source_format: SourceFormat,
    pub parse_errors: usize,
    pub duration_ms: u64,
}
