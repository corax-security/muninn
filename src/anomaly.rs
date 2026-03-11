use anyhow::Result;
use serde::Serialize;
use std::collections::HashMap;

use crate::search::SearchEngine;

#[derive(Debug, Clone, Serialize)]
pub struct Anomaly {
    pub category: String,
    pub description: String,
    pub severity: String,
    pub score: f64,
    pub evidence: Vec<HashMap<String, String>>,
}

pub fn detect_anomalies(engine: &SearchEngine) -> Result<Vec<Anomaly>> {
    let mut anomalies = Vec::new();

    // 1. Rare processes (seen <= 2 times)
    if engine.fields().iter().any(|f| f == "Image") {
        let result = engine.query_sql(
            "SELECT \"Image\", COUNT(*) as cnt FROM \"events\" \
             WHERE \"Image\" IS NOT NULL AND \"Image\" != '' \
             GROUP BY \"Image\" HAVING cnt <= 2 ORDER BY cnt ASC",
        )?;
        if result.count > 0 {
            anomalies.push(Anomaly {
                category: "rare_process".into(),
                description: format!(
                    "{} rare process(es) seen only 1-2 times",
                    result.count
                ),
                severity: "medium".into(),
                score: (result.count as f64).min(10.0),
                evidence: result.rows,
            });
        }
    }

    // 2. Off-hours logons (outside 8:00-18:00)
    if engine.fields().iter().any(|f| f == "EventID")
        && engine.fields().iter().any(|f| f == "SystemTime")
    {
        let result = engine.query_sql(
            "SELECT \"SystemTime\", \"User\", \"LogonType\", \"SourceIp\" FROM \"events\" \
             WHERE \"EventID\" = '4624' \
             AND CAST(SUBSTR(\"SystemTime\", 12, 2) AS INTEGER) NOT BETWEEN 8 AND 18",
        )?;
        if result.count > 0 {
            anomalies.push(Anomaly {
                category: "off_hours_logon".into(),
                description: format!("{} logon(s) outside business hours (08-18)", result.count),
                severity: "low".into(),
                score: (result.count as f64 * 0.5).min(10.0),
                evidence: result.rows,
            });
        }
    }

    // 3. Rare parent-child process combinations
    if engine.fields().iter().any(|f| f == "ParentImage")
        && engine.fields().iter().any(|f| f == "Image")
    {
        let result = engine.query_sql(
            "SELECT \"ParentImage\", \"Image\", COUNT(*) as cnt FROM \"events\" \
             WHERE \"ParentImage\" IS NOT NULL AND \"ParentImage\" != '' \
             AND \"Image\" IS NOT NULL AND \"Image\" != '' \
             GROUP BY \"ParentImage\", \"Image\" HAVING cnt = 1 \
             ORDER BY \"ParentImage\"",
        )?;
        if result.count > 0 {
            anomalies.push(Anomaly {
                category: "rare_parent_child".into(),
                description: format!(
                    "{} unique parent-child process pair(s) seen only once",
                    result.count
                ),
                severity: "medium".into(),
                score: (result.count as f64 * 0.5).min(10.0),
                evidence: result.rows,
            });
        }
    }

    // 4. Failed logons (potential brute force)
    if engine.fields().iter().any(|f| f == "EventID") {
        let result = engine.query_sql(
            "SELECT \"User\", \"SourceIp\", COUNT(*) as cnt FROM \"events\" \
             WHERE \"EventID\" = '4625' \
             GROUP BY \"User\", \"SourceIp\" HAVING cnt >= 5 \
             ORDER BY cnt DESC",
        )?;
        if result.count > 0 {
            anomalies.push(Anomaly {
                category: "brute_force".into(),
                description: format!(
                    "{} source(s) with 5+ failed logon attempts",
                    result.count
                ),
                severity: "high".into(),
                score: (result.count as f64 * 2.0).min(10.0),
                evidence: result.rows,
            });
        }
    }

    // 5. Commands with high entropy (potential obfuscation)
    // This requires in-app computation since SQLite doesn't have entropy function
    if engine.fields().iter().any(|f| f == "CommandLine") {
        let result = engine.query_sql(
            "SELECT \"CommandLine\", \"Image\" FROM \"events\" \
             WHERE \"CommandLine\" IS NOT NULL AND LENGTH(\"CommandLine\") > 200",
        )?;
        let mut high_entropy_rows = Vec::new();
        for row in &result.rows {
            if let Some(cmd) = row.get("CommandLine") {
                let entropy = shannon_entropy(cmd);
                if entropy > 4.5 {
                    let mut r = row.clone();
                    r.insert("_entropy".into(), format!("{:.2}", entropy));
                    high_entropy_rows.push(r);
                }
            }
        }
        if !high_entropy_rows.is_empty() {
            anomalies.push(Anomaly {
                category: "high_entropy_command".into(),
                description: format!(
                    "{} command(s) with high entropy (>4.5), possible obfuscation",
                    high_entropy_rows.len()
                ),
                severity: "medium".into(),
                score: (high_entropy_rows.len() as f64).min(10.0),
                evidence: high_entropy_rows,
            });
        }
    }

    Ok(anomalies)
}

fn shannon_entropy(s: &str) -> f64 {
    let mut freq = [0u32; 256];
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn render_anomalies(anomalies: &[Anomaly]) -> String {
    if anomalies.is_empty() {
        return "  No anomalies detected.\n".into();
    }

    let mut output = String::new();
    output.push_str("\n  Anomaly Detection Results\n");
    output.push_str(&format!("  {}\n", "═".repeat(70)));

    for anomaly in anomalies {
        let marker = match anomaly.severity.as_str() {
            "high" | "critical" => "●",
            "medium" => "●",
            _ => "○",
        };
        output.push_str(&format!(
            "  {} {:<8} {} (score: {:.1}, {} evidence rows)\n",
            marker,
            anomaly.severity.to_uppercase(),
            anomaly.description,
            anomaly.score,
            anomaly.evidence.len(),
        ));
    }

    output.push_str(&format!("  {}\n", "═".repeat(70)));
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Event, SourceFormat};

    fn make_event(fields: &[(&str, &str)]) -> Event {
        let mut event = Event::new("test.log", SourceFormat::JsonLines);
        for (k, v) in fields {
            event.set(*k, *v);
        }
        event.raw = serde_json::to_string(
            &fields.iter().map(|(k, v)| (*k, *v)).collect::<HashMap<_, _>>(),
        )
        .unwrap();
        event.fields.insert("_raw".into(), event.raw.clone());
        event
    }

    #[test]
    fn test_rare_process_detection() {
        let mut engine = SearchEngine::new().unwrap();
        let mut events = Vec::new();
        // 50 common processes
        for _ in 0..50 {
            events.push(make_event(&[("Image", "svchost.exe")]));
        }
        // 1 rare process
        events.push(make_event(&[("Image", "evil_malware.exe")]));

        engine.load_events(&events).unwrap();
        let anomalies = detect_anomalies(&engine).unwrap();
        assert!(anomalies.iter().any(|a| a.category == "rare_process"));
    }
}
