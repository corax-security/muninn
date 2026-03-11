use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct ThreatScore {
    pub entity: String,
    pub entity_type: String,
    pub score: f64,
    pub rules: Vec<(String, String, usize)>, // (title, level, count)
}

fn level_weight(level: &str) -> f64 {
    match level.to_lowercase().as_str() {
        "critical" => 10.0,
        "high" => 5.0,
        "medium" => 2.0,
        "low" => 1.0,
        "informational" | "info" => 0.5,
        _ => 0.0,
    }
}

/// Compute per-entity threat scores from detection results.
/// `detections`: (title, level, rows) tuples
pub fn compute_scores(
    detections: &[(String, String, Vec<HashMap<String, String>>)],
) -> Vec<ThreatScore> {
    let entity_fields = ["Computer", "hostname", "User", "SourceIp", "src_ip"];

    // entity -> (entity_type, Vec<(title, level, count)>)
    let mut entity_map: HashMap<String, (String, Vec<(String, String, usize)>)> = HashMap::new();

    for (title, level, rows) in detections {
        // Group by entity within each detection
        let mut entity_counts: HashMap<(String, String), usize> = HashMap::new();
        for row in rows {
            for field in &entity_fields {
                if let Some(val) = row.get(*field) {
                    if !val.is_empty() {
                        let etype = match *field {
                            "Computer" | "hostname" => "host",
                            "User" => "user",
                            "SourceIp" | "src_ip" => "ip",
                            _ => "unknown",
                        };
                        *entity_counts
                            .entry((val.clone(), etype.to_string()))
                            .or_default() += 1;
                    }
                }
            }
        }

        for ((entity, etype), count) in entity_counts {
            let entry = entity_map
                .entry(entity)
                .or_insert_with(|| (etype, Vec::new()));
            entry
                .1
                .push((title.clone(), level.clone(), count));
        }
    }

    let mut scores: Vec<ThreatScore> = entity_map
        .into_iter()
        .map(|(entity, (entity_type, rules))| {
            let raw_score: f64 = rules
                .iter()
                .map(|(_, level, count)| level_weight(level) * *count as f64)
                .sum();
            ThreatScore {
                entity,
                entity_type,
                score: raw_score,
                rules,
            }
        })
        .collect();

    // Normalize to 0-100
    let max_score = scores
        .iter()
        .map(|s| s.score)
        .fold(0.0f64, f64::max);

    if max_score > 0.0 {
        for s in &mut scores {
            s.score = (s.score / max_score * 100.0).round().min(100.0);
        }
    }

    scores.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    scores
}

pub fn render_scores(scores: &[ThreatScore]) -> String {
    if scores.is_empty() {
        return "  No threat scores computed.\n".into();
    }

    let mut output = String::new();
    output.push_str("\n  Threat Scores\n");
    output.push_str(&format!("  {}\n", "═".repeat(70)));
    output.push_str(&format!(
        "  {:<30} {:<6} {:>6}  {}\n",
        "Entity", "Type", "Score", "Top Rules"
    ));
    output.push_str(&format!("  {}\n", "─".repeat(70)));

    for score in scores.iter().take(20) {
        let top_rules: Vec<String> = score
            .rules
            .iter()
            .take(3)
            .map(|(title, _, count)| {
                let short: String = title.chars().take(20).collect();
                format!("{}({})", short, count)
            })
            .collect();

        let entity_display: String = score.entity.chars().take(28).collect();
        output.push_str(&format!(
            "  {:<30} {:<6} {:>5.0}  {}\n",
            entity_display,
            score.entity_type,
            score.score,
            top_rules.join(", "),
        ));
    }

    if scores.len() > 20 {
        output.push_str(&format!("  ... and {} more\n", scores.len() - 20));
    }

    output.push_str(&format!("  {}\n", "═".repeat(70)));
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_scores() {
        let mut row1 = HashMap::new();
        row1.insert("Computer".into(), "DC01".into());
        row1.insert("User".into(), "admin".into());

        let mut row2 = HashMap::new();
        row2.insert("Computer".into(), "DC01".into());

        let mut row3 = HashMap::new();
        row3.insert("Computer".into(), "WS01".into());

        let detections = vec![
            ("Critical Rule".into(), "critical".into(), vec![row1, row2]),
            ("Low Rule".into(), "low".into(), vec![row3]),
        ];

        let scores = compute_scores(&detections);
        assert!(!scores.is_empty());
        // DC01 should have higher score than WS01
        let dc01 = scores.iter().find(|s| s.entity == "DC01").unwrap();
        let ws01 = scores.iter().find(|s| s.entity == "WS01").unwrap();
        assert!(dc01.score > ws01.score);
    }

    #[test]
    fn test_normalize_to_100() {
        let mut row = HashMap::new();
        row.insert("Computer".into(), "HOST".into());
        let detections = vec![("Rule".into(), "critical".into(), vec![row])];
        let scores = compute_scores(&detections);
        assert_eq!(scores[0].score, 100.0);
    }
}
