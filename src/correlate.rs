use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct AttackChain {
    pub id: String,
    pub entity: String,
    pub events: Vec<ChainEvent>,
    pub duration_sec: f64,
    pub tactics: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainEvent {
    pub timestamp: String,
    pub rule_title: String,
    pub level: String,
    pub key_fields: HashMap<String, String>,
}

const TIMESTAMP_FIELDS: &[&str] = &[
    "SystemTime",
    "timestamp",
    "@timestamp",
    "TimeCreated",
    "UtcTime",
    "date",
    "_time",
    "time",
    "datetime",
];

const CORRELATION_FIELDS: &[&str] = &["User", "Computer", "hostname", "LogonId", "ProcessId"];

/// Correlate detections into attack chains based on shared entity fields.
pub fn correlate(
    detections: &[(String, String, Vec<String>, Vec<HashMap<String, String>>)],
    // (title, level, tags, rows)
) -> Vec<AttackChain> {
    // entity -> Vec<ChainEvent>
    let mut entity_events: HashMap<String, Vec<ChainEvent>> = HashMap::new();

    for (title, level, tags, rows) in detections {
        let mitre_tactics: Vec<String> = crate::mitre::MitreMapper::parse_tags(tags)
            .iter()
            .filter_map(|r| r.tactic.clone())
            .collect();

        for row in rows {
            // Find correlation entity
            let entity = CORRELATION_FIELDS
                .iter()
                .find_map(|f| row.get(*f).filter(|v| !v.is_empty()))
                .cloned()
                .unwrap_or_default();

            if entity.is_empty() {
                continue;
            }

            let timestamp = TIMESTAMP_FIELDS
                .iter()
                .find_map(|f| row.get(*f).filter(|v| !v.is_empty()))
                .cloned()
                .unwrap_or_default();

            let mut key_fields = HashMap::new();
            for field in &["Image", "CommandLine", "EventID", "SourceIp", "DestinationIp"] {
                if let Some(val) = row.get(*field) {
                    if !val.is_empty() {
                        key_fields.insert(field.to_string(), val.clone());
                    }
                }
            }

            let event = ChainEvent {
                timestamp,
                rule_title: title.clone(),
                level: level.clone(),
                key_fields,
            };

            entity_events
                .entry(entity)
                .or_default()
                .push(event);

            // Store tactics for this entity
            for t in &mitre_tactics {
                entity_events
                    .entry(format!("__tactic_{}_{}", row.get("Computer").or(row.get("User")).unwrap_or(&String::new()), t))
                    .or_default();
            }
        }
    }

    // Build chains from entities with 2+ events from different rules
    let mut chains = Vec::new();
    let mut chain_id = 0;

    for (entity, mut events) in entity_events {
        if entity.starts_with("__tactic_") {
            continue;
        }
        if events.len() < 2 {
            continue;
        }

        // Sort by timestamp
        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        // Check if events come from different rules
        let unique_rules: std::collections::HashSet<_> =
            events.iter().map(|e| &e.rule_title).collect();
        if unique_rules.len() < 2 {
            continue;
        }

        // Collect unique tactics
        let mapper = crate::mitre::MitreMapper::new();
        let mut tactics: Vec<String> = Vec::new();
        for (title, _level, tags, _rows) in detections {
            if unique_rules.contains(title) {
                for r in crate::mitre::MitreMapper::parse_tags(tags) {
                    if let Some(ref id) = r.technique_id {
                        if let Some(tech) = mapper.resolve(id) {
                            if !tactics.contains(&tech.tactic) {
                                tactics.push(tech.tactic.clone());
                            }
                        }
                    }
                    if let Some(ref t) = r.tactic {
                        if !tactics.contains(t) {
                            tactics.push(t.clone());
                        }
                    }
                }
            }
        }

        chain_id += 1;
        chains.push(AttackChain {
            id: format!("chain_{}", chain_id),
            entity: entity.clone(),
            events,
            duration_sec: 0.0, // Would need proper timestamp parsing
            tactics,
        });
    }

    // Sort by number of events descending
    chains.sort_by(|a, b| b.events.len().cmp(&a.events.len()));
    chains
}

pub fn render_chains(chains: &[AttackChain]) -> String {
    if chains.is_empty() {
        return "  No attack chains detected.\n".into();
    }

    let mut output = String::new();
    output.push_str("\n  Attack Chain Correlation\n");
    output.push_str(&format!("  {}\n", "═".repeat(70)));

    for chain in chains.iter().take(10) {
        output.push_str(&format!(
            "\n  Chain {} — Entity: {} ({} events, {} tactics)\n",
            chain.id,
            chain.entity,
            chain.events.len(),
            chain.tactics.len(),
        ));
        if !chain.tactics.is_empty() {
            let tactic_names: Vec<&str> = chain
                .tactics
                .iter()
                .map(|t| crate::mitre::tactic_display_name(t))
                .collect();
            output.push_str(&format!("  Tactics: {}\n", tactic_names.join(" → ")));
        }
        output.push_str(&format!("  {}\n", "─".repeat(60)));
        for event in chain.events.iter().take(20) {
            let ts = if event.timestamp.is_empty() {
                "(no time)"
            } else if event.timestamp.len() > 19 {
                &event.timestamp[..19]
            } else {
                &event.timestamp
            };
            output.push_str(&format!(
                "    {} | {:<8} | {}\n",
                ts,
                event.level.to_uppercase(),
                event.rule_title,
            ));
        }
        if chain.events.len() > 20 {
            output.push_str(&format!(
                "    ... and {} more events\n",
                chain.events.len() - 20
            ));
        }
    }

    output.push_str(&format!("\n  {}\n", "═".repeat(70)));
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlate_single_chain() {
        let mut row1 = HashMap::new();
        row1.insert("User".into(), "admin".into());
        row1.insert("SystemTime".into(), "2024-01-01T10:00:00".into());
        row1.insert("Image".into(), "whoami.exe".into());

        let mut row2 = HashMap::new();
        row2.insert("User".into(), "admin".into());
        row2.insert("SystemTime".into(), "2024-01-01T10:05:00".into());
        row2.insert("Image".into(), "mimikatz.exe".into());

        let detections = vec![
            (
                "Recon".into(),
                "medium".into(),
                vec!["attack.discovery".into()],
                vec![row1],
            ),
            (
                "CredDump".into(),
                "critical".into(),
                vec!["attack.credential-access".into()],
                vec![row2],
            ),
        ];

        let chains = correlate(&detections);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].entity, "admin");
        assert_eq!(chains[0].events.len(), 2);
    }

    #[test]
    fn test_no_chain_single_rule() {
        let mut row1 = HashMap::new();
        row1.insert("User".into(), "admin".into());
        let mut row2 = HashMap::new();
        row2.insert("User".into(), "admin".into());

        let detections = vec![(
            "Same Rule".into(),
            "medium".into(),
            vec![],
            vec![row1, row2],
        )];

        let chains = correlate(&detections);
        // Should not create chain - only 1 unique rule
        assert!(chains.is_empty());
    }
}
