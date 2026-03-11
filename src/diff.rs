use anyhow::Result;
use serde::Serialize;
use std::collections::HashSet;

use crate::search::SearchEngine;
use crate::sigma;

#[derive(Debug, Clone, Serialize)]
pub struct DiffResult {
    pub only_first: usize,
    pub only_second: usize,
    pub common: usize,
    pub new_detections: Vec<String>,
    pub resolved_detections: Vec<String>,
    pub common_detections: Vec<String>,
}

/// Compare two evidence sets.
/// Both engines should already have events loaded.
/// Rules are run against both and compared.
pub fn diff_evidence(
    engine_a: &SearchEngine,
    engine_b: &SearchEngine,
    rules: &[sigma::Rule],
) -> Result<DiffResult> {
    let mut detections_a: HashSet<String> = HashSet::new();
    let mut detections_b: HashSet<String> = HashSet::new();

    for rule in rules {
        if let Ok(sql) = sigma::compile(rule) {
            if let Ok(r) = engine_a.query_sql(&sql) {
                if r.count > 0 {
                    detections_a.insert(rule.title.clone());
                }
            }
            if let Ok(r) = engine_b.query_sql(&sql) {
                if r.count > 0 {
                    detections_b.insert(rule.title.clone());
                }
            }
        }
    }

    let common: HashSet<_> = detections_a.intersection(&detections_b).cloned().collect();
    let only_a: Vec<String> = detections_a.difference(&detections_b).cloned().collect();
    let only_b: Vec<String> = detections_b.difference(&detections_a).cloned().collect();

    let count_a = engine_a.event_count();
    let count_b = engine_b.event_count();

    Ok(DiffResult {
        only_first: count_a,
        only_second: count_b,
        common: common.len(),
        new_detections: only_b,
        resolved_detections: only_a,
        common_detections: common.into_iter().collect(),
    })
}

pub fn render_diff(diff: &DiffResult) -> String {
    let mut output = String::new();
    output.push_str("\n  Evidence Diff\n");
    output.push_str(&format!("  {}\n", "═".repeat(60)));
    output.push_str(&format!("  Events in first set:   {}\n", diff.only_first));
    output.push_str(&format!("  Events in second set:  {}\n", diff.only_second));
    output.push_str(&format!("  Common detections:     {}\n", diff.common));

    if !diff.new_detections.is_empty() {
        output.push_str(&format!(
            "\n  New detections (only in second set): {}\n",
            diff.new_detections.len()
        ));
        for d in &diff.new_detections {
            output.push_str(&format!("    + {}\n", d));
        }
    }

    if !diff.resolved_detections.is_empty() {
        output.push_str(&format!(
            "\n  Resolved detections (only in first set): {}\n",
            diff.resolved_detections.len()
        ));
        for d in &diff.resolved_detections {
            output.push_str(&format!("    - {}\n", d));
        }
    }

    if !diff.common_detections.is_empty() {
        output.push_str(&format!(
            "\n  Common detections: {}\n",
            diff.common_detections.len()
        ));
        for d in &diff.common_detections {
            output.push_str(&format!("    = {}\n", d));
        }
    }

    output.push_str(&format!("  {}\n", "═".repeat(60)));
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Event, SourceFormat};
    use std::collections::HashMap;

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
    fn test_diff_no_overlap() {
        let mut engine_a = SearchEngine::new().unwrap();
        let mut engine_b = SearchEngine::new().unwrap();

        engine_a
            .load_events(&[make_event(&[("CommandLine", "whoami")])])
            .unwrap();
        engine_b
            .load_events(&[make_event(&[("CommandLine", "ipconfig")])])
            .unwrap();

        let diff = diff_evidence(&engine_a, &engine_b, &[]).unwrap();
        assert_eq!(diff.only_first, 1);
        assert_eq!(diff.only_second, 1);
    }
}
