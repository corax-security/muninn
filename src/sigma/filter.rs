use std::collections::{HashMap, HashSet};

use super::parser::Rule;
use crate::model::Event;

/// Pre-filters events based on logsource fields extracted from SIGMA rules.
/// This allows skipping events that can never match any rule, improving performance.
pub struct EventFilter {
    /// Required field values: field_name -> set of acceptable values
    required: HashMap<String, HashSet<String>>,
    /// If true, filter is empty and all events pass
    pass_all: bool,
}

impl EventFilter {
    /// Build a filter from SIGMA rules by extracting EventID/Channel requirements
    /// from detection selections.
    pub fn from_rules(rules: &[Rule]) -> Self {
        if rules.is_empty() {
            return Self {
                required: HashMap::new(),
                pass_all: true,
            };
        }

        let mut event_ids: HashSet<String> = HashSet::new();
        let mut channels: HashSet<String> = HashSet::new();

        for rule in rules {
            for (_name, value) in &rule.detection.selections {
                Self::extract_field_values(value, "EventID", &mut event_ids);
                Self::extract_field_values(value, "Channel", &mut channels);
            }
        }

        let mut required = HashMap::new();
        if !event_ids.is_empty() {
            required.insert("EventID".to_string(), event_ids);
        }
        if !channels.is_empty() {
            required.insert("Channel".to_string(), channels);
        }

        // If no filterable fields found, pass everything
        let pass_all = required.is_empty();

        Self { required, pass_all }
    }

    fn extract_field_values(
        value: &serde_yaml::Value,
        field: &str,
        out: &mut HashSet<String>,
    ) {
        match value {
            serde_yaml::Value::Mapping(map) => {
                for (k, v) in map {
                    let key = match k {
                        serde_yaml::Value::String(s) => s.clone(),
                        _ => continue,
                    };
                    // Handle field name with modifiers like "EventID|contains"
                    let base_field = key.split('|').next().unwrap_or(&key);
                    if base_field == field {
                        match v {
                            serde_yaml::Value::String(s) => {
                                out.insert(s.clone());
                            }
                            serde_yaml::Value::Number(n) => {
                                out.insert(n.to_string());
                            }
                            serde_yaml::Value::Sequence(seq) => {
                                for item in seq {
                                    match item {
                                        serde_yaml::Value::String(s) => {
                                            out.insert(s.clone());
                                        }
                                        serde_yaml::Value::Number(n) => {
                                            out.insert(n.to_string());
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            serde_yaml::Value::Sequence(seq) => {
                for item in seq {
                    Self::extract_field_values(item, field, out);
                }
            }
            _ => {}
        }
    }

    /// Check if an event matches the filter (i.e., could potentially match some rule).
    pub fn matches(&self, event: &Event) -> bool {
        if self.pass_all {
            return true;
        }

        // Event must match at least one required field
        // (we use OR across fields — if ANY required field matches, the event passes)
        for (field, values) in &self.required {
            if let Some(event_val) = event.fields.get(field) {
                if values.contains(event_val) {
                    return true;
                }
            }
        }

        // If no required fields matched, check if event has none of the required fields
        // (it might match a rule that doesn't filter on these fields)
        let has_any_required_field = self
            .required
            .keys()
            .any(|f| event.fields.contains_key(f));

        // If event doesn't have any of the filterable fields, let it pass
        // (it might be from a different log source entirely)
        !has_any_required_field
    }

    /// Return how many required fields are tracked
    pub fn field_count(&self) -> usize {
        self.required.len()
    }

    /// Return whether this filter passes all events
    pub fn is_pass_all(&self) -> bool {
        self.pass_all
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SourceFormat;

    #[test]
    fn test_empty_rules_pass_all() {
        let filter = EventFilter::from_rules(&[]);
        assert!(filter.is_pass_all());

        let event = Event::new("test.log", SourceFormat::JsonLines);
        assert!(filter.matches(&event));
    }

    #[test]
    fn test_filter_by_event_id() {
        // Create a rule that requires EventID=4624
        let yaml = r#"
title: Test Rule
detection:
    selection:
        EventID: 4624
    condition: selection
level: medium
"#;
        let rule: Rule = serde_yaml::from_str(yaml).unwrap();
        let filter = EventFilter::from_rules(&[rule]);

        assert!(!filter.is_pass_all());

        // Event with matching EventID should pass
        let mut event1 = Event::new("test.log", SourceFormat::JsonLines);
        event1.set("EventID", "4624");
        assert!(filter.matches(&event1));

        // Event with non-matching EventID should not pass
        let mut event2 = Event::new("test.log", SourceFormat::JsonLines);
        event2.set("EventID", "4625");
        assert!(!filter.matches(&event2));

        // Event without EventID should pass (different log source)
        let event3 = Event::new("test.log", SourceFormat::JsonLines);
        assert!(filter.matches(&event3));
    }

    #[test]
    fn test_filter_multiple_event_ids() {
        let yaml1 = r#"
title: Rule1
detection:
    selection:
        EventID: 4624
    condition: selection
level: medium
"#;
        let yaml2 = r#"
title: Rule2
detection:
    selection:
        EventID: 4688
    condition: selection
level: medium
"#;
        let rule1: Rule = serde_yaml::from_str(yaml1).unwrap();
        let rule2: Rule = serde_yaml::from_str(yaml2).unwrap();
        let filter = EventFilter::from_rules(&[rule1, rule2]);

        let mut event = Event::new("test.log", SourceFormat::JsonLines);
        event.set("EventID", "4688");
        assert!(filter.matches(&event));
    }
}
