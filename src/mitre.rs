use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub tactic: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MitreRef {
    pub technique_id: Option<String>,
    pub tactic: Option<String>,
}

pub const TACTIC_ORDER: &[&str] = &[
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
];

pub const TACTIC_DISPLAY: &[(&str, &str)] = &[
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion", "Defense Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
];

pub struct MitreMapper {
    techniques: HashMap<String, Technique>,
}

impl MitreMapper {
    pub fn new() -> Self {
        let mut techniques = HashMap::new();
        let entries: &[(&str, &str, &str)] = &[
            ("T1059", "Command and Scripting Interpreter", "execution"),
            ("T1059.001", "PowerShell", "execution"),
            ("T1059.003", "Windows Command Shell", "execution"),
            ("T1059.005", "Visual Basic", "execution"),
            ("T1059.006", "Python", "execution"),
            ("T1059.007", "JavaScript", "execution"),
            ("T1047", "Windows Management Instrumentation", "execution"),
            ("T1053", "Scheduled Task/Job", "execution"),
            ("T1053.005", "Scheduled Task", "execution"),
            ("T1569", "System Services", "execution"),
            ("T1569.002", "Service Execution", "execution"),
            ("T1204", "User Execution", "execution"),
            ("T1106", "Native API", "execution"),
            ("T1078", "Valid Accounts", "initial-access"),
            ("T1078.002", "Domain Accounts", "initial-access"),
            ("T1078.003", "Local Accounts", "initial-access"),
            ("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1566", "Phishing", "initial-access"),
            ("T1566.001", "Spearphishing Attachment", "initial-access"),
            ("T1566.002", "Spearphishing Link", "initial-access"),
            ("T1133", "External Remote Services", "initial-access"),
            ("T1547", "Boot or Logon Autostart Execution", "persistence"),
            ("T1547.001", "Registry Run Keys / Startup Folder", "persistence"),
            ("T1543", "Create or Modify System Process", "persistence"),
            ("T1543.003", "Windows Service", "persistence"),
            ("T1546", "Event Triggered Execution", "persistence"),
            ("T1136", "Create Account", "persistence"),
            ("T1136.001", "Local Account", "persistence"),
            ("T1098", "Account Manipulation", "persistence"),
            ("T1574", "Hijack Execution Flow", "persistence"),
            ("T1574.001", "DLL Search Order Hijacking", "persistence"),
            ("T1574.002", "DLL Side-Loading", "persistence"),
            ("T1548", "Abuse Elevation Control Mechanism", "privilege-escalation"),
            ("T1548.002", "Bypass User Account Control", "privilege-escalation"),
            ("T1134", "Access Token Manipulation", "privilege-escalation"),
            ("T1068", "Exploitation for Privilege Escalation", "privilege-escalation"),
            ("T1055", "Process Injection", "defense-evasion"),
            ("T1055.001", "Dynamic-link Library Injection", "defense-evasion"),
            ("T1055.012", "Process Hollowing", "defense-evasion"),
            ("T1070", "Indicator Removal", "defense-evasion"),
            ("T1070.001", "Clear Windows Event Logs", "defense-evasion"),
            ("T1070.004", "File Deletion", "defense-evasion"),
            ("T1036", "Masquerading", "defense-evasion"),
            ("T1036.003", "Rename System Utilities", "defense-evasion"),
            ("T1036.005", "Match Legitimate Name or Location", "defense-evasion"),
            ("T1027", "Obfuscated Files or Information", "defense-evasion"),
            ("T1562", "Impair Defenses", "defense-evasion"),
            ("T1562.001", "Disable or Modify Tools", "defense-evasion"),
            ("T1112", "Modify Registry", "defense-evasion"),
            ("T1218", "System Binary Proxy Execution", "defense-evasion"),
            ("T1218.001", "Compiled HTML File", "defense-evasion"),
            ("T1218.005", "Mshta", "defense-evasion"),
            ("T1218.010", "Regsvr32", "defense-evasion"),
            ("T1218.011", "Rundll32", "defense-evasion"),
            ("T1003", "OS Credential Dumping", "credential-access"),
            ("T1003.001", "LSASS Memory", "credential-access"),
            ("T1003.002", "Security Account Manager", "credential-access"),
            ("T1003.003", "NTDS", "credential-access"),
            ("T1003.006", "DCSync", "credential-access"),
            ("T1110", "Brute Force", "credential-access"),
            ("T1110.001", "Password Guessing", "credential-access"),
            ("T1110.003", "Password Spraying", "credential-access"),
            ("T1558", "Steal or Forge Kerberos Tickets", "credential-access"),
            ("T1558.003", "Kerberoasting", "credential-access"),
            ("T1552", "Unsecured Credentials", "credential-access"),
            ("T1087", "Account Discovery", "discovery"),
            ("T1082", "System Information Discovery", "discovery"),
            ("T1083", "File and Directory Discovery", "discovery"),
            ("T1057", "Process Discovery", "discovery"),
            ("T1018", "Remote System Discovery", "discovery"),
            ("T1016", "System Network Configuration Discovery", "discovery"),
            ("T1049", "System Network Connections Discovery", "discovery"),
            ("T1033", "System Owner/User Discovery", "discovery"),
            ("T1069", "Permission Groups Discovery", "discovery"),
            ("T1012", "Query Registry", "discovery"),
            ("T1007", "System Service Discovery", "discovery"),
            ("T1021", "Remote Services", "lateral-movement"),
            ("T1021.001", "Remote Desktop Protocol", "lateral-movement"),
            ("T1021.002", "SMB/Windows Admin Shares", "lateral-movement"),
            ("T1021.003", "Distributed Component Object Model", "lateral-movement"),
            ("T1021.006", "Windows Remote Management", "lateral-movement"),
            ("T1570", "Lateral Tool Transfer", "lateral-movement"),
            ("T1080", "Taint Shared Content", "lateral-movement"),
            ("T1560", "Archive Collected Data", "collection"),
            ("T1115", "Clipboard Data", "collection"),
            ("T1005", "Data from Local System", "collection"),
            ("T1039", "Data from Network Shared Drive", "collection"),
            ("T1113", "Screen Capture", "collection"),
            ("T1071", "Application Layer Protocol", "command-and-control"),
            ("T1071.001", "Web Protocols", "command-and-control"),
            ("T1071.004", "DNS", "command-and-control"),
            ("T1105", "Ingress Tool Transfer", "command-and-control"),
            ("T1572", "Protocol Tunneling", "command-and-control"),
            ("T1573", "Encrypted Channel", "command-and-control"),
            ("T1219", "Remote Access Software", "command-and-control"),
            ("T1132", "Data Encoding", "command-and-control"),
            ("T1048", "Exfiltration Over Alternative Protocol", "exfiltration"),
            ("T1041", "Exfiltration Over C2 Channel", "exfiltration"),
            ("T1567", "Exfiltration Over Web Service", "exfiltration"),
            ("T1486", "Data Encrypted for Impact", "impact"),
            ("T1490", "Inhibit System Recovery", "impact"),
            ("T1489", "Service Stop", "impact"),
            ("T1529", "System Shutdown/Reboot", "impact"),
            ("T1531", "Account Access Removal", "impact"),
            ("T1485", "Data Destruction", "impact"),
            ("T1499", "Endpoint Denial of Service", "impact"),
            ("T1595", "Active Scanning", "reconnaissance"),
            ("T1592", "Gather Victim Host Information", "reconnaissance"),
            ("T1589", "Gather Victim Identity Information", "reconnaissance"),
            ("T1588", "Obtain Capabilities", "resource-development"),
            ("T1588.002", "Tool", "resource-development"),
        ];

        for (id, name, tactic) in entries {
            techniques.insert(
                id.to_lowercase(),
                Technique {
                    id: id.to_string(),
                    name: name.to_string(),
                    tactic: tactic.to_string(),
                },
            );
        }

        MitreMapper { techniques }
    }

    pub fn parse_tags(tags: &[String]) -> Vec<MitreRef> {
        let mut refs = Vec::new();
        for tag in tags {
            let lower = tag.to_lowercase();
            if lower.starts_with("attack.t") {
                let id = lower.strip_prefix("attack.").unwrap_or(&lower);
                refs.push(MitreRef {
                    technique_id: Some(id.to_uppercase()),
                    tactic: None,
                });
            } else if lower.starts_with("attack.") {
                let tactic = lower.strip_prefix("attack.").unwrap_or(&lower);
                // Convert underscore to hyphen for tactic matching
                let tactic = tactic.replace('_', "-");
                refs.push(MitreRef {
                    technique_id: None,
                    tactic: Some(tactic),
                });
            }
        }
        refs
    }

    pub fn resolve(&self, id: &str) -> Option<&Technique> {
        self.techniques.get(&id.to_lowercase())
    }

    pub fn resolve_refs(&self, refs: &[MitreRef]) -> Vec<Technique> {
        let mut result = Vec::new();
        for r in refs {
            if let Some(ref id) = r.technique_id {
                if let Some(tech) = self.resolve(id) {
                    result.push(tech.clone());
                }
            }
        }
        result
    }
}

pub fn tactic_display_name(tactic: &str) -> &str {
    for (key, display) in TACTIC_DISPLAY {
        if *key == tactic {
            return display;
        }
    }
    tactic
}

/// Generate ATT&CK Navigator layer JSON
pub fn export_navigator_layer(
    detections: &[(Vec<MitreRef>, String, usize)], // (refs, level, count)
    mapper: &MitreMapper,
) -> serde_json::Value {
    let mut tech_scores: HashMap<String, (usize, String)> = HashMap::new();

    for (refs, level, count) in detections {
        for r in refs {
            if let Some(ref id) = r.technique_id {
                let entry = tech_scores.entry(id.clone()).or_insert((0, String::new()));
                entry.0 += count;
                if entry.1.is_empty() {
                    entry.1 = level.clone();
                }
            }
        }
    }

    let techniques: Vec<serde_json::Value> = tech_scores
        .iter()
        .map(|(id, (score, level))| {
            let color = match level.as_str() {
                "critical" => "#ff0000",
                "high" => "#ff6666",
                "medium" => "#ffcc00",
                "low" => "#66ccff",
                _ => "#99ccff",
            };
            let name = mapper
                .resolve(id)
                .map(|t| t.name.as_str())
                .unwrap_or("Unknown");
            serde_json::json!({
                "techniqueID": id,
                "score": score,
                "color": color,
                "comment": format!("{} ({} events)", name, score),
                "enabled": true,
            })
        })
        .collect();

    serde_json::json!({
        "name": "Muninn Detection Coverage",
        "versions": {
            "attack": "14",
            "navigator": "4.9",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "Generated by Muninn",
        "techniques": techniques,
        "gradient": {
            "colors": ["#66ccff", "#ffcc00", "#ff0000"],
            "minValue": 0,
            "maxValue": tech_scores.values().map(|v| v.0).max().unwrap_or(10)
        },
        "legendItems": [],
        "showTacticRowBackground": true,
        "tacticRowBackground": "#dddddd",
    })
}

/// Render kill chain ASCII view
pub fn render_killchain(
    detections: &[(String, Vec<MitreRef>, String, usize)], // (title, refs, level, count)
    mapper: &MitreMapper,
) -> String {
    let mut tactic_detections: HashMap<String, Vec<(String, String, usize)>> = HashMap::new();

    for (title, refs, level, count) in detections {
        let mut tactics_for_detection = std::collections::HashSet::new();
        // Resolve techniques to tactics
        for r in refs {
            if let Some(ref id) = r.technique_id {
                if let Some(tech) = mapper.resolve(id) {
                    tactics_for_detection.insert(tech.tactic.clone());
                }
            }
            if let Some(ref tactic) = r.tactic {
                tactics_for_detection.insert(tactic.clone());
            }
        }
        for tactic in tactics_for_detection {
            tactic_detections
                .entry(tactic)
                .or_default()
                .push((title.clone(), level.clone(), *count));
        }
    }

    let mut output = String::new();
    output.push_str("\n  Kill Chain View\n");
    output.push_str(&format!("  {}\n", "─".repeat(70)));

    for tactic_key in TACTIC_ORDER {
        if let Some(dets) = tactic_detections.get(*tactic_key) {
            let display = tactic_display_name(tactic_key);
            let items: Vec<String> = dets
                .iter()
                .map(|(title, _level, count)| format!("{} ({})", title, count))
                .collect();
            let max_severity = dets
                .iter()
                .map(|(_, l, _)| match l.as_str() {
                    "critical" => 4,
                    "high" => 3,
                    "medium" => 2,
                    _ => 1,
                })
                .max()
                .unwrap_or(0);
            let marker = match max_severity {
                4 => "■",
                3 => "■",
                2 => "■",
                _ => "□",
            };
            output.push_str(&format!(
                "  {} {:<22} {} {}\n",
                marker,
                display,
                "───",
                items.join(", ")
            ));
        }
    }

    output.push_str(&format!("  {}\n", "─".repeat(70)));
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tags() {
        let tags = vec![
            "attack.execution".to_string(),
            "attack.t1059.001".to_string(),
            "attack.defense_evasion".to_string(),
        ];
        let refs = MitreMapper::parse_tags(&tags);
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].tactic, Some("execution".into()));
        assert_eq!(refs[1].technique_id, Some("T1059.001".into()));
        assert_eq!(refs[2].tactic, Some("defense-evasion".into()));
    }

    #[test]
    fn test_resolve() {
        let mapper = MitreMapper::new();
        let tech = mapper.resolve("T1059.001").unwrap();
        assert_eq!(tech.name, "PowerShell");
        assert_eq!(tech.tactic, "execution");
    }

    #[test]
    fn test_resolve_case_insensitive() {
        let mapper = MitreMapper::new();
        assert!(mapper.resolve("t1059.001").is_some());
        assert!(mapper.resolve("T1059.001").is_some());
    }

    #[test]
    fn test_unknown_technique() {
        let mapper = MitreMapper::new();
        assert!(mapper.resolve("T9999").is_none());
    }

    #[test]
    fn test_navigator_export() {
        let mapper = MitreMapper::new();
        let refs = vec![MitreRef {
            technique_id: Some("T1059.001".into()),
            tactic: None,
        }];
        let detections = vec![(refs, "high".to_string(), 5)];
        let layer = export_navigator_layer(&detections, &mapper);
        assert!(layer["techniques"].as_array().unwrap().len() > 0);
        assert_eq!(layer["domain"], "enterprise-attack");
    }

    #[test]
    fn test_killchain_render() {
        let mapper = MitreMapper::new();
        let refs1 = vec![MitreRef {
            technique_id: Some("T1059.001".into()),
            tactic: None,
        }];
        let refs2 = vec![MitreRef {
            technique_id: Some("T1003.001".into()),
            tactic: None,
        }];
        let detections = vec![
            ("Encoded PowerShell".into(), refs1, "high".into(), 5),
            ("LSASS Dump".into(), refs2, "critical".into(), 2),
        ];
        let output = render_killchain(&detections, &mapper);
        assert!(output.contains("Execution"));
        assert!(output.contains("Credential Access"));
        assert!(output.contains("Encoded PowerShell"));
    }
}
