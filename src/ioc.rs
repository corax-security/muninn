use anyhow::Result;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;

use crate::search::SearchEngine;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum IocType {
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Md5,
    Sha1,
    Sha256,
    Email,
}

impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IocType::Ipv4 => write!(f, "IPv4"),
            IocType::Ipv6 => write!(f, "IPv6"),
            IocType::Domain => write!(f, "Domain"),
            IocType::Url => write!(f, "URL"),
            IocType::Md5 => write!(f, "MD5"),
            IocType::Sha1 => write!(f, "SHA1"),
            IocType::Sha256 => write!(f, "SHA256"),
            IocType::Email => write!(f, "Email"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Ioc {
    pub ioc_type: IocType,
    pub value: String,
    pub count: usize,
    pub source_fields: Vec<String>,
}

pub fn extract_iocs(engine: &SearchEngine) -> Result<Vec<Ioc>> {
    // Query all raw data
    let _raw_query = engine.query_sql("SELECT \"_raw\" FROM \"events\" WHERE \"_raw\" IS NOT NULL AND \"_raw\" != ''")?;

    let mut ioc_counts: HashMap<(IocType, String), usize> = HashMap::new();

    let ipv4_re = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")?;
    let md5_re = Regex::new(r"\b([a-fA-F0-9]{32})\b")?;
    let sha1_re = Regex::new(r"\b([a-fA-F0-9]{40})\b")?;
    let sha256_re = Regex::new(r"\b([a-fA-F0-9]{64})\b")?;
    let url_re = Regex::new(r#"https?://[^\s'"<>\])}]+"#)?;
    let email_re = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")?;
    let domain_re = Regex::new(
        r#"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.(?:com|net|org|io|xyz|top|ru|cn|tk|pw|info|biz|cc|me|co|uk|de|fr|jp|br|in|au|gov|edu|mil))\b"#
    )?;

    // We need raw field - but execute_query skips _raw. Query differently.
    let raw_result = engine.query_sql(
        "SELECT * FROM \"events\""
    )?;

    for row in &raw_result.rows {
        let text: String = row.values().cloned().collect::<Vec<_>>().join(" ");

        // IPv4
        for cap in ipv4_re.captures_iter(&text) {
            let ip = cap[1].to_string();
            if is_valid_public_ip(&ip) {
                *ioc_counts.entry((IocType::Ipv4, ip)).or_default() += 1;
            }
        }

        // SHA256 (check before SHA1 and MD5 to avoid substrings)
        for cap in sha256_re.captures_iter(&text) {
            let hash = cap[1].to_lowercase();
            *ioc_counts.entry((IocType::Sha256, hash)).or_default() += 1;
        }

        // SHA1
        for cap in sha1_re.captures_iter(&text) {
            let hash = cap[1].to_lowercase();
            // Skip if it's part of a SHA256
            if hash.len() == 40 {
                *ioc_counts.entry((IocType::Sha1, hash)).or_default() += 1;
            }
        }

        // MD5
        for cap in md5_re.captures_iter(&text) {
            let hash = cap[1].to_lowercase();
            if hash.len() == 32 {
                *ioc_counts.entry((IocType::Md5, hash)).or_default() += 1;
            }
        }

        // URLs
        for m in url_re.find_iter(&text) {
            let url = m.as_str().to_string();
            *ioc_counts.entry((IocType::Url, url)).or_default() += 1;
        }

        // Emails
        for cap in email_re.captures_iter(&text) {
            let email = cap[1].to_lowercase();
            *ioc_counts.entry((IocType::Email, email)).or_default() += 1;
        }

        // Domains (from DNS fields primarily)
        for cap in domain_re.captures_iter(&text) {
            let domain = cap[1].to_lowercase();
            *ioc_counts.entry((IocType::Domain, domain)).or_default() += 1;
        }
    }

    let mut iocs: Vec<Ioc> = ioc_counts
        .into_iter()
        .map(|((ioc_type, value), count)| Ioc {
            ioc_type,
            value,
            count,
            source_fields: vec![],
        })
        .collect();

    iocs.sort_by(|a, b| b.count.cmp(&a.count));
    Ok(iocs)
}

fn is_valid_public_ip(ip: &str) -> bool {
    let parts: Vec<u8> = ip
        .split('.')
        .filter_map(|p| p.parse().ok())
        .collect();
    if parts.len() != 4 {
        return false;
    }
    // Exclude private, loopback, link-local, multicast
    !(parts[0] == 10
        || (parts[0] == 172 && (16..=31).contains(&parts[1]))
        || (parts[0] == 192 && parts[1] == 168)
        || parts[0] == 127
        || parts[0] == 0
        || parts[0] >= 224)
}

pub fn render_iocs(iocs: &[Ioc]) -> String {
    if iocs.is_empty() {
        return "  No IOCs extracted.\n".into();
    }

    let mut output = String::new();
    output.push_str("\n  Extracted IOCs\n");
    output.push_str(&format!("  {}\n", "═".repeat(70)));
    output.push_str(&format!(
        "  {:<8} {:<50} {:>6}\n",
        "Type", "Value", "Count"
    ));
    output.push_str(&format!("  {}\n", "─".repeat(70)));

    for ioc in iocs.iter().take(50) {
        let value_display: String = ioc.value.chars().take(48).collect();
        output.push_str(&format!(
            "  {:<8} {:<50} {:>6}\n",
            ioc.ioc_type.to_string(),
            value_display,
            ioc.count,
        ));
    }

    if iocs.len() > 50 {
        output.push_str(&format!("  ... and {} more\n", iocs.len() - 50));
    }

    output.push_str(&format!("  {}\n", "═".repeat(70)));
    output
}

// === IOC Enrichment (feature-gated behind ioc-enrich) ===

#[derive(Debug, Clone, Serialize)]
pub struct EnrichedIoc {
    pub ioc: Ioc,
    pub verdict: String,       // "malicious", "suspicious", "clean", "unknown"
    pub source: String,        // "VirusTotal", "AbuseIPDB"
    pub details: String,       // Human-readable details
    pub score: Option<f64>,    // 0.0-100.0
    pub raw_response: Option<String>,
}

#[cfg(feature = "ioc-enrich")]
pub fn enrich_virustotal(iocs: &[Ioc], api_key: &str) -> Result<Vec<EnrichedIoc>> {
    let mut enriched = Vec::new();
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(15))
        .build();

    for ioc in iocs.iter().take(25) {
        // Rate limit: VT free tier = 4 req/min
        let endpoint = match ioc.ioc_type {
            IocType::Ipv4 => format!(
                "https://www.virustotal.com/api/v3/ip_addresses/{}",
                ioc.value
            ),
            IocType::Domain => format!(
                "https://www.virustotal.com/api/v3/domains/{}",
                ioc.value
            ),
            IocType::Url => {
                // VT requires base64-encoded URL id
                let url_id = base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    ioc.value.as_bytes(),
                );
                format!(
                    "https://www.virustotal.com/api/v3/urls/{}",
                    url_id
                )
            }
            IocType::Md5 | IocType::Sha1 | IocType::Sha256 => format!(
                "https://www.virustotal.com/api/v3/files/{}",
                ioc.value
            ),
            _ => continue,
        };

        match agent
            .get(&endpoint)
            .set("x-apikey", api_key)
            .call()
        {
            Ok(resp) => {
                let body = resp.into_string().unwrap_or_default();
                let (verdict, score, details) = parse_vt_response(&body, &ioc.ioc_type);
                enriched.push(EnrichedIoc {
                    ioc: ioc.clone(),
                    verdict,
                    source: "VirusTotal".into(),
                    details,
                    score: Some(score),
                    raw_response: Some(body),
                });
            }
            Err(ureq::Error::Status(404, _)) => {
                enriched.push(EnrichedIoc {
                    ioc: ioc.clone(),
                    verdict: "unknown".into(),
                    source: "VirusTotal".into(),
                    details: "Not found in VT database".into(),
                    score: None,
                    raw_response: None,
                });
            }
            Err(ureq::Error::Status(429, _)) => {
                enriched.push(EnrichedIoc {
                    ioc: ioc.clone(),
                    verdict: "unknown".into(),
                    source: "VirusTotal".into(),
                    details: "Rate limit exceeded".into(),
                    score: None,
                    raw_response: None,
                });
                break; // Stop on rate limit
            }
            Err(e) => {
                log::debug!("VT request failed for {}: {}", ioc.value, e);
            }
        }

        // Basic rate limiting: wait 15s between requests (VT free = 4/min)
        std::thread::sleep(std::time::Duration::from_millis(15500));
    }

    Ok(enriched)
}

#[cfg(feature = "ioc-enrich")]
fn parse_vt_response(body: &str, ioc_type: &IocType) -> (String, f64, String) {
    let json: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return ("unknown".into(), 0.0, "Failed to parse response".into()),
    };

    let attrs = &json["data"]["attributes"];

    match ioc_type {
        IocType::Md5 | IocType::Sha1 | IocType::Sha256 => {
            let stats = &attrs["last_analysis_stats"];
            let malicious = stats["malicious"].as_u64().unwrap_or(0);
            let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
            let undetected = stats["undetected"].as_u64().unwrap_or(0);
            let total = malicious + suspicious + undetected;
            let score = if total > 0 {
                (malicious as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let verdict = if malicious >= 5 {
                "malicious"
            } else if malicious >= 1 || suspicious >= 3 {
                "suspicious"
            } else {
                "clean"
            };
            (
                verdict.into(),
                score,
                format!("{}/{} malicious, {}/{} suspicious", malicious, total, suspicious, total),
            )
        }
        IocType::Ipv4 | IocType::Domain => {
            let stats = &attrs["last_analysis_stats"];
            let malicious = stats["malicious"].as_u64().unwrap_or(0);
            let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
            let harmless = stats["harmless"].as_u64().unwrap_or(0);
            let total = malicious + suspicious + harmless;
            let score = if total > 0 {
                (malicious as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let verdict = if malicious >= 3 {
                "malicious"
            } else if malicious >= 1 || suspicious >= 2 {
                "suspicious"
            } else {
                "clean"
            };
            let rep = attrs["reputation"].as_i64().unwrap_or(0);
            (
                verdict.into(),
                score,
                format!(
                    "{} malicious, {} suspicious, reputation: {}",
                    malicious, suspicious, rep
                ),
            )
        }
        IocType::Url => {
            let stats = &attrs["last_analysis_stats"];
            let malicious = stats["malicious"].as_u64().unwrap_or(0);
            let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
            let total = malicious + suspicious + stats["harmless"].as_u64().unwrap_or(0);
            let score = if total > 0 {
                (malicious as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let verdict = if malicious >= 3 {
                "malicious"
            } else if malicious >= 1 {
                "suspicious"
            } else {
                "clean"
            };
            (
                verdict.into(),
                score,
                format!("{}/{} malicious", malicious, total),
            )
        }
        _ => ("unknown".into(), 0.0, String::new()),
    }
}

#[cfg(feature = "ioc-enrich")]
pub fn enrich_abuseipdb(iocs: &[Ioc], api_key: &str) -> Result<Vec<EnrichedIoc>> {
    let mut enriched = Vec::new();
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(15))
        .build();

    let ip_iocs: Vec<&Ioc> = iocs
        .iter()
        .filter(|i| i.ioc_type == IocType::Ipv4)
        .take(25)
        .collect();

    for ioc in &ip_iocs {
        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
            ioc.value
        );

        match agent
            .get(&url)
            .set("Key", api_key)
            .set("Accept", "application/json")
            .call()
        {
            Ok(resp) => {
                let body = resp.into_string().unwrap_or_default();
                let json: serde_json::Value =
                    serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                let data = &json["data"];
                let abuse_score = data["abuseConfidenceScore"].as_u64().unwrap_or(0);
                let total_reports = data["totalReports"].as_u64().unwrap_or(0);
                let isp = data["isp"].as_str().unwrap_or("unknown");
                let country = data["countryCode"].as_str().unwrap_or("??");

                let verdict = if abuse_score >= 75 {
                    "malicious"
                } else if abuse_score >= 25 {
                    "suspicious"
                } else {
                    "clean"
                };

                enriched.push(EnrichedIoc {
                    ioc: (*ioc).clone(),
                    verdict: verdict.into(),
                    source: "AbuseIPDB".into(),
                    details: format!(
                        "abuse score: {}%, {} reports, ISP: {}, country: {}",
                        abuse_score, total_reports, isp, country
                    ),
                    score: Some(abuse_score as f64),
                    raw_response: Some(body),
                });
            }
            Err(ureq::Error::Status(429, _)) => {
                enriched.push(EnrichedIoc {
                    ioc: (*ioc).clone(),
                    verdict: "unknown".into(),
                    source: "AbuseIPDB".into(),
                    details: "Rate limit exceeded".into(),
                    score: None,
                    raw_response: None,
                });
                break;
            }
            Err(e) => {
                log::debug!("AbuseIPDB request failed for {}: {}", ioc.value, e);
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(1100));
    }

    Ok(enriched)
}

#[cfg(feature = "ioc-enrich")]
pub fn enrich_opentip(iocs: &[Ioc], api_key: &str) -> Result<Vec<EnrichedIoc>> {
    let mut enriched = Vec::new();
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(15))
        .build();

    for ioc in iocs.iter().take(25) {
        let (endpoint, request_body) = match ioc.ioc_type {
            IocType::Md5 | IocType::Sha1 | IocType::Sha256 => (
                "https://opentip.kaspersky.com/api/v1/search/hash",
                serde_json::json!({"request": [{"hash": &ioc.value}]}),
            ),
            IocType::Ipv4 => (
                "https://opentip.kaspersky.com/api/v1/search/ip",
                serde_json::json!({"request": [{"ip": &ioc.value}]}),
            ),
            IocType::Domain => (
                "https://opentip.kaspersky.com/api/v1/search/domain",
                serde_json::json!({"request": [{"domain": &ioc.value}]}),
            ),
            IocType::Url => (
                "https://opentip.kaspersky.com/api/v1/search/url",
                serde_json::json!({"request": [{"url": &ioc.value}]}),
            ),
            _ => continue,
        };

        match agent
            .post(endpoint)
            .set("x-api-key", api_key)
            .set("Content-Type", "application/json")
            .send_string(&request_body.to_string())
        {
            Ok(resp) => {
                let body = resp.into_string().unwrap_or_default();
                let json: serde_json::Value =
                    serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);

                // OpenTIP returns zone: "Red", "Orange", "Yellow", "Green", "Grey"
                let zone = json["response"][0]["zone"]
                    .as_str()
                    .unwrap_or("Grey");

                let (verdict, score) = match zone {
                    "Red" => ("malicious", 90.0),
                    "Orange" => ("suspicious", 60.0),
                    "Yellow" => ("suspicious", 40.0),
                    "Green" => ("clean", 5.0),
                    _ => ("unknown", 0.0),
                };

                let categories: Vec<String> = json["response"][0]["categories"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                let details = if categories.is_empty() {
                    format!("zone: {}", zone)
                } else {
                    format!("zone: {}, categories: {}", zone, categories.join(", "))
                };

                enriched.push(EnrichedIoc {
                    ioc: ioc.clone(),
                    verdict: verdict.into(),
                    source: "OpenTIP".into(),
                    details,
                    score: Some(score),
                    raw_response: Some(body),
                });
            }
            Err(ureq::Error::Status(429, _)) => {
                enriched.push(EnrichedIoc {
                    ioc: ioc.clone(),
                    verdict: "unknown".into(),
                    source: "OpenTIP".into(),
                    details: "Rate limit exceeded".into(),
                    score: None,
                    raw_response: None,
                });
                break;
            }
            Err(ureq::Error::Status(404, _)) => {
                enriched.push(EnrichedIoc {
                    ioc: ioc.clone(),
                    verdict: "unknown".into(),
                    source: "OpenTIP".into(),
                    details: "Not found".into(),
                    score: None,
                    raw_response: None,
                });
            }
            Err(e) => {
                log::debug!("OpenTIP request failed for {}: {}", ioc.value, e);
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    Ok(enriched)
}

pub fn render_enriched(enriched: &[EnrichedIoc]) -> String {
    if enriched.is_empty() {
        return "  No enrichment results.\n".into();
    }

    let mut output = String::new();
    output.push_str("\n  IOC Enrichment Results\n");
    output.push_str(&format!("  {}\n", "═".repeat(80)));
    output.push_str(&format!(
        "  {:<10} {:<8} {:<40} {:<12} {}\n",
        "Verdict", "Type", "Value", "Source", "Details"
    ));
    output.push_str(&format!("  {}\n", "─".repeat(80)));

    for e in enriched {
        let verdict_display = match e.verdict.as_str() {
            "malicious" => "MALICIOUS",
            "suspicious" => "SUSPECT",
            "clean" => "CLEAN",
            _ => "UNKNOWN",
        };
        let value_display: String = e.ioc.value.chars().take(38).collect();
        let details_display: String = e.details.chars().take(40).collect();
        output.push_str(&format!(
            "  {:<10} {:<8} {:<40} {:<12} {}\n",
            verdict_display,
            e.ioc.ioc_type.to_string(),
            value_display,
            e.source,
            details_display,
        ));
    }

    output.push_str(&format!("  {}\n", "═".repeat(80)));
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
    fn test_extract_ipv4() {
        let mut engine = SearchEngine::new().unwrap();
        let events = vec![make_event(&[
            ("DestinationIp", "8.8.8.8"),
            ("SourceIp", "192.168.1.1"),
        ])];
        engine.load_events(&events).unwrap();
        let iocs = extract_iocs(&engine).unwrap();
        assert!(iocs.iter().any(|i| i.ioc_type == IocType::Ipv4 && i.value == "8.8.8.8"));
        // Private IPs should be excluded
        assert!(!iocs.iter().any(|i| i.value == "192.168.1.1"));
    }

    #[test]
    fn test_extract_hash() {
        let mut engine = SearchEngine::new().unwrap();
        let events = vec![make_event(&[
            ("Hash", "d41d8cd98f00b204e9800998ecf8427e"),
        ])];
        engine.load_events(&events).unwrap();
        let iocs = extract_iocs(&engine).unwrap();
        assert!(iocs.iter().any(|i| i.ioc_type == IocType::Md5));
    }

    #[test]
    fn test_is_valid_public_ip() {
        assert!(is_valid_public_ip("8.8.8.8"));
        assert!(!is_valid_public_ip("10.0.0.1"));
        assert!(!is_valid_public_ip("192.168.1.1"));
        assert!(!is_valid_public_ip("127.0.0.1"));
    }
}
