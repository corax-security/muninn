use crate::model::Event;

pub trait Transform: Send + Sync {
    fn name(&self) -> &str;
    fn apply(&self, event: &mut Event);
}

pub struct Base64Decoder;
pub struct IocExtractor;
pub struct LolbinDetector;
pub struct DnsEntropyScorer;
pub struct ObfuscationDetector;

impl Transform for Base64Decoder {
    fn name(&self) -> &str {
        "base64_decoder"
    }

    fn apply(&self, event: &mut Event) {
        for field in &["CommandLine", "ScriptBlockText", "Payload", "ServiceFileName"] {
            if let Some(val) = event.fields.get(*field).cloned() {
                if let Some(decoded) = try_decode_base64_in_string(&val) {
                    event
                        .fields
                        .insert(format!("decoded_{}", field), decoded);
                }
            }
        }
    }
}

fn try_decode_base64_in_string(s: &str) -> Option<String> {
    let re = regex::Regex::new(r"[A-Za-z0-9+/]{8,}={0,2}").ok()?;
    for m in re.find_iter(s) {
        if let Ok(decoded) = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            m.as_str(),
        ) {
            if let Ok(text) = String::from_utf8(decoded.clone()) {
                if text.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t') {
                    return Some(text);
                }
            }
            // Try UTF-16LE (common in PowerShell)
            if decoded.len() >= 2 && decoded.len() % 2 == 0 {
                let u16s: Vec<u16> = decoded
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                if let Ok(text) = String::from_utf16(&u16s) {
                    if text.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t') {
                        return Some(text);
                    }
                }
            }
        }
    }
    None
}

const LOLBINS: &[&str] = &[
    "certutil", "mshta", "regsvr32", "rundll32", "cmstp", "msiexec",
    "wmic", "cscript", "wscript", "bitsadmin", "forfiles", "pcalua",
    "hh.exe", "msbuild", "installutil", "regasm", "regsvcs",
    "msconfig", "control", "explorer.exe", "dfsvc", "ieexec",
    "dnscmd", "ftp.exe", "replace.exe", "xwizard", "presentationhost",
    "bash.exe", "powershell", "pwsh", "cmd.exe",
];

impl Transform for LolbinDetector {
    fn name(&self) -> &str {
        "lolbin_detector"
    }

    fn apply(&self, event: &mut Event) {
        if let Some(image) = event.fields.get("Image").cloned() {
            let image_lower = image.to_lowercase();
            for lolbin in LOLBINS {
                if image_lower.contains(lolbin) {
                    event.fields.insert("is_lolbin".into(), "true".into());
                    event
                        .fields
                        .insert("lolbin_name".into(), lolbin.to_string());
                    break;
                }
            }
        }
    }
}

impl Transform for IocExtractor {
    fn name(&self) -> &str {
        "ioc_extractor"
    }

    fn apply(&self, event: &mut Event) {
        let raw = event.raw.clone();
        let mut ips = Vec::new();
        let mut urls = Vec::new();
        let mut domains = Vec::new();

        let ip_re =
            regex::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();
        for cap in ip_re.captures_iter(&raw) {
            let ip = cap[1].to_string();
            if !ip.starts_with("10.")
                && !ip.starts_with("192.168.")
                && !ip.starts_with("127.")
                && !ip.starts_with("0.")
                && !ips.contains(&ip)
            {
                ips.push(ip);
            }
        }

        let url_re =
            regex::Regex::new(r#"https?://[^\s'"<>]+"#).unwrap();
        for m in url_re.find_iter(&raw) {
            let url = m.as_str().to_string();
            if !urls.contains(&url) {
                urls.push(url);
            }
        }

        let domain_re =
            regex::Regex::new(r#"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.(?:com|net|org|io|xyz|top|ru|cn|tk|pw|info|biz|cc))\b"#).unwrap();
        for cap in domain_re.captures_iter(&raw) {
            let domain = cap[1].to_string();
            if !domains.contains(&domain) {
                domains.push(domain);
            }
        }

        if !ips.is_empty() {
            event.fields.insert("ioc_ips".into(), ips.join(", "));
        }
        if !urls.is_empty() {
            event.fields.insert("ioc_urls".into(), urls.join(", "));
        }
        if !domains.is_empty() {
            event
                .fields
                .insert("ioc_domains".into(), domains.join(", "));
        }
    }
}

impl Transform for DnsEntropyScorer {
    fn name(&self) -> &str {
        "dns_entropy_scorer"
    }

    fn apply(&self, event: &mut Event) {
        if let Some(query) = event.fields.get("QueryName").cloned() {
            let entropy = shannon_entropy(&query);
            event
                .fields
                .insert("dns_entropy".into(), format!("{:.2}", entropy));
            let level = if entropy > 4.5 {
                "very_high"
            } else if entropy > 3.5 {
                "high"
            } else if entropy > 2.5 {
                "medium"
            } else {
                "low"
            };
            event
                .fields
                .insert("dns_entropy_level".into(), level.into());
        }
    }
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

impl Transform for ObfuscationDetector {
    fn name(&self) -> &str {
        "obfuscation_detector"
    }

    fn apply(&self, event: &mut Event) {
        if let Some(cmd) = event.fields.get("CommandLine").cloned() {
            let mut indicators = Vec::new();
            let mut score: u32 = 0;

            // Caret obfuscation: p^o^w^e^r^s^h^e^l^l
            if cmd.matches('^').count() >= 3 {
                indicators.push("CARET_OBFUSCATION");
                score += 3;
            }
            // String concatenation: "po"+"wer"+"shell"
            if cmd.contains(r#""+""#) || cmd.contains("'+'") {
                indicators.push("STRING_CONCAT");
                score += 3;
            }
            // Tick obfuscation: p`ow`er`sh`ell
            if cmd.matches('`').count() >= 2 {
                indicators.push("TICK_OBFUSCATION");
                score += 2;
            }
            // Env variable abuse: %COMSPEC%
            let env_count = cmd.matches('%').count();
            if env_count >= 4 {
                indicators.push("ENV_VAR_ABUSE");
                score += 2;
            }
            // Very long command line
            if cmd.len() > 1000 {
                indicators.push("VERY_LONG_CMDLINE");
                score += 1;
            }
            // High entropy
            if shannon_entropy(&cmd) > 4.5 {
                indicators.push("HIGH_ENTROPY");
                score += 2;
            }

            if !indicators.is_empty() {
                event
                    .fields
                    .insert("obfuscation_indicators".into(), indicators.join(", "));
                event
                    .fields
                    .insert("obfuscation_score".into(), score.to_string());
            }
        }
    }
}

pub fn default_transforms() -> Vec<Box<dyn Transform>> {
    vec![
        Box::new(Base64Decoder),
        Box::new(LolbinDetector),
        Box::new(IocExtractor),
        Box::new(DnsEntropyScorer),
        Box::new(ObfuscationDetector),
    ]
}

pub fn apply_transforms(events: &mut [Event], transforms: &[Box<dyn Transform>]) {
    for event in events.iter_mut() {
        for transform in transforms {
            transform.apply(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SourceFormat;

    fn make_event(fields: &[(&str, &str)]) -> Event {
        let mut event = Event::new("test.log", SourceFormat::JsonLines);
        for (k, v) in fields {
            event.set(*k, *v);
        }
        event.raw = serde_json::to_string(
            &fields
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect::<std::collections::HashMap<_, _>>(),
        )
        .unwrap();
        event
    }

    #[test]
    fn test_base64_decoder_utf16() {
        // "echo" encoded as UTF-16LE then base64
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "ZQBjAGgAbwA=".as_bytes(),
        );
        // Directly test with known PS base64: "echo" = ZQBjAGgAbwA= in UTF-16LE
        let mut event = make_event(&[("CommandLine", "powershell -enc ZQBjAGgAbwA=")]);
        Base64Decoder.apply(&mut event);
        assert!(event.fields.contains_key("decoded_CommandLine"));
        let _ = encoded;
    }

    #[test]
    fn test_lolbin_detector() {
        let mut event = make_event(&[("Image", r"C:\Windows\System32\certutil.exe")]);
        LolbinDetector.apply(&mut event);
        assert_eq!(event.get("is_lolbin"), Some("true"));
        assert_eq!(event.get("lolbin_name"), Some("certutil"));
    }

    #[test]
    fn test_lolbin_no_match() {
        let mut event = make_event(&[("Image", r"C:\Program Files\myapp.exe")]);
        LolbinDetector.apply(&mut event);
        assert!(event.get("is_lolbin").is_none());
    }

    #[test]
    fn test_ioc_extractor() {
        let mut event = Event::new("test.log", SourceFormat::JsonLines);
        event.raw = "connection to 8.8.8.8 from https://evil.com/payload".into();
        IocExtractor.apply(&mut event);
        assert!(event.get("ioc_ips").unwrap().contains("8.8.8.8"));
        assert!(event.get("ioc_urls").unwrap().contains("https://evil.com/payload"));
    }

    #[test]
    fn test_dns_entropy() {
        let mut event = make_event(&[("QueryName", "asdkjqwelkjsadoiqwjelkasjd.xyz")]);
        DnsEntropyScorer.apply(&mut event);
        assert!(event.get("dns_entropy").is_some());
        let entropy: f64 = event.get("dns_entropy").unwrap().parse().unwrap();
        assert!(entropy > 3.0);
    }

    #[test]
    fn test_obfuscation_detector() {
        let mut event = make_event(&[("CommandLine", "p^o^w^e^r^s^h^e^l^l -enc abc")]);
        ObfuscationDetector.apply(&mut event);
        assert!(event
            .get("obfuscation_indicators")
            .unwrap()
            .contains("CARET_OBFUSCATION"));
    }
}
