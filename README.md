<p align="center">
  <img src="https://github.com/corax-security/muninn/blob/main/.github/raven-logo-blue.png?raw=true" alt="Muninn" width="120">
</p>

<h1 align="center">Muninn</h1>

<p align="center">
  <b>Log parser &bull; SIGMA engine &bull; Threat detection &bull; IOC enrichment</b><br>
  <i>by corax team</i>
</p>

<p align="center">
  <a href="#english">English</a> &bull; <a href="#russian">Русский</a>
</p>

<p align="center">
  <a href="https://github.com/corax-security/muninn/actions"><img src="https://github.com/corax-security/muninn/workflows/Build%20%26%20Release/badge.svg" alt="CI"></a>
  <a href="https://github.com/corax-security/muninn/releases"><img src="https://img.shields.io/github/v/release/corax-security/muninn" alt="Release"></a>
  <img src="https://img.shields.io/badge/license-AGPL--3.0-blue" alt="License">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-brightgreen" alt="Platform">
</p>

---

<a id="english"></a>

## Overview

Muninn is a standalone forensic tool for log analysis, SIGMA-based threat detection, and IOC enrichment. One binary, 15+ log formats, 3100+ SIGMA rules, MITRE ATT&CK mapping, anomaly detection, attack correlation, and real-time monitoring — zero external dependencies. No SIEM required.

Feed it a directory of logs — EVTX, JSON, Syslog, Zeek, CSV, XML, CEF, LEEF, Auditd, W3C, archives (.gz/.zip/.tar.gz) — Muninn auto-detects the format, loads everything into an in-memory SQLite database, and runs SIGMA rules or your custom queries against it.

### What can you analyze

| Source | Examples |
|---|---|
| **Windows Event Logs** | Security (4624/4625/4688/4720), Sysmon (1/3/11/13/22), PowerShell (4104), System (7045), `.evtx` files |
| **Linux / Unix** | auth.log, syslog, auditd, journald exports |
| **Network** | Zeek/Bro (dns, http, conn, ssl), Suricata EVE JSON, Snort |
| **Firewalls** | iptables, Palo Alto, Fortinet, Check Point — CSV/Syslog/CEF/LEEF |
| **Cloud** | AWS CloudTrail, Azure Activity, GCP Audit, M365, Okta — JSON |
| **Web** | IIS (W3C), Apache/Nginx access logs, proxy logs |
| **EDR / XDR** | Any telemetry exported as JSON, CSV, or Syslog |
| **Archives** | `.gz`, `.zip`, `.bz2`, `.tar.gz`, `.tgz` — auto-extracted |

## Download & Run

Pre-built binaries: [Releases](https://github.com/corax-security/muninn/releases)

**Linux:**
```bash
curl -sL https://github.com/corax-security/muninn/releases/latest/download/muninn-linux-amd64 -o muninn
chmod +x muninn
./muninn -e /path/to/logs/ -r rules/ --stats
```

**Windows:**
```powershell
Invoke-WebRequest -Uri "https://github.com/corax-security/muninn/releases/latest/download/muninn-windows-amd64.exe" -OutFile muninn.exe
.\muninn.exe -e C:\Logs\ -r rules\windows\ --stats
```

## Quick Start

```bash
# SIGMA detection with full analysis
muninn -e ./evidence/ -r rules/ --stats --timeline --killchain --threat-score

# Keyword search
muninn -e ./evidence/ -k "mimikatz"

# Field search
muninn -e ./evidence/ -f "EventID=4624"

# SQL query
muninn -e ./evidence/ --sql "SELECT * FROM events WHERE \"CommandLine\" LIKE '%whoami%'"

# Regex
muninn -e ./evidence/ --regex "CommandLine=.*-enc\s+[A-Za-z0-9+/=]+"

# Extract IOCs with VirusTotal enrichment
muninn -e ./evidence/ --ioc-extract --vt-key YOUR_API_KEY

# Anomaly detection
muninn -e ./evidence/ --anomalies

# HTML report
muninn -e ./evidence/ -r rules/ --gui report.html

# Export for SIEM
muninn -e ./evidence/ -r rules/ --template splunk --template-output detections.json
```

## Features

### Core

| | |
|---|---|
| **15+ formats** | EVTX, JSON, CSV, XML, Syslog, CEF, LEEF, Zeek, W3C, Auditd, macOS — auto-detected |
| **3100+ SIGMA rules** | Full [SigmaHQ](https://github.com/SigmaHQ/sigma) ruleset included |
| **SIGMA compiler** | YAML → SQL with modifiers: `contains`, `endswith`, `startswith`, `re`, `base64`, `base64offset`, `windash`, `cidr`, `all`, `gt/gte/lt/lte` |
| **Search engine** | SQLite-backed: keyword, field, regex, raw SQL |
| **~6 MB binary** | Static, no runtime dependencies |
| **Cross-platform** | Linux x86_64, Windows x86_64 |
| **Library + CLI** | Use as Rust crate, CLI tool, or Python module |

### v0.3.0 — Advanced Analysis

| Feature | Flag | Description |
|---------|------|-------------|
| **MITRE ATT&CK mapping** | *(auto)* | Maps detections to techniques/tactics from rule tags |
| **ATT&CK Navigator** | `--navigator layer.json` | Export layer for ATT&CK Navigator |
| **Kill chain view** | `--killchain` | ASCII kill chain visualization by tactic |
| **Attack timeline** | `--timeline` | Chronological attack timeline |
| **Anomaly detection** | `--anomalies` | Rare processes, off-hours logons, unusual parent-child |
| **IOC extraction** | `--ioc-extract` | Extract IPs, domains, URLs, hashes, emails |
| **IOC enrichment** | `--vt-key` / `--abuseipdb-key` / `--opentip-key` | VirusTotal, AbuseIPDB, Kaspersky OpenTIP |
| **Threat scoring** | `--threat-score` | Per-host/user risk scoring |
| **Attack correlation** | `--correlate` | Group detections into attack chains |
| **Diff mode** | `--diff /path/to/second/` | Compare two evidence sets |
| **Field transforms** | `--transforms` | Base64 decode, LOLBin detect, DNS entropy, obfuscation scoring |
| **Field mapping** | `--field-map map.yaml` | Rename fields across all events |
| **Early filtering** | *(auto)* | Pre-filter events by EventID/Channel from rules |
| **Per-file mode** | `--per-file` | Parallel processing with per-file SQLite DBs |
| **Time filter** | `--after` / `--before` | Filter events by timestamp |
| **Rule profiling** | `--profile-rules` | Show rule execution time ranking |
| **Config file** | `--config muninn.yaml` | YAML config for all settings |
| **YAML config** | `--config file.yaml` | Persist settings in YAML |

### Export & Output

| Format | Flag | Description |
|--------|------|-------------|
| **JSON report** | *(auto)* | Auto-generated with MITRE mapping, tags, descriptions |
| **HTML report** | `--gui report.html` | Interactive self-contained HTML with filtering |
| **Splunk** | `--template splunk` | NDJSON with `source`, `sourcetype`, `_time` |
| **ELK** | `--template elk` | NDJSON with `@timestamp`, `_index` |
| **Timesketch** | `--template timesketch` | JSONL for Timesketch import |
| **CSV** | `--template csv` | Standard CSV export |
| **SARIF** | `--template sarif` | Static Analysis Results Interchange Format |
| **SQLite** | `--dbfile case.db` | Full event database |
| **JSONL** | `--keepflat events.jsonl` | Flattened events export |

### Performance

| Feature | Flag | Description |
|---------|------|-------------|
| **Parallel parsing** | *(auto)* | Files parsed in parallel with rayon |
| **Parallel SIGMA compile** | *(auto)* | Rules compiled to SQL in parallel |
| **Worker control** | `--workers N` | Thread pool size (default: CPU cores) |
| **Memory limit** | `--max-events N` | Cap total events loaded |
| **Batch loading** | `--batch-size N` | SQLite insert batch size (default: 50,000) |
| **Result limit** | `--limit N` | Limit result rows per query |
| **Custom indexes** | `--add-index Field` | Create SQLite indexes on specific fields |

### Optional Features (compile-time)

| Feature | Flag | Description |
|---------|------|-------------|
| **Archive support** | `--features archive` | Parse .gz/.zip/.bz2/.tar.gz files |
| **Interactive TUI** | `--features tui` | Terminal UI with detection browser |
| **Live monitoring** | `--features live` | Watch directory for new events in real-time |
| **IOC enrichment** | `--features ioc-enrich` | VT/AbuseIPDB/OpenTIP API queries |

## Example Output

```
  ███╗   ███╗██╗   ██╗███╗   ██╗██╗███╗   ██╗███╗   ██╗
  ████╗ ████║██║   ██║████╗  ██║██║████╗  ██║████╗  ██║
  ██╔████╔██║██║   ██║██╔██╗ ██║██║██╔██╗ ██║██╔██╗ ██║
  ██║╚██╔╝██║██║   ██║██║╚██╗██║██║██║╚██╗██║██║╚██╗██║
  ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║██║ ╚████║██║ ╚████║
  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝
  -= SIGMA Detection Engine for EVTX/JSON/Syslog/CEF/Zeek v0.3.0 =-

  [+] Processing
    [>] Files       42
    [>] Events      847293
    [>] Formats     312450 EVTX, 52441 Syslog, 482402 JSON Lines
    [>] Duration    3.20s (264778 events/s)
    [>] Workers     8 threads

  [+] 2384 SIGMA rules loaded
  [+] Executing ruleset: 12 rules matched

  ┌──────────────┬────────────────────────────────────────────────────┬────────┬──────────────┐
  │ Severity     │ Rule                                               │ Events │ ATT&CK       │
  ├──────────────┼────────────────────────────────────────────────────┼────────┼──────────────┤
  │ CRITICAL     │ Mimikatz Command Line                              │     14 │ T1003        │
  │ HIGH         │ Suspicious Encoded PowerShell                      │     23 │ T1059.001    │
  │ HIGH         │ Remote Thread in LSASS                             │      3 │ T1003.001    │
  │ MEDIUM       │ WhoAmi Execution                                   │     47 │ T1033        │
  │ MEDIUM       │ Scheduled Task Created via CLI                     │      8 │ T1053.005    │
  │ LOW          │ Sysmon Configuration Change                        │      2 │              │
  └──────────────┴────────────────────────────────────────────────────┴────────┴──────────────┘

  ✦ Summary
  ╭──────────────────────────────────────────────────────────────╮
  │  ⏱ Duration      3.20s
  │  📁 Files         42
  │  📊 Events        847293
  │  ⚡ Throughput    264778 events/s
  │  🔥 Detections    1 CRITICAL  2 HIGH  2 MEDIUM  1 LOW
  │  📋 Coverage      12/2384 rules matched (0.5%)
  │  🎯 Matched       116 events across 12 rules
  │  🏆 Top Hits
  │                CRITICAL Mimikatz Command Line (14)
  │                HIGH Suspicious Encoded PowerShell (23)
  ╰──────────────────────────────────────────────────────────────╯

  🛡 ATT&CK Coverage
  Execution              ████████████████████  2 technique(s) (70 hits)
  Credential Access      ██████████            2 technique(s) (17 hits)
  Persistence            █████                 1 technique(s) (8 hits)
  Discovery              ████████████████      1 technique(s) (47 hits)

  → muninn_report_2026-03-11_14-30-00.json
```

## Search Examples

<details>
<summary><b>Incident Response — lateral movement</b></summary>

```bash
# Remote logons (network + RDP)
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '4624' AND \"LogonType\" IN ('3','10')"

# PsExec
muninn -e evidence/ -k "psexec"

# Pass-the-hash
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '4624' AND \"LogonType\" = '3' AND \"AuthenticationPackageName\" = 'NTLM'"
```
</details>

<details>
<summary><b>Threat Hunting — suspicious processes</b></summary>

```bash
# Encoded PowerShell
muninn -e evidence/ --regex "CommandLine=.*-[eE]nc[oO]?d?e?d?C?o?m?m?a?n?d?\s+[A-Za-z0-9+/=]{20,}"

# LOLBins downloading files
muninn -e evidence/ --sql "SELECT \"Image\",\"CommandLine\" FROM events WHERE \"CommandLine\" LIKE '%http%' AND (\"Image\" LIKE '%certutil%' OR \"Image\" LIKE '%mshta%' OR \"Image\" LIKE '%regsvr32%')"

# Office spawning processes
muninn -e evidence/ --sql "SELECT \"Image\",\"CommandLine\",\"ParentImage\" FROM events WHERE \"ParentImage\" LIKE '%WINWORD%' OR \"ParentImage\" LIKE '%EXCEL%' OR \"ParentImage\" LIKE '%OUTLOOK%'"

# Reconnaissance
muninn -e evidence/ --sql "SELECT \"CommandLine\",\"User\" FROM events WHERE \"Image\" LIKE '%whoami%' OR \"Image\" LIKE '%net.exe' OR \"Image\" LIKE '%ipconfig%' OR \"Image\" LIKE '%systeminfo%'"
```
</details>

<details>
<summary><b>Persistence</b></summary>

```bash
# Scheduled tasks
muninn -e evidence/ --sql "SELECT \"CommandLine\" FROM events WHERE \"EventID\" = '1' AND \"CommandLine\" LIKE '%schtasks%create%'"

# New services
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '7045'"

# Registry Run keys
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '13' AND \"TargetObject\" LIKE '%\\Run\\%'"
```
</details>

<details>
<summary><b>Credential Access</b></summary>

```bash
# LSASS access
muninn -e evidence/ --sql "SELECT \"SourceImage\",\"GrantedAccess\" FROM events WHERE \"EventID\" = '10' AND \"TargetImage\" LIKE '%lsass.exe'"

# Kerberoasting
muninn -e evidence/ --sql "SELECT \"TargetUserName\",\"ServiceName\",\"TicketEncryptionType\" FROM events WHERE \"EventID\" = '4769' AND \"TicketEncryptionType\" = '0x17'"

# SSH brute force
muninn -e auth.log -k "Invalid user" --stats
```
</details>

<details>
<summary><b>Network — external IPs & domains</b></summary>

```bash
# External IPs (exclude RFC1918)
muninn -e evidence/ --sql "
  SELECT DISTINCT \"DestinationIp\" FROM events
  WHERE \"DestinationIp\" IS NOT NULL AND \"DestinationIp\" != ''
    AND \"DestinationIp\" NOT LIKE '10.%'
    AND \"DestinationIp\" NOT LIKE '172.16.%' AND \"DestinationIp\" NOT LIKE '172.17.%'
    AND \"DestinationIp\" NOT LIKE '172.18.%' AND \"DestinationIp\" NOT LIKE '172.19.%'
    AND \"DestinationIp\" NOT LIKE '172.2_.%' AND \"DestinationIp\" NOT LIKE '172.30.%'
    AND \"DestinationIp\" NOT LIKE '172.31.%'
    AND \"DestinationIp\" NOT LIKE '192.168.%' AND \"DestinationIp\" NOT LIKE '127.%'
"

# C2 ports
muninn -e evidence/ --sql "
  SELECT \"DestinationIp\",\"DestinationPort\",\"Image\" FROM events
  WHERE \"DestinationPort\" IN ('4444','5555','8080','8443','1337','9001')
"

# Suspicious TLDs
muninn -e evidence/ --sql "
  SELECT \"QueryName\",\"Image\" FROM events WHERE \"EventID\" = '22'
    AND (\"QueryName\" LIKE '%.xyz' OR \"QueryName\" LIKE '%.top' OR \"QueryName\" LIKE '%.tk'
      OR \"QueryName\" LIKE '%.pw' OR \"QueryName\" LIKE '%.onion')
"

# All unique domains
muninn -e evidence/ --distinct QueryName
```
</details>

<details>
<summary><b>Data exploration</b></summary>

```bash
muninn -e evidence/ --distinct EventID
muninn -e evidence/ --distinct Image
muninn -e evidence/ --stats
muninn -e evidence/ --dbfile case.db
sqlite3 case.db "SELECT \"Image\", COUNT(*) as cnt FROM events WHERE \"EventID\" = '1' GROUP BY \"Image\" ORDER BY cnt DESC LIMIT 20"
```
</details>

## SIGMA Rules

3100+ rules from [SigmaHQ](https://github.com/SigmaHQ/sigma) included in `rules/`:

| Category | Rules |
|----------|-------|
| Windows | 2384 |
| Cloud (AWS, Azure, GCP, M365) | 226 |
| Linux | 207 |
| Application | 92 |
| macOS | 69 |
| Network | 52 |
| Web | 45 |
| Identity | 24 |

```bash
muninn -e events.json -r rules/                            # all rules
muninn -e events.json -r rules/windows/process_creation/   # Windows process creation
muninn -e events.json -r rules/linux/                      # Linux only
muninn -e events.json -r rules/cloud/                      # cloud only
```

<details>
<summary><b>Supported SIGMA modifiers</b></summary>

| Modifier | Example | Description |
|----------|---------|-------------|
| `contains` | `CommandLine\|contains: 'whoami'` | Substring match |
| `startswith` | `Image\|startswith: 'C:\Windows'` | Prefix match |
| `endswith` | `Image\|endswith: '\cmd.exe'` | Suffix match |
| `re` | `CommandLine\|re: '.*-enc\s+'` | Regular expression |
| `all` | `CommandLine\|contains\|all:` | All values must match |
| `base64` | `CommandLine\|base64: 'whoami'` | Base64-encoded value |
| `base64offset` | `CommandLine\|base64offset: 'admin'` | Base64 with offset variants |
| `windash` | `CommandLine\|windash\|contains: '-enc'` | Dash variants (`-`, `/`, `--`) |
| `cidr` | `SourceIp\|cidr: '10.0.0.0/8'` | IP range |
| `gt/gte/lt/lte` | `EventID\|gte: 4624` | Numeric comparisons |
</details>

Rules licensed under [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License) by SigmaHQ.

## CLI Reference

```
muninn [OPTIONS] -e <LOG_PATH>

INPUT / OUTPUT:
  -e, --events <PATH>           Log file or directory (recursive)
  -r, --rules <PATH>            SIGMA rules (file or directory)
  -o, --output <FILE>           JSON output file
      --dbfile <FILE>            Export SQLite database
      --keepflat <FILE>          Export flattened events as JSONL
      --no-report                Disable auto-report
  -q, --quiet                   Suppress output

SEARCH:
  -k, --keyword <TEXT>           Full-text keyword search
  -f, --field <FIELD=PAT>        Field search (LIKE: %, _)
      --regex <FIELD=RE>         Regex search
      --sql <QUERY>              Raw SQL query
      --sql-file <FILE>          SQL queries from file
      --stats                    Field statistics
      --distinct <FIELD>         Unique field values

SIGMA:
      --min-level <LEVEL>        Minimum severity [default: low]
      --rulefilter <PATTERN>     Exclude rules matching pattern (repeatable)
      --profile-rules            Show rule execution time ranking
      --hashes                   Compute event hashes

ANALYSIS:
      --timeline                 Show attack timeline
      --killchain                Kill chain visualization
      --anomalies                Detect statistical anomalies
      --ioc-extract              Extract IOCs (IPs, domains, hashes, URLs)
      --threat-score             Per-host/user threat scoring
      --correlate                Correlate events into attack chains
      --transforms               Field transforms (base64 decode, LOLBin, DNS entropy)

IOC ENRICHMENT (requires --features ioc-enrich):
      --vt-key <KEY>             VirusTotal API key
      --abuseipdb-key <KEY>      AbuseIPDB API key
      --opentip-key <KEY>        Kaspersky OpenTIP API key

EXPORT:
      --navigator <FILE>         ATT&CK Navigator layer JSON
      --template <FORMAT>        Export: splunk, elk, timesketch, csv, sarif
      --template-output <FILE>   Template output path
      --gui <FILE>               Self-contained HTML report

FILTERING:
  -s, --select <GLOB>            Only matching files
  -a, --avoid <GLOB>             Exclude matching files
      --after <TIMESTAMP>        Only events after timestamp (ISO 8601)
      --before <TIMESTAMP>       Only events before timestamp (ISO 8601)
      --field-map <FILE>         YAML field rename mapping

PERFORMANCE:
      --workers <N>              Parallel workers (default: CPU cores)
      --max-events <N>           Maximum events to load
      --batch-size <N>           Events per batch (default: 50000)
      --limit <N>                Limit result rows per query
      --add-index <FIELD>        Create index on field(s)
      --remove-index <NAME>      Remove index by name
      --per-file                 Per-file parallel processing

MODE:
      --diff <PATH>              Compare with second evidence set
      --config <FILE>            YAML config file
      --tui                      Interactive terminal UI (requires --features tui)
      --live                     Real-time monitoring (requires --features live)
```

## Using as a Library

```toml
[dependencies]
muninn = { git = "https://github.com/corax-security/muninn" }
```

```rust
use muninn::{parsers, search::SearchEngine, sigma};

let result = parsers::parse_file("events.json")?;
let mut engine = SearchEngine::new()?;
engine.load_events(&result.events)?;

// SIGMA detection
let rules = sigma::load_rules("rules/windows/")?;
for rule in &rules {
    let sql = sigma::compile(rule)?;
    let result = engine.query_sql(&sql)?;
    if result.count > 0 {
        println!("[{}] {} — {} matches", rule.level, rule.title, result.count);
    }
}

// IOC extraction
let iocs = muninn::ioc::extract_iocs(&engine)?;

// Anomaly detection
let anomalies = muninn::anomaly::detect_anomalies(&engine)?;

// Search
let hits = engine.search_keyword("mimikatz")?;
engine.export_db("evidence.db")?;
```

## Building from Source

```bash
# Standard build (~6 MB)
cargo build --release --features "all-parsers,cli"

# Full build with all optional features
cargo build --release --features "all-parsers,cli,archive,tui,live,ioc-enrich"

# Run tests
cargo test --features "all-parsers,cli,archive,tui,live,ioc-enrich"
```

<details>
<summary><b>Feature flags, Docker, cross-compilation</b></summary>

| Feature | Description |
|---------|-------------|
| `all-parsers` | All format parsers (default) |
| `cli` | CLI binary |
| `archive` | .gz/.zip/.bz2/.tar.gz support (flate2, zip, bzip2, tar) |
| `ioc-enrich` | IOC enrichment via VirusTotal, AbuseIPDB, OpenTIP (ureq) |
| `tui` | Interactive terminal UI (ratatui, crossterm) |
| `live` | Real-time directory monitoring (notify) |
| `parser-evtx` | Windows EVTX |
| `parser-syslog` | Syslog RFC 3164/5424 |
| `parser-cef` | Common Event Format |
| `parser-leef` | Log Event Extended Format |
| `parser-zeek` | Zeek/Bro TSV |
| `parser-w3c` | W3C Extended Log |
| `python` | Python bindings (PyO3) |

```bash
# Docker
docker build -t muninn .
docker run -v ./evidence:/data muninn /data/events.json -r /app/rules/ --stats

# Cross-compile for Windows
rustup target add x86_64-pc-windows-msvc
cargo build --release --features "all-parsers,cli" --target x86_64-pc-windows-msvc
```
</details>

## Public Log Datasets

| Dataset | Format | Link |
|---------|--------|------|
| EVTX-ATTACK-SAMPLES | EVTX | [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) |
| Hayabusa Sample EVTX | EVTX | [Yamato-Security/hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) |
| EVTX-to-MITRE-Attack | EVTX | [mdecrevoisier/EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) |
| SecRepo auth.log | Syslog | [secrepo.com](https://www.secrepo.com/auth.log/) |
| SecRepo Zeek DNS/HTTP | Zeek TSV | [secrepo.com](https://www.secrepo.com/maccdc2012/) |
| Mordor / Security Datasets | JSON | [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) |

```bash
git clone --depth=1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
muninn -e EVTX-ATTACK-SAMPLES/ -r rules/windows/ --timeline --killchain --threat-score
```

## Performance

| Metric | Value |
|--------|-------|
| Parsing | ~250K events/sec (parallel, JSON Lines) |
| SQLite load | 100K events < 5 sec |
| Binary size | ~6 MB (release, stripped, LTO) |
| Memory | SQLite-backed, handles millions of events |
| Parallelism | File parsing + SIGMA compile via rayon |

## License

**AGPL-3.0** — see [LICENSE](LICENSE).

SIGMA rules in `rules/` licensed under [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License) by SigmaHQ.

---

<a id="russian"></a>

## Обзор

Muninn — автономный инструмент для анализа логов, обнаружения угроз на основе SIGMA-правил и обогащения IOC. Один бинарник, 15+ форматов логов, 3100+ SIGMA-правил, маппинг MITRE ATT&CK, детекция аномалий, корреляция атак, мониторинг в реальном времени — ноль внешних зависимостей. SIEM не требуется.

Передайте директорию с логами — EVTX, JSON, Syslog, Zeek, CSV, XML, CEF, LEEF, Auditd, W3C, архивы (.gz/.zip/.tar.gz) — Muninn автоматически определит формат, загрузит всё в SQLite и применит SIGMA-правила или ваши запросы.

### Что можно анализировать

| Источник | Примеры |
|---|---|
| **Windows Event Logs** | Security (4624/4625/4688/4720), Sysmon (1/3/11/13/22), PowerShell (4104), System (7045), файлы `.evtx` |
| **Linux / Unix** | auth.log, syslog, auditd, экспорт journald |
| **Сетевые сенсоры** | Zeek/Bro (dns, http, conn, ssl), Suricata EVE JSON, Snort |
| **Межсетевые экраны** | iptables, Palo Alto, Fortinet, Check Point — CSV/Syslog/CEF/LEEF |
| **Облако** | AWS CloudTrail, Azure Activity, GCP Audit, M365, Okta — JSON |
| **Веб-серверы** | IIS (W3C), Apache/Nginx, прокси-серверы |
| **EDR / XDR** | Любая телеметрия в JSON, CSV или Syslog |
| **Архивы** | `.gz`, `.zip`, `.bz2`, `.tar.gz`, `.tgz` — автораспаковка |

### Скачать и запустить

Готовые бинарники: [Releases](https://github.com/corax-security/muninn/releases)

**Linux:**
```bash
curl -sL https://github.com/corax-security/muninn/releases/latest/download/muninn-linux-amd64 -o muninn
chmod +x muninn
./muninn -e /path/to/logs/ -r rules/ --stats
```

**Windows:**
```powershell
Invoke-WebRequest -Uri "https://github.com/corax-security/muninn/releases/latest/download/muninn-windows-amd64.exe" -OutFile muninn.exe
.\muninn.exe -e C:\Logs\ -r rules\windows\ --stats
```

### Быстрый старт

```bash
# SIGMA-обнаружение с полным анализом
muninn -e ./evidence/ -r rules/ --stats --timeline --killchain --threat-score

# Поиск по ключевому слову
muninn -e ./evidence/ -k "mimikatz"

# Извлечение IOC с обогащением через VirusTotal
muninn -e ./evidence/ --ioc-extract --vt-key YOUR_API_KEY

# Детекция аномалий
muninn -e ./evidence/ --anomalies

# HTML-отчёт
muninn -e ./evidence/ -r rules/ --gui report.html

# Экспорт для SIEM
muninn -e ./evidence/ -r rules/ --template splunk --template-output detections.json
```

### Возможности

#### Ядро

| | |
|---|---|
| **15+ форматов** | EVTX, JSON, CSV, XML, Syslog, CEF, LEEF, Zeek, W3C, Auditd, macOS — автоопределение |
| **3100+ SIGMA-правил** | Полный набор [SigmaHQ](https://github.com/SigmaHQ/sigma) |
| **Компилятор SIGMA** | YAML → SQL с модификаторами: `contains`, `endswith`, `startswith`, `re`, `base64`, `base64offset`, `windash`, `cidr`, `all`, `gt/gte/lt/lte` |
| **Поисковый движок** | На базе SQLite: ключевые слова, поля, регулярные выражения, SQL |
| **~6 МБ бинарник** | Статический, без внешних зависимостей |
| **Кроссплатформенный** | Linux x86_64, Windows x86_64 |
| **Библиотека + CLI** | Rust-крейт, CLI-утилита или Python-модуль |

#### v0.3.0 — Продвинутая аналитика

| Функция | Флаг | Описание |
|---------|------|----------|
| **Маппинг MITRE ATT&CK** | *(авто)* | Привязка детектов к техникам и тактикам из тегов правил |
| **ATT&CK Navigator** | `--navigator layer.json` | Экспорт слоя для ATT&CK Navigator |
| **Kill chain** | `--killchain` | ASCII-визуализация по тактикам |
| **Таймлайн атаки** | `--timeline` | Хронологический таймлайн атаки |
| **Детекция аномалий** | `--anomalies` | Редкие процессы, нетипичное время логона, необычные parent-child |
| **Извлечение IOC** | `--ioc-extract` | IP-адреса, домены, URL, хэши, email |
| **Обогащение IOC** | `--vt-key` / `--abuseipdb-key` / `--opentip-key` | VirusTotal, AbuseIPDB, Kaspersky OpenTIP |
| **Threat scoring** | `--threat-score` | Оценка рисков по хостам/пользователям |
| **Корреляция атак** | `--correlate` | Группировка детектов в цепочки атак |
| **Diff-режим** | `--diff /path/second/` | Сравнение двух наборов данных |
| **Трансформации** | `--transforms` | Base64-декодирование, LOLBin-детект, DNS-энтропия, обфускация |
| **Маппинг полей** | `--field-map map.yaml` | Переименование полей во всех событиях |
| **Ранняя фильтрация** | *(авто)* | Предварительная фильтрация по EventID/Channel из правил |
| **Per-file режим** | `--per-file` | Параллельная обработка с отдельным SQLite на файл |
| **Фильтр времени** | `--after` / `--before` | Фильтрация по метке времени |
| **Профилирование правил** | `--profile-rules` | Рейтинг скорости выполнения правил |
| **YAML-конфиг** | `--config muninn.yaml` | Все настройки в YAML-файле |

#### Экспорт

| Формат | Флаг | Описание |
|--------|------|----------|
| **JSON-отчёт** | *(авто)* | С MITRE-маппингом, тегами, описаниями |
| **HTML-отчёт** | `--gui report.html` | Интерактивный HTML с фильтрацией |
| **Splunk** | `--template splunk` | NDJSON с `source`, `sourcetype`, `_time` |
| **ELK** | `--template elk` | NDJSON с `@timestamp`, `_index` |
| **Timesketch** | `--template timesketch` | JSONL для импорта в Timesketch |
| **CSV** | `--template csv` | Стандартный CSV |
| **SARIF** | `--template sarif` | Static Analysis Results Interchange Format |
| **SQLite** | `--dbfile case.db` | Полная БД событий |

#### Производительность

| Функция | Флаг | Описание |
|---------|------|----------|
| **Параллельный парсинг** | *(авто)* | Файлы парсятся параллельно через rayon |
| **Параллельная компиляция** | *(авто)* | SIGMA-правила компилируются параллельно |
| **Контроль потоков** | `--workers N` | Размер пула потоков (по умолчанию: кол-во ядер) |
| **Лимит памяти** | `--max-events N` | Максимум загружаемых событий |
| **Батчевая загрузка** | `--batch-size N` | Размер батча для SQLite (по умолчанию: 50,000) |
| **Лимит результатов** | `--limit N` | Лимит строк на запрос |
| **Индексы** | `--add-index Field` | Создание SQLite-индексов на полях |

### Как получить данные

- Скопировать `.evtx` из `C:\Windows\System32\winevt\Logs\`
- Экспортировать из SIEM (Splunk, Elastic, QRadar) в JSON/CSV
- Собрать логи Zeek из `/opt/zeek/logs/`
- Скачать CloudTrail: `aws s3 sync s3://bucket/AWSLogs/ ./cloudtrail/`
- Экспортировать auditd: `ausearch --start today --format text > audit.log`

### Сборка из исходников

```bash
# Стандартная сборка (~6 МБ)
cargo build --release --features "all-parsers,cli"

# Полная сборка со всеми опциональными фичами
cargo build --release --features "all-parsers,cli,archive,tui,live,ioc-enrich"

# Запуск тестов
cargo test --features "all-parsers,cli,archive,tui,live,ioc-enrich"
```

### Лицензия

**AGPL-3.0** — см. [LICENSE](LICENSE).

SIGMA-правила в `rules/` — [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License) от SigmaHQ.
