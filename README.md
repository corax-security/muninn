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
# 1. Download SIGMA rules (one-time)
muninn --download-rules all

# 2. Run full analysis
muninn -e ./evidence/ -r sigma-rules/ --stats --timeline --killchain --threat-score
```

## Usage Examples

<details open>
<summary><b>Getting started</b></summary>

```bash
# Download SIGMA rules — pick a ruleset
muninn --download-rules all                          # all 3100+ rules
muninn --download-rules core                         # curated core only
muninn --download-rules core+                        # core + extended
muninn --download-rules emerging                     # emerging threats addon
muninn --download-rules all --rules-dir ./my-rules/  # custom output dir

# Basic scan with all rules
muninn -e ./evidence/ -r sigma-rules/

# Scan with statistics
muninn -e ./evidence/ -r sigma-rules/ --stats

# Scan specific log file
muninn -e ./Security.evtx -r sigma-rules/rules/windows/

# Quiet mode (only detections)
muninn -e ./evidence/ -r sigma-rules/ -q

# Custom JSON output
muninn -e ./evidence/ -r sigma-rules/ -o results.json

# Disable auto-report
muninn -e ./evidence/ -r sigma-rules/ --no-report
```
</details>

<details>
<summary><b>Search — keyword, field, regex, SQL</b></summary>

```bash
# Keyword search (full-text across all fields)
muninn -e ./evidence/ -k "mimikatz"
muninn -e ./evidence/ -k "powershell"
muninn -e ./evidence/ -k "cmd.exe"
muninn -e ./evidence/ -k "admin"

# Field search (LIKE syntax: % = wildcard, _ = single char)
muninn -e ./evidence/ -f "EventID=4624"
muninn -e ./evidence/ -f "Image=%cmd.exe"
muninn -e ./evidence/ -f "User=%admin%"
muninn -e ./evidence/ -f "SourceIp=192.168.%"
muninn -e ./evidence/ -f "CommandLine=%whoami%"
muninn -e ./evidence/ -f "LogonType=10"

# Regex search
muninn -e ./evidence/ --regex "CommandLine=.*-[eE]nc[oO]?d?e?d?C?o?m?m?a?n?d?\s+[A-Za-z0-9+/=]{20,}"
muninn -e ./evidence/ --regex "Image=.*\\\\(cmd|powershell|pwsh)\.exe$"
muninn -e ./evidence/ --regex "DestinationIp=^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"

# Raw SQL queries
muninn -e ./evidence/ --sql "SELECT * FROM events WHERE \"CommandLine\" LIKE '%whoami%'"
muninn -e ./evidence/ --sql "SELECT \"Image\", COUNT(*) as cnt FROM events GROUP BY \"Image\" ORDER BY cnt DESC LIMIT 20"
muninn -e ./evidence/ --sql "SELECT DISTINCT \"User\" FROM events WHERE \"EventID\" = '4624'"
muninn -e ./evidence/ --sql "SELECT * FROM events WHERE \"EventID\" IN ('4624','4625','4648') LIMIT 100"

# SQL from file
muninn -e ./evidence/ --sql-file queries.sql

# Statistics and exploration
muninn -e ./evidence/ --stats
muninn -e ./evidence/ --distinct EventID
muninn -e ./evidence/ --distinct Image
muninn -e ./evidence/ --distinct User
muninn -e ./evidence/ --distinct SourceIp
muninn -e ./evidence/ --distinct Channel

# Limit results
muninn -e ./evidence/ -k "error" --limit 50
```
</details>

<details>
<summary><b>SIGMA detection — filtering and profiling</b></summary>

```bash
# Minimum severity filter
muninn -e ./evidence/ -r sigma-rules/ --min-level high        # only high + critical
muninn -e ./evidence/ -r sigma-rules/ --min-level critical     # only critical
muninn -e ./evidence/ -r sigma-rules/ --min-level medium       # medium and above

# Exclude noisy rules
muninn -e ./evidence/ -r sigma-rules/ --rulefilter "sysmon config"
muninn -e ./evidence/ -r sigma-rules/ --rulefilter "sysmon" --rulefilter "defender"

# Profile rule performance
muninn -e ./evidence/ -r sigma-rules/ --profile-rules

# Specific rule directories
muninn -e ./evidence/ -r sigma-rules/rules/windows/process_creation/
muninn -e ./evidence/ -r sigma-rules/rules/windows/powershell/
muninn -e ./evidence/ -r sigma-rules/rules/linux/
muninn -e ./evidence/ -r sigma-rules/rules/cloud/aws/
muninn -e ./evidence/ -r sigma-rules/rules/network/

# Use your own rules
muninn -e ./evidence/ -r ./custom-rules/my-rule.yml
muninn -e ./evidence/ -r ./custom-rules/

# Event hashing
muninn -e ./evidence/ -r sigma-rules/ --hashes
```
</details>

<details>
<summary><b>Advanced analysis — MITRE, timeline, anomalies, IOC, scoring</b></summary>

```bash
# Full analysis pipeline
muninn -e ./evidence/ -r sigma-rules/ --stats --timeline --killchain --threat-score --anomalies --ioc-extract --correlate --transforms

# MITRE ATT&CK
muninn -e ./evidence/ -r sigma-rules/ --killchain              # console + auto-save .txt
muninn -e ./evidence/ -r sigma-rules/ --killchain kc.html      # save as HTML report
muninn -e ./evidence/ -r sigma-rules/ --navigator layer.json   # ATT&CK Navigator export

# Attack timeline
muninn -e ./evidence/ -r sigma-rules/ --timeline               # console + auto-save .txt
muninn -e ./evidence/ -r sigma-rules/ --timeline tl.html       # save as HTML

# Anomaly detection (no rules needed)
muninn -e ./evidence/ --anomalies                              # console + auto-save .txt
muninn -e ./evidence/ --anomalies anomalies.json               # save as JSON
muninn -e ./evidence/ --anomalies anomalies.html               # save as HTML

# IOC extraction
muninn -e ./evidence/ --ioc-extract                            # console + auto-save .txt
muninn -e ./evidence/ --ioc-extract iocs.html                  # save as HTML

# IOC enrichment with threat intelligence
muninn -e ./evidence/ --ioc-extract --vt-key YOUR_VT_KEY
muninn -e ./evidence/ --ioc-extract --abuseipdb-key YOUR_ABUSEIPDB_KEY
muninn -e ./evidence/ --ioc-extract --opentip-key YOUR_OPENTIP_KEY
muninn -e ./evidence/ --ioc-extract --vt-key VT_KEY --abuseipdb-key ABUSEIPDB_KEY  # multiple

# Threat scoring per host/user
muninn -e ./evidence/ -r sigma-rules/ --threat-score           # console + auto-save .txt
muninn -e ./evidence/ -r sigma-rules/ --threat-score scores.html  # HTML report

# Attack chain correlation
muninn -e ./evidence/ -r sigma-rules/ --correlate              # console + auto-save .txt
muninn -e ./evidence/ -r sigma-rules/ --correlate chains.json  # save as JSON

# Field transforms (base64 decode, LOLBin detect, DNS entropy, obfuscation)
muninn -e ./evidence/ --transforms -r sigma-rules/

# Diff two evidence sets
muninn -e ./evidence-before/ -r sigma-rules/ --diff ./evidence-after/
```
</details>

<details>
<summary><b>Export — HTML, SIEM, SQLite, CSV</b></summary>

```bash
# HTML interactive report
muninn -e ./evidence/ -r sigma-rules/ --gui report.html

# Export for Splunk
muninn -e ./evidence/ -r sigma-rules/ --template splunk --template-output detections.json

# Export for ELK/OpenSearch
muninn -e ./evidence/ -r sigma-rules/ --template elk --template-output detections.ndjson

# Export for Timesketch
muninn -e ./evidence/ -r sigma-rules/ --template timesketch --template-output timeline.jsonl

# Export as CSV
muninn -e ./evidence/ -r sigma-rules/ --template csv --template-output detections.csv

# Export as SARIF (for GitHub Security tab, etc.)
muninn -e ./evidence/ -r sigma-rules/ --template sarif --template-output results.sarif

# Export SQLite database for custom queries
muninn -e ./evidence/ --dbfile case.db
sqlite3 case.db "SELECT \"Image\", COUNT(*) FROM events GROUP BY \"Image\" ORDER BY COUNT(*) DESC LIMIT 20"

# Export flattened events as JSONL
muninn -e ./evidence/ --keepflat events.jsonl

# ATT&CK Navigator layer
muninn -e ./evidence/ -r sigma-rules/ --navigator layer.json
```
</details>

<details>
<summary><b>Filtering — time, files, fields</b></summary>

```bash
# Time-based filtering (ISO 8601)
muninn -e ./evidence/ -r sigma-rules/ --after "2025-01-15T00:00:00"
muninn -e ./evidence/ -r sigma-rules/ --before "2025-01-16T00:00:00"
muninn -e ./evidence/ -r sigma-rules/ --after "2025-01-15T08:00:00" --before "2025-01-15T18:00:00"

# File selection by glob
muninn -e ./evidence/ -s "*.evtx" -r sigma-rules/         # only EVTX
muninn -e ./evidence/ -s "Security*" -r sigma-rules/       # only Security logs
muninn -e ./evidence/ -a "*.csv" -r sigma-rules/           # exclude CSV files

# Field mapping (rename fields across all events)
muninn -e ./evidence/ -r sigma-rules/ --field-map mapping.yaml
# mapping.yaml: { "EventID": "event_id", "SourceIp": "src_ip" }
```
</details>

<details>
<summary><b>Performance tuning</b></summary>

```bash
# Control parallelism
muninn -e ./evidence/ -r sigma-rules/ --workers 4          # 4 threads
muninn -e ./evidence/ -r sigma-rules/ --workers 16         # 16 threads

# Limit memory usage
muninn -e ./evidence/ -r sigma-rules/ --max-events 500000  # cap at 500K events
muninn -e ./evidence/ -r sigma-rules/ --batch-size 100000  # larger batches

# Create indexes for faster queries
muninn -e ./evidence/ -r sigma-rules/ --add-index EventID --add-index Image

# Per-file parallel processing
muninn -e ./evidence/ -r sigma-rules/ --per-file
```
</details>

<details>
<summary><b>Interactive & live modes</b></summary>

```bash
# Interactive terminal UI (requires --features tui)
muninn -e ./evidence/ -r sigma-rules/ --tui

# Real-time monitoring (requires --features live)
muninn -e /var/log/ -r sigma-rules/ --live

# YAML config file (persist all settings)
muninn --config muninn.yaml
# muninn.yaml:
#   events: ./evidence/
#   rules: sigma-rules/
#   min_level: medium
#   stats: true
#   timeline: true
#   killchain: true
#   threat_score: true
```
</details>

## Features

### Core

| | |
|---|---|
| **15+ formats** | EVTX, JSON, CSV, XML, Syslog, CEF, LEEF, Zeek, W3C, Auditd, macOS — auto-detected |
| **3100+ SIGMA rules** | Full [SigmaHQ](https://github.com/SigmaHQ/sigma) ruleset — download with `--download-rules` |
| **SIGMA compiler** | YAML → SQL with modifiers: `contains`, `endswith`, `startswith`, `re`, `base64`, `base64offset`, `windash`, `cidr`, `all`, `gt/gte/lt/lte` |
| **Search engine** | SQLite-backed: keyword, field, regex, raw SQL |
| **Single binary** | Static, no runtime dependencies |
| **Cross-platform** | Linux x86_64, Windows x86_64 |
| **Library + CLI** | Use as Rust crate, CLI tool, or Python module |

### v0.4.0 — Advanced Analysis

| Feature | Flag | Description |
|---------|------|-------------|
| **MITRE ATT&CK mapping** | *(auto)* | Maps detections to techniques/tactics from rule tags |
| **ATT&CK Navigator** | `--navigator layer.json` | Export layer for ATT&CK Navigator |
| **Kill chain view** | `--killchain [FILE]` | ASCII kill chain visualization by tactic |
| **Attack timeline** | `--timeline [FILE]` | Chronological attack timeline |
| **Anomaly detection** | `--anomalies [FILE]` | Rare processes, off-hours logons, unusual parent-child |
| **IOC extraction** | `--ioc-extract [FILE]` | Extract IPs, domains, URLs, hashes, emails |
| **IOC enrichment** | `--vt-key` / `--abuseipdb-key` / `--opentip-key` | VirusTotal, AbuseIPDB, Kaspersky OpenTIP |
| **Threat scoring** | `--threat-score [FILE]` | Per-host/user risk scoring |
| **Attack correlation** | `--correlate [FILE]` | Group detections into attack chains |
| **Diff mode** | `--diff /path/to/second/` | Compare two evidence sets |
| **Field transforms** | `--transforms` | Base64 decode, LOLBin detect, DNS entropy, obfuscation scoring |
| **Field mapping** | `--field-map map.yaml` | Rename fields across all events |
| **Early filtering** | *(auto)* | Pre-filter events by EventID/Channel from rules |
| **Per-file mode** | `--per-file` | Parallel processing with per-file SQLite DBs |
| **Time filter** | `--after` / `--before` | Filter events by timestamp |
| **Rule profiling** | `--profile-rules` | Show rule execution time ranking |
| **Config file** | `--config muninn.yaml` | YAML config for all settings |
| **Rule download** | `--download-rules <SET>` | Download SIGMA rules from SigmaHQ (core, core+, all, emerging) |

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
| **Rule download** | `--features download` | Download SIGMA rules from SigmaHQ releases |
| **IOC enrichment** | `--features ioc-enrich` | VT/AbuseIPDB/OpenTIP API queries |

## Example Output

```
  ███    ███  ██    ██  ███    ██  ██  ███    ██  ███    ██
  ████  ████  ██    ██  ████   ██  ██  ████   ██  ████   ██
  ██ ████ ██  ██    ██  ██ ██  ██  ██  ██ ██  ██  ██ ██  ██
  ██  ██  ██  ██    ██  ██  ██ ██  ██  ██  ██ ██  ██  ██ ██
  ██  ██  ██  ██    ██  ██   ████  ██  ██   ████  ██   ████
  ██      ██   ██████   ██    ███  ██  ██    ███  ██    ███
              Memory of Corax
  -= SIGMA Detection Engine for EVTX/JSON/Syslog/CEF/Zeek v0.4.0 =-

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

  [*] Summary
      Duration      3.20s
      Files         42
      Events        847293
      Throughput    264778 events/s
      Detections    1 CRITICAL  2 HIGH  2 MEDIUM  1 LOW
      Coverage      12/2384 rules matched (0.5%)
      Matched       116 events across 12 rules
      Top Hits
                    CRITICAL Mimikatz Command Line (14)
                    HIGH Suspicious Encoded PowerShell (23)

  ATT&CK Coverage
  Execution              ####################  2 technique(s) (70 hits)
  Credential Access      ##########            2 technique(s) (17 hits)
  Persistence            #####                 1 technique(s) (8 hits)
  Discovery              ################      1 technique(s) (47 hits)

  -> muninn_report_2026-03-11_14-30-00.json
```

## Forensic SQL Cookbook

<details>
<summary><b>Incident Response — lateral movement</b></summary>

```bash
# Remote logons (network + RDP)
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '4624' AND \"LogonType\" IN ('3','10')"

# PsExec detection
muninn -e evidence/ -k "psexec"

# Pass-the-hash
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '4624' AND \"LogonType\" = '3' AND \"AuthenticationPackageName\" = 'NTLM'"

# WMI lateral movement
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"ParentImage\" LIKE '%wmiprvse.exe' AND \"EventID\" = '1'"

# Remote service creation
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '7045' AND \"ServiceFileName\" LIKE '%\\\\%'"

# RDP sessions
muninn -e evidence/ --sql "SELECT \"TargetUserName\",\"IpAddress\",\"LogonType\" FROM events WHERE \"EventID\" = '4624' AND \"LogonType\" = '10'"

# SMB file copies
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '5145' AND \"RelativeTargetName\" LIKE '%.exe'"
```
</details>

<details>
<summary><b>Threat Hunting — suspicious processes</b></summary>

```bash
# Encoded PowerShell
muninn -e evidence/ --regex "CommandLine=.*-[eE]nc[oO]?d?e?d?C?o?m?m?a?n?d?\s+[A-Za-z0-9+/=]{20,}"

# LOLBins downloading files
muninn -e evidence/ --sql "SELECT \"Image\",\"CommandLine\" FROM events WHERE \"CommandLine\" LIKE '%http%' AND (\"Image\" LIKE '%certutil%' OR \"Image\" LIKE '%mshta%' OR \"Image\" LIKE '%regsvr32%' OR \"Image\" LIKE '%bitsadmin%')"

# Office spawning processes
muninn -e evidence/ --sql "SELECT \"Image\",\"CommandLine\",\"ParentImage\" FROM events WHERE \"ParentImage\" LIKE '%WINWORD%' OR \"ParentImage\" LIKE '%EXCEL%' OR \"ParentImage\" LIKE '%OUTLOOK%' OR \"ParentImage\" LIKE '%POWERPNT%'"

# Reconnaissance commands
muninn -e evidence/ --sql "SELECT \"CommandLine\",\"User\",\"Image\" FROM events WHERE \"Image\" LIKE '%whoami%' OR \"Image\" LIKE '%net.exe' OR \"Image\" LIKE '%ipconfig%' OR \"Image\" LIKE '%systeminfo%' OR \"Image\" LIKE '%nltest%' OR \"Image\" LIKE '%tasklist%' OR \"Image\" LIKE '%qprocess%'"

# Suspicious PowerShell downloads
muninn -e evidence/ --sql "SELECT \"CommandLine\" FROM events WHERE \"CommandLine\" LIKE '%Invoke-WebRequest%' OR \"CommandLine\" LIKE '%wget%' OR \"CommandLine\" LIKE '%curl%' OR \"CommandLine\" LIKE '%DownloadString%' OR \"CommandLine\" LIKE '%DownloadFile%'"

# Process injection indicators (Sysmon 8 — CreateRemoteThread)
muninn -e evidence/ --sql "SELECT \"SourceImage\",\"TargetImage\" FROM events WHERE \"EventID\" = '8'"

# Unsigned processes from temp
muninn -e evidence/ --sql "SELECT \"Image\",\"CommandLine\" FROM events WHERE \"Image\" LIKE '%\\Temp\\%' OR \"Image\" LIKE '%\\tmp\\%' OR \"Image\" LIKE '%\\AppData\\%'"

# Renamed system binaries
muninn -e evidence/ --sql "SELECT \"Image\",\"OriginalFileName\",\"CommandLine\" FROM events WHERE \"OriginalFileName\" IS NOT NULL AND \"Image\" NOT LIKE '%\\' || \"OriginalFileName\""
```
</details>

<details>
<summary><b>Persistence</b></summary>

```bash
# Scheduled tasks
muninn -e evidence/ --sql "SELECT \"CommandLine\" FROM events WHERE \"EventID\" = '1' AND \"CommandLine\" LIKE '%schtasks%create%'"

# New services
muninn -e evidence/ --sql "SELECT \"ServiceName\",\"ImagePath\",\"ServiceType\" FROM events WHERE \"EventID\" = '7045'"

# Registry Run keys (Sysmon 13)
muninn -e evidence/ --sql "SELECT \"Image\",\"TargetObject\",\"Details\" FROM events WHERE \"EventID\" = '13' AND \"TargetObject\" LIKE '%\\Run\\%'"

# WMI event subscriptions
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" IN ('19','20','21')"

# Startup folder file creation (Sysmon 11)
muninn -e evidence/ --sql "SELECT \"Image\",\"TargetFilename\" FROM events WHERE \"EventID\" = '11' AND \"TargetFilename\" LIKE '%Startup%'"

# DLL hijacking (Sysmon 7 — Image Load)
muninn -e evidence/ --sql "SELECT \"Image\",\"ImageLoaded\" FROM events WHERE \"EventID\" = '7' AND \"Signed\" = 'false'"
```
</details>

<details>
<summary><b>Credential Access</b></summary>

```bash
# LSASS access (Sysmon 10)
muninn -e evidence/ --sql "SELECT \"SourceImage\",\"GrantedAccess\" FROM events WHERE \"EventID\" = '10' AND \"TargetImage\" LIKE '%lsass.exe'"

# Kerberoasting (TGS with RC4)
muninn -e evidence/ --sql "SELECT \"TargetUserName\",\"ServiceName\",\"TicketEncryptionType\" FROM events WHERE \"EventID\" = '4769' AND \"TicketEncryptionType\" = '0x17'"

# AS-REP Roasting
muninn -e evidence/ --sql "SELECT \"TargetUserName\" FROM events WHERE \"EventID\" = '4768' AND \"TicketEncryptionType\" = '0x17'"

# SAM database access
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '10' AND \"TargetImage\" LIKE '%\\lsass.exe' AND \"GrantedAccess\" IN ('0x1010','0x1038','0x1fffff')"

# SSH brute force
muninn -e auth.log -k "Invalid user" --stats

# Failed logons
muninn -e evidence/ --sql "SELECT \"TargetUserName\",\"IpAddress\",COUNT(*) as cnt FROM events WHERE \"EventID\" = '4625' GROUP BY \"TargetUserName\",\"IpAddress\" ORDER BY cnt DESC"

# DCSync (directory replication)
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '4662' AND \"Properties\" LIKE '%1131f6ad%'"
```
</details>

<details>
<summary><b>Network analysis — IPs, domains, C2</b></summary>

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

# C2 common ports
muninn -e evidence/ --sql "
  SELECT \"DestinationIp\",\"DestinationPort\",\"Image\" FROM events
  WHERE \"DestinationPort\" IN ('4444','5555','8080','8443','1337','9001','6666','1234')
"

# Suspicious TLDs
muninn -e evidence/ --sql "
  SELECT \"QueryName\",\"Image\" FROM events WHERE \"EventID\" = '22'
    AND (\"QueryName\" LIKE '%.xyz' OR \"QueryName\" LIKE '%.top' OR \"QueryName\" LIKE '%.tk'
      OR \"QueryName\" LIKE '%.pw' OR \"QueryName\" LIKE '%.onion' OR \"QueryName\" LIKE '%.bit')
"

# High-frequency DNS queries (possible beaconing)
muninn -e evidence/ --sql "SELECT \"QueryName\", COUNT(*) as cnt FROM events WHERE \"EventID\" = '22' GROUP BY \"QueryName\" HAVING cnt > 100 ORDER BY cnt DESC"

# Long DNS names (possible tunneling)
muninn -e evidence/ --sql "SELECT \"QueryName\" FROM events WHERE \"EventID\" = '22' AND LENGTH(\"QueryName\") > 50"

# Outbound connections by process
muninn -e evidence/ --sql "SELECT \"Image\", COUNT(DISTINCT \"DestinationIp\") as ips FROM events WHERE \"EventID\" = '3' GROUP BY \"Image\" ORDER BY ips DESC LIMIT 20"

# All unique external IPs
muninn -e evidence/ --distinct DestinationIp

# All unique DNS queries
muninn -e evidence/ --distinct QueryName
```
</details>

<details>
<summary><b>Defense evasion</b></summary>

```bash
# Sysmon config tampering
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '16'"

# Log clearing
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" IN ('1102','104')"

# Disable Windows Defender
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"CommandLine\" LIKE '%DisableRealtimeMonitoring%' OR \"CommandLine\" LIKE '%Set-MpPreference%'"

# AMSI bypass attempts
muninn -e evidence/ -k "AmsiUtils"
muninn -e evidence/ --sql "SELECT \"CommandLine\" FROM events WHERE \"CommandLine\" LIKE '%amsi%bypass%' OR \"CommandLine\" LIKE '%AmsiInitFailed%'"

# Timestomping (Sysmon 2 — FileCreateTime changed)
muninn -e evidence/ --sql "SELECT \"Image\",\"TargetFilename\" FROM events WHERE \"EventID\" = '2'"

# Process hollowing (Sysmon 25 — ProcessTampering)
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '25'"
```
</details>

<details>
<summary><b>Linux & Cloud</b></summary>

```bash
# Linux — sudo abuse
muninn -e /var/log/auth.log -k "sudo" --stats

# Linux — SSH brute force
muninn -e /var/log/auth.log --sql "SELECT * FROM events WHERE \"_raw\" LIKE '%Failed password%'"

# Linux — cron persistence
muninn -e /var/log/syslog -k "CRON" --stats

# Linux — new users
muninn -e /var/log/auth.log -k "useradd"

# AWS CloudTrail — console login without MFA
muninn -e cloudtrail/ --sql "SELECT * FROM events WHERE \"eventName\" = 'ConsoleLogin' AND \"additionalEventData\" NOT LIKE '%MFAUsed%Yes%'"

# AWS — IAM changes
muninn -e cloudtrail/ --sql "SELECT \"eventName\",\"userIdentity\",\"requestParameters\" FROM events WHERE \"eventSource\" = 'iam.amazonaws.com'"

# Azure — risky sign-ins
muninn -e azure-logs/ --sql "SELECT * FROM events WHERE \"riskState\" = 'atRisk'"

# Zeek — DNS queries
muninn -e zeek-logs/dns.log --distinct query
muninn -e zeek-logs/dns.log --sql "SELECT \"query\", COUNT(*) as cnt FROM events GROUP BY \"query\" ORDER BY cnt DESC LIMIT 30"
```
</details>

<details>
<summary><b>Data exploration & export</b></summary>

```bash
# Field statistics
muninn -e evidence/ --stats
muninn -e evidence/ --distinct EventID
muninn -e evidence/ --distinct Image
muninn -e evidence/ --distinct User
muninn -e evidence/ --distinct Channel
muninn -e evidence/ --distinct LogonType

# Export to SQLite for advanced analysis
muninn -e evidence/ --dbfile case.db
sqlite3 case.db "SELECT \"Image\", COUNT(*) as cnt FROM events WHERE \"EventID\" = '1' GROUP BY \"Image\" ORDER BY cnt DESC LIMIT 20"
sqlite3 case.db ".schema events"

# Top processes by count
muninn -e evidence/ --sql "SELECT \"Image\", COUNT(*) as cnt FROM events WHERE \"Image\" IS NOT NULL GROUP BY \"Image\" ORDER BY cnt DESC LIMIT 30"

# Event timeline (hourly distribution)
muninn -e evidence/ --sql "SELECT SUBSTR(\"SystemTime\",1,13) as hour, COUNT(*) as cnt FROM events WHERE \"SystemTime\" IS NOT NULL GROUP BY hour ORDER BY hour"

# Users with most activity
muninn -e evidence/ --sql "SELECT \"User\", COUNT(*) as cnt FROM events WHERE \"User\" IS NOT NULL GROUP BY \"User\" ORDER BY cnt DESC LIMIT 20"
```
</details>

<details>
<summary><b>Complete investigation workflow</b></summary>

```bash
# Step 1: Download rules
muninn --download-rules all

# Step 2: Quick triage
muninn -e ./evidence/ -r sigma-rules/ --min-level high --stats

# Step 3: Full analysis
muninn -e ./evidence/ -r sigma-rules/ --stats --timeline --killchain --threat-score --anomalies --ioc-extract --correlate --gui report.html

# Step 4: Export for SIEM ingestion
muninn -e ./evidence/ -r sigma-rules/ --template splunk --template-output splunk-import.json

# Step 5: Deep-dive with TUI
muninn -e ./evidence/ -r sigma-rules/ --tui

# Step 6: Export enriched IOCs
muninn -e ./evidence/ --ioc-extract --vt-key YOUR_KEY -o ioc-report.json

# Step 7: Compare before/after remediation
muninn -e ./evidence-before/ -r sigma-rules/ --diff ./evidence-after/
```
</details>

## SIGMA Rules

3100+ rules from [SigmaHQ](https://github.com/SigmaHQ/sigma). Download directly or use your own:

```bash
# Download rules from SigmaHQ (requires --features download)
muninn --download-rules all                    # all 3100+ rules → sigma-rules/
muninn --download-rules core                   # curated core ruleset
muninn --download-rules core+                  # core + extended
muninn --download-rules emerging               # emerging threats addon
muninn --download-rules all --rules-dir ./my-rules/  # custom output directory
```

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
muninn -e events.json -r sigma-rules/                            # all rules
muninn -e events.json -r sigma-rules/rules/windows/process_creation/   # Windows process creation
muninn -e events.json -r sigma-rules/rules/linux/                      # Linux only
muninn -e events.json -r sigma-rules/rules/cloud/                      # cloud only
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
      --dbfile [FILE]            Export SQLite database (auto-named if no path given)
      --keepflat [FILE]          Export flattened events as JSONL (auto-named if no path given)
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

ANALYSIS (all support optional FILE path — .txt default, .html/.json by extension):
      --timeline [FILE]          Show attack timeline and save to file
      --killchain [FILE]         Kill chain visualization and save to file
      --anomalies [FILE]         Detect statistical anomalies and save to file
      --ioc-extract [FILE]       Extract IOCs and save to file
      --threat-score [FILE]      Per-host/user threat scoring and save to file
      --correlate [FILE]         Correlate events into attack chains and save to file
      --transforms               Field transforms (base64 decode, LOLBin, DNS entropy)

IOC ENRICHMENT (requires --features ioc-enrich):
      --vt-key <KEY>             VirusTotal API key
      --abuseipdb-key <KEY>      AbuseIPDB API key
      --opentip-key <KEY>        Kaspersky OpenTIP API key

EXPORT:
      --navigator [FILE]         ATT&CK Navigator layer JSON (auto-named if no path given)
      --template <FORMAT>        Export: splunk, elk, timesketch, csv, sarif
      --template-output [FILE]   Template output path (auto-named if no path given)
      --gui [FILE]               Self-contained HTML report (auto-named if no path given)

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

RULES DOWNLOAD (requires --features download):
      --download-rules <SET>     Download SIGMA rules: core, core+, all, emerging
      --rules-dir <PATH>         Output directory for downloaded rules [default: sigma-rules]

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
# Standard build
cargo build --release --features "all-parsers,cli"

# Full build with all optional features
cargo build --release --features "all-parsers,cli,archive,download,tui,live,ioc-enrich"

# Run tests
cargo test --features "all-parsers,cli,archive,download,tui,live,ioc-enrich"
```

<details>
<summary><b>Feature flags, Docker, cross-compilation</b></summary>

| Feature | Description |
|---------|-------------|
| `all-parsers` | All format parsers (default) |
| `cli` | CLI binary |
| `archive` | .gz/.zip/.bz2/.tar.gz support (flate2, zip, bzip2, tar) |
| `download` | Download SIGMA rules from SigmaHQ releases (ureq, zip) |
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
| Binary size | Single static binary (release, stripped, LTO) |
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
# Скачать SIGMA-правила (один раз)
muninn --download-rules all

# Полный анализ
muninn -e ./evidence/ -r sigma-rules/ --stats --timeline --killchain --threat-score

# Поиск по ключевому слову
muninn -e ./evidence/ -k "mimikatz"

# Извлечение IOC с обогащением через VirusTotal
muninn -e ./evidence/ --ioc-extract --vt-key YOUR_API_KEY

# Детекция аномалий
muninn -e ./evidence/ --anomalies

# HTML-отчёт
muninn -e ./evidence/ -r sigma-rules/ --gui report.html

# Экспорт для SIEM
muninn -e ./evidence/ -r sigma-rules/ --template splunk --template-output detections.json

# Скачать разные наборы правил
muninn --download-rules core                         # базовый набор
muninn --download-rules core+                        # расширенный набор
muninn --download-rules all                          # все 3100+ правил
muninn --download-rules emerging                     # новые угрозы
muninn --download-rules all --rules-dir ./my-rules/  # своя директория
```

### Возможности

#### Ядро

| | |
|---|---|
| **15+ форматов** | EVTX, JSON, CSV, XML, Syslog, CEF, LEEF, Zeek, W3C, Auditd, macOS — автоопределение |
| **3100+ SIGMA-правил** | Полный набор [SigmaHQ](https://github.com/SigmaHQ/sigma) — скачать через `--download-rules` |
| **Компилятор SIGMA** | YAML → SQL с модификаторами: `contains`, `endswith`, `startswith`, `re`, `base64`, `base64offset`, `windash`, `cidr`, `all`, `gt/gte/lt/lte` |
| **Поисковый движок** | На базе SQLite: ключевые слова, поля, регулярные выражения, SQL |
| **Один бинарник** | Статический, без внешних зависимостей |
| **Кроссплатформенный** | Linux x86_64, Windows x86_64 |
| **Библиотека + CLI** | Rust-крейт, CLI-утилита или Python-модуль |

#### v0.4.0 — Продвинутая аналитика

| Функция | Флаг | Описание |
|---------|------|----------|
| **Маппинг MITRE ATT&CK** | *(авто)* | Привязка детектов к техникам и тактикам из тегов правил |
| **ATT&CK Navigator** | `--navigator layer.json` | Экспорт слоя для ATT&CK Navigator |
| **Kill chain** | `--killchain [FILE]` | ASCII-визуализация по тактикам, сохранение в файл |
| **Таймлайн атаки** | `--timeline [FILE]` | Хронологический таймлайн атаки, сохранение в файл |
| **Детекция аномалий** | `--anomalies [FILE]` | Редкие процессы, нетипичное время логона, необычные parent-child |
| **Извлечение IOC** | `--ioc-extract [FILE]` | IP-адреса, домены, URL, хэши, email |
| **Обогащение IOC** | `--vt-key` / `--abuseipdb-key` / `--opentip-key` | VirusTotal, AbuseIPDB, Kaspersky OpenTIP |
| **Threat scoring** | `--threat-score [FILE]` | Оценка рисков по хостам/пользователям |
| **Корреляция атак** | `--correlate [FILE]` | Группировка детектов в цепочки атак |
| **Diff-режим** | `--diff /path/second/` | Сравнение двух наборов данных |
| **Трансформации** | `--transforms` | Base64-декодирование, LOLBin-детект, DNS-энтропия, обфускация |
| **Маппинг полей** | `--field-map map.yaml` | Переименование полей во всех событиях |
| **Ранняя фильтрация** | *(авто)* | Предварительная фильтрация по EventID/Channel из правил |
| **Per-file режим** | `--per-file` | Параллельная обработка с отдельным SQLite на файл |
| **Фильтр времени** | `--after` / `--before` | Фильтрация по метке времени |
| **Профилирование правил** | `--profile-rules` | Рейтинг скорости выполнения правил |
| **YAML-конфиг** | `--config muninn.yaml` | Все настройки в YAML-файле |
| **Скачивание правил** | `--download-rules <SET>` | Скачивание SIGMA-правил из SigmaHQ (core, core+, all, emerging) |

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
| **JSONL** | `--keepflat events.jsonl` | Экспорт выровненных событий |

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
# Стандартная сборка
cargo build --release --features "all-parsers,cli"

# Полная сборка со всеми опциональными фичами
cargo build --release --features "all-parsers,cli,archive,download,tui,live,ioc-enrich"

# Запуск тестов
cargo test --features "all-parsers,cli,archive,download,tui,live,ioc-enrich"
```

### Лицензия

**AGPL-3.0** — см. [LICENSE](LICENSE).

SIGMA-правила в `rules/` — [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License) от SigmaHQ.
