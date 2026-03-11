use anyhow::{Context, Result};
use chrono::Local;
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use muninn::{parsers, search::SearchEngine, sigma};

#[derive(serde::Deserialize, Default)]
#[allow(dead_code)]
struct Config {
    events: Option<PathBuf>,
    rules: Option<PathBuf>,
    min_level: Option<String>,
    limit: Option<usize>,
    hashes: Option<bool>,
    quiet: Option<bool>,
    no_report: Option<bool>,
    stats: Option<bool>,
    select: Option<String>,
    avoid: Option<String>,
    output: Option<PathBuf>,
    dbfile: Option<PathBuf>,
    distinct: Option<String>,
    rulefilter: Option<Vec<String>>,
    profile_rules: Option<bool>,
    after: Option<String>,
    before: Option<String>,
    transforms: Option<bool>,
    timeline: Option<bool>,
    anomalies: Option<bool>,
    ioc_extract: Option<bool>,
    threat_score: Option<bool>,
    correlate: Option<bool>,
    killchain: Option<bool>,
    max_events: Option<usize>,
    workers: Option<usize>,
    batch_size: Option<usize>,
}

#[derive(Parser)]
#[command(
    name = "muninn",
    version,
    about = "Muninn — memory of Corax. Universal log parser, SIGMA detection engine, and search tool. 15+ formats, one binary, zero dependencies."
)]
struct Cli {
    #[arg(short = 'e', long = "events")]
    events: PathBuf,

    #[arg(short = 'r', long = "rules")]
    rules: Option<PathBuf>,

    #[arg(long = "sql-file")]
    sql_file: Option<PathBuf>,

    #[arg(long = "sql")]
    sql: Option<String>,

    #[arg(short = 'k', long = "keyword")]
    keyword: Option<String>,

    #[arg(short = 'f', long = "field")]
    field_search: Option<String>,

    #[arg(long = "regex")]
    regex_search: Option<String>,

    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,

    #[arg(long = "dbfile")]
    dbfile: Option<PathBuf>,

    #[arg(short = 's', long = "select")]
    select: Option<String>,

    #[arg(short = 'a', long = "avoid")]
    avoid: Option<String>,

    #[arg(long = "hashes")]
    hashes: bool,

    #[arg(long = "stats")]
    stats: bool,

    #[arg(long = "distinct")]
    distinct: Option<String>,

    #[arg(long = "min-level", default_value = "low")]
    min_level: String,

    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    #[arg(long = "no-report")]
    no_report: bool,

    // --- Phase 1 features ---
    #[arg(long = "limit", help = "Limit number of result rows")]
    limit: Option<usize>,

    #[arg(
        long = "rulefilter",
        help = "Exclude rules matching pattern (repeatable)"
    )]
    rulefilter: Vec<String>,

    #[arg(long = "profile-rules", help = "Show rule execution time ranking")]
    profile_rules: bool,

    #[arg(long = "after", help = "Only events after timestamp (ISO 8601)")]
    after: Option<String>,

    #[arg(long = "before", help = "Only events before timestamp (ISO 8601)")]
    before: Option<String>,

    #[arg(long = "config", help = "YAML config file")]
    config: Option<PathBuf>,

    // --- Phase 2 features ---
    #[arg(long = "add-index", num_args = 1.., help = "Create index on field(s)")]
    add_index: Vec<String>,

    #[arg(long = "remove-index", num_args = 1.., help = "Remove index by name")]
    remove_index: Vec<String>,

    #[arg(long = "field-map", help = "YAML field rename mapping file")]
    field_map: Option<PathBuf>,

    #[arg(long = "keepflat", help = "Export flattened events as JSONL")]
    keepflat: Option<PathBuf>,

    // --- Phase 3 features ---
    #[arg(long = "navigator", help = "Export ATT&CK Navigator layer JSON")]
    navigator: Option<PathBuf>,

    #[arg(long = "killchain", help = "Show kill chain view of detections")]
    killchain: bool,

    // --- Phase 4 features ---
    #[arg(
        long = "template",
        help = "Output template: splunk, elk, timesketch, csv, sarif"
    )]
    template: Option<String>,

    #[arg(long = "template-output", help = "Template output file path")]
    template_output: Option<PathBuf>,

    #[arg(long = "gui", help = "Generate self-contained HTML report")]
    gui: Option<PathBuf>,

    // --- Phase 5 features ---
    #[arg(
        long = "transforms",
        help = "Apply field transforms (base64 decode, IOC extract, LOLBin detect)"
    )]
    transforms: bool,

    #[arg(long = "timeline", help = "Show attack timeline")]
    timeline: bool,

    #[arg(long = "anomalies", help = "Detect statistical anomalies")]
    anomalies: bool,

    #[arg(long = "ioc-extract", help = "Extract IOCs from events")]
    ioc_extract: bool,

    #[arg(long = "vt-key", help = "VirusTotal API key for IOC enrichment")]
    vt_key: Option<String>,

    #[arg(long = "abuseipdb-key", help = "AbuseIPDB API key for IP enrichment")]
    abuseipdb_key: Option<String>,

    #[arg(
        long = "opentip-key",
        help = "Kaspersky OpenTIP API key for IOC enrichment"
    )]
    opentip_key: Option<String>,

    #[arg(long = "threat-score", help = "Compute per-host/user threat scores")]
    threat_score: bool,

    // --- Phase 6 features ---
    #[arg(long = "diff", help = "Compare with second evidence set")]
    diff: Option<PathBuf>,

    #[arg(long = "correlate", help = "Correlate events into attack chains")]
    correlate: bool,

    #[arg(
        long = "per-file",
        help = "Process each file in separate DB (parallel)"
    )]
    per_file: bool,

    // --- Phase 7 features ---
    #[cfg(feature = "tui")]
    #[arg(long = "tui", help = "Launch interactive terminal UI")]
    tui: bool,

    #[cfg(feature = "live")]
    #[arg(
        long = "live",
        help = "Watch directory for changes and detect in real-time"
    )]
    live: bool,

    // --- Performance controls ---
    #[arg(long = "max-events", help = "Maximum events to load (memory control)")]
    max_events: Option<usize>,

    #[arg(
        long = "workers",
        help = "Number of parallel workers (default: CPU cores)"
    )]
    workers: Option<usize>,

    #[arg(
        long = "batch-size",
        help = "Events per batch for loading (default: 50000)"
    )]
    batch_size: Option<usize>,
}

struct Detection {
    title: String,
    level: String,
    description: String,
    id: String,
    author: String,
    tags: Vec<String>,
    result: muninn::SearchResult,
}

fn level_rank(level: &str) -> u8 {
    match level.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "informational" | "info" => 1,
        _ => 0,
    }
}

fn level_color(level: &str) -> colored::ColoredString {
    match level.to_lowercase().as_str() {
        "critical" => level.to_uppercase().bold().red(),
        "high" => level.to_uppercase().bold().magenta(),
        "medium" => level.to_uppercase().bold().yellow(),
        "low" => level.to_uppercase().green(),
        _ => level.to_uppercase().dimmed(),
    }
}

fn main() -> Result<()> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Warn)
        .init();
    let mut cli = Cli::parse();
    let start = Instant::now();
    let run_timestamp = Local::now();

    // Merge YAML config if provided
    if let Some(ref config_path) = cli.config {
        let content = std::fs::read_to_string(config_path)
            .context(format!("Failed to read config {:?}", config_path))?;
        let cfg: Config = serde_yaml::from_str(&content)
            .context(format!("Failed to parse config {:?}", config_path))?;
        // CLI flags take precedence over config
        if cli.rules.is_none() {
            cli.rules = cfg.rules;
        }
        if cli.min_level == "low" {
            if let Some(ml) = cfg.min_level {
                cli.min_level = ml;
            }
        }
        if cli.limit.is_none() {
            cli.limit = cfg.limit;
        }
        if !cli.hashes {
            cli.hashes = cfg.hashes.unwrap_or(false);
        }
        if !cli.quiet {
            cli.quiet = cfg.quiet.unwrap_or(false);
        }
        if !cli.no_report {
            cli.no_report = cfg.no_report.unwrap_or(false);
        }
        if !cli.stats {
            cli.stats = cfg.stats.unwrap_or(false);
        }
        if cli.select.is_none() {
            cli.select = cfg.select;
        }
        if cli.avoid.is_none() {
            cli.avoid = cfg.avoid;
        }
        if cli.output.is_none() {
            cli.output = cfg.output;
        }
        if cli.dbfile.is_none() {
            cli.dbfile = cfg.dbfile;
        }
        if cli.distinct.is_none() {
            cli.distinct = cfg.distinct;
        }
        if cli.rulefilter.is_empty() {
            cli.rulefilter = cfg.rulefilter.unwrap_or_default();
        }
        if !cli.profile_rules {
            cli.profile_rules = cfg.profile_rules.unwrap_or(false);
        }
        if cli.after.is_none() {
            cli.after = cfg.after;
        }
        if cli.before.is_none() {
            cli.before = cfg.before;
        }
        if !cli.transforms {
            cli.transforms = cfg.transforms.unwrap_or(false);
        }
        if !cli.timeline {
            cli.timeline = cfg.timeline.unwrap_or(false);
        }
        if !cli.anomalies {
            cli.anomalies = cfg.anomalies.unwrap_or(false);
        }
        if !cli.ioc_extract {
            cli.ioc_extract = cfg.ioc_extract.unwrap_or(false);
        }
        if !cli.threat_score {
            cli.threat_score = cfg.threat_score.unwrap_or(false);
        }
        if !cli.correlate {
            cli.correlate = cfg.correlate.unwrap_or(false);
        }
        if !cli.killchain {
            cli.killchain = cfg.killchain.unwrap_or(false);
        }
    }

    // Load field mapping if provided
    let field_map: Option<HashMap<String, String>> = if let Some(ref map_path) = cli.field_map {
        let content = std::fs::read_to_string(map_path)
            .context(format!("Failed to read field map {:?}", map_path))?;
        Some(
            serde_yaml::from_str(&content)
                .context(format!("Failed to parse field map {:?}", map_path))?,
        )
    } else {
        None
    };

    if !cli.quiet {
        println!();
        println!(
            "{}",
            "  ███╗   ███╗██╗   ██╗███╗   ██╗██╗███╗   ██╗███╗   ██╗"
                .truecolor(200, 200, 210)
                .bold()
        );
        println!(
            "{}",
            "  ████╗ ████║██║   ██║████╗  ██║██║████╗  ██║████╗  ██║"
                .truecolor(170, 160, 200)
                .bold()
        );
        println!(
            "{}",
            "  ██╔████╔██║██║   ██║██╔██╗ ██║██║██╔██╗ ██║██╔██╗ ██║"
                .truecolor(140, 120, 190)
                .bold()
        );
        println!(
            "{}",
            "  ██║╚██╔╝██║██║   ██║██║╚██╗██║██║██║╚██╗██║██║╚██╗██║"
                .truecolor(110, 80, 170)
                .bold()
        );
        println!(
            "{}",
            "  ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║██║ ╚████║██║ ╚████║".truecolor(80, 50, 140)
        );
        println!(
            "{}",
            "  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝".truecolor(60, 30, 110)
        );
        println!(
            "  {} SIGMA Detection Engine for EVTX/JSON/Syslog/CEF/Zeek {}",
            "-=".truecolor(100, 80, 150),
            format!("v{} =-", env!("CARGO_PKG_VERSION")).truecolor(100, 80, 150)
        );
        println!();
    }

    let files = parsers::discover_files(
        &cli.events,
        cli.select.as_deref(),
        cli.avoid.as_deref(),
        true,
    )?;

    if files.is_empty() {
        if !cli.quiet {
            println!("  {} No log files found in {:?}", "✗".red(), cli.events);
        }
        return Ok(());
    }

    let pb = if !cli.quiet {
        let pb = ProgressBar::new(files.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  {spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} files | {msg}")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏ "),
        );
        Some(pb)
    } else {
        None
    };

    // Build early event filter from rules (if available)
    let event_filter = if let Some(ref rules_path) = cli.rules {
        match sigma::load_rules(rules_path) {
            Ok(rules) => {
                let filter = muninn::EventFilter::from_rules(&rules);
                if !filter.is_pass_all() && !cli.quiet {
                    println!(
                        "  {} Early filter active ({} field constraints)",
                        "✓".green(),
                        filter.field_count()
                    );
                }
                Some(filter)
            }
            Err(_) => None,
        }
    } else {
        None
    };

    // Configure thread pool for parallel operations
    if let Some(workers) = cli.workers {
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build_global()
            .ok(); // ignore if already initialized
    }

    let batch_size = cli.batch_size.unwrap_or(50_000);
    let max_events = cli.max_events;

    let mut engine = SearchEngine::new()?;
    let mut total_events = 0usize;
    let filtered_events = 0usize;
    let mut format_stats: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut parse_errors: Vec<String> = Vec::new();

    // Phase 1: Parse files in parallel with rayon
    let do_transforms = cli.transforms;
    let do_hashes = cli.hashes;

    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let progress_counter = AtomicUsize::new(0);

    let parsed_results: Vec<(PathBuf, Result<muninn::ParseResult, String>)> = files
        .par_iter()
        .map(|file| {
            let result = parsers::parse_file(file);
            // Update progress (atomic for thread safety)
            progress_counter.fetch_add(1, Ordering::Relaxed);
            match result {
                Ok(mut pr) => {
                    // Apply field mapping (per-event, parallelizable)
                    if let Some(ref fmap) = field_map {
                        for ev in &mut pr.events {
                            ev.apply_field_map(fmap);
                        }
                    }
                    // Apply transforms
                    if do_transforms {
                        muninn::transforms::apply_transforms(
                            &mut pr.events,
                            &muninn::transforms::default_transforms(),
                        );
                    }
                    // Compute hashes
                    if do_hashes {
                        for ev in &mut pr.events {
                            ev.compute_hash();
                        }
                    }
                    // Apply early event filter
                    if let Some(ref filter) = event_filter {
                        pr.events.retain(|ev| filter.matches(ev));
                    }
                    (file.clone(), Ok(pr))
                }
                Err(e) => {
                    let msg = format!(
                        "{}: {}",
                        file.file_name().unwrap_or_default().to_string_lossy(),
                        e
                    );
                    (file.clone(), Err(msg))
                }
            }
        })
        .collect();

    // Phase 2: Load parsed results into SearchEngine sequentially (SQLite is single-threaded)
    let total_parsed = parsed_results.len();
    for (i, (_file, result)) in parsed_results.into_iter().enumerate() {
        if let Some(ref pb) = pb {
            let name = _file
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            pb.set_message(format!("Loading {}", name));
            pb.set_position((i + 1) as u64);
        }
        match result {
            Ok(pr) => {
                let original_count = pr.events.len();
                let events_to_load = if let Some(max) = max_events {
                    if total_events >= max {
                        continue; // skip remaining files
                    }
                    let remaining = max - total_events;
                    if pr.events.len() > remaining {
                        pr.events[..remaining].to_vec()
                    } else {
                        pr.events
                    }
                } else {
                    pr.events
                };

                // Track filtered events (difference from early filter)
                if event_filter.is_some() {
                    // We don't know the pre-filter count here since filtering happened in parallel,
                    // but we can track that some were loaded
                }

                let n = events_to_load.len();
                *format_stats
                    .entry(pr.source_format.to_string())
                    .or_default() += n;

                // Load in batches for memory control
                if n > batch_size {
                    for chunk in events_to_load.chunks(batch_size) {
                        engine.load_events(chunk)?;
                    }
                } else {
                    engine.load_events(&events_to_load)?;
                }
                total_events += n;

                // Track filtered count (rough — filter ran in parallel)
                let _ = original_count; // original_count == n since filter already applied
            }
            Err(msg) => {
                parse_errors.push(msg.clone());
                if !cli.quiet {
                    if let Some(ref pb) = pb {
                        pb.suspend(|| {
                            eprintln!("  {} {}", "✗".red(), msg);
                        });
                    }
                }
            }
        }
    }

    if let Some(pb) = pb {
        pb.set_position(total_parsed as u64);
        pb.finish_and_clear();
    }

    // Apply time filter
    if cli.after.is_some() || cli.before.is_some() {
        if let Some(time_field) = engine.detect_time_field() {
            let deleted = engine.apply_time_filter(
                &time_field,
                cli.after.as_deref(),
                cli.before.as_deref(),
            )?;
            if !cli.quiet && deleted > 0 {
                println!(
                    "  {} Filtered {} events by time range (field: {})",
                    "✓".green(),
                    deleted,
                    time_field
                );
            }
        } else if !cli.quiet {
            println!(
                "  {} No timestamp field detected, --after/--before ignored",
                "⚠".yellow()
            );
        }
    }

    if !cli.quiet && total_events > 10000 {
        let idx_pb = ProgressBar::new_spinner();
        idx_pb.set_style(
            ProgressStyle::default_spinner()
                .template("  {spinner:.green} Creating indexes...")
                .unwrap(),
        );
        idx_pb.enable_steady_tick(std::time::Duration::from_millis(80));
        engine.create_indexes()?;
        idx_pb.finish_and_clear();
    } else {
        engine.create_indexes()?;
    }

    // Custom index management
    for field in &cli.add_index {
        engine.create_index_on(field)?;
        if !cli.quiet {
            println!("  {} Index created on \"{}\"", "✓".green(), field);
        }
    }
    for idx in &cli.remove_index {
        engine.drop_index(idx)?;
        if !cli.quiet {
            println!("  {} Index \"{}\" removed", "✓".green(), idx);
        }
    }

    // Export flattened JSONL
    if let Some(ref flat_path) = cli.keepflat {
        let count = engine.export_jsonl(flat_path)?;
        if !cli.quiet {
            println!(
                "  {} Exported {} events → {:?}",
                "✓".green(),
                count,
                flat_path
            );
        }
    }

    if !cli.quiet {
        let formats: Vec<String> = format_stats
            .iter()
            .map(|(f, c)| format!("{} {}", c, f))
            .collect();

        // Zircolite-style Processing section
        println!(
            "  {} {}",
            "[+]".green().bold(),
            "Processing".bold().underline()
        );
        println!(
            "    {} Files       {}",
            "[>]".cyan(),
            format!("{}", files.len()).bold()
        );
        println!(
            "    {} Events      {}",
            "[>]".cyan(),
            format!("{}", total_events).bold()
        );
        println!("    {} Formats     {}", "[>]".cyan(), formats.join(", "));
        if filtered_events > 0 {
            println!(
                "    {} Filtered    {} events excluded by early filter",
                "[>]".cyan(),
                filtered_events
            );
        }
        println!(
            "    {} Duration    {:.2}s ({:.0} events/s)",
            "[>]".cyan(),
            start.elapsed().as_secs_f64(),
            if start.elapsed().as_secs_f64() > 0.0 {
                total_events as f64 / start.elapsed().as_secs_f64()
            } else {
                total_events as f64
            }
        );
        if cli.per_file {
            println!("    {} DB Mode     {}", "[>]".cyan(), "PER-FILE".bold());
        }
        let worker_count = cli.workers.unwrap_or_else(rayon::current_num_threads);
        println!(
            "    {} Workers     {} threads",
            "[>]".cyan(),
            format!("{}", worker_count).bold()
        );
        if let Some(max) = max_events {
            println!(
                "    {} Max Events  {}",
                "[>]".cyan(),
                format!("{}", max).bold()
            );
        }
        println!();
    }

    if let Some(ref dbfile) = cli.dbfile {
        engine.export_db(dbfile)?;
        if !cli.quiet {
            println!("  {} Database → {:?}", "✓".green(), dbfile);
        }
    }

    if cli.stats {
        let s = engine.stats()?;
        println!("\n  {:<40} {}", "Field".bold(), "Count".bold());
        println!("  {}", "─".repeat(52));
        let mut fields: Vec<_> = s.populated_fields.iter().collect();
        fields.sort_by(|a, b| b.1.cmp(a.1));
        for (name, count) in fields.iter().take(30) {
            if name.starts_with('_') {
                continue;
            }
            println!("  {:<40} {}", name, count);
        }
        println!("  {}", "─".repeat(52));
        println!("  {} fields, {} events\n", s.total_fields, s.total_events);
    }

    if let Some(ref field) = cli.distinct {
        let values = engine.distinct_values(field)?;
        println!("\n  Distinct \"{}\" ({} values):", field, values.len());
        for v in &values {
            println!("    {}", v);
        }
        println!();
    }

    let mut results: Vec<Detection> = Vec::new();
    let min_rank = level_rank(&cli.min_level);

    if let Some(ref rules_path) = cli.rules {
        let mut rules = sigma::load_rules(rules_path)
            .context(format!("Failed to load SIGMA rules from {:?}", rules_path))?;

        // Apply rule filters
        if !cli.rulefilter.is_empty() {
            let before_count = rules.len();
            rules.retain(|r| {
                !cli.rulefilter
                    .iter()
                    .any(|pat| r.title.to_lowercase().contains(&pat.to_lowercase()))
            });
            if !cli.quiet && rules.len() < before_count {
                println!(
                    "  {} Filtered {} rules (excluded {})",
                    "✓".green(),
                    rules.len(),
                    before_count - rules.len()
                );
            }
        }

        if !cli.quiet {
            println!(
                "  {} {} SIGMA rules loaded",
                "[+]".green().bold(),
                rules.len().to_string().bold()
            );
            if !cli.rulefilter.is_empty() {
                println!("  {} Event filter enabled", "[+]".green().bold());
            }
        }

        if cli.per_file {
            // Per-file mode: process each file in its own SearchEngine via rayon
            use rayon::prelude::*;

            if !cli.quiet {
                println!(
                    "  {} Per-file mode: processing {} files in parallel",
                    "▶".cyan(),
                    files.len()
                );
            }

            // Pre-compile rules to SQL
            let compiled: Vec<_> = rules
                .iter()
                .filter(|r| level_rank(&r.level) >= min_rank)
                .filter_map(|r| sigma::compile(r).ok().map(|sql| (r.clone(), sql)))
                .collect();

            // Process files in parallel
            let per_file_results: Vec<Vec<Detection>> = files
                .par_iter()
                .filter_map(|file| {
                    let mut file_engine = SearchEngine::new().ok()?;
                    let result = parsers::parse_file(file).ok()?;
                    file_engine.load_events(&result.events).ok()?;
                    let _ = file_engine.create_indexes();

                    let mut file_detections = Vec::new();
                    for (rule, sql) in &compiled {
                        let query_result = if let Some(limit) = cli.limit {
                            file_engine.query_sql_with_limit(sql, limit)
                        } else {
                            file_engine.query_sql(sql)
                        };
                        if let Ok(r) = query_result {
                            if r.count > 0 {
                                file_detections.push(Detection {
                                    title: rule.title.clone(),
                                    level: rule.level.clone(),
                                    description: rule.description.clone(),
                                    id: rule.id.clone(),
                                    author: rule.author.clone(),
                                    tags: rule.tags.clone(),
                                    result: r,
                                });
                            }
                        }
                    }
                    Some(file_detections)
                })
                .collect();

            // Merge: aggregate detections by rule title
            let mut merged: HashMap<String, Detection> = HashMap::new();
            for file_dets in per_file_results {
                for det in file_dets {
                    let entry = merged.entry(det.title.clone()).or_insert(Detection {
                        title: det.title.clone(),
                        level: det.level.clone(),
                        description: det.description.clone(),
                        id: det.id.clone(),
                        author: det.author.clone(),
                        tags: det.tags.clone(),
                        result: muninn::SearchResult {
                            rows: Vec::new(),
                            count: 0,
                            query: det.result.query.clone(),
                            duration_ms: 0,
                        },
                    });
                    entry.result.count += det.result.count;
                    entry.result.duration_ms += det.result.duration_ms;
                    entry.result.rows.extend(det.result.rows);
                }
            }
            results = merged.into_values().collect();

            let matched = results.len();
            if !cli.quiet {
                println!(
                    "  {} Executing ruleset (per-file): {} rules matched\n",
                    "[+]".green().bold(),
                    matched.to_string().bold()
                );
            }
        } else {
            // Standard mode: single unified SearchEngine
            // Step 1: Pre-compile all rules to SQL in parallel
            let compile_start = Instant::now();
            let compiled: Vec<_> = {
                use rayon::prelude::*;
                rules
                    .par_iter()
                    .filter(|r| level_rank(&r.level) >= min_rank)
                    .filter_map(|r| match sigma::compile(r) {
                        Ok(sql) => Some((r.clone(), sql)),
                        Err(e) => {
                            log::debug!("Rule '{}' compile error: {}", r.title, e);
                            None
                        }
                    })
                    .collect()
            };

            if !cli.quiet && compiled.len() > 50 {
                println!(
                    "  {} Pre-compiled {} rules in {:.0}ms",
                    "✓".green(),
                    compiled.len(),
                    compile_start.elapsed().as_millis()
                );
            }

            // Step 2: Execute compiled queries sequentially (SQLite single-connection)
            let sigma_pb = if !cli.quiet && compiled.len() > 50 {
                let pb = ProgressBar::new(compiled.len() as u64);
                pb.set_style(
                    ProgressStyle::default_bar()
                        .template(
                            "  {spinner:.green} [{bar:40.magenta/blue}] {pos}/{len} rules | {msg}",
                        )
                        .unwrap()
                        .progress_chars("█▉▊▋▌▍▎▏ "),
                );
                Some(pb)
            } else {
                None
            };

            let mut matched = 0;
            for (rule, sql) in &compiled {
                if let Some(ref pb) = sigma_pb {
                    pb.set_message(rule.title.chars().take(50).collect::<String>());
                    pb.inc(1);
                }

                let query_result = if let Some(limit) = cli.limit {
                    engine.query_sql_with_limit(sql, limit)
                } else {
                    engine.query_sql(sql)
                };
                match query_result {
                    Ok(r) if r.count > 0 => {
                        matched += 1;
                        results.push(Detection {
                            title: rule.title.clone(),
                            level: rule.level.clone(),
                            description: rule.description.clone(),
                            id: rule.id.clone(),
                            author: rule.author.clone(),
                            tags: rule.tags.clone(),
                            result: r,
                        });
                    }
                    Ok(_) => {}
                    Err(e) => log::debug!("Rule '{}' SQL error: {}", rule.title, e),
                }
            }

            if let Some(pb) = sigma_pb {
                pb.finish_and_clear();
            }

            if !cli.quiet {
                println!(
                    "  {} Executing ruleset: {} rules matched\n",
                    "[+]".green().bold(),
                    matched.to_string().bold()
                );
            }
        }

        // Profile rules: show sorted execution time table
        if cli.profile_rules && !cli.quiet && !results.is_empty() {
            let mut profile: Vec<(&str, u64, usize)> = results
                .iter()
                .map(|d| (d.title.as_str(), d.result.duration_ms, d.result.count))
                .collect();
            profile.sort_by(|a, b| b.1.cmp(&a.1));

            println!("  {}", "Rule Performance Profile".bold().underline());
            println!(
                "  {:<50} {:>8} {:>8}",
                "Rule".bold(),
                "Time(ms)".bold(),
                "Matches".bold()
            );
            println!("  {}", "─".repeat(68));
            for (title, ms, count) in &profile {
                let title_display: String = title.chars().take(48).collect();
                let time_str = if *ms >= 500 {
                    format!("{}", ms).red().to_string()
                } else if *ms >= 100 {
                    format!("{}", ms).yellow().to_string()
                } else {
                    format!("{}", ms)
                };
                println!("  {:<50} {:>8} {:>8}", title_display, time_str, count);
            }
            println!("  {}\n", "─".repeat(68));
        }
    }

    if let Some(ref sql_path) = cli.sql_file {
        let content = std::fs::read_to_string(sql_path)?;
        for line in content.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let (label, sql) = if t.contains("|||") {
                let mut parts = t.splitn(2, "|||");
                (
                    parts.next().unwrap_or("rule").to_string(),
                    parts.next().unwrap_or("").to_string(),
                )
            } else {
                ("sql".to_string(), t.to_string())
            };

            match engine.query_sql(&sql) {
                Ok(r) if r.count > 0 => results.push(Detection {
                    title: label,
                    level: "medium".into(),
                    description: String::new(),
                    id: String::new(),
                    author: String::new(),
                    tags: Vec::new(),
                    result: r,
                }),
                Ok(_) => {}
                Err(e) => {
                    if !cli.quiet {
                        eprintln!("  {} {}: {}", "✗".red(), label, e);
                    }
                }
            }
        }
    }

    if let Some(ref sql) = cli.sql {
        let r = engine.query_sql(sql)?;
        results.push(Detection {
            title: "SQL query".into(),
            level: "medium".into(),
            description: String::new(),
            id: String::new(),
            author: String::new(),
            tags: Vec::new(),
            result: r,
        });
    }

    if let Some(ref kw) = cli.keyword {
        let r = engine.search_keyword(kw)?;
        results.push(Detection {
            title: format!("keyword: {}", kw),
            level: "medium".into(),
            description: String::new(),
            id: String::new(),
            author: String::new(),
            tags: Vec::new(),
            result: r,
        });
    }

    if let Some(ref fs) = cli.field_search {
        if let Some((field, pattern)) = fs.split_once('=') {
            let r = engine.search_field(field, pattern)?;
            results.push(Detection {
                title: format!("{}={}", field, pattern),
                level: "medium".into(),
                description: String::new(),
                id: String::new(),
                author: String::new(),
                tags: Vec::new(),
                result: r,
            });
        }
    }

    if let Some(ref rs) = cli.regex_search {
        if let Some((field, pattern)) = rs.split_once('=') {
            let r = engine.search_regex(field, pattern)?;
            results.push(Detection {
                title: format!("{} =~ /{}/", field, pattern),
                level: "medium".into(),
                description: String::new(),
                id: String::new(),
                author: String::new(),
                tags: Vec::new(),
                result: r,
            });
        }
    }

    if !results.is_empty() {
        results.sort_by(|a, b| {
            level_rank(&b.level)
                .cmp(&level_rank(&a.level))
                .then(b.result.count.cmp(&a.result.count))
        });

        let mapper = muninn::mitre::MitreMapper::new();

        if !cli.quiet {
            let total_matches: usize = results.iter().map(|d| d.result.count).sum();
            let total_rules_loaded = if let Some(ref rules_path) = cli.rules {
                sigma::load_rules(rules_path).map(|r| r.len()).unwrap_or(0)
            } else {
                0
            };

            // Detection table header
            println!(
                "  {}",
                "┌──────────────┬────────────────────────────────────────────────────┬────────┬──────────────┐"
                    .cyan()
            );
            println!(
                "  {} {:<12} {} {:<50} {} {:>6} {} {:<12} {}",
                "│".cyan(),
                "Severity".bold(),
                "│".cyan(),
                "Rule".bold(),
                "│".cyan(),
                "Events".bold(),
                "│".cyan(),
                "ATT&CK".bold(),
                "│".cyan()
            );
            println!(
                "  {}",
                "├──────────────┼────────────────────────────────────────────────────┼────────┼──────────────┤"
                    .cyan()
            );

            for d in &results {
                let mitre_refs = muninn::mitre::MitreMapper::parse_tags(&d.tags);
                let techniques = mapper.resolve_refs(&mitre_refs);
                let mitre_str = if techniques.is_empty() {
                    String::new()
                } else {
                    techniques
                        .iter()
                        .map(|t| t.id.clone())
                        .collect::<Vec<_>>()
                        .join(",")
                };

                let title_display: String = d.title.chars().take(50).collect();
                let mitre_display: String = mitre_str.chars().take(12).collect();

                println!(
                    "  {} {:<12} {} {:<50} {} {:>6} {} {:<12} {}",
                    "│".cyan(),
                    level_color(&d.level),
                    "│".cyan(),
                    title_display,
                    "│".cyan(),
                    d.result.count,
                    "│".cyan(),
                    mitre_display,
                    "│".cyan()
                );
            }

            println!(
                "  {}",
                "└──────────────┴────────────────────────────────────────────────────┴────────┴──────────────┘"
                    .cyan()
            );
            println!();

            // Summary box
            let elapsed = start.elapsed().as_secs_f64();
            let throughput = if elapsed > 0.0 {
                total_events as f64 / elapsed
            } else {
                total_events as f64
            };

            let coverage_pct = if total_rules_loaded > 0 {
                (results.len() as f64 / total_rules_loaded as f64) * 100.0
            } else {
                0.0
            };

            // Count by severity
            let crit_count = results.iter().filter(|d| level_rank(&d.level) == 5).count();
            let high_count = results.iter().filter(|d| level_rank(&d.level) == 4).count();
            let med_count = results.iter().filter(|d| level_rank(&d.level) == 3).count();
            let low_count = results.iter().filter(|d| level_rank(&d.level) <= 2).count();

            // Coverage bar
            let bar_width = 30;
            let filled = ((coverage_pct / 100.0) * bar_width as f64) as usize;
            let bar: String = format!(
                "{}{}",
                "█".repeat(filled.min(bar_width)),
                "░".repeat(bar_width - filled.min(bar_width))
            );

            println!("  {} {}", "✦".cyan().bold(), "Summary".bold().underline());
            println!(
                "  {}",
                "╭──────────────────────────────────────────────────────────────╮".dimmed()
            );
            println!(
                "  {}  {} Duration      {}",
                "│".dimmed(),
                "⏱".dimmed(),
                format!("{:.2}s", elapsed).bold()
            );
            println!(
                "  {}  {} Files         {}",
                "│".dimmed(),
                "📁".dimmed(),
                format!("{}", files.len()).bold()
            );
            println!(
                "  {}  {} Events        {}",
                "│".dimmed(),
                "📊".dimmed(),
                format!("{}", total_events).bold()
            );
            println!(
                "  {}  {} Throughput    {}",
                "│".dimmed(),
                "⚡".dimmed(),
                format!("{:.0} events/s", throughput).bold()
            );
            println!(
                "  {}  {} Detections    {}{}{}{}",
                "│".dimmed(),
                "🔥".dimmed(),
                if crit_count > 0 {
                    format!("{} CRITICAL ", crit_count).red().bold().to_string()
                } else {
                    String::new()
                },
                if high_count > 0 {
                    format!("{} HIGH ", high_count).magenta().bold().to_string()
                } else {
                    String::new()
                },
                if med_count > 0 {
                    format!("{} MEDIUM ", med_count).yellow().bold().to_string()
                } else {
                    String::new()
                },
                if low_count > 0 {
                    format!("{} LOW", low_count).green().to_string()
                } else {
                    String::new()
                },
            );
            println!(
                "  {}  {} Coverage      {}/{} rules matched ({:.1}%)  {}",
                "│".dimmed(),
                "📋".dimmed(),
                results.len().to_string().bold(),
                total_rules_loaded,
                coverage_pct,
                bar.cyan()
            );
            println!(
                "  {}  {} Matched       {} events across {} rules",
                "│".dimmed(),
                "🎯".dimmed(),
                total_matches.to_string().bold(),
                results.len().to_string().bold()
            );

            // Top hits
            if !results.is_empty() {
                println!("  {}  {} Top Hits", "│".dimmed(), "🏆".dimmed(),);
                for d in results.iter().take(5) {
                    println!(
                        "  {}                {} {} ({})",
                        "│".dimmed(),
                        level_color(&d.level),
                        d.title,
                        d.result.count
                    );
                }
            }

            println!(
                "  {}",
                "╰──────────────────────────────────────────────────────────────╯".dimmed()
            );
            println!();

            // ATT&CK Coverage mini-view (like Zircolite)
            let mut tactic_hits: std::collections::HashMap<String, (usize, usize)> =
                std::collections::HashMap::new();
            for d in &results {
                let refs = muninn::mitre::MitreMapper::parse_tags(&d.tags);
                let techs = mapper.resolve_refs(&refs);
                for t in &techs {
                    let entry = tactic_hits.entry(t.tactic.clone()).or_insert((0, 0));
                    entry.0 += 1; // technique count
                    entry.1 += d.result.count; // hit count
                }
            }

            if !tactic_hits.is_empty() {
                println!(
                    "  {} {}",
                    "🛡".dimmed(),
                    "ATT&CK Coverage".bold().underline()
                );
                let max_hits = tactic_hits.values().map(|v| v.1).max().unwrap_or(1);
                let tactic_order = [
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
                for tactic in &tactic_order {
                    if let Some(&(tech_count, hit_count)) = tactic_hits.get(*tactic) {
                        let tactic_name = muninn::mitre::tactic_display_name(tactic);
                        let bar_len = ((hit_count as f64 / max_hits as f64) * 20.0) as usize;
                        let bar_str: String = "█".repeat(bar_len.max(1));
                        println!(
                            "  {:<22} {}  {} technique(s) ({} hits)",
                            tactic_name,
                            bar_str.magenta(),
                            tech_count,
                            hit_count
                        );
                    }
                }
                println!();
            }
        }

        // Kill Chain View
        if cli.killchain && !cli.quiet {
            let kc_data: Vec<_> = results
                .iter()
                .map(|d| {
                    let refs = muninn::mitre::MitreMapper::parse_tags(&d.tags);
                    (d.title.clone(), refs, d.level.clone(), d.result.count)
                })
                .collect();
            let kc_output = muninn::mitre::render_killchain(&kc_data, &mapper);
            print!("{}", kc_output);
        }

        // Attack Timeline
        if cli.timeline && !cli.quiet {
            let tl_data: Vec<_> = results
                .iter()
                .map(|d| {
                    (
                        d.title.clone(),
                        d.level.clone(),
                        d.tags.clone(),
                        d.result.rows.clone(),
                    )
                })
                .collect();
            let entries = muninn::timeline::build_timeline(&tl_data);
            let tl_output = muninn::timeline::render_ascii_timeline(&entries);
            print!("{}", tl_output);
        }

        // Correlation Engine
        if cli.correlate && !cli.quiet {
            let corr_data: Vec<_> = results
                .iter()
                .map(|d| {
                    (
                        d.title.clone(),
                        d.level.clone(),
                        d.tags.clone(),
                        d.result.rows.clone(),
                    )
                })
                .collect();
            let chains = muninn::correlate::correlate(&corr_data);
            if !chains.is_empty() {
                let corr_output = muninn::correlate::render_chains(&chains);
                print!("{}", corr_output);
            }
        }

        // Threat Score
        if cli.threat_score && !cli.quiet {
            let score_data: Vec<_> = results
                .iter()
                .map(|d| (d.title.clone(), d.level.clone(), d.result.rows.clone()))
                .collect();
            let scores = muninn::scoring::compute_scores(&score_data);
            if !scores.is_empty() {
                let score_output = muninn::scoring::render_scores(&scores);
                print!("{}", score_output);
            }
        }

        // ATT&CK Navigator export
        if let Some(ref nav_path) = cli.navigator {
            let nav_data: Vec<_> = results
                .iter()
                .map(|d| {
                    let refs = muninn::mitre::MitreMapper::parse_tags(&d.tags);
                    (refs, d.level.clone(), d.result.count)
                })
                .collect();
            let layer = muninn::mitre::export_navigator_layer(&nav_data, &mapper);
            std::fs::write(nav_path, serde_json::to_string_pretty(&layer)?)?;
            if !cli.quiet {
                println!("  {} Navigator layer → {:?}", "✓".green(), nav_path);
            }
        }

        // Template-based output
        if let Some(ref template_name) = cli.template {
            let format = muninn::output::templates::OutputFormat::from_name(template_name)?;
            let det_data: Vec<muninn::output::templates::DetectionData> = results
                .iter()
                .map(|d| muninn::output::templates::DetectionData {
                    title: d.title.clone(),
                    level: d.level.clone(),
                    count: d.result.count,
                    duration_ms: d.result.duration_ms,
                    tags: d.tags.clone(),
                    events: d.result.rows.clone(),
                })
                .collect();
            let rendered = format.render(&det_data)?;
            let out_path = if let Some(ref p) = cli.template_output {
                p.clone()
            } else {
                PathBuf::from(format!(
                    "muninn_export_{}.{}",
                    run_timestamp.format("%Y-%m-%d_%H-%M-%S"),
                    format.default_extension()
                ))
            };
            std::fs::write(&out_path, &rendered)?;
            if !cli.quiet {
                println!(
                    "  {} Template ({}) → {:?}",
                    "✓".green(),
                    template_name,
                    out_path
                );
            }
        }

        // Mini-GUI HTML report
        if let Some(ref gui_path) = cli.gui {
            let total_matches: usize = results.iter().map(|d| d.result.count).sum();
            let gui_data: Vec<_> = results
                .iter()
                .map(|d| {
                    (
                        d.title.clone(),
                        d.level.clone(),
                        d.result.count,
                        d.tags.clone(),
                        d.result.rows.clone(),
                    )
                })
                .collect();
            let summary = serde_json::json!({
                "files_scanned": files.len(),
                "total_events": total_events,
                "rules_matched": results.len(),
                "total_detections": total_matches,
            });
            let html = muninn::output::gui::generate_html_report(&gui_data, &summary)?;
            std::fs::write(gui_path, &html)?;
            if !cli.quiet {
                println!("  {} HTML report → {:?}", "✓".green(), gui_path);
            }
        }
    } else if !cli.stats && cli.distinct.is_none() && cli.dbfile.is_none() && !cli.quiet {
        println!("  {} No matches found.\n", "[*]".yellow());
    }

    // Anomaly Detection (independent of SIGMA results)
    if cli.anomalies {
        let anomalies = muninn::anomaly::detect_anomalies(&engine)?;
        if !cli.quiet {
            let output = muninn::anomaly::render_anomalies(&anomalies);
            print!("{}", output);
        }
    }

    // IOC Extraction (independent of SIGMA results)
    if cli.ioc_extract {
        let iocs = muninn::ioc::extract_iocs(&engine)?;
        if !cli.quiet {
            let output = muninn::ioc::render_iocs(&iocs);
            print!("{}", output);
        }

        // IOC Enrichment via external APIs (feature-gated)
        #[cfg(feature = "ioc-enrich")]
        {
            let mut all_enriched = Vec::new();

            if let Some(ref vt_key) = cli.vt_key {
                if !cli.quiet {
                    println!("  {} Enriching IOCs via VirusTotal...", "▶".cyan());
                }
                match muninn::ioc::enrich_virustotal(&iocs, vt_key) {
                    Ok(enriched) => all_enriched.extend(enriched),
                    Err(e) => {
                        if !cli.quiet {
                            eprintln!("  {} VT enrichment failed: {}", "✗".red(), e);
                        }
                    }
                }
            }

            if let Some(ref abuse_key) = cli.abuseipdb_key {
                if !cli.quiet {
                    println!("  {} Enriching IPs via AbuseIPDB...", "▶".cyan());
                }
                match muninn::ioc::enrich_abuseipdb(&iocs, abuse_key) {
                    Ok(enriched) => all_enriched.extend(enriched),
                    Err(e) => {
                        if !cli.quiet {
                            eprintln!("  {} AbuseIPDB enrichment failed: {}", "✗".red(), e);
                        }
                    }
                }
            }

            if let Some(ref opentip_key) = cli.opentip_key {
                if !cli.quiet {
                    println!("  {} Enriching IOCs via Kaspersky OpenTIP...", "▶".cyan());
                }
                match muninn::ioc::enrich_opentip(&iocs, opentip_key) {
                    Ok(enriched) => all_enriched.extend(enriched),
                    Err(e) => {
                        if !cli.quiet {
                            eprintln!("  {} OpenTIP enrichment failed: {}", "✗".red(), e);
                        }
                    }
                }
            }

            if !all_enriched.is_empty() && !cli.quiet {
                let output = muninn::ioc::render_enriched(&all_enriched);
                print!("{}", output);
            }
        }
    }

    // Diff Mode
    if let Some(ref diff_path) = cli.diff {
        let diff_files =
            parsers::discover_files(diff_path, cli.select.as_deref(), cli.avoid.as_deref(), true)?;
        let mut engine_b = SearchEngine::new()?;
        for file in &diff_files {
            if let Ok(result) = parsers::parse_file(file) {
                let _ = engine_b.load_events(&result.events);
            }
        }
        let rules = if let Some(ref rules_path) = cli.rules {
            muninn::sigma::load_rules(rules_path).unwrap_or_default()
        } else {
            Vec::new()
        };
        let diff_result = muninn::diff::diff_evidence(&engine, &engine_b, &rules)?;
        if !cli.quiet {
            let output = muninn::diff::render_diff(&diff_result);
            print!("{}", output);
        }
    }

    let has_any_output =
        !results.is_empty() || cli.stats || cli.distinct.is_some() || cli.dbfile.is_some();

    if has_any_output || !parse_errors.is_empty() {
        let output_path = if let Some(ref output) = cli.output {
            output.clone()
        } else if !cli.no_report {
            PathBuf::from(format!(
                "muninn_report_{}.json",
                run_timestamp.format("%Y-%m-%d_%H-%M-%S")
            ))
        } else {
            PathBuf::new()
        };

        if !output_path.as_os_str().is_empty() {
            let total_matches: usize = results.iter().map(|d| d.result.count).sum();
            let elapsed = start.elapsed().as_secs_f64();

            let report = serde_json::json!({
                "tool": "muninn",
                "version": env!("CARGO_PKG_VERSION"),
                "timestamp": run_timestamp.to_rfc3339(),
                "duration_sec": format!("{:.1}", elapsed),
                "source": cli.events.to_string_lossy(),
                "summary": {
                    "files_scanned": files.len(),
                    "total_events": total_events,
                    "rules_matched": results.len(),
                    "total_detections": total_matches,
                    "formats": &format_stats,
                    "errors": parse_errors.len(),
                },
                "detections": results.iter().map(|d| {
                    let report_mapper = muninn::mitre::MitreMapper::new();
                    let mitre_refs = muninn::mitre::MitreMapper::parse_tags(&d.tags);
                    let mitre_techniques = report_mapper.resolve_refs(&mitre_refs);
                    let mut det = serde_json::json!({
                        "title": d.title,
                        "level": d.level,
                        "count": d.result.count,
                        "duration_ms": d.result.duration_ms,
                        "query": d.result.query,
                        "events": d.result.rows,
                    });
                    if !d.id.is_empty() {
                        det["id"] = serde_json::json!(d.id);
                    }
                    if !d.description.is_empty() {
                        det["description"] = serde_json::json!(d.description);
                    }
                    if !d.author.is_empty() {
                        det["author"] = serde_json::json!(d.author);
                    }
                    if !d.tags.is_empty() {
                        det["tags"] = serde_json::json!(d.tags);
                    }
                    if !mitre_techniques.is_empty() {
                        det["mitre"] = serde_json::json!(mitre_techniques);
                    }
                    det
                }).collect::<Vec<_>>(),
                "errors": parse_errors,
            });

            std::fs::write(&output_path, serde_json::to_string_pretty(&report)?)?;
            if !cli.quiet {
                println!(
                    "  {} Output: {}",
                    "→".cyan().bold(),
                    output_path.display().to_string().bold()
                );
                println!();
            }
        }
    }

    // Interactive TUI
    #[cfg(feature = "tui")]
    if cli.tui && !results.is_empty() {
        let tui_detections: Vec<muninn::tui::DetectionInfo> = results
            .iter()
            .map(|d| muninn::tui::DetectionInfo {
                title: d.title.clone(),
                level: d.level.clone(),
                count: d.result.count,
                tags: d.tags.clone(),
                rows: d.result.rows.clone(),
            })
            .collect();
        muninn::tui::run_tui(tui_detections)?;
    }

    // Live monitoring mode
    #[cfg(feature = "live")]
    if cli.live {
        if let Some(ref rules_path) = cli.rules {
            println!(
                "  {} Entering live monitoring mode (Ctrl+C to stop)...",
                "▶".green()
            );
            muninn::live::watch_directory(&cli.events, rules_path)?;
        } else if !cli.quiet {
            println!("  {} --live requires --rules to be specified", "✗".red());
        }
    }

    Ok(())
}
