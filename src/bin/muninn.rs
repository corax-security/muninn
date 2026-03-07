use anyhow::{Context, Result};
use chrono::Local;
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::time::Instant;

use muninn::{parsers, search::SearchEngine, sigma};

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
    let cli = Cli::parse();
    let start = Instant::now();
    let run_timestamp = Local::now();

    if !cli.quiet {
        println!(
            "\n  {} {}",
            "Muninn".cyan().bold(),
            "by corax team".dimmed()
        );
        println!(
            "  {}\n",
            run_timestamp
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
                .dimmed()
        );
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

    let mut engine = SearchEngine::new()?;
    let mut total_events = 0;
    let mut format_stats: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut parse_errors: Vec<String> = Vec::new();

    for file in &files {
        if let Some(ref pb) = pb {
            let name = file
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            pb.set_message(name);
        }
        match parsers::parse_file(file) {
            Ok(mut result) => {
                if cli.hashes {
                    for ev in &mut result.events {
                        ev.compute_hash();
                    }
                }
                let n = result.events.len();
                *format_stats
                    .entry(result.source_format.to_string())
                    .or_default() += n;
                engine.load_events(&result.events)?;
                total_events += n;
            }
            Err(e) => {
                let msg = format!(
                    "{}: {}",
                    file.file_name().unwrap_or_default().to_string_lossy(),
                    e
                );
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
        if let Some(ref pb) = pb {
            pb.inc(1);
        }
    }

    if let Some(pb) = pb {
        pb.finish_and_clear();
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

    if !cli.quiet {
        let formats: Vec<String> = format_stats
            .iter()
            .map(|(f, c)| format!("{} {}", c, f))
            .collect();
        println!(
            "  {} {} events from {} files in {:.1}s ({})",
            "✓".green(),
            total_events,
            files.len(),
            start.elapsed().as_secs_f64(),
            formats.join(", ")
        );
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
        let rules = sigma::load_rules(rules_path)
            .context(format!("Failed to load SIGMA rules from {:?}", rules_path))?;

        if !cli.quiet {
            println!("  {} Loaded {} SIGMA rule(s)", "✓".green(), rules.len());
        }

        let sigma_pb = if !cli.quiet && rules.len() > 50 {
            let pb = ProgressBar::new(rules.len() as u64);
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
        for rule in &rules {
            if let Some(ref pb) = sigma_pb {
                pb.set_message(rule.title.chars().take(50).collect::<String>());
                pb.inc(1);
            }

            if level_rank(&rule.level) < min_rank {
                continue;
            }

            match sigma::compile(rule) {
                Ok(sql) => match engine.query_sql(&sql) {
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
                },
                Err(e) => log::debug!("Rule '{}' compile error: {}", rule.title, e),
            }
        }

        if let Some(pb) = sigma_pb {
            pb.finish_and_clear();
        }

        if !cli.quiet {
            println!("  {} {} rule(s) matched\n", "✓".green(), matched);
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
                    title: label, level: "medium".into(), description: String::new(),
                    id: String::new(), author: String::new(), tags: Vec::new(), result: r,
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
            title: "SQL query".into(), level: "medium".into(), description: String::new(),
            id: String::new(), author: String::new(), tags: Vec::new(), result: r,
        });
    }

    if let Some(ref kw) = cli.keyword {
        let r = engine.search_keyword(kw)?;
        results.push(Detection {
            title: format!("keyword: {}", kw), level: "medium".into(), description: String::new(),
            id: String::new(), author: String::new(), tags: Vec::new(), result: r,
        });
    }

    if let Some(ref fs) = cli.field_search {
        if let Some((field, pattern)) = fs.split_once('=') {
            let r = engine.search_field(field, pattern)?;
            results.push(Detection {
                title: format!("{}={}", field, pattern), level: "medium".into(), description: String::new(),
                id: String::new(), author: String::new(), tags: Vec::new(), result: r,
            });
        }
    }

    if let Some(ref rs) = cli.regex_search {
        if let Some((field, pattern)) = rs.split_once('=') {
            let r = engine.search_regex(field, pattern)?;
            results.push(Detection {
                title: format!("{} =~ /{}/", field, pattern), level: "medium".into(), description: String::new(),
                id: String::new(), author: String::new(), tags: Vec::new(), result: r,
            });
        }
    }

    if !results.is_empty() {
        results.sort_by(|a, b| {
            level_rank(&b.level)
                .cmp(&level_rank(&a.level))
                .then(b.result.count.cmp(&a.result.count))
        });

        if !cli.quiet {
            println!(
                "{}",
                "  ══════════════════════════════════════════════════════════════════════".cyan()
            );
            for d in &results {
                println!(
                    "  {} {:<12} {} — {} matches ({}ms)",
                    "●".bold(),
                    level_color(&d.level),
                    d.title,
                    d.result.count.to_string().bold(),
                    d.result.duration_ms
                );
            }
            let total_matches: usize = results.iter().map(|d| d.result.count).sum();
            println!(
                "{}",
                "  ══════════════════════════════════════════════════════════════════════".cyan()
            );
            println!(
                "  {} rules matched, {} total events flagged\n",
                results.len().to_string().bold(),
                total_matches.to_string().bold()
            );
        }
    } else if !cli.stats && cli.distinct.is_none() && cli.dbfile.is_none() && !cli.quiet {
        println!("  No matches found.\n");
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
                    det
                }).collect::<Vec<_>>(),
                "errors": parse_errors,
            });

            std::fs::write(&output_path, serde_json::to_string_pretty(&report)?)?;
            if !cli.quiet {
                println!("  {} Report → {:?}\n", "✓".green(), output_path);
            }
        }
    }

    Ok(())
}
