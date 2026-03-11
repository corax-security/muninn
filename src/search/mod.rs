use anyhow::{Context, Result};
use log::{debug, info};
use rusqlite::{params, Connection};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::model::Event;

const TABLE: &str = "events";

#[derive(Debug, Clone, serde::Serialize)]
pub struct SearchResult {
    pub rows: Vec<HashMap<String, String>>,
    pub count: usize,
    pub query: String,
    pub duration_ms: u64,
}

pub struct SearchEngine {
    conn: Connection,
    columns: Vec<String>,
    event_count: usize,
}

fn register_regexp(conn: &Connection) -> Result<()> {
    conn.create_scalar_function(
        "REGEXP",
        2,
        rusqlite::functions::FunctionFlags::SQLITE_UTF8
            | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let pattern: String = ctx.get(0)?;
            let text: String = ctx.get::<String>(1).unwrap_or_default();
            let re = regex::Regex::new(&pattern)
                .map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))?;
            Ok(re.is_match(&text))
        },
    )?;
    Ok(())
}

impl SearchEngine {
    pub fn new() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "PRAGMA journal_mode = OFF;
             PRAGMA synchronous = OFF;
             PRAGMA cache_size = -131072;
             PRAGMA temp_store = MEMORY;
             PRAGMA mmap_size = 268435456;",
        )?;

        register_regexp(&conn)?;

        Ok(SearchEngine {
            conn,
            columns: Vec::new(),
            event_count: 0,
        })
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        register_regexp(&conn)?;

        let columns: Vec<String> = {
            let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{}\")", TABLE))?;
            let result: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(1))?
                .filter_map(|r| r.ok())
                .collect();
            result
        };
        let event_count = conn
            .query_row(&format!("SELECT COUNT(*) FROM \"{}\"", TABLE), [], |row| {
                row.get::<_, usize>(0)
            })
            .unwrap_or(0);

        Ok(SearchEngine {
            conn,
            columns,
            event_count,
        })
    }

    pub fn load_events(&mut self, events: &[Event]) -> Result<usize> {
        if events.is_empty() {
            return Ok(0);
        }

        let mut col_set: HashSet<String> = self.columns.iter().cloned().collect();
        for ev in events {
            for k in ev.fields.keys() {
                col_set.insert(k.clone());
            }
        }

        let new_columns: Vec<String> = col_set.into_iter().collect();

        if self.columns.is_empty() {
            let col_defs: Vec<String> = new_columns
                .iter()
                .map(|c| format!("\"{}\" TEXT", c))
                .collect();
            let sql = format!(
                "CREATE TABLE IF NOT EXISTS \"{}\" ({})",
                TABLE,
                col_defs.join(", ")
            );
            self.conn.execute(&sql, [])?;
            self.columns = new_columns;
        } else {
            for col in &new_columns {
                if !self.columns.contains(col) {
                    let sql = format!("ALTER TABLE \"{}\" ADD COLUMN \"{}\" TEXT", TABLE, col);
                    if let Err(e) = self.conn.execute(&sql, []) {
                        debug!("Column '{}' may already exist: {}", col, e);
                    }
                    self.columns.push(col.clone());
                }
            }
        }

        let tx = self.conn.transaction()?;
        let col_names: Vec<String> = self.columns.iter().map(|c| format!("\"{}\"", c)).collect();
        let placeholders: Vec<String> = self.columns.iter().map(|_| "?".into()).collect();
        let insert_sql = format!(
            "INSERT INTO \"{}\" ({}) VALUES ({})",
            TABLE,
            col_names.join(", "),
            placeholders.join(", ")
        );

        let mut stmt = tx.prepare(&insert_sql)?;
        let mut loaded = 0;

        for ev in events {
            let values: Vec<String> = self
                .columns
                .iter()
                .map(|col| ev.fields.get(col).cloned().unwrap_or_default())
                .collect();
            let params: Vec<&dyn rusqlite::types::ToSql> = values
                .iter()
                .map(|v| v as &dyn rusqlite::types::ToSql)
                .collect();
            if stmt.execute(params.as_slice()).is_ok() {
                loaded += 1;
            }
        }

        drop(stmt);
        tx.commit()?;
        self.event_count += loaded;

        info!("Loaded {} events (total: {})", loaded, self.event_count);
        Ok(loaded)
    }

    pub fn create_indexes(&self) -> Result<()> {
        let index_fields = [
            "EventID",
            "Channel",
            "CommandLine",
            "Image",
            "ParentImage",
            "TargetFilename",
            "SourceIp",
            "DestinationIp",
            "User",
            "LogonType",
            "ServiceName",
            "hostname",
            "app_name",
            "message",
            "level",
            "src_ip",
            "dst_ip",
            "cs-method",
            "sc-status",
            "DeviceEventClassID",
            "eventType",
            "eventSource",
            "Operation",
        ];
        for field in &index_fields {
            if self.columns.iter().any(|c| c == *field) {
                let sql = format!(
                    "CREATE INDEX IF NOT EXISTS \"idx_{}\" ON \"{}\" (\"{}\")",
                    field, TABLE, field
                );
                let _ = self.conn.execute(&sql, []);
            }
        }
        Ok(())
    }

    pub fn query_sql(&self, sql: &str) -> Result<SearchResult> {
        let start = std::time::Instant::now();
        let rows = self.execute_query(sql)?;
        let count = rows.len();
        Ok(SearchResult {
            rows,
            count,
            query: sql.to_string(),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    pub fn search_field(&self, field: &str, pattern: &str) -> Result<SearchResult> {
        let sql = format!(
            "SELECT * FROM \"{}\" WHERE \"{}\" LIKE ? ESCAPE '\\'",
            TABLE, field
        );
        let start = std::time::Instant::now();

        let mut stmt = self.conn.prepare(&sql)?;
        let col_names: Vec<String> = stmt.column_names().iter().map(|n| n.to_string()).collect();

        let rows: Vec<HashMap<String, String>> = stmt
            .query_map(params![pattern], |row| {
                let mut map = HashMap::new();
                for (i, col) in col_names.iter().enumerate() {
                    if col == "_raw" {
                        continue;
                    }
                    if let Ok(v) = row.get::<_, String>(i) {
                        if !v.is_empty() {
                            map.insert(col.clone(), v);
                        }
                    }
                }
                Ok(map)
            })?
            .filter_map(|r| r.ok())
            .collect();

        let count = rows.len();
        Ok(SearchResult {
            rows,
            count,
            query: format!("{} LIKE '{}'", field, pattern),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    pub fn search_keyword(&self, keyword: &str) -> Result<SearchResult> {
        let sql = format!(
            "SELECT * FROM \"{}\" WHERE \"_raw\" LIKE ? ESCAPE '\\'",
            TABLE
        );
        let pattern = format!("%{}%", keyword.replace('%', "\\%").replace('_', "\\_"));
        let start = std::time::Instant::now();

        let mut stmt = self.conn.prepare(&sql)?;
        let col_names: Vec<String> = stmt.column_names().iter().map(|n| n.to_string()).collect();

        let rows: Vec<HashMap<String, String>> = stmt
            .query_map(params![pattern], |row| {
                let mut map = HashMap::new();
                for (i, col) in col_names.iter().enumerate() {
                    if col == "_raw" {
                        continue;
                    }
                    if let Ok(v) = row.get::<_, String>(i) {
                        if !v.is_empty() {
                            map.insert(col.clone(), v);
                        }
                    }
                }
                Ok(map)
            })?
            .filter_map(|r| r.ok())
            .collect();

        let count = rows.len();
        Ok(SearchResult {
            rows,
            count,
            query: format!("keyword: {}", keyword),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    pub fn search_regex(&self, field: &str, pattern: &str) -> Result<SearchResult> {
        let sql = format!("SELECT * FROM \"{}\" WHERE \"{}\" REGEXP ?", TABLE, field);
        let start = std::time::Instant::now();

        let mut stmt = self.conn.prepare(&sql)?;
        let col_names: Vec<String> = stmt.column_names().iter().map(|n| n.to_string()).collect();

        let rows: Vec<HashMap<String, String>> = stmt
            .query_map(params![pattern], |row| {
                let mut map = HashMap::new();
                for (i, col) in col_names.iter().enumerate() {
                    if col == "_raw" {
                        continue;
                    }
                    if let Ok(v) = row.get::<_, String>(i) {
                        if !v.is_empty() {
                            map.insert(col.clone(), v);
                        }
                    }
                }
                Ok(map)
            })?
            .filter_map(|r| r.ok())
            .collect();

        let count = rows.len();
        Ok(SearchResult {
            rows,
            count,
            query: format!("{} REGEXP '{}'", field, pattern),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    pub fn run_queries(&self, queries: &[(&str, &str)]) -> Vec<(String, SearchResult)> {
        queries
            .iter()
            .filter_map(|(label, sql)| match self.query_sql(sql) {
                Ok(result) if result.count > 0 => Some((label.to_string(), result)),
                Ok(_) => None,
                Err(e) => {
                    debug!("Query '{}' failed: {}", label, e);
                    None
                }
            })
            .collect()
    }

    pub fn distinct_values(&self, field: &str) -> Result<Vec<String>> {
        let sql = format!(
            "SELECT DISTINCT \"{}\" FROM \"{}\" WHERE \"{}\" IS NOT NULL AND \"{}\" != '' ORDER BY \"{}\"",
            field, TABLE, field, field, field
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let values: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(values)
    }

    pub fn fields(&self) -> &[String] {
        &self.columns
    }

    pub fn event_count(&self) -> usize {
        self.event_count
    }

    pub fn query_sql_with_limit(&self, sql: &str, limit: usize) -> Result<SearchResult> {
        let trimmed = sql.trim().trim_end_matches(';');
        let limited = format!("{} LIMIT {}", trimmed, limit);
        self.query_sql(&limited)
    }

    pub fn apply_time_filter(
        &self,
        time_field: &str,
        after: Option<&str>,
        before: Option<&str>,
    ) -> Result<usize> {
        let mut conditions = Vec::new();
        if let Some(a) = after {
            conditions.push(format!("\"{}\" < '{}'", time_field, a));
        }
        if let Some(b) = before {
            conditions.push(format!("\"{}\" > '{}'", time_field, b));
        }
        if conditions.is_empty() {
            return Ok(0);
        }
        let sql = format!(
            "DELETE FROM \"{}\" WHERE {}",
            TABLE,
            conditions.join(" OR ")
        );
        let deleted = self.conn.execute(&sql, [])?;
        self.conn.execute(
            &format!(
                "DELETE FROM \"{}\" WHERE \"{}\" IS NULL OR \"{}\" = ''",
                TABLE, time_field, time_field
            ),
            [],
        )?;
        Ok(deleted)
    }

    pub fn detect_time_field(&self) -> Option<String> {
        const CANDIDATES: &[&str] = &[
            "SystemTime",
            "timestamp",
            "@timestamp",
            "TimeCreated",
            "date",
            "_time",
            "time",
            "datetime",
            "EventTime",
            "UtcTime",
        ];
        for field in CANDIDATES {
            if self.columns.iter().any(|c| c == *field) {
                let sql = format!(
                    "SELECT COUNT(*) FROM \"{}\" WHERE \"{}\" IS NOT NULL AND \"{}\" != ''",
                    TABLE, field, field
                );
                if let Ok(count) = self
                    .conn
                    .query_row(&sql, [], |row| row.get::<_, usize>(0))
                {
                    if count > 0 {
                        return Some(field.to_string());
                    }
                }
            }
        }
        None
    }

    pub fn create_index_on(&self, field: &str) -> Result<()> {
        let sql = format!(
            "CREATE INDEX IF NOT EXISTS \"idx_custom_{}\" ON \"{}\" (\"{}\")",
            field, TABLE, field
        );
        self.conn.execute(&sql, [])?;
        Ok(())
    }

    pub fn drop_index(&self, index_name: &str) -> Result<()> {
        let sql = format!("DROP INDEX IF EXISTS \"{}\"", index_name);
        self.conn.execute(&sql, [])?;
        Ok(())
    }

    pub fn list_indexes(&self) -> Result<Vec<String>> {
        let sql = format!("PRAGMA index_list(\"{}\")", TABLE);
        let mut stmt = self.conn.prepare(&sql)?;
        let indexes: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(indexes)
    }

    pub fn export_jsonl(&self, path: &Path) -> Result<usize> {
        let sql = format!("SELECT * FROM \"{}\"", TABLE);
        let mut stmt = self.conn.prepare(&sql)?;
        let col_names: Vec<String> = stmt.column_names().iter().map(|n| n.to_string()).collect();

        let mut file = std::io::BufWriter::new(std::fs::File::create(path)?);
        let mut count = 0;

        let rows = stmt.query_map([], |row| {
            let mut map = serde_json::Map::new();
            for (i, col) in col_names.iter().enumerate() {
                if col == "_raw" {
                    continue;
                }
                if let Ok(v) = row.get::<_, String>(i) {
                    if !v.is_empty() {
                        map.insert(col.clone(), serde_json::Value::String(v));
                    }
                }
            }
            Ok(map)
        })?;

        use std::io::Write;
        for row in rows {
            if let Ok(map) = row {
                let json = serde_json::Value::Object(map);
                writeln!(file, "{}", json)?;
                count += 1;
            }
        }

        Ok(count)
    }

    pub fn export_db(&self, path: &Path) -> Result<()> {
        let mut dest = Connection::open(path)?;
        let backup = rusqlite::backup::Backup::new(&self.conn, &mut dest)?;
        backup.run_to_completion(100, std::time::Duration::from_millis(10), None)?;
        info!("Database exported to {:?}", path);
        Ok(())
    }

    pub fn stats(&self) -> Result<EngineStats> {
        let field_count = self.columns.len();
        let non_empty: HashMap<String, usize> = self
            .columns
            .iter()
            .filter_map(|col| {
                let sql = format!(
                    "SELECT COUNT(*) FROM \"{}\" WHERE \"{}\" IS NOT NULL AND \"{}\" != ''",
                    TABLE, col, col
                );
                self.conn
                    .query_row(&sql, [], |row| row.get::<_, usize>(0))
                    .ok()
                    .map(|c| (col.clone(), c))
            })
            .filter(|(_, c)| *c > 0)
            .collect();

        Ok(EngineStats {
            total_events: self.event_count,
            total_fields: field_count,
            populated_fields: non_empty,
        })
    }

    fn execute_query(&self, sql: &str) -> Result<Vec<HashMap<String, String>>> {
        let mut stmt = self.conn.prepare(sql).context("Failed to prepare SQL")?;
        let col_names: Vec<String> = stmt.column_names().iter().map(|n| n.to_string()).collect();

        let rows: Vec<HashMap<String, String>> = stmt
            .query_map([], |row| {
                let mut map = HashMap::new();
                for (i, col) in col_names.iter().enumerate() {
                    if col == "_raw" {
                        continue;
                    }
                    if let Ok(v) = row.get::<_, String>(i) {
                        if !v.is_empty() {
                            map.insert(col.clone(), v);
                        }
                    }
                }
                Ok(map)
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(rows)
    }
}

#[derive(Debug, serde::Serialize)]
pub struct EngineStats {
    pub total_events: usize,
    pub total_fields: usize,
    pub populated_fields: HashMap<String, usize>,
}
