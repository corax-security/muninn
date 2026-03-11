//! Interactive terminal UI for browsing Muninn SIGMA detection results.
//!
//! This module is feature-gated behind the `tui` feature flag.

#[cfg(feature = "tui")]
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
#[cfg(feature = "tui")]
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table},
    Frame, Terminal,
};

use std::collections::HashMap;

/// Information about a single SIGMA detection and its matched events.
pub struct DetectionInfo {
    pub title: String,
    pub level: String,
    pub count: usize,
    pub tags: Vec<String>,
    pub rows: Vec<HashMap<String, String>>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum View {
    DetectionList,
    EventBrowser,
    FieldDetail,
}

/// Application state for the TUI.
pub struct App {
    detections: Vec<DetectionInfo>,
    view: View,
    selected_detection: usize,
    selected_event: usize,
    scroll: usize,
    search_query: String,
    searching: bool,
    should_quit: bool,
}

impl App {
    /// Create a new App with the given detection results.
    pub fn new(detections: Vec<DetectionInfo>) -> Self {
        Self {
            detections,
            view: View::DetectionList,
            selected_detection: 0,
            selected_event: 0,
            scroll: 0,
            search_query: String::new(),
            searching: false,
            should_quit: false,
        }
    }

    /// Move selection down by one.
    fn next(&mut self) {
        let len = self.current_list_len();
        if len == 0 {
            return;
        }
        match self.view {
            View::DetectionList => {
                self.selected_detection = (self.selected_detection + 1).min(len - 1);
            }
            View::EventBrowser => {
                self.selected_event = (self.selected_event + 1).min(len - 1);
            }
            View::FieldDetail => {
                self.scroll = self.scroll.saturating_add(1);
            }
        }
    }

    /// Move selection up by one.
    fn previous(&mut self) {
        match self.view {
            View::DetectionList => {
                self.selected_detection = self.selected_detection.saturating_sub(1);
            }
            View::EventBrowser => {
                self.selected_event = self.selected_event.saturating_sub(1);
            }
            View::FieldDetail => {
                self.scroll = self.scroll.saturating_sub(1);
            }
        }
    }

    /// Drill down into the currently selected item.
    fn enter(&mut self) {
        match self.view {
            View::DetectionList => {
                if !self.detections.is_empty() {
                    self.view = View::EventBrowser;
                    self.selected_event = 0;
                    self.scroll = 0;
                }
            }
            View::EventBrowser => {
                if self.current_list_len() > 0 {
                    self.view = View::FieldDetail;
                    self.scroll = 0;
                }
            }
            View::FieldDetail => {
                // Already at deepest level; do nothing.
            }
        }
    }

    /// Go back to the previous view.
    fn back(&mut self) {
        match self.view {
            View::DetectionList => {
                // Already at top level; do nothing.
            }
            View::EventBrowser => {
                self.view = View::DetectionList;
            }
            View::FieldDetail => {
                self.view = View::EventBrowser;
                self.scroll = 0;
            }
        }
    }

    /// Return the number of items in the current view's list.
    fn current_list_len(&self) -> usize {
        match self.view {
            View::DetectionList => self.detections.len(),
            View::EventBrowser => {
                if let Some(det) = self.detections.get(self.selected_detection) {
                    det.rows.len()
                } else {
                    0
                }
            }
            View::FieldDetail => {
                if let Some(det) = self.detections.get(self.selected_detection) {
                    if let Some(row) = det.rows.get(self.selected_event) {
                        row.len()
                    } else {
                        0
                    }
                } else {
                    0
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TUI rendering and event loop (feature-gated)
// ---------------------------------------------------------------------------

/// Set up the terminal, run the interactive event loop, and restore the
/// terminal on exit.
#[cfg(feature = "tui")]
pub fn run_tui(detections: Vec<DetectionInfo>) -> anyhow::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(detections);

    let result = run_event_loop(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

#[cfg(feature = "tui")]
fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
) -> anyhow::Result<()> {
    loop {
        terminal.draw(|frame| ui(frame, app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            if app.searching {
                match key.code {
                    KeyCode::Esc => {
                        app.searching = false;
                        app.search_query.clear();
                    }
                    KeyCode::Enter => {
                        app.searching = false;
                    }
                    KeyCode::Backspace => {
                        app.search_query.pop();
                    }
                    KeyCode::Char(c) => {
                        app.search_query.push(c);
                    }
                    _ => {}
                }
                continue;
            }

            match key.code {
                KeyCode::Char('q') => {
                    app.should_quit = true;
                    return Ok(());
                }
                KeyCode::Down | KeyCode::Char('j') => app.next(),
                KeyCode::Up | KeyCode::Char('k') => app.previous(),
                KeyCode::Enter => app.enter(),
                KeyCode::Esc => app.back(),
                KeyCode::Char('/') => {
                    app.searching = true;
                    app.search_query.clear();
                }
                _ => {}
            }
        }
    }
}

#[cfg(feature = "tui")]
fn ui(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title bar
            Constraint::Min(0),   // main content
            Constraint::Length(1), // status bar
        ])
        .split(frame.area());

    // Title bar
    let view_name = match app.view {
        View::DetectionList => "Detections",
        View::EventBrowser => "Events",
        View::FieldDetail => "Field Detail",
    };
    let title = Paragraph::new(Line::from(vec![
        Span::styled(" Muninn ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("| "),
        Span::styled(view_name, Style::default().fg(Color::Yellow)),
    ]))
    .block(Block::default().borders(Borders::BOTTOM));
    frame.render_widget(title, chunks[0]);

    // Main content
    match app.view {
        View::DetectionList => render_detection_list(frame, app, chunks[1]),
        View::EventBrowser => render_event_browser(frame, app, chunks[1]),
        View::FieldDetail => render_field_detail(frame, app, chunks[1]),
    }

    // Status bar
    let status_text = if app.searching {
        format!(" /{}_ ", app.search_query)
    } else {
        " q:quit  j/k:nav  Enter:select  Esc:back  /:search ".to_string()
    };
    let status = Paragraph::new(Span::styled(
        status_text,
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(status, chunks[2]);
}

#[cfg(feature = "tui")]
fn render_detection_list(frame: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .detections
        .iter()
        .enumerate()
        .filter(|(_, d)| {
            if app.search_query.is_empty() {
                true
            } else {
                d.title.to_lowercase().contains(&app.search_query.to_lowercase())
            }
        })
        .map(|(i, d)| {
            let level_color = match d.level.to_lowercase().as_str() {
                "critical" => Color::Red,
                "high" => Color::LightRed,
                "medium" => Color::Yellow,
                "low" => Color::Green,
                _ => Color::White,
            };
            let style = if i == app.selected_detection {
                Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let line = Line::from(vec![
                Span::styled(format!("[{:>8}] ", d.level), Style::default().fg(level_color)),
                Span::raw(format!("{} ", d.title)),
                Span::styled(format!("({})", d.count), Style::default().fg(Color::Cyan)),
            ]);
            ListItem::new(line).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} detections ", app.detections.len())),
    );
    frame.render_widget(list, area);
}

#[cfg(feature = "tui")]
fn render_event_browser(frame: &mut Frame, app: &App, area: Rect) {
    let det = match app.detections.get(app.selected_detection) {
        Some(d) => d,
        None => return,
    };

    let header_cells = ["#", "Event Summary"];
    let header = Row::new(header_cells).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = det
        .rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let summary = row
                .iter()
                .take(3)
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("  ");
            let style = if i == app.selected_event {
                Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Row::new(vec![format!("{}", i + 1), summary]).style(style)
        })
        .collect();

    let table = Table::new(rows, [Constraint::Length(6), Constraint::Min(0)])
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} — {} events ", det.title, det.count)),
        );
    frame.render_widget(table, area);
}

#[cfg(feature = "tui")]
fn render_field_detail(frame: &mut Frame, app: &App, area: Rect) {
    let det = match app.detections.get(app.selected_detection) {
        Some(d) => d,
        None => return,
    };
    let row = match det.rows.get(app.selected_event) {
        Some(r) => r,
        None => return,
    };

    let mut fields: Vec<(&String, &String)> = row.iter().collect();
    fields.sort_by_key(|(k, _)| k.to_lowercase());

    let items: Vec<ListItem> = fields
        .iter()
        .skip(app.scroll)
        .map(|(k, v)| {
            let line = Line::from(vec![
                Span::styled(format!("{}: ", k), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw(v.to_string()),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(
                " Event {}/{} — {} fields ",
                app.selected_event + 1,
                det.rows.len(),
                row.len()
            )),
    );
    frame.render_widget(list, area);
}

// ---------------------------------------------------------------------------
// Unit tests — NOT behind feature gate, test only App state machine
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_detections() -> Vec<DetectionInfo> {
        vec![
            DetectionInfo {
                title: "Suspicious Process".into(),
                level: "high".into(),
                count: 2,
                tags: vec!["attack.execution".into()],
                rows: vec![
                    HashMap::from([
                        ("CommandLine".into(), "cmd.exe /c whoami".into()),
                        ("User".into(), "SYSTEM".into()),
                    ]),
                    HashMap::from([
                        ("CommandLine".into(), "powershell -enc ...".into()),
                        ("User".into(), "admin".into()),
                    ]),
                ],
            },
            DetectionInfo {
                title: "Lateral Movement".into(),
                level: "critical".into(),
                count: 1,
                tags: vec!["attack.lateral_movement".into()],
                rows: vec![HashMap::from([
                    ("SourceIP".into(), "10.0.0.5".into()),
                    ("DestIP".into(), "10.0.0.10".into()),
                ])],
            },
            DetectionInfo {
                title: "Info Event".into(),
                level: "low".into(),
                count: 0,
                tags: vec![],
                rows: vec![],
            },
        ]
    }

    #[test]
    fn test_app_navigation() {
        let mut app = App::new(sample_detections());

        // Starts at index 0
        assert_eq!(app.selected_detection, 0);

        // Move down
        app.next();
        assert_eq!(app.selected_detection, 1);

        app.next();
        assert_eq!(app.selected_detection, 2);

        // Should clamp at last item
        app.next();
        assert_eq!(app.selected_detection, 2);

        // Move up
        app.previous();
        assert_eq!(app.selected_detection, 1);

        app.previous();
        assert_eq!(app.selected_detection, 0);

        // Should clamp at 0
        app.previous();
        assert_eq!(app.selected_detection, 0);
    }

    #[test]
    fn test_app_view_transitions() {
        let mut app = App::new(sample_detections());

        // Starts in DetectionList
        assert_eq!(app.view, View::DetectionList);

        // Enter -> EventBrowser
        app.enter();
        assert_eq!(app.view, View::EventBrowser);
        assert_eq!(app.selected_event, 0);

        // Enter -> FieldDetail
        app.enter();
        assert_eq!(app.view, View::FieldDetail);

        // Enter at FieldDetail does nothing
        app.enter();
        assert_eq!(app.view, View::FieldDetail);

        // Back -> EventBrowser
        app.back();
        assert_eq!(app.view, View::EventBrowser);

        // Back -> DetectionList
        app.back();
        assert_eq!(app.view, View::DetectionList);

        // Back at DetectionList does nothing
        app.back();
        assert_eq!(app.view, View::DetectionList);
    }
}
