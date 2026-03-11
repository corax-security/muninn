pub mod model;
pub mod parsers;
pub mod search;
pub mod sigma;

pub mod mitre;
pub mod transforms;
pub mod timeline;
pub mod anomaly;
pub mod ioc;
pub mod scoring;
pub mod diff;
pub mod correlate;
pub mod output;

pub use model::{Event, ParseResult, SourceFormat};
pub use parsers::{detect_format, discover_files, parse_file, parse_file_as, parse_files_parallel};
pub use search::{SearchEngine, SearchResult};
pub use sigma::{compile, load_rules, EventFilter, Rule};

#[cfg(feature = "tui")]
pub mod tui;

#[cfg(feature = "live")]
pub mod live;
