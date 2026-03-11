use anyhow::Result;
use std::collections::HashMap;

pub fn generate_html_report(
    detections: &[(String, String, usize, Vec<String>, Vec<HashMap<String, String>>)],
    // (title, level, count, tags, events)
    summary: &serde_json::Value,
) -> Result<String> {
    let det_json: Vec<serde_json::Value> = detections
        .iter()
        .map(|(title, level, count, tags, events)| {
            serde_json::json!({
                "title": title,
                "level": level,
                "count": count,
                "tags": tags,
                "events": events,
            })
        })
        .collect();

    let data = serde_json::json!({
        "summary": summary,
        "detections": det_json,
    });

    let data_json = serde_json::to_string(&data)?;

    Ok(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Muninn Report</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #1a1a2e; color: #e0e0e0; }}
h1 {{ color: #00d4ff; }}
h2 {{ color: #00aacc; margin-top: 30px; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
.card {{ background: #16213e; padding: 20px; border-radius: 8px; border-left: 4px solid #00d4ff; }}
.card .number {{ font-size: 2em; font-weight: bold; color: #00d4ff; }}
.card .label {{ color: #888; font-size: 0.9em; }}
table.dataTable {{ background: #16213e; color: #e0e0e0; }}
table.dataTable thead {{ background: #0f3460; }}
table.dataTable tbody tr:hover {{ background: #1a1a4e !important; }}
.level-critical {{ color: #ff4444; font-weight: bold; }}
.level-high {{ color: #ff8800; font-weight: bold; }}
.level-medium {{ color: #ffcc00; }}
.level-low {{ color: #66ccff; }}
.event-detail {{ display: none; background: #0d1b2a; padding: 10px; margin: 5px 0; border-radius: 4px; font-family: monospace; font-size: 0.85em; white-space: pre-wrap; max-height: 400px; overflow-y: auto; }}
.toggle-btn {{ cursor: pointer; color: #00d4ff; text-decoration: underline; }}
#filterControls {{ margin: 15px 0; }}
#filterControls select {{ background: #16213e; color: #e0e0e0; border: 1px solid #333; padding: 5px 10px; border-radius: 4px; }}
</style>
</head>
<body>
<h1>Muninn Detection Report</h1>

<div class="summary" id="summary"></div>

<div id="filterControls">
  <label>Filter by severity: </label>
  <select id="levelFilter" onchange="filterTable()">
    <option value="">All</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
  </select>
</div>

<h2>Detections</h2>
<table id="detectionsTable" class="display" style="width:100%">
<thead><tr><th>Level</th><th>Rule</th><th>Count</th><th>Tags</th><th>Events</th></tr></thead>
<tbody></tbody>
</table>

<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
<script>
const DATA = {data_json};

function initSummary() {{
    const s = DATA.summary;
    const el = document.getElementById('summary');
    const cards = [
        ['Files Scanned', s.files_scanned || 0],
        ['Total Events', s.total_events || 0],
        ['Rules Matched', s.rules_matched || 0],
        ['Total Detections', s.total_detections || 0],
    ];
    el.innerHTML = cards.map(([label, num]) =>
        `<div class="card"><div class="number">${{num}}</div><div class="label">${{label}}</div></div>`
    ).join('');
}}

function initTable() {{
    const tbody = document.querySelector('#detectionsTable tbody');
    DATA.detections.forEach((det, idx) => {{
        const levelClass = 'level-' + det.level;
        const tags = (det.tags || []).join(', ');
        const eventsPreview = det.events.length > 0
            ? `<span class="toggle-btn" onclick="toggleEvents(${{idx}})">Show ${{det.events.length}} events</span><div class="event-detail" id="events-${{idx}}">${{JSON.stringify(det.events, null, 2)}}</div>`
            : '-';
        tbody.innerHTML += `<tr data-level="${{det.level}}">
            <td class="${{levelClass}}">${{det.level.toUpperCase()}}</td>
            <td>${{det.title}}</td>
            <td>${{det.count}}</td>
            <td>${{tags}}</td>
            <td>${{eventsPreview}}</td>
        </tr>`;
    }});
    $('#detectionsTable').DataTable({{ pageLength: 25, order: [[2, 'desc']] }});
}}

function toggleEvents(idx) {{
    const el = document.getElementById('events-' + idx);
    el.style.display = el.style.display === 'none' ? 'block' : 'none';
}}

function filterTable() {{
    const level = document.getElementById('levelFilter').value;
    const table = $('#detectionsTable').DataTable();
    table.column(0).search(level).draw();
}}

initSummary();
initTable();
</script>
</body>
</html>"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_html() {
        let mut event = HashMap::new();
        event.insert("EventID".into(), "4624".into());

        let detections = vec![(
            "Test Rule".into(),
            "high".into(),
            1usize,
            vec!["attack.execution".into()],
            vec![event],
        )];

        let summary = serde_json::json!({
            "files_scanned": 1,
            "total_events": 100,
            "rules_matched": 1,
            "total_detections": 1,
        });

        let html = generate_html_report(&detections, &summary).unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Test Rule"));
        assert!(html.contains("DataTable"));
    }
}
