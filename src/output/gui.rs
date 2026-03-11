use anyhow::Result;
use std::collections::HashMap;

/// (title, level, count, tags, matched_rows)
pub type GuiDetectionTuple = (
    String,
    String,
    usize,
    Vec<String>,
    Vec<HashMap<String, String>>,
);

pub fn generate_html_report(
    detections: &[GuiDetectionTuple],
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
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Muninn Report</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
<link rel="stylesheet" href="https://unpkg.com/vis-timeline@7.7.3/styles/vis-timeline-graph2d.min.css">
<style>
:root {{
  --bg-deep: #0d1117;
  --bg-main: #161b22;
  --bg-card: #1c2333;
  --bg-surface: #21262d;
  --bg-hover: #292e36;
  --frost: #7dd3fc;
  --ice: #38bdf8;
  --steel: #0ea5e9;
  --accent: #00d4ff;
  --text: #e6edf3;
  --text-dim: #8b949e;
  --border: #30363d;
  --critical: #ff4444;
  --high: #ff8800;
  --medium: #e3b341;
  --low: #58a6ff;
  --info: #8b949e;
}}

* {{ box-sizing: border-box; margin: 0; padding: 0; }}

body {{
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
  background: var(--bg-deep);
  color: var(--text);
  line-height: 1.5;
}}

/* ── Header ── */
.header {{
  background: linear-gradient(135deg, #0d1117 0%, #161b2e 50%, #0d1117 100%);
  border-bottom: 1px solid var(--border);
  padding: 24px 32px;
  display: flex;
  align-items: center;
  gap: 20px;
}}
.header-logo {{
  font-size: 1.8em;
  font-weight: 800;
  background: linear-gradient(135deg, var(--frost) 0%, var(--steel) 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  letter-spacing: 2px;
}}
.header-sub {{
  color: var(--text-dim);
  font-size: 0.85em;
}}

/* ── Navigation tabs ── */
.nav {{
  display: flex;
  background: var(--bg-main);
  border-bottom: 1px solid var(--border);
  padding: 0 32px;
  gap: 0;
  position: sticky;
  top: 0;
  z-index: 100;
}}
.nav-tab {{
  padding: 12px 24px;
  cursor: pointer;
  color: var(--text-dim);
  border-bottom: 2px solid transparent;
  transition: all 0.2s;
  font-size: 0.9em;
  font-weight: 500;
  user-select: none;
}}
.nav-tab:hover {{ color: var(--text); background: var(--bg-surface); }}
.nav-tab.active {{
  color: var(--accent);
  border-bottom-color: var(--accent);
}}

/* ── Content ── */
.content {{ padding: 24px 32px; max-width: 1600px; margin: 0 auto; }}
.section {{ display: none; }}
.section.active {{ display: block; }}

/* ── Summary cards ── */
.cards {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}}
.card {{
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px;
  text-align: center;
  transition: transform 0.15s, border-color 0.15s;
}}
.card:hover {{ transform: translateY(-2px); border-color: var(--accent); }}
.card .value {{
  font-size: 2em;
  font-weight: 700;
  color: var(--accent);
  line-height: 1.2;
}}
.card .label {{
  font-size: 0.8em;
  color: var(--text-dim);
  margin-top: 4px;
  text-transform: uppercase;
  letter-spacing: 1px;
}}
.card.critical .value {{ color: var(--critical); }}
.card.high .value {{ color: var(--high); }}
.card.medium .value {{ color: var(--medium); }}
.card.low .value {{ color: var(--low); }}

/* ── Severity badges ── */
.badge {{
  display: inline-block;
  padding: 2px 10px;
  border-radius: 12px;
  font-size: 0.75em;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}}
.badge-critical {{ background: rgba(255,68,68,0.15); color: var(--critical); border: 1px solid rgba(255,68,68,0.3); }}
.badge-high {{ background: rgba(255,136,0,0.15); color: var(--high); border: 1px solid rgba(255,136,0,0.3); }}
.badge-medium {{ background: rgba(227,179,65,0.15); color: var(--medium); border: 1px solid rgba(227,179,65,0.3); }}
.badge-low {{ background: rgba(88,166,255,0.15); color: var(--low); border: 1px solid rgba(88,166,255,0.3); }}
.badge-info {{ background: rgba(139,148,158,0.15); color: var(--info); border: 1px solid rgba(139,148,158,0.3); }}

/* ── Severity distribution bar ── */
.sev-bar {{
  display: flex;
  height: 8px;
  border-radius: 4px;
  overflow: hidden;
  margin: 16px 0 24px;
  background: var(--bg-surface);
}}
.sev-bar span {{ transition: width 0.5s ease; }}

/* ── Timeline ── */
#timeline {{
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  margin-bottom: 24px;
  min-height: 400px;
}}
.vis-timeline {{
  border: none !important;
  font-family: inherit !important;
}}
.vis-panel.vis-background, .vis-panel.vis-center {{
  background: transparent !important;
}}
.vis-time-axis .vis-text {{ color: var(--text-dim) !important; font-size: 0.8em !important; }}
.vis-time-axis .vis-grid.vis-minor {{ border-color: rgba(48,54,61,0.5) !important; }}
.vis-time-axis .vis-grid.vis-major {{ border-color: rgba(48,54,61,0.8) !important; }}
.vis-labelset .vis-label {{
  background: var(--bg-surface) !important;
  color: var(--text) !important;
  border-bottom: 1px solid var(--border) !important;
  font-size: 0.85em !important;
}}
.vis-foreground .vis-group {{ border-bottom: 1px solid var(--border) !important; }}
.vis-item {{
  border-radius: 4px !important;
  border: none !important;
  font-size: 0.8em !important;
  color: #fff !important;
  padding: 2px 8px !important;
  cursor: pointer !important;
}}
.vis-item.vis-selected {{ box-shadow: 0 0 0 2px var(--accent) !important; }}
.vis-item.sev-critical {{ background-color: var(--critical) !important; }}
.vis-item.sev-high {{ background-color: var(--high) !important; }}
.vis-item.sev-medium {{ background-color: var(--medium) !important; }}
.vis-item.sev-low {{ background-color: var(--low) !important; }}
.vis-item.sev-info {{ background-color: var(--info) !important; }}

.timeline-controls {{
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
  align-items: center;
}}
.btn {{
  background: var(--bg-surface);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 6px 16px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 0.85em;
  transition: all 0.15s;
}}
.btn:hover {{ background: var(--bg-hover); border-color: var(--accent); }}
.btn-accent {{ background: var(--steel); border-color: var(--steel); color: #fff; }}
.btn-accent:hover {{ background: var(--accent); }}

/* ── MITRE Matrix ── */
.mitre-matrix {{
  display: grid;
  grid-template-columns: repeat(14, 1fr);
  gap: 2px;
  margin-top: 16px;
}}
.mitre-col {{
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
}}
.mitre-col-header {{
  background: var(--bg-surface);
  padding: 8px 6px;
  font-size: 0.7em;
  font-weight: 600;
  text-align: center;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.3px;
  min-height: 52px;
  display: flex;
  align-items: center;
  justify-content: center;
}}
.mitre-tech {{
  padding: 4px 6px;
  margin: 2px;
  border-radius: 3px;
  font-size: 0.7em;
  cursor: pointer;
  transition: all 0.15s;
  text-align: center;
  line-height: 1.3;
}}
.mitre-tech:hover {{ filter: brightness(1.2); transform: scale(1.02); }}
.mitre-tech .tech-id {{ font-weight: 700; display: block; }}
.mitre-tech .tech-count {{ font-size: 0.85em; opacity: 0.8; }}

/* ── Detections table ── */
.filter-bar {{
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
  flex-wrap: wrap;
  align-items: center;
}}
.filter-bar select, .filter-bar input {{
  background: var(--bg-surface);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 0.85em;
}}
.filter-bar select:focus, .filter-bar input:focus {{
  outline: none;
  border-color: var(--accent);
}}

table.dataTable {{ background: var(--bg-card) !important; color: var(--text) !important; border-collapse: collapse !important; }}
table.dataTable thead th {{
  background: var(--bg-surface) !important;
  color: var(--text) !important;
  border-bottom: 2px solid var(--border) !important;
  padding: 10px 12px !important;
  font-size: 0.85em !important;
}}
table.dataTable tbody td {{
  border-bottom: 1px solid var(--border) !important;
  padding: 8px 12px !important;
  font-size: 0.85em !important;
}}
table.dataTable tbody tr:hover {{ background: var(--bg-hover) !important; }}
.dataTables_wrapper .dataTables_filter input {{
  background: var(--bg-surface) !important;
  border: 1px solid var(--border) !important;
  color: var(--text) !important;
  border-radius: 6px !important;
  padding: 4px 8px !important;
}}
.dataTables_wrapper .dataTables_length select {{
  background: var(--bg-surface) !important;
  border: 1px solid var(--border) !important;
  color: var(--text) !important;
  border-radius: 6px !important;
}}
.dataTables_wrapper .dataTables_info,
.dataTables_wrapper .dataTables_paginate {{
  color: var(--text-dim) !important;
  font-size: 0.85em !important;
  margin-top: 12px !important;
}}
.dataTables_wrapper .dataTables_paginate .paginate_button {{
  color: var(--text-dim) !important;
  border: 1px solid var(--border) !important;
  background: var(--bg-surface) !important;
  border-radius: 4px !important;
  margin: 0 2px !important;
}}
.dataTables_wrapper .dataTables_paginate .paginate_button.current {{
  background: var(--steel) !important;
  color: #fff !important;
  border-color: var(--steel) !important;
}}
.dataTables_wrapper .dataTables_paginate .paginate_button:hover {{
  background: var(--bg-hover) !important;
  color: var(--text) !important;
  border-color: var(--accent) !important;
}}

/* ── Event modal ── */
.modal-overlay {{
  display: none;
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.7);
  z-index: 1000;
  justify-content: center;
  align-items: center;
  padding: 20px;
}}
.modal-overlay.show {{ display: flex; }}
.modal {{
  background: var(--bg-main);
  border: 1px solid var(--border);
  border-radius: 12px;
  width: 90%;
  max-width: 1200px;
  max-height: 85vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}}
.modal-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 24px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-surface);
}}
.modal-header h3 {{ color: var(--accent); font-size: 1em; }}
.modal-close {{
  background: none;
  border: none;
  color: var(--text-dim);
  font-size: 1.5em;
  cursor: pointer;
  padding: 0 4px;
}}
.modal-close:hover {{ color: var(--text); }}
.modal-body {{
  padding: 16px 24px;
  overflow-y: auto;
  flex: 1;
}}
.event-card {{
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 8px;
  overflow: hidden;
}}
.event-card-header {{
  padding: 8px 12px;
  background: var(--bg-surface);
  cursor: pointer;
  font-size: 0.85em;
  display: flex;
  justify-content: space-between;
  align-items: center;
}}
.event-card-header:hover {{ background: var(--bg-hover); }}
.event-card-body {{
  display: none;
  padding: 12px;
  font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
  font-size: 0.8em;
  line-height: 1.6;
}}
.event-card-body.open {{ display: block; }}
.event-field {{ display: flex; padding: 2px 0; }}
.event-field .fname {{ color: var(--ice); min-width: 200px; flex-shrink: 0; }}
.event-field .fval {{ color: var(--text); word-break: break-all; }}

/* ── Tag chips ── */
.tag {{
  display: inline-block;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  padding: 1px 8px;
  border-radius: 10px;
  font-size: 0.75em;
  margin: 1px 2px;
  color: var(--text-dim);
}}
.tag.mitre {{ border-color: rgba(14,165,233,0.4); color: var(--ice); }}

/* ── Footer ── */
.footer {{
  text-align: center;
  padding: 24px;
  color: var(--text-dim);
  font-size: 0.8em;
  border-top: 1px solid var(--border);
  margin-top: 32px;
}}
.footer a {{ color: var(--accent); text-decoration: none; }}
.footer a:hover {{ text-decoration: underline; }}

/* ── Responsive ── */
@media (max-width: 1200px) {{
  .mitre-matrix {{ grid-template-columns: repeat(7, 1fr); }}
}}
@media (max-width: 768px) {{
  .content {{ padding: 16px; }}
  .mitre-matrix {{ grid-template-columns: repeat(4, 1fr); }}
  .cards {{ grid-template-columns: repeat(2, 1fr); }}
  .nav {{ overflow-x: auto; padding: 0 16px; }}
}}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div>
    <div class="header-logo">MUNINN</div>
    <div class="header-sub">Memory of Corax &mdash; Detection Report</div>
  </div>
</div>

<!-- Navigation -->
<div class="nav">
  <div class="nav-tab active" data-tab="dashboard">Dashboard</div>
  <div class="nav-tab" data-tab="timeline">Timeline</div>
  <div class="nav-tab" data-tab="detections">Detections</div>
  <div class="nav-tab" data-tab="mitre">MITRE ATT&CK</div>
</div>

<!-- Content -->
<div class="content">

  <!-- Dashboard -->
  <div class="section active" id="sec-dashboard">
    <div class="cards" id="summaryCards"></div>
    <div class="sev-bar" id="sevBar"></div>
    <h2 style="color:var(--accent);margin-bottom:16px;font-size:1.1em;">Top Detections</h2>
    <div id="topDetections"></div>
  </div>

  <!-- Timeline -->
  <div class="section" id="sec-timeline">
    <div class="timeline-controls">
      <button class="btn btn-accent" onclick="tlFit()">Fit All</button>
      <button class="btn" onclick="tlZoomIn()">Zoom In</button>
      <button class="btn" onclick="tlZoomOut()">Zoom Out</button>
      <span style="color:var(--text-dim);font-size:0.85em;margin-left:12px;">
        Click detection to view events. Scroll to zoom. Drag to pan.
      </span>
    </div>
    <div id="timeline"></div>
  </div>

  <!-- Detections Table -->
  <div class="section" id="sec-detections">
    <div class="filter-bar">
      <select id="sevFilter" onchange="filterDetections()">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="informational">Informational</option>
      </select>
      <select id="tacticFilter" onchange="filterDetections()">
        <option value="">All Tactics</option>
      </select>
    </div>
    <table id="detectionsTable" class="display" style="width:100%">
      <thead><tr>
        <th>Severity</th>
        <th>Rule</th>
        <th>Count</th>
        <th>Techniques</th>
        <th>Tags</th>
        <th>Actions</th>
      </tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <!-- MITRE ATT&CK Matrix -->
  <div class="section" id="sec-mitre">
    <p style="color:var(--text-dim);margin-bottom:16px;font-size:0.9em;">
      MITRE ATT&CK coverage from detected techniques. Color intensity reflects detection count.
    </p>
    <div class="mitre-matrix" id="mitreMatrix"></div>
  </div>

</div>

<!-- Event Modal -->
<div class="modal-overlay" id="eventModal">
  <div class="modal">
    <div class="modal-header">
      <h3 id="modalTitle">Events</h3>
      <button class="modal-close" onclick="closeModal()">&times;</button>
    </div>
    <div class="modal-body" id="modalBody"></div>
  </div>
</div>

<!-- Footer -->
<div class="footer">
  Generated by <a href="https://github.com/corax-security/muninn">Muninn</a> &mdash; Memory of Corax
</div>

<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
<script src="https://unpkg.com/vis-timeline@7.7.3/standalone/umd/vis-timeline-graph2d.min.js"></script>
<script>
const DATA = {data_json};

const TACTIC_ORDER = [
  'reconnaissance','resource-development','initial-access','execution',
  'persistence','privilege-escalation','defense-evasion','credential-access',
  'discovery','lateral-movement','collection','command-and-control',
  'exfiltration','impact'
];
const TACTIC_NAMES = {{
  'reconnaissance':'Reconnaissance','resource-development':'Resource Development',
  'initial-access':'Initial Access','execution':'Execution',
  'persistence':'Persistence','privilege-escalation':'Privilege Escalation',
  'defense-evasion':'Defense Evasion','credential-access':'Credential Access',
  'discovery':'Discovery','lateral-movement':'Lateral Movement',
  'collection':'Collection','command-and-control':'Command and Control',
  'exfiltration':'Exfiltration','impact':'Impact'
}};
const SEV_COLORS = {{critical:'#ff4444',high:'#ff8800',medium:'#e3b341',low:'#58a6ff',informational:'#8b949e'}};
const SEV_ORDER = ['critical','high','medium','low','informational'];
const TS_FIELDS = ['SystemTime','timestamp','@timestamp','TimeCreated','UtcTime',
                   'date','_time','time','datetime','EventTime','ts'];

/* ── Helpers ── */
function parseTags(tags) {{
  const tactics = [], techniques = [];
  (tags||[]).forEach(t => {{
    const low = t.toLowerCase().replace('attack.','');
    if (TACTIC_ORDER.includes(low)) tactics.push(low);
    else if (/^t\d{{4}}/.test(low)) techniques.push(low.toUpperCase());
  }});
  return {{ tactics, techniques }};
}}

function getTimestamp(event) {{
  for (const f of TS_FIELDS) {{
    if (event[f]) return event[f];
  }}
  return null;
}}

function escHtml(s) {{
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

/* ── Tab switching ── */
document.querySelectorAll('.nav-tab').forEach(tab => {{
  tab.addEventListener('click', () => {{
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('sec-' + tab.dataset.tab).classList.add('active');
    if (tab.dataset.tab === 'timeline' && !window._tlInit) initTimeline();
    if (tab.dataset.tab === 'mitre' && !window._mitreInit) initMitre();
  }});
}});

/* ── Dashboard ── */
(function initDashboard() {{
  const s = DATA.summary;
  const dets = DATA.detections;
  const sevCounts = {{}};
  SEV_ORDER.forEach(l => sevCounts[l] = 0);
  dets.forEach(d => {{
    const l = d.level.toLowerCase();
    sevCounts[l] = (sevCounts[l]||0) + d.count;
  }});
  const totalDet = Object.values(sevCounts).reduce((a,b)=>a+b,0);

  const cards = [
    ['Files Scanned', s.files_scanned||0, ''],
    ['Total Events', (s.total_events||0).toLocaleString(), ''],
    ['Rules Matched', s.rules_matched||0, ''],
    ['Critical', sevCounts.critical, 'critical'],
    ['High', sevCounts.high, 'high'],
    ['Medium', sevCounts.medium, 'medium'],
    ['Low', sevCounts.low, 'low'],
  ];
  document.getElementById('summaryCards').innerHTML = cards.map(([label,val,cls]) =>
    `<div class="card ${{cls}}"><div class="value">${{val}}</div><div class="label">${{label}}</div></div>`
  ).join('');

  // Severity bar
  if (totalDet > 0) {{
    document.getElementById('sevBar').innerHTML = SEV_ORDER.map(l => {{
      const pct = (sevCounts[l]/totalDet*100);
      return pct > 0 ? `<span style="width:${{pct}}%;background:${{SEV_COLORS[l]}}"></span>` : '';
    }}).join('');
  }}

  // Top detections
  const sorted = [...dets].sort((a,b) => {{
    const oi = l => SEV_ORDER.indexOf(l.toLowerCase());
    return oi(a.level) - oi(b.level) || b.count - a.count;
  }}).slice(0, 10);
  document.getElementById('topDetections').innerHTML = sorted.map(d => {{
    const parsed = parseTags(d.tags);
    const techBadges = parsed.techniques.map(t => `<span class="tag mitre">${{t}}</span>`).join('');
    return `<div style="display:flex;align-items:center;gap:12px;padding:10px 12px;background:var(--bg-card);
      border:1px solid var(--border);border-radius:8px;margin-bottom:6px;cursor:pointer"
      onclick="showEvents(${{dets.indexOf(d)}})">
      <span class="badge badge-${{d.level.toLowerCase()}}">${{d.level.toUpperCase()}}</span>
      <span style="flex:1">${{escHtml(d.title)}}</span>
      ${{techBadges}}
      <span style="color:var(--text-dim);font-size:0.85em">${{d.count}} events</span>
    </div>`;
  }}).join('');
}})();

/* ── Timeline (vis-timeline) ── */
let timeline;
function initTimeline() {{
  window._tlInit = true;
  const groups = new vis.DataSet();
  const items = new vis.DataSet();

  // Create groups for each tactic
  TACTIC_ORDER.forEach((tactic, i) => {{
    groups.add({{ id: tactic, content: TACTIC_NAMES[tactic], order: i }});
  }});
  groups.add({{ id: 'other', content: 'Other', order: TACTIC_ORDER.length }});

  let itemId = 0;
  DATA.detections.forEach((det, detIdx) => {{
    const parsed = parseTags(det.tags);
    const tactics = parsed.tactics.length > 0 ? parsed.tactics : ['other'];
    const techniques = parsed.techniques;

    // Find time range from events
    let times = [];
    det.events.forEach(ev => {{
      const ts = getTimestamp(ev);
      if (ts) {{
        const d = new Date(ts);
        if (!isNaN(d.getTime())) times.push(d);
      }}
    }});

    if (times.length === 0) return; // skip detections without timestamps

    times.sort((a,b) => a-b);
    const start = times[0];
    const end = times.length > 1 ? times[times.length-1] : new Date(start.getTime() + 60000);

    tactics.forEach(tactic => {{
      const techStr = techniques.length > 0 ? ` [${{techniques.join(',')}}]` : '';
      items.add({{
        id: itemId++,
        group: tactic,
        content: `${{escHtml(det.title)}}${{techStr}} (${{det.count}})`,
        start: start,
        end: end.getTime() > start.getTime() ? end : new Date(start.getTime() + 60000),
        className: 'sev-' + det.level.toLowerCase(),
        title: `${{det.title}}\nSeverity: ${{det.level.toUpperCase()}}\nCount: ${{det.count}}\n${{techniques.join(', ')}}`,
        _detIdx: detIdx
      }});
    }});
  }});

  const container = document.getElementById('timeline');
  timeline = new vis.Timeline(container, items, groups, {{
    stack: true,
    showCurrentTime: false,
    orientation: 'top',
    margin: {{ item: {{ horizontal: 2, vertical: 4 }} }},
    zoomMin: 60000,
    tooltip: {{ followMouse: true }},
    height: '500px'
  }});

  timeline.on('select', function(props) {{
    if (props.items.length > 0) {{
      const item = items.get(props.items[0]);
      if (item && item._detIdx !== undefined) showEvents(item._detIdx);
    }}
  }});
}}

function tlFit() {{ if (timeline) timeline.fit(); }}
function tlZoomIn() {{ if (timeline) timeline.zoomIn(0.3); }}
function tlZoomOut() {{ if (timeline) timeline.zoomOut(0.3); }}

/* ── MITRE Matrix ── */
function initMitre() {{
  window._mitreInit = true;
  // Build technique → tactic → count mapping
  const matrix = {{}};
  TACTIC_ORDER.forEach(t => matrix[t] = {{}});

  DATA.detections.forEach(det => {{
    const parsed = parseTags(det.tags);
    const tactics = parsed.tactics.length > 0 ? parsed.tactics : [];
    const techniques = parsed.techniques;
    tactics.forEach(tactic => {{
      techniques.forEach(tech => {{
        if (!matrix[tactic]) matrix[tactic] = {{}};
        if (!matrix[tactic][tech]) matrix[tactic][tech] = {{ count: 0, rules: [] }};
        matrix[tactic][tech].count += det.count;
        matrix[tactic][tech].rules.push(det.title);
      }});
    }});
  }});

  // Find max for color scaling
  let maxCount = 1;
  Object.values(matrix).forEach(techs => {{
    Object.values(techs).forEach(t => {{ if (t.count > maxCount) maxCount = t.count; }});
  }});

  const container = document.getElementById('mitreMatrix');
  container.innerHTML = TACTIC_ORDER.map(tactic => {{
    const techs = matrix[tactic];
    const techIds = Object.keys(techs).sort();
    const techHtml = techIds.map(tech => {{
      const info = techs[tech];
      const intensity = Math.max(0.2, info.count / maxCount);
      const color = `rgba(14,165,233,${{intensity}})`;
      const rules = info.rules.map(r => escHtml(r)).join('\\n');
      return `<div class="mitre-tech" style="background:${{color}}"
        title="${{tech}} (${{info.count}} events)\\n${{rules}}">
        <span class="tech-id">${{tech}}</span>
        <span class="tech-count">${{info.count}}</span>
      </div>`;
    }}).join('');
    return `<div class="mitre-col">
      <div class="mitre-col-header">${{TACTIC_NAMES[tactic]}}</div>
      ${{techHtml || '<div style="padding:8px;text-align:center;color:var(--text-dim);font-size:0.75em">-</div>'}}
    </div>`;
  }}).join('');
}}

/* ── Detections Table ── */
let dtTable;
(function initDetectionsTable() {{
  const tbody = document.querySelector('#detectionsTable tbody');
  const tacticSet = new Set();

  DATA.detections.forEach((det, idx) => {{
    const parsed = parseTags(det.tags);
    parsed.tactics.forEach(t => tacticSet.add(t));
    const techBadges = parsed.techniques.map(t => `<span class="tag mitre">${{t}}</span>`).join(' ');
    const tagBadges = (det.tags||[])
      .filter(t => !t.toLowerCase().startsWith('attack.'))
      .map(t => `<span class="tag">${{escHtml(t)}}</span>`).join(' ');

    tbody.innerHTML += `<tr data-level="${{det.level.toLowerCase()}}">
      <td><span class="badge badge-${{det.level.toLowerCase()}}">${{det.level.toUpperCase()}}</span></td>
      <td>${{escHtml(det.title)}}</td>
      <td>${{det.count}}</td>
      <td>${{techBadges || '-'}}</td>
      <td>${{tagBadges || '-'}}</td>
      <td><button class="btn" onclick="showEvents(${{idx}})">View Events</button></td>
    </tr>`;
  }});

  // Populate tactic filter
  const tacticSel = document.getElementById('tacticFilter');
  [...tacticSet].sort().forEach(t => {{
    const opt = document.createElement('option');
    opt.value = t;
    opt.textContent = TACTIC_NAMES[t] || t;
    tacticSel.appendChild(opt);
  }});

  dtTable = $('#detectionsTable').DataTable({{
    pageLength: 25,
    order: [[2, 'desc']],
    columnDefs: [{{ orderable: false, targets: [5] }}]
  }});
}})();

function filterDetections() {{
  const sev = document.getElementById('sevFilter').value;
  const tactic = document.getElementById('tacticFilter').value;
  dtTable.column(0).search(sev).draw();
  // For tactic filtering, we search tags column
  if (tactic) {{
    dtTable.column(4).search(tactic).draw();
  }} else {{
    dtTable.column(4).search('').draw();
  }}
}}

/* ── Event Modal ── */
function showEvents(detIdx) {{
  const det = DATA.detections[detIdx];
  if (!det) return;
  document.getElementById('modalTitle').innerHTML =
    `<span class="badge badge-${{det.level.toLowerCase()}}" style="margin-right:8px">${{det.level.toUpperCase()}}</span> ${{escHtml(det.title)}} &mdash; ${{det.count}} events`;

  const body = document.getElementById('modalBody');
  if (det.events.length === 0) {{
    body.innerHTML = '<p style="color:var(--text-dim)">No event details available.</p>';
  }} else {{
    body.innerHTML = det.events.slice(0, 200).map((ev, i) => {{
      const ts = getTimestamp(ev) || '';
      const preview = ts ? ts : Object.values(ev).filter(Boolean).slice(0,2).join(' | ');
      const fields = Object.entries(ev)
        .filter(([k,v]) => v)
        .map(([k,v]) => `<div class="event-field"><span class="fname">${{escHtml(k)}}</span><span class="fval">${{escHtml(v)}}</span></div>`)
        .join('');
      return `<div class="event-card">
        <div class="event-card-header" onclick="this.nextElementSibling.classList.toggle('open')">
          <span>Event #${{i+1}} &mdash; ${{escHtml(preview.substring(0,80))}}</span>
          <span style="color:var(--text-dim)">&#9660;</span>
        </div>
        <div class="event-card-body">${{fields}}</div>
      </div>`;
    }}).join('');
    if (det.events.length > 200) {{
      body.innerHTML += `<p style="color:var(--text-dim);margin-top:8px">Showing 200 of ${{det.events.length}} events.</p>`;
    }}
  }}
  document.getElementById('eventModal').classList.add('show');
}}

function closeModal() {{
  document.getElementById('eventModal').classList.remove('show');
}}
document.getElementById('eventModal').addEventListener('click', function(e) {{
  if (e.target === this) closeModal();
}});
document.addEventListener('keydown', e => {{ if (e.key === 'Escape') closeModal(); }});
</script>
</body>
</html>"##
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_html() {
        let mut event = HashMap::new();
        event.insert("EventID".into(), "4624".into());
        event.insert("SystemTime".into(), "2024-01-01T10:00:00Z".into());

        let detections = vec![(
            "Test Rule".into(),
            "high".into(),
            1usize,
            vec!["attack.execution".into(), "attack.t1059.001".into()],
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
        assert!(html.contains("vis-timeline"));
        assert!(html.contains("MUNINN"));
        assert!(html.contains("MITRE"));
    }
}
