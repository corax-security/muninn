pub mod gui;
pub mod templates;

/// Generate a self-contained HTML report with DataTables for any JSON array data.
/// Supports nested objects — flattens them into columns automatically.
pub fn render_html_table(title: &str, data_json: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Muninn — {title}</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #1a1a2e; color: #e0e0e0; }}
h1 {{ color: #00d4ff; }}
table.dataTable {{ background: #16213e; color: #e0e0e0; }}
table.dataTable thead {{ background: #0f3460; }}
table.dataTable tbody tr:hover {{ background: #1a1a4e !important; }}
.level-critical, .severity-critical {{ color: #ff4444; font-weight: bold; }}
.level-high, .severity-high {{ color: #ff8800; font-weight: bold; }}
.level-medium, .severity-medium {{ color: #ffcc00; }}
.level-low, .severity-low {{ color: #66ccff; }}
.score-bar {{ display: inline-block; height: 14px; background: #00d4ff; border-radius: 3px; }}
.nested {{ font-family: monospace; font-size: 0.85em; white-space: pre-wrap; max-height: 200px; overflow-y: auto; }}
</style>
</head>
<body>
<h1>Muninn &mdash; {title}</h1>
<table id="reportTable" class="display" style="width:100%">
<thead><tr id="headerRow"></tr></thead>
<tbody></tbody>
</table>

<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
<script>
const DATA = {data_json};

function flatten(obj, prefix) {{
    let result = {{}};
    for (let key in obj) {{
        let val = obj[key];
        let newKey = prefix ? prefix + '.' + key : key;
        if (val && typeof val === 'object' && !Array.isArray(val)) {{
            Object.assign(result, flatten(val, newKey));
        }} else if (Array.isArray(val)) {{
            result[newKey] = val.length > 3 ? val.slice(0, 3).join(', ') + ' ...(+' + (val.length - 3) + ')' : val.join(', ');
        }} else {{
            result[newKey] = val;
        }}
    }}
    return result;
}}

function renderCell(val) {{
    if (val === null || val === undefined) return '';
    let s = String(val);
    let lc = s.toLowerCase();
    if (['critical','high','medium','low'].includes(lc)) {{
        return '<span class="level-' + lc + '">' + s.toUpperCase() + '</span>';
    }}
    if (!isNaN(parseFloat(s)) && s.includes('.') && parseFloat(s) <= 100 && parseFloat(s) >= 0) {{
        let w = Math.max(2, Math.round(parseFloat(s)));
        return '<span class="score-bar" style="width:' + w + 'px"></span> ' + parseFloat(s).toFixed(1);
    }}
    return s;
}}

(function() {{
    let rows = Array.isArray(DATA) ? DATA.map(d => flatten(d, '')) : [flatten(DATA, '')];
    let cols = [...new Set(rows.flatMap(r => Object.keys(r)))];
    let headerRow = document.getElementById('headerRow');
    cols.forEach(c => {{ let th = document.createElement('th'); th.textContent = c; headerRow.appendChild(th); }});
    let tbody = document.querySelector('#reportTable tbody');
    rows.forEach(r => {{
        let tr = document.createElement('tr');
        cols.forEach(c => {{ let td = document.createElement('td'); td.innerHTML = renderCell(r[c]); tr.appendChild(td); }});
        tbody.appendChild(tr);
    }});
    $('#reportTable').DataTable({{ pageLength: 50, order: [] }});
}})();
</script>
</body>
</html>"#,
        title = title,
        data_json = data_json,
    )
}
