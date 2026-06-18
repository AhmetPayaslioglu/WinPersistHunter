import html
from typing import List
from collections import Counter
from ..base import Detection

SEVERITY_COLORS = {
    "critical": "#ff3860",
    "high": "#ff7849",
    "medium": "#ffdd57",
    "low": "#48c774",
    "info": "#8a8a8a",
}

HTML_SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WinPersist Hunter Report</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:24px;}}
h1{{margin:0 0 6px 0;font-size:22px;}}
.sub{{color:#8b949e;margin-bottom:24px;font-size:13px;}}
.summary{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px;}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 18px;min-width:120px;}}
.card .n{{font-size:24px;font-weight:600;}}
.card .l{{font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;}}
table{{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden;}}
th{{background:#21262d;text-align:left;padding:10px 12px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:#8b949e;border-bottom:1px solid #30363d;}}
td{{padding:12px;border-bottom:1px solid #21262d;vertical-align:top;font-size:13px;}}
tr:last-child td{{border-bottom:none;}}
.sev{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;color:#0d1117;}}
.value{{font-family:Consolas,Monaco,monospace;font-size:12px;color:#a5d6ff;word-break:break-all;max-width:520px;}}
.loc{{font-family:Consolas,Monaco,monospace;font-size:11px;color:#7ee787;word-break:break-all;}}
.tech{{color:#d2a8ff;font-size:11px;}}
.artifact{{color:#79c0ff;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px;}}
.desc{{color:#8b949e;font-size:11.5px;margin:4px 0 6px 0;line-height:1.4;}}
.reasons{{color:#ffa657;font-size:11px;margin:6px 0 0 0;padding-left:18px;}}
.reasons li{{margin:2px 0;}}
.filter-bar{{margin-bottom:14px;}}
.filter-bar button{{background:#21262d;color:#e6edf3;border:1px solid #30363d;padding:6px 12px;margin-right:6px;border-radius:6px;cursor:pointer;font-size:12px;}}
.filter-bar button.active{{background:#1f6feb;border-color:#1f6feb;}}
.score{{font-weight:600;}}
.empty{{text-align:center;padding:36px;color:#8b949e;}}
.empty .ok{{font-size:48px;}}
</style>
</head>
<body>
<h1>WinPersist Hunter Report</h1>
<div class="sub">Scan time: {scan_time} &middot; Host: {hostname} &middot; Modules: {modules}</div>
<div class="summary">{cards}</div>
<div class="filter-bar">
  <button class="active" data-sev="all">All ({total})</button>
  {filter_buttons}
</div>
<table id="detections">
  <thead><tr><th>Sev</th><th>Score</th><th>Technique</th><th>Location</th><th>Artifact</th></tr></thead>
  <tbody>
  {rows}
  </tbody>
</table>
<script>
document.querySelectorAll('.filter-bar button').forEach(b => {{
  b.addEventListener('click', () => {{
    document.querySelectorAll('.filter-bar button').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    const sev = b.dataset.sev;
    document.querySelectorAll('#detections tbody tr').forEach(tr => {{
      tr.style.display = (sev === 'all' || tr.dataset.sev === sev) ? '' : 'none';
    }});
  }});
}});
</script>
</body></html>
"""


def _row(d: Detection) -> str:
    color = SEVERITY_COLORS.get(d.severity, "#8a8a8a")
    reasons = "".join(f"<li>{html.escape(r)}</li>" for r in d.reasons)
    reasons_html = f'<ul class="reasons">{reasons}</ul>' if reasons else ""
    desc = f'<div class="desc">{html.escape(d.description)}</div>' if d.description else ""
    return (
        f'<tr data-sev="{d.severity}">'
        f'<td><span class="sev" style="background:{color}">{d.severity.upper()}</span></td>'
        f'<td class="score">{d.score}</td>'
        f'<td><div class="tech">{html.escape(d.technique_id)}<br>{html.escape(d.technique_name)}</div></td>'
        f'<td class="loc">{html.escape(d.location)}</td>'
        f'<td><div class="artifact">{html.escape(d.artifact)}</div>'
        f'{desc}'
        f'<div><b>{html.escape(d.name)}</b></div>'
        f'<div class="value">{html.escape(d.value)[:600]}</div>{reasons_html}</td>'
        f"</tr>"
    )


def write_html(path: str, detections: List[Detection], meta: dict) -> None:
    detections = sorted(detections, key=lambda d: (-d.score, d.module))
    sev_counts = Counter(d.severity for d in detections)
    cards = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        n = sev_counts.get(sev, 0)
        color = SEVERITY_COLORS[sev]
        cards += (f'<div class="card"><div class="n" style="color:{color}">{n}</div>'
                  f'<div class="l">{sev}</div></div>')
    filter_buttons = "".join(
        f'<button data-sev="{s}">{s.title()} ({sev_counts.get(s,0)})</button>'
        for s in ["critical", "high", "medium", "low", "info"]
    )
    if detections:
        rows = "\n".join(_row(d) for d in detections)
    else:
        rows = ('<tr><td colspan="5"><div class="empty">'
                '<div class="ok">&#10003;</div>'
                'No persistence anomalies detected.</div></td></tr>')
    out = HTML_SHELL.format(
        scan_time=html.escape(meta.get("scan_time", "")),
        hostname=html.escape(meta.get("hostname", "")),
        modules=html.escape(", ".join(meta.get("modules", []))),
        total=len(detections),
        cards=cards,
        filter_buttons=filter_buttons,
        rows=rows,
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(out)
