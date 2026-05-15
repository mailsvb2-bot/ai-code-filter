from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

def load_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))

def write_trend_dashboard(report_paths: list[str | Path], output: str | Path, *, title: str = "AI Code Filter Trends") -> None:
    rows = []
    for idx, path in enumerate(report_paths, start=1):
        data = load_report(path); summary = data.get("summary", {})
        rows.append({"run": idx, "path": str(path), "total": int(summary.get("TOTAL", 0)), "critical": int(summary.get("CRITICAL", 0)), "high": int(summary.get("HIGH", 0)), "medium": int(summary.get("MEDIUM", 0)), "low": int(summary.get("LOW", 0))})
    points = json.dumps(rows, ensure_ascii=False)
    table = "\n".join(f"<tr><td>{r['run']}</td><td>{html.escape(r['path'])}</td><td>{r['total']}</td><td>{r['critical']}</td><td>{r['high']}</td><td>{r['medium']}</td><td>{r['low']}</td></tr>" for r in rows)
    doc = f"""<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title><style>body{{font-family:system-ui,sans-serif;margin:32px;background:#0f172a;color:#e2e8f0}}.card{{background:#111827;border:1px solid #334155;border-radius:14px;padding:20px;margin:16px 0}}table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #334155;padding:8px;text-align:left}}.bar{{height:18px;background:#64748b;border-radius:8px;margin:4px 0}}</style></head><body><h1>{html.escape(title)}</h1><div class='card'><h2>Trend bars</h2><div id='bars'></div></div><div class='card'><h2>Runs</h2><table><thead><tr><th>Run</th><th>Report</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr></thead><tbody>{table}</tbody></table></div><script>const rows={points};const max=Math.max(1,...rows.map(r=>r.total));document.getElementById('bars').innerHTML=rows.map(r=>`<div><b>#${{r.run}}</b> ${{r.total}} findings<div class='bar' style='width:${{Math.max(2,r.total/max*100)}}%'></div></div>`).join('');</script></body></html>"""
    Path(output).write_text(doc, encoding="utf-8")
