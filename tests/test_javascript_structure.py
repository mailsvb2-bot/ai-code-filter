from pathlib import Path

from ai_code_filter.analyzers.javascript_structure import JavaScriptStructureAnalyzer
from ai_code_filter.models import FilePayload


def payload(tmp_path: Path, source: str, name: str = "app.js") -> FilePayload:
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return FilePayload(path=path, project_root=tmp_path, content=source)


def ids(issues):
    return {issue.category.split(":", 1)[0] for issue in issues}


def test_detects_postmessage_and_message_listener_without_origin(tmp_path: Path):
    source = '''
window.addEventListener("message", (event) => {
  handle(event.data)
})
iframe.contentWindow.postMessage(payload, "*")
'''
    issues = JavaScriptStructureAnalyzer().analyze(payload(tmp_path, source))
    assert {"JSSTR001", "JSSTR002"}.issubset(ids(issues))


def test_origin_check_and_explicit_postmessage_origin_are_clean(tmp_path: Path):
    source = '''
window.addEventListener("message", (event) => {
  if (event.origin !== "https://example.com") return
  handle(event.data)
})
iframe.contentWindow.postMessage(payload, "https://example.com")
'''
    issues = JavaScriptStructureAnalyzer().analyze(payload(tmp_path, source))
    assert not {"JSSTR001", "JSSTR002"}.intersection(ids(issues))


def test_detects_redirect_sink_near_url_params(tmp_path: Path):
    source = '''
const params = new URLSearchParams(location.search)
const next = params.get("next")
window.location = next
'''
    issues = JavaScriptStructureAnalyzer().analyze(payload(tmp_path, source))
    assert "JSSTR003" in ids(issues)


def test_detects_extra_browser_structure_risks(tmp_path: Path):
    source = '''
const params = new URLSearchParams(location.search)
const next = params.get("next")
window.open(next)
document.domain = "example.com"
setTimeout("alert(1)", 10)
const html = localStorage.getItem("html")
div.innerHTML = html
'''
    issues = JavaScriptStructureAnalyzer().analyze(payload(tmp_path, source))
    assert {"JSSTR004", "JSSTR005", "JSSTR006", "JSSTR007"}.issubset(ids(issues))
