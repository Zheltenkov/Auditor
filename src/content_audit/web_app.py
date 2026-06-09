"""Локальный веб-интерфейс для запуска аудита и просмотра отчёта."""

from __future__ import annotations

import argparse
import html
import json
import mimetypes
import os
from collections import Counter
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse

from content_audit.domain import (
    CRITERION_LABELS,
    SEVERITY_LABELS,
    VERDICT_LABELS,
    AuditReport,
    AuditSettings,
    Criterion,
    Finding,
    Severity,
)
from content_audit.env import get_env_value, load_env_file
from content_audit.exporters import write_report
from content_audit.orchestrator import AuditRunner


DEFAULT_REPORT_DIR = Path("reports") / "ui_latest"
DEFAULT_MODEL = "openai/gpt-4o-mini"
DEFAULT_FACT_MODEL = "perplexity/sonar"
DEFAULT_TECH_MODEL = "qwen/qwen3-coder"


class WebState:
    """Состояние локального веб-сервера."""

    def __init__(self, default_input: Path | None, report_dir: Path, env_values: dict[str, str]) -> None:
        self.default_input = default_input
        self.report_dir = report_dir
        self.env_values = env_values
        self.last_error: str | None = None


class AuditWebHandler(BaseHTTPRequestHandler):
    """Обрабатывает страницы запуска аудита и просмотра отчёта."""

    state: WebState

    def do_GET(self) -> None:  # noqa: N802 - интерфейс стандартной библиотеки.
        """Отдаём главную страницу или файл отчёта."""

        route = urlparse(self.path)
        if route.path == "/":
            self._send_html(render_page(None, self.state))
            return
        if route.path == "/download":
            params = parse_qs(route.query)
            self._send_report_file(params.get("file", [""])[0])
            return
        if route.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Страница не найдена")

    def do_POST(self) -> None:  # noqa: N802 - интерфейс стандартной библиотеки.
        """Запускаем аудит по данным формы."""

        route = urlparse(self.path)
        if route.path != "/run":
            self.send_error(HTTPStatus.NOT_FOUND, "Страница не найдена")
            return

        form: dict[str, str] = {}
        try:
            form = self._read_form()
            report = run_from_form(form, self.state)
            self.state.last_error = None
            self._send_html(render_page(report, self.state, form_values=form))
        except Exception as exc:  # noqa: BLE001 - ошибка должна быть показана пользователю.
            self.state.last_error = str(exc)
            self._send_html(render_page(None, self.state, form_values=form), status=HTTPStatus.BAD_REQUEST)

    def log_message(self, format: str, *args: Any) -> None:
        """Убираем шумный стандартный журнал запросов."""

    def _read_form(self) -> dict[str, str]:
        """Разбираем тело формы."""

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        parsed = parse_qs(body, keep_blank_values=True)
        return {key: values[0] for key, values in parsed.items()}

    def _send_html(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        """Отправляем HTML-страницу."""

        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_report_file(self, file_name: str) -> None:
        """Отдаём CSV/JSON отчёт из текущей папки результатов."""

        safe_names = {"report.csv", "report.json", "run_summary.json", "evaluation.json"}
        if file_name not in safe_names:
            self.send_error(HTTPStatus.BAD_REQUEST, "Неверное имя файла")
            return
        path = self.state.report_dir / file_name
        if not path.exists():
            self.send_error(HTTPStatus.NOT_FOUND, "Файл отчёта не найден")
            return
        payload = path.read_bytes()
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main(argv: list[str] | None = None) -> int:
    """Запускает локальный веб-сервер."""

    parser = argparse.ArgumentParser(description="Веб-интерфейс аудита учебного контента.")
    parser.add_argument("--host", default="127.0.0.1", help="Адрес сервера.")
    parser.add_argument("--port", type=int, default=8021, help="Порт сервера.")
    parser.add_argument("--default-input", type=Path, default=None, help="Путь по умолчанию в форме.")
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR, help="Папка для последних отчётов.")
    args = parser.parse_args(argv)

    env_values = load_env_file(Path(".env"))
    state = WebState(
        default_input=args.default_input.expanduser().resolve() if args.default_input else None,
        report_dir=args.report_dir.expanduser().resolve(),
        env_values=env_values,
    )
    AuditWebHandler.state = state
    server = ThreadingHTTPServer((args.host, args.port), AuditWebHandler)
    print(f"Панель отчёта: http://{args.host}:{args.port}")
    server.serve_forever()
    return 0


def run_from_form(form: dict[str, str], state: WebState) -> AuditReport:
    """Создаёт настройки из формы, запускает аудит и сохраняет отчёт."""

    raw_input = (form.get("input_path") or "").strip()
    if not raw_input and state.default_input is not None:
        raw_input = str(state.default_input)
    if not raw_input:
        raise ValueError("Укажите путь к проекту.")
    input_path = Path(raw_input).expanduser().resolve()
    model_name = get_env_value(("OPENROUTER_MODEL", "OPEN_ROUTER_MODEL"), state.env_values) or DEFAULT_MODEL
    fact_model_name = get_env_value(("OPENROUTER_FACT_MODEL", "OPEN_ROUTER_FACT_MODEL"), state.env_values) or DEFAULT_FACT_MODEL
    tech_model_name = get_env_value(("OPENROUTER_TECH_MODEL", "OPEN_ROUTER_TECH_MODEL"), state.env_values) or DEFAULT_TECH_MODEL
    api_key = get_env_value(("OPENROUTER_API_KEY", "OPEN_ROUTER_API_KEY"), state.env_values)
    settings = AuditSettings(
        input_path=input_path,
        output_path=state.report_dir,
        allow_network=True,
        use_model=True,
        include_unknown=True,
        openrouter_api_key=api_key,
        openrouter_model=model_name,
        openrouter_fact_model=fact_model_name,
        openrouter_tech_model=tech_model_name,
    )
    report = AuditRunner(settings).run()
    write_report(report, state.report_dir)
    return report


def load_latest_report(report_dir: Path) -> AuditReport | None:
    """Загружает последний отчёт, если он уже есть."""

    path = report_dir / "report.json"
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    return AuditReport.model_validate(payload)


def render_page(report: AuditReport | None, state: WebState, form_values: dict[str, str] | None = None) -> str:
    """Собирает полную страницу веб-интерфейса."""

    form = form_values or {}
    input_value = form.get("input_path") or (report.summary.input_path if report else str(state.default_input or ""))
    body = "\n".join(
        [
            _render_topbar(),
            '<main class="shell">',
            _render_run_panel(
                report,
                input_value,
            ),
            _render_error(state.last_error),
            _render_dashboard(report, state.report_dir) if report else _render_empty_state(),
            "</main>",
            _render_script(),
        ]
    )
    return f"<!doctype html><html lang=\"ru\"><head>{_render_head()}</head><body>{body}</body></html>"


def _render_head() -> str:
    """Возвращает заголовок страницы и стили."""

    return """
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Аудит контента · Панель отчёта</title>
<style>
:root {
  --bg: #f4f1ea;
  --bg-top: #f7f4ed;
  --surface: #fffdfa;
  --surface-strong: #ffffff;
  --surface-muted: #f1ece2;
  --border: #d9cfbf;
  --border-soft: rgba(31, 42, 42, .12);
  --border-strong: rgba(31, 42, 42, .18);
  --text: #1f2a2a;
  --muted: #586469;
  --accent: #0e8f6f;
  --accent-bright: #26b28f;
  --accent-deep: #15735a;
  --accent-soft: #d8f2ea;
  --warn: #b85c38;
  --warn-soft: #fbe5dc;
  --info: #1d5fd0;
  --amber: #9a6420;
  --danger: #a33a32;
  --danger-soft: #f8ded8;
  --shadow-sm: 0 8px 22px rgba(31, 42, 42, .06);
  --shadow: 0 18px 44px rgba(31, 42, 42, .09);
  --radius: 20px;
  --radius-md: 16px;
  --radius-sm: 12px;
  --font-sans: "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
  --font-mono: "JetBrains Mono", "Consolas", ui-monospace, monospace;
}
* { box-sizing: border-box; }
html, body { margin: 0; }
body {
  min-height: 100vh;
  color: var(--text);
  background:
    linear-gradient(180deg, rgba(247,244,237,.96), rgba(244,241,234,.96)),
    var(--bg);
  font-family: var(--font-sans);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
.topbar {
  position: sticky;
  top: 0;
  z-index: 20;
  backdrop-filter: blur(18px);
  background: rgba(247, 244, 237, .86);
  border-bottom: 1px solid var(--border-soft);
}
.topbar-inner, .shell { max-width: 1720px; margin: 0 auto; padding-left: 32px; padding-right: 32px; }
.topbar-inner { min-height: 62px; display: flex; align-items: center; justify-content: space-between; gap: 18px; }
.wordmark { display: flex; align-items: center; gap: 12px; min-width: 0; }
.glyph {
  width: 32px; height: 32px; border-radius: var(--radius-sm);
  display: grid; place-items: center; color: #fff; font-weight: 800;
  background: linear-gradient(135deg, var(--accent), var(--accent-bright));
  box-shadow: 0 10px 24px rgba(14, 143, 111, .24);
}
.brand-title { font-weight: 800; font-size: 15px; }
.brand-sub { color: var(--muted); font-size: 12px; font-weight: 600; }
.top-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.shell { padding-top: 26px; padding-bottom: 72px; }
.run-panel {
  background: var(--surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 22px;
}
.panel-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 18px; margin-bottom: 18px; }
h1 { margin: 0; font-size: 24px; line-height: 1.15; letter-spacing: 0; }
.muted { color: var(--muted); font-size: 13px; margin: 6px 0 0; }
.form-grid { display: grid; grid-template-columns: minmax(0, 1fr) 138px; gap: 12px; align-items: end; }
label { display: block; font-size: 12px; color: var(--muted); font-weight: 800; letter-spacing: 0; margin-bottom: 7px; }
input[type="text"], select {
  width: 100%;
  height: 44px;
  border: 1px solid var(--border-strong);
  border-radius: 999px;
  padding: 0 16px;
  background: var(--surface-strong);
  color: var(--text);
  font: 14px var(--font-mono);
  outline: none;
}
input[type="text"]:focus, select:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(14,143,111,.14); }
.button {
  border: 0;
  border-radius: 999px;
  height: 44px;
  padding: 0 18px;
  font: 800 14px var(--font-sans);
  cursor: pointer;
  color: #fff;
  background: linear-gradient(135deg, var(--accent), var(--accent-bright));
  box-shadow: 0 12px 24px rgba(14, 143, 111, .22);
}
.link-button {
  display: inline-flex; align-items: center; justify-content: center;
  height: 34px; padding: 0 13px; border-radius: 999px;
  text-decoration: none; color: var(--text); background: var(--surface-strong);
  border: 1px solid var(--border-strong); font-weight: 800; font-size: 12px;
}
.options { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }
.check {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 8px 12px; border-radius: 999px; border: 1px solid var(--border-soft);
  background: var(--surface-strong); font-size: 13px; font-weight: 700; color: var(--text);
}
.check input { accent-color: var(--accent); }
.alert {
  margin-top: 18px; padding: 14px 16px; border-radius: var(--radius-sm);
  border: 1px solid rgba(184,92,56,.25); background: var(--warn-soft); color: #78371f;
  font-weight: 700; font-size: 13px;
}
.empty {
  margin-top: 20px; padding: 30px; border: 1px dashed var(--border);
  border-radius: var(--radius); color: var(--muted); background: rgba(255,253,250,.58);
}
.summary-strip {
  margin-top: 18px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  background: var(--surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-sm);
  padding: 16px 18px;
}
.summary-main { display: flex; align-items: baseline; gap: 12px; min-width: 0; flex-wrap: wrap; }
.summary-number { font-size: 30px; font-weight: 900; color: var(--text); line-height: 1; }
.summary-text { color: var(--muted); font-size: 14px; font-weight: 800; }
.severity-inline { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
.severity-chip {
  display: inline-flex; align-items: center; min-height: 32px;
  border-radius: 999px; padding: 5px 12px;
  font-size: 13px; font-weight: 900; white-space: nowrap;
}
.severity-chip-critical { color: var(--danger); background: var(--danger-soft); }
.severity-chip-major { color: #98630c; background: #f3dfac; }
.severity-chip-minor { color: var(--muted); background: #ece7dc; }
.severity-chip-info { color: var(--muted); background: var(--surface-muted); }
.section { margin-top: 26px; }
.section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 14px; border-bottom: 1px solid var(--border-soft); padding-bottom: 12px; margin-bottom: 14px; }
.section h2 { margin: 0; font-size: 20px; }
.grid-three { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; }
.criteria-strip { margin-top: 22px; }
.criteria-title { color: var(--muted); font-size: 13px; font-weight: 900; margin-bottom: 8px; }
.criteria-hint { color: var(--muted); font-size: 13px; margin-bottom: 10px; }
.criteria-chips { display: flex; flex-wrap: wrap; gap: 8px; }
.criterion-filter {
  min-height: 38px;
  border: 1px solid var(--border-soft);
  border-radius: 999px;
  padding: 7px 13px;
  background: var(--surface-strong);
  color: var(--text);
  display: inline-flex;
  align-items: center;
  gap: 7px;
  cursor: pointer;
  font: 900 13px var(--font-sans);
}
.criterion-filter:hover,
.criterion-filter.is-active {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(14,143,111,.12);
}
.criterion-filter.is-active { background: var(--accent-soft); }
.criterion-filter.is-empty { color: #8b8b84; background: transparent; opacity: .7; }
.criterion-filter.is-empty:not(.is-active) { box-shadow: none; }
.criterion-count { color: inherit; font: 900 13px var(--font-mono); }
.panel {
  background: var(--surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  box-shadow: var(--shadow-sm);
  padding: 18px;
}
.bar-row { display: grid; grid-template-columns: minmax(118px, 1fr) minmax(84px, 1.1fr) 44px; gap: 12px; align-items: center; padding: 9px 0; border-bottom: 1px solid var(--border-soft); }
.bar-row:last-child { border-bottom: 0; }
.bar-label { font-size: 13px; font-weight: 800; overflow-wrap: anywhere; }
.bar-track { height: 10px; border-radius: 999px; background: var(--surface-muted); overflow: hidden; }
.bar-fill { height: 100%; border-radius: 999px; background: linear-gradient(90deg, var(--accent), var(--accent-bright)); }
.bar-count { color: var(--muted); text-align: right; font: 700 12px var(--font-mono); }
.metric-item { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 9px 0; border-bottom: 1px solid var(--border-soft); }
.metric-item:last-child { border-bottom: 0; }
.metric-name { font-size: 13px; font-weight: 800; }
.metric-value { color: var(--muted); font-size: 12px; font-weight: 900; text-align: right; }
.metric-empty { color: var(--muted); font-size: 13px; font-weight: 700; padding: 10px 0; }
.table-wrap {
  overflow-x: auto;
  background: var(--surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  box-shadow: var(--shadow-sm);
}
table {
  width: 100%;
  min-width: 2720px;
  table-layout: fixed;
  border-collapse: collapse;
}
col.col-criterion { width: 150px; }
col.col-verdict { width: 170px; }
col.col-severity { width: 130px; }
col.col-file { width: 260px; }
col.col-line { width: 82px; }
col.col-quote { width: 360px; }
col.col-evidence { width: 380px; }
col.col-source { width: 320px; }
col.col-checked { width: 190px; }
col.col-support { width: 160px; }
col.col-latest { width: 160px; }
col.col-recommended { width: 190px; }
col.col-recommendation { width: 380px; }
col.col-confidence { width: 110px; }
col.col-module { width: 190px; }
th, td {
  padding: 14px 13px;
  border-bottom: 1px solid var(--border-soft);
  text-align: left;
  vertical-align: top;
  font-size: 13px;
  overflow-wrap: anywhere;
  word-break: normal;
}
th { background: var(--surface-muted); color: var(--muted); font-size: 11px; letter-spacing: 0; }
tr:last-child td { border-bottom: 0; }
.mono { font-family: var(--font-mono); font-size: 12px; overflow-wrap: anywhere; }
.pill {
  display: inline-flex; align-items: center; white-space: nowrap;
  border-radius: 999px; padding: 4px 9px; font-size: 12px; font-weight: 900;
}
.pill-critical { color: var(--danger); background: var(--danger-soft); }
.pill-major { color: var(--warn); background: var(--warn-soft); }
.pill-minor { color: var(--info); background: #e7eefb; }
.pill-info { color: var(--muted); background: #ece7dc; }
.pill-fail { color: var(--danger); background: var(--danger-soft); }
.pill-warning, .pill-unknown { color: var(--warn); background: var(--warn-soft); }
.pill-pass { color: var(--accent-deep); background: var(--accent-soft); }
.quote, .evidence, .source, .recommendation {
  color: var(--text);
  white-space: normal;
  overflow-wrap: anywhere;
}
.downloads { display: flex; gap: 8px; flex-wrap: wrap; }
.loading { opacity: .72; pointer-events: none; }
.run-details > summary { list-style: none; cursor: pointer; outline: none; }
.run-details > summary::-webkit-details-marker { display: none; }
.run-bar { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.run-details[open] .run-bar { margin-bottom: 18px; padding-bottom: 16px; border-bottom: 1px solid var(--border-soft); }
.run-bar-text { font-weight: 900; font-size: 16px; overflow-wrap: anywhere; }
.run-bar-actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
.run-bar-edit { color: var(--info); font-size: 13px; font-weight: 900; white-space: nowrap; }
.run-details:not([open]) .run-bar-edit::after { content: "Изменить"; }
.run-details[open] .run-bar-edit::after { content: "Свернуть"; }
.run-restart { cursor: pointer; }
.run-progress[hidden] { display: none; }
.run-progress {
  margin-top: 14px;
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-sm);
  padding: 12px;
  background: var(--surface-strong);
}
.run-progress-head {
  display: flex; justify-content: space-between; gap: 12px; align-items: baseline;
  color: var(--muted); font-size: 12px; font-weight: 900;
}
.run-progress-stage { color: var(--text); overflow-wrap: anywhere; }
.run-progress-track {
  height: 10px; margin-top: 10px; overflow: hidden;
  border-radius: 999px; background: var(--surface-muted);
}
.run-progress-fill {
  width: 0%; height: 100%; border-radius: inherit;
  background: linear-gradient(90deg, var(--accent), var(--accent-bright));
  transition: width .45s ease;
}
.run-progress-meta {
  display: flex; justify-content: space-between; gap: 12px; margin-top: 8px;
  color: var(--muted); font-size: 12px; font-weight: 800;
}
.run-progress.is-error { border-color: rgba(196, 54, 54, .35); background: var(--danger-soft); }
.filter-note {
  display: inline-flex; align-items: center; border-radius: 999px;
  padding: 5px 10px; font-size: 12px; font-weight: 800;
}
.filter-note { color: var(--info); background: #e7eefb; }
.filter-bar {
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
  margin: 16px 0 12px; padding: 12px 14px;
  background: var(--surface); border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm); box-shadow: var(--shadow-sm);
}
.filter-bar-label { color: var(--muted); font-size: 12px; font-weight: 900; letter-spacing: 0; }
.filter-chip {
  display: inline-flex; align-items: center; min-height: 30px;
  border-radius: 999px; padding: 5px 10px;
  color: var(--accent-deep); background: var(--accent-soft);
  font-size: 12px; font-weight: 900;
}
table.findings.hide-unknown tr[data-verdict="unknown"] { display: none; }
.diagnostics {
  background: var(--surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  box-shadow: var(--shadow-sm);
  padding: 0;
}
.diagnostics > summary {
  cursor: pointer;
  list-style: none;
  padding: 16px 18px;
  font-weight: 900;
  color: var(--muted);
}
.diagnostics > summary::-webkit-details-marker { display: none; }
.diagnostics-body { padding: 0 18px 18px; }
@media (max-width: 980px) {
  .form-grid, .grid-three { grid-template-columns: 1fr; }
  .summary-strip { align-items: flex-start; flex-direction: column; }
  .severity-inline { justify-content: flex-start; }
  .panel-head { display: block; }
  .topbar-inner, .shell { padding-left: 16px; padding-right: 16px; }
}
</style>
"""


def _render_topbar() -> str:
    """Возвращает верхнюю панель."""

    return """
<header class="topbar">
  <div class="topbar-inner">
    <div class="wordmark">
      <span class="glyph">А</span>
      <span>
        <div class="brand-title">Аудит контента</div>
        <div class="brand-sub">проверка учебных проектов</div>
      </span>
    </div>
    <nav class="top-actions">
      <a class="link-button" href="#summary">Сводка</a>
      <a class="link-button" href="#findings">Таблица</a>
    </nav>
  </div>
</header>
"""


def _render_run_panel(
    report: AuditReport | None,
    input_value: str,
) -> str:
    """Возвращает форму запуска, свёрнутую после построения отчёта."""

    open_attr = "" if report is not None else " open"
    restart_button = '<span class="link-button run-restart" role="button" tabindex="0">Перезапустить</span>' if report is not None else ""
    return f"""
<section class="run-panel">
  <details class="run-details"{open_attr}>
    <summary class="run-bar">
      <span class="run-bar-text">{_esc(_run_bar_text(report, input_value))}</span>
      <span class="run-bar-actions">
        {restart_button}
        <span class="run-bar-edit"></span>
      </span>
    </summary>
    <div class="panel-head">
      <div>
        <h1>Проверка локального проекта</h1>
      </div>
    </div>
    <form id="run-form" method="post" action="/run">
      <div class="form-grid">
        <div>
          <label for="input_path">Путь к проекту</label>
          <input id="input_path" name="input_path" type="text" value="{_esc(input_value)}" spellcheck="false">
        </div>
        <button class="button" type="submit">Запустить</button>
      </div>
      <div class="run-progress" id="run-progress" role="status" aria-live="polite" aria-busy="false" hidden>
        <div class="run-progress-head">
          <span>Готовность отчёта</span>
          <span class="run-progress-stage" id="run-progress-stage">Подготовка запуска</span>
        </div>
        <div class="run-progress-track" aria-hidden="true">
          <div class="run-progress-fill" id="run-progress-fill"></div>
        </div>
        <div class="run-progress-meta">
          <span id="run-progress-percent">0%</span>
          <span id="run-progress-elapsed">0 с</span>
        </div>
      </div>
    </form>
  </details>
</section>
"""


def _run_bar_text(report: AuditReport | None, input_value: str) -> str:
    """Короткая строка-шапка для свёрнутого блока запуска."""

    if report is None:
        return "Проверка локального проекта"
    project = Path(report.summary.input_path).name or Path(input_value).name or input_value
    cases = len(report.findings)
    return f"{project} · {cases} случаев"


def _render_error(error: str | None) -> str:
    """Показывает ошибку запуска, если она есть."""

    if not error:
        return ""
    return f'<div class="alert">{_esc(error)}</div>'


def _render_empty_state() -> str:
    """Показывает состояние до первого запуска."""

    return """
<section class="empty">
  <strong>Отчёта пока нет.</strong>
  <div>Запустите проверку по пути к проекту, чтобы увидеть панель отчёта.</div>
</section>
"""


def _render_dashboard(report: AuditReport, report_dir: Path) -> str:
    """Собирает панель отчёта."""

    return "\n".join(
        [
            _render_summary(report),
            _render_criterion_filters(report),
            _render_filter_bar(),
            _render_findings_table(report.findings),
            _render_observability(report),
            _render_downloads(report_dir),
        ]
    )


def _render_filter_bar() -> str:
    """Фильтры таблицы: работают на клиенте, без повторного прогона."""

    return """
<section class="filter-bar" id="filter-bar">
  <span class="filter-bar-label">Фильтры таблицы</span>
  <span class="filter-chip" id="active-criterion-label">Критерий: все</span>
  <label class="check"><input type="checkbox" id="flt-hide-unknown"> Скрыть «нужна проверка»</label>
  <span class="filter-note" id="filter-result-count">видно: 0</span>
  <span class="filter-note">мгновенно, без перезапуска</span>
</section>
"""


def _case_findings(report: AuditReport) -> list[Finding]:
    """Возвращает строки, требующие внимания аудитора."""

    return list(report.findings)


def _render_summary(report: AuditReport) -> str:
    """Показывает главные счётчики."""

    summary = report.summary
    cases = _case_findings(report)
    by_severity = Counter(finding.severity.value for finding in cases)
    return f"""
<section id="summary" class="summary-strip">
  <div class="summary-main">
    <span class="summary-number">{len(cases)}</span>
    <span class="summary-text">случаев · {summary.files_total} файлов</span>
  </div>
  <div class="severity-inline">
    {_severity_chip(Severity.CRITICAL, by_severity.get(Severity.CRITICAL.value, 0))}
    {_severity_chip(Severity.MAJOR, by_severity.get(Severity.MAJOR.value, 0))}
    {_severity_chip(Severity.MINOR, by_severity.get(Severity.MINOR.value, 0))}
    {_severity_chip(Severity.INFO, by_severity.get(Severity.INFO.value, 0))}
  </div>
</section>
"""


def _render_observability(report: AuditReport) -> str:
    """Показывает техническую сводку выполнения."""

    usage = report.summary.model_usage
    usage_rows = {
        "Свежие вызовы": usage.calls_total,
        "Ответы из кэша": usage.cache_hits,
        "Токены": usage.total_tokens,
        "Стоимость, $": round(usage.cost_usd, 6),
    }
    step_rows = {step.name: step.duration_ms for step in report.summary.steps}
    usage_markup = (
        _bars(usage_rows, {})
        if any(value for value in usage_rows.values())
        else '<div class="metric-empty">Свежих вызовов моделей нет.</div>'
    )
    return f"""
<details class="section diagnostics">
  <summary>Диагностика прогона — шаги, стоимость, покрытие ТЗ, версии запросов</summary>
  <div class="diagnostics-body">
    <div class="muted">версии запросов: {_esc(', '.join(report.summary.prompt_versions.values()) or 'нет')}</div>
    <div class="grid-three">
    <div class="panel">
      <label>Стоимость и кэш</label>
      {usage_markup}
    </div>
    <div class="panel">
      <label>Шаги, мс</label>
      {_bars(step_rows, {})}
    </div>
    <div class="panel">
      <label>Покрытие ТЗ</label>
      {_render_requirement_status(report)}
    </div>
  </div>
  </div>
</details>
"""


def _render_criterion_filters(report: AuditReport) -> str:
    """Рисует компактные чипы критериев, которые фильтруют таблицу."""

    cases = _case_findings(report)
    by_criterion = Counter(finding.criterion.value for finding in cases)
    buttons = [
        f"""
<button type="button" class="criterion-filter is-active" data-criterion-filter="all" data-criterion-label="все">
  <span>Все</span><span class="criterion-count">{len(cases)}</span>
</button>
"""
    ]
    for criterion in Criterion:
        count = by_criterion.get(criterion.value, 0)
        empty_class = " is-empty" if count == 0 else ""
        buttons.append(
            f"""
<button type="button" class="criterion-filter{empty_class}" data-criterion-filter="{criterion.value}" data-criterion-label="{_esc(CRITERION_LABELS[criterion])}" title="{_esc(CRITERION_LABELS[criterion])}">
  <span>{_esc(_criterion_short_label(criterion))}</span><span class="criterion-count">{count}</span>
</button>
"""
        )
    return f"""
<section class="criteria-strip">
  <div class="criteria-title">Критерий — фильтр таблицы</div>
  <div class="criteria-hint">Нажмите критерий, чтобы оставить в таблице только связанные с ним сообщения.</div>
  <div class="criteria-chips">{"".join(buttons)}</div>
</section>
"""


def _render_requirement_status(report: AuditReport) -> str:
    """Показывает, какие управленческие поля из ТЗ есть в текущем отчёте."""

    summary = report.summary
    usage = summary.model_usage
    cases = _case_findings(report)
    affected_units = len({finding.unit_id for finding in cases})
    affected_branches = len({finding.branch or "без ветки" for finding in cases})
    rows = [
        ("Ветка и единица", f"{affected_branches} веток · {affected_units} ед."),
        ("Критичность", "Critical / Major / Minor / Info"),
        ("Экспорт", "CSV и JSON"),
        ("Ссылки", "сеть использовалась" if summary.network_used else "сеть выключена"),
        ("Стоимость", "учтена" if usage.calls_total or usage.cache_hits else "нет модельных вызовов"),
    ]
    return _metric_rows(rows)


def _severity_chip(severity: Severity, count: int) -> str:
    """Рисует компактный счётчик критичности в общей сводке."""

    return (
        f'<span class="severity-chip severity-chip-{severity.value}">'
        f'{count} {_esc(SEVERITY_LABELS[severity].lower())}</span>'
    )


def _criterion_short_label(criterion: Criterion) -> str:
    """Короткие подписи нужны, чтобы фильтры помещались в одну строку."""

    labels = {
        Criterion.ACTUALITY: "Актуальность",
        Criterion.MARKET_FIT: "Рынок",
        Criterion.RIGHTS: "Права",
        Criterion.CORRECTNESS: "Точность",
        Criterion.READABILITY: "Грамотность",
        Criterion.CHECKLIST_ALIGNMENT: "Чек-лист",
        Criterion.WORKLOAD: "Трудоёмкость",
        Criterion.EXAM: "Экзамен",
        Criterion.LANGUAGE: "Язык",
        Criterion.IMAGE_QUALITY: "Изображения",
    }
    return labels[criterion]


def _render_findings_table(findings: list[Finding]) -> str:
    """Показывает таблицу найденных случаев."""

    rows = "\n".join(_render_finding_row(finding) for finding in findings)
    if not rows:
        rows = '<tr><td colspan="15">По выбранным условиям случаев нет.</td></tr>'
    rows += '\n<tr id="no-match" class="no-match" style="display:none"><td colspan="15">Под выбранные фильтры ничего не попадает.</td></tr>'
    return f"""
<section id="findings" class="section">
  <div class="section-head">
    <h2>Таблица результата</h2>
    <span class="muted">одна строка — один найденный случай</span>
  </div>
  <div class="table-wrap">
    <table id="findings-table" class="findings">
      <colgroup>
        <col class="col-criterion">
        <col class="col-verdict">
        <col class="col-severity">
        <col class="col-file">
        <col class="col-line">
        <col class="col-quote">
        <col class="col-evidence">
        <col class="col-source">
        <col class="col-checked">
        <col class="col-support">
        <col class="col-latest">
        <col class="col-recommended">
        <col class="col-recommendation">
        <col class="col-confidence">
        <col class="col-module">
      </colgroup>
      <thead>
        <tr>
          <th>Критерий</th>
          <th>Вердикт</th>
          <th>Критичность</th>
          <th>Файл</th>
          <th>Строка</th>
          <th>Цитата</th>
          <th>Обоснование</th>
          <th>Источник</th>
          <th>Дата проверки</th>
          <th>Статус поддержки</th>
          <th>Последняя версия</th>
          <th>Рекомендуемая версия</th>
          <th>Рекомендация</th>
          <th>Уверенность</th>
          <th>Модуль</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>
"""


def _render_finding_row(finding: Finding) -> str:
    """Показывает строку найденного случая."""

    evidence = " | ".join(f"{item.title}: {item.detail}" for item in finding.evidence)
    file_path = finding.location.file_path if finding.location else ""
    line = str(finding.location.line_start or "") if finding.location else ""
    checked_at = finding.checked_at.isoformat() if finding.checked_at else ""
    return f"""
<tr class="frow" data-criterion="{finding.criterion.value}" data-verdict="{finding.verdict.value}" data-severity="{finding.severity.value}">
  <td>{_esc(CRITERION_LABELS[finding.criterion])}</td>
  <td>{_pill(VERDICT_LABELS[finding.verdict], f"pill-{finding.verdict.value}")}</td>
  <td>{_pill(SEVERITY_LABELS[finding.severity], f"pill-{finding.severity.value}")}</td>
  <td class="mono">{_esc(file_path)}</td>
  <td class="mono">{_esc(line)}</td>
  <td class="quote">{_esc(finding.quote or "")}</td>
  <td class="evidence">{_esc(evidence)}</td>
  <td class="source">{_esc(finding.source or "")}</td>
  <td class="mono">{_esc(checked_at)}</td>
  <td>{_esc(finding.support_status or "")}</td>
  <td class="mono">{_esc(finding.latest_version or "")}</td>
  <td class="mono">{_esc(finding.recommended_version or "")}</td>
  <td class="recommendation">{_esc(finding.recommendation)}</td>
  <td class="mono">{finding.confidence:.2f}</td>
  <td class="mono">{_esc(finding.checker_name)}</td>
</tr>
"""


def _render_downloads(report_dir: Path) -> str:
    """Показывает ссылки на файлы отчёта."""

    links = [
        ("CSV", "report.csv"),
        ("JSON", "report.json"),
        ("Сводка", "run_summary.json"),
    ]
    if (report_dir / "evaluation.json").exists():
        links.append(("Метрики", "evaluation.json"))
    items = "\n".join(f'<a class="link-button" href="/download?file={quote(name)}">{label}</a>' for label, name in links)
    return f"""
<section class="section">
  <div class="section-head">
    <h2>Файлы отчёта</h2>
  </div>
  <div class="downloads">{items}</div>
</section>
"""


def _render_script() -> str:
    """Добавляет минимальное поведение формы."""

    return """
<script>
(() => {
const form = document.getElementById("run-form");
const progressPanel = document.getElementById("run-progress");
const progressFill = document.getElementById("run-progress-fill");
const progressPercent = document.getElementById("run-progress-percent");
const progressStage = document.getElementById("run-progress-stage");
const progressElapsed = document.getElementById("run-progress-elapsed");
const progressStages = [
  [8, "Подготовка запуска"],
  [22, "Загрузка файлов"],
  [42, "Извлечение сущностей"],
  [62, "Проверка ссылок и файлов"],
  [82, "Проверка фактов и версий"],
  [96, "Сборка отчёта"],
  [100, "Отчёт готов"]
];
let progressTimer = null;
let progressStartedAt = 0;
let progressValue = 0;

function progressLabel(value) {
  for (const item of progressStages) {
    if (value <= item[0]) return item[1];
  }
  return "Сборка отчёта";
}

function setProgress(value, label) {
  progressValue = Math.max(0, Math.min(100, Math.round(value)));
  if (progressFill) progressFill.style.width = `${progressValue}%`;
  if (progressPercent) progressPercent.textContent = `${progressValue}%`;
  if (progressStage) progressStage.textContent = label || progressLabel(progressValue);
}

function startProgress() {
  if (!progressPanel) return;
  progressPanel.hidden = false;
  progressPanel.classList.remove("is-error");
  progressPanel.setAttribute("aria-busy", "true");
  progressStartedAt = Date.now();
  setProgress(3, "Подготовка запуска");
  if (progressTimer) window.clearInterval(progressTimer);
  progressTimer = window.setInterval(() => {
    const elapsedSeconds = Math.max(0, Math.floor((Date.now() - progressStartedAt) / 1000));
    const nextValue = Math.min(94, 3 + Math.log2(elapsedSeconds + 1) * 18);
    setProgress(nextValue);
    if (progressElapsed) progressElapsed.textContent = `${elapsedSeconds} с`;
  }, 700);
}

function stopProgress(value, label) {
  if (progressTimer) window.clearInterval(progressTimer);
  progressTimer = null;
  if (progressPanel) progressPanel.setAttribute("aria-busy", "false");
  setProgress(value, label);
}

if (form) {
  form.addEventListener("submit", async (event) => {
    if (form.dataset.submitting === "1") {
      event.preventDefault();
      return;
    }
    if (!window.fetch) return;
    event.preventDefault();
    form.dataset.submitting = "1";
    form.classList.add("loading");
    const button = form.querySelector("button[type='submit']");
    if (button) {
      button.disabled = true;
      button.textContent = "Проверяю...";
    }
    startProgress();

    try {
      const payload = new URLSearchParams(new FormData(form));
      const response = await fetch(form.action, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
        body: payload
      });
      const html = await response.text();
      stopProgress(100, response.ok ? "Отчёт готов" : "Проверка завершилась с ошибкой");
      window.setTimeout(() => {
        document.open();
        document.write(html);
        document.close();
      }, 250);
    } catch (error) {
      stopProgress(progressValue, "Не удалось получить ответ");
      if (progressPanel) progressPanel.classList.add("is-error");
      form.classList.remove("loading");
      delete form.dataset.submitting;
      if (button) {
        button.disabled = false;
        button.textContent = "Запустить";
      }
    }
  });
}

const restart = document.querySelector(".run-restart");
if (restart && form) {
  const submitCurrentForm = (event) => {
    event.preventDefault();
    event.stopPropagation();
    if (form.requestSubmit) form.requestSubmit();
    else form.submit();
  };
  restart.addEventListener("click", submitCurrentForm);
  restart.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") submitCurrentForm(event);
  });
}

const diagnostics = document.querySelector(".diagnostics");
if (diagnostics) diagnostics.removeAttribute("open");

const table = document.getElementById("findings-table");
const hideUnknown = document.getElementById("flt-hide-unknown");
const criterionButtons = document.querySelectorAll("[data-criterion-filter]");
const activeCriterionLabel = document.getElementById("active-criterion-label");
const resultCount = document.getElementById("filter-result-count");
let activeCriterion = "all";

function updateEmptyState() {
  if (!table) return;
  const rows = table.querySelectorAll("tbody tr.frow");
  let visible = 0;
  rows.forEach((row) => {
    if (getComputedStyle(row).display !== "none") visible += 1;
  });
  const note = document.getElementById("no-match");
  if (note) note.style.display = rows.length > 0 && visible === 0 ? "" : "none";
  if (resultCount) resultCount.textContent = `видно: ${visible} из ${rows.length}`;
}

function applyFilters() {
  if (!table) return;
  table.classList.toggle("hide-unknown", !!(hideUnknown && hideUnknown.checked));
  const rows = table.querySelectorAll("tbody tr.frow");
  rows.forEach((row) => {
    const byCriterion = activeCriterion === "all" || row.dataset.criterion === activeCriterion;
    row.style.display = byCriterion ? "" : "none";
  });
  updateEmptyState();
}

criterionButtons.forEach((button) => {
  button.addEventListener("click", () => {
    activeCriterion = button.dataset.criterionFilter || "all";
    criterionButtons.forEach((item) => item.classList.toggle("is-active", item === button));
    if (activeCriterionLabel) {
      const label = button.dataset.criterionLabel || "все";
      activeCriterionLabel.textContent = `Критерий: ${label}`;
    }
    applyFilters();
    const findings = document.getElementById("findings");
    if (findings) findings.scrollIntoView({ behavior: "smooth", block: "start" });
  });
});

if (hideUnknown) hideUnknown.addEventListener("change", applyFilters);
applyFilters();
})();
</script>
"""


def _metric_rows(rows: list[tuple[str, object]]) -> str:
    """Рисует компактные строки без шкалы, когда важнее статус, а не объём."""

    if not rows:
        return '<div class="metric-empty">Нет данных.</div>'
    return "\n".join(
        f"""
<div class="metric-item">
  <div class="metric-name">{_esc(name)}</div>
  <div class="metric-value">{_esc(str(value))}</div>
</div>
"""
        for name, value in rows
    )


def _bars(values: dict[str, int | float], labels: dict[str, str], sort_by_count: bool = True) -> str:
    """Рисует горизонтальные полосы распределения."""

    if not values:
        return '<div class="muted">Нет данных.</div>'
    max_value = max(values.values()) or 1
    rows = []
    items = sorted(values.items(), key=lambda item: item[1], reverse=True) if sort_by_count else values.items()
    for key, count in items:
        width = 0 if count <= 0 else max(4, round(count / max_value * 100))
        rows.append(
            f"""
<div class="bar-row">
  <div class="bar-label">{_esc(labels.get(key, key))}</div>
  <div class="bar-track"><div class="bar-fill" style="width:{width}%"></div></div>
  <div class="bar-count">{count}</div>
</div>
"""
        )
    return "\n".join(rows)


def _pill(label: str, css_class: str) -> str:
    """Рисует статусную метку."""

    return f'<span class="pill {css_class}">{_esc(label)}</span>'


def _esc(value: str) -> str:
    """Экранирует текст для HTML."""

    return html.escape(unquote(value), quote=True)


if __name__ == "__main__":
    raise SystemExit(main())
