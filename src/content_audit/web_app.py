"""Локальный веб-интерфейс для запуска аудита и просмотра отчёта."""

from __future__ import annotations

import argparse
import html
import json
import mimetypes
import os
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
    Verdict,
)
from content_audit.env import get_env_value, load_env_file
from content_audit.exporters import write_report
from content_audit.orchestrator import AuditRunner


DEFAULT_REPORT_DIR = Path("reports") / "ui_latest"
DEFAULT_MODEL = "openai/gpt-4o-mini"
DEFAULT_FACT_MODEL = "perplexity/sonar"


class WebState:
    """Состояние локального веб-сервера."""

    def __init__(self, default_input: Path, report_dir: Path, env_values: dict[str, str]) -> None:
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
            self._send_html(render_page(load_latest_report(self.state.report_dir), self.state))
            return
        if route.path == "/download":
            params = parse_qs(route.query)
            self._send_report_file(params.get("file", [""])[0])
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Страница не найдена")

    def do_POST(self) -> None:  # noqa: N802 - интерфейс стандартной библиотеки.
        """Запускаем аудит по данным формы."""

        route = urlparse(self.path)
        if route.path != "/run":
            self.send_error(HTTPStatus.NOT_FOUND, "Страница не найдена")
            return

        try:
            form = self._read_form()
            report = run_from_form(form, self.state)
            self.state.last_error = None
            self._send_html(render_page(report, self.state, form_values=form))
        except Exception as exc:  # noqa: BLE001 - ошибка должна быть показана пользователю.
            self.state.last_error = str(exc)
            self._send_html(render_page(load_latest_report(self.state.report_dir), self.state), status=HTTPStatus.BAD_REQUEST)

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

        safe_names = {"report.csv", "report.json", "run_summary.json"}
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
    parser.add_argument("--default-input", type=Path, default=Path("proj_example"), help="Путь по умолчанию в форме.")
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR, help="Папка для последних отчётов.")
    args = parser.parse_args(argv)

    env_values = load_env_file(Path(".env"))
    state = WebState(
        default_input=args.default_input.expanduser().resolve(),
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

    input_path = Path(form.get("input_path") or state.default_input).expanduser().resolve()
    model_name = form.get("model_name") or get_env_value(("OPENROUTER_MODEL", "OPEN_ROUTER_MODEL"), state.env_values) or DEFAULT_MODEL
    fact_model_name = get_env_value(("OPENROUTER_FACT_MODEL", "OPEN_ROUTER_FACT_MODEL"), state.env_values) or DEFAULT_FACT_MODEL
    tech_model_name = get_env_value(("OPENROUTER_TECH_MODEL", "OPEN_ROUTER_TECH_MODEL"), state.env_values) or model_name
    api_key = get_env_value(("OPENROUTER_API_KEY", "OPEN_ROUTER_API_KEY"), state.env_values)
    settings = AuditSettings(
        input_path=input_path,
        output_path=state.report_dir,
        allow_network=form.get("check_links") == "on",
        use_model=form.get("use_model") == "on",
        include_unknown=form.get("hide_unknown") != "on",
        include_pass=form.get("include_pass") == "on",
        openrouter_api_key=api_key,
        openrouter_model=model_name,
        openrouter_fact_model=fact_model_name,
        openrouter_tech_model=tech_model_name,
    )
    report = AuditRunner(settings).run()
    write_report(report, state.report_dir, include_pass=settings.include_pass)
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
    input_value = form.get("input_path") or str(state.default_input)
    model_name = form.get("model_name") or get_env_value(("OPENROUTER_MODEL", "OPEN_ROUTER_MODEL"), state.env_values) or DEFAULT_MODEL
    body = "\n".join(
        [
            _render_topbar(),
            '<main class="shell">',
            _render_run_panel(input_value, model_name, state),
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
.form-grid { display: grid; grid-template-columns: minmax(0, 1fr) 210px 138px; gap: 12px; align-items: end; }
label { display: block; font-size: 12px; color: var(--muted); font-weight: 800; text-transform: uppercase; letter-spacing: .04em; margin-bottom: 7px; }
input[type="text"] {
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
input[type="text"]:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(14,143,111,.14); }
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
.summary { margin-top: 20px; display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.stat {
  background: var(--surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-sm);
  padding: 16px 18px;
}
.stat-value { font-size: 28px; font-weight: 900; color: var(--accent); line-height: 1; }
.stat-label { margin-top: 8px; color: var(--muted); font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: .04em; }
.section { margin-top: 26px; }
.section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 14px; border-bottom: 1px solid var(--border-soft); padding-bottom: 12px; margin-bottom: 14px; }
.section h2 { margin: 0; font-size: 20px; }
.grid-two { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.panel {
  background: var(--surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  box-shadow: var(--shadow-sm);
  padding: 18px;
}
.bar-row { display: grid; grid-template-columns: 160px 1fr 44px; gap: 12px; align-items: center; padding: 9px 0; border-bottom: 1px solid var(--border-soft); }
.bar-row:last-child { border-bottom: 0; }
.bar-label { font-size: 13px; font-weight: 800; overflow-wrap: anywhere; }
.bar-track { height: 10px; border-radius: 999px; background: var(--surface-muted); overflow: hidden; }
.bar-fill { height: 100%; border-radius: 999px; background: linear-gradient(90deg, var(--accent), var(--accent-bright)); }
.bar-count { color: var(--muted); text-align: right; font: 700 12px var(--font-mono); }
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
th { background: var(--surface-muted); color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
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
@media (max-width: 980px) {
  .form-grid, .summary, .grid-two { grid-template-columns: 1fr; }
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


def _render_run_panel(input_value: str, model_name: str, state: WebState) -> str:
    """Возвращает форму запуска аудита."""

    has_key = bool(get_env_value(("OPENROUTER_API_KEY", "OPEN_ROUTER_API_KEY"), state.env_values))
    key_note = "ключ OpenRouter найден" if has_key else "ключ OpenRouter не найден"
    return f"""
<section class="run-panel">
  <div class="panel-head">
    <div>
      <h1>Проверка локального проекта</h1>
      <p class="muted">Укажите путь к папке учебного проекта. После запуска появится сводка, разрезы по критериям и таблица найденных случаев.</p>
    </div>
    <span class="link-button">{_esc(key_note)}</span>
  </div>
  <form id="run-form" method="post" action="/run">
    <div class="form-grid">
      <div>
        <label for="input_path">Путь к проекту</label>
        <input id="input_path" name="input_path" type="text" value="{_esc(input_value)}" spellcheck="false">
      </div>
      <div>
        <label for="model_name">Модель</label>
        <input id="model_name" name="model_name" type="text" value="{_esc(model_name)}" spellcheck="false">
      </div>
      <button class="button" type="submit">Запустить</button>
    </div>
    <div class="options">
      <label class="check"><input type="checkbox" name="use_model" checked> Модельные проверки</label>
      <label class="check"><input type="checkbox" name="check_links"> Проверять внешние ссылки</label>
      <label class="check"><input type="checkbox" name="hide_unknown"> Скрыть “нужна проверка”</label>
      <label class="check"><input type="checkbox" name="include_pass"> Показывать успешные проверки</label>
    </div>
  </form>
</section>
"""


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
            _render_breakdowns(report),
            _render_findings_table(report.findings),
            _render_downloads(report_dir),
        ]
    )


def _render_summary(report: AuditReport) -> str:
    """Показывает главные счётчики."""

    summary = report.summary
    critical = summary.by_severity.get(Severity.CRITICAL.value, 0)
    major = summary.by_severity.get(Severity.MAJOR.value, 0)
    return f"""
<section id="summary" class="summary">
  {_stat("Единицы", summary.units_total)}
  {_stat("Файлы", summary.files_total)}
  {_stat("Случаи", summary.findings_total)}
  {_stat("Крит. / высокие", f"{critical} / {major}")}
</section>
"""


def _render_breakdowns(report: AuditReport) -> str:
    """Показывает разрезы по критериям и критичности."""

    return f"""
<section class="section">
  <div class="section-head">
    <h2>Разрезы отчёта</h2>
    <span class="muted">модель: {'включена' if report.summary.model_used else 'выключена'} · сеть: {'использовалась' if report.summary.network_used else 'не использовалась'}</span>
  </div>
  <div class="grid-two">
    <div class="panel">
      <label>По критериям</label>
      {_bars(report.summary.by_criterion, {item.value: CRITERION_LABELS[item] for item in Criterion})}
    </div>
    <div class="panel">
      <label>По критичности</label>
      {_bars(report.summary.by_severity, {item.value: SEVERITY_LABELS[item] for item in Severity})}
    </div>
  </div>
</section>
"""


def _render_findings_table(findings: list[Finding]) -> str:
    """Показывает таблицу найденных случаев."""

    rows = "\n".join(_render_finding_row(finding) for finding in findings)
    if not rows:
        rows = '<tr><td colspan="15">По выбранным условиям случаев нет.</td></tr>'
    return f"""
<section id="findings" class="section">
  <div class="section-head">
    <h2>Таблица результата</h2>
    <span class="muted">одна строка — один найденный случай</span>
  </div>
  <div class="table-wrap">
    <table>
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
<tr>
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

    del report_dir
    links = [
        ("CSV", "report.csv"),
        ("JSON", "report.json"),
        ("Сводка", "run_summary.json"),
    ]
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
const form = document.getElementById("run-form");
if (form) {
  form.addEventListener("submit", () => {
    form.classList.add("loading");
    const button = form.querySelector("button[type='submit']");
    if (button) button.textContent = "Проверяю...";
  });
}
</script>
"""


def _stat(label: str, value: object) -> str:
    """Рисует счётчик."""

    return f'<div class="stat"><div class="stat-value">{_esc(str(value))}</div><div class="stat-label">{_esc(label)}</div></div>'


def _bars(values: dict[str, int], labels: dict[str, str]) -> str:
    """Рисует горизонтальные полосы распределения."""

    if not values:
        return '<div class="muted">Нет данных.</div>'
    max_value = max(values.values()) or 1
    rows = []
    for key, count in sorted(values.items(), key=lambda item: item[1], reverse=True):
        width = max(4, round(count / max_value * 100))
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
