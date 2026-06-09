from pathlib import Path

from content_audit.domain import AuditReport, Finding, RunSummary, Severity, Verdict, Criterion
from content_audit.web_app import WebState, load_latest_report, render_page, run_from_form


def test_render_page_contains_project_input(workspace_tmp_path: Path) -> None:
    state = WebState(default_input=workspace_tmp_path, report_dir=workspace_tmp_path / "reports", env_values={})

    html = render_page(None, state)

    assert "Проверка локального проекта" in html
    assert "Путь к проекту" in html
    assert str(workspace_tmp_path) in html
    assert html.count("<input") == 1
    assert 'name="input_path"' in html
    assert "<select" not in html
    assert "ключ OpenRouter" not in html
    assert "Укажите папку проекта" not in html


def test_render_page_has_no_demo_project_by_default(workspace_tmp_path: Path) -> None:
    state = WebState(default_input=None, report_dir=workspace_tmp_path / "reports", env_values={})

    html = render_page(None, state)

    assert "proj_example" not in html
    assert 'id="input_path" name="input_path" type="text" value=""' in html


def test_render_page_contains_extended_report_columns(workspace_tmp_path: Path) -> None:
    state = WebState(default_input=workspace_tmp_path, report_dir=workspace_tmp_path / "reports", env_values={})
    report = AuditReport(
        summary=RunSummary(
            started_at="2026-06-08T00:00:00+00:00",
            input_path=str(workspace_tmp_path),
            units_total=0,
            files_total=0,
            findings_total=1,
        ),
        units=[],
        entities=[],
        findings=[
            Finding(
                finding_id="fnd_test",
                unit_id="unit",
                branch=None,
                criterion=Criterion.ACTUALITY,
                severity=Severity.INFO,
                verdict=Verdict.UNKNOWN,
                confidence=0.5,
                recommendation="Проверить вручную.",
                needs_human_review=True,
                checker_name="tech_freshness_checker",
            )
        ],
    )

    html = render_page(report, state)

    assert "Источник" in html
    assert "Статус поддержки" in html
    assert "Info" in html
    assert "Critical / Major" in html
    assert "Критерий — фильтр таблицы" in html
    assert "Диагностика прогона" in html
    assert "Покрытие ТЗ" in html
    assert "Свежих вызовов моделей нет" in html
    assert "случаев" in html
    assert 'data-criterion-filter="all"' in html
    assert 'data-criterion-filter="actuality"' in html
    assert 'data-criterion="actuality"' in html
    assert 'id="active-criterion-label"' in html
    assert 'id="filter-result-count"' in html
    summary_block = html.split('class="summary-strip"', 1)[1]
    assert summary_block.index("critical") < summary_block.index("major")
    assert summary_block.index("major") < summary_block.index("minor")
    assert summary_block.index("minor") < summary_block.index("info")
    assert 'id="flt-hide-unknown"' in html
    assert 'id="flt-show-pass"' in html
    assert 'name="hide_unknown"' not in html
    assert 'name="include_pass"' not in html
    assert 'data-verdict="unknown"' in html
    assert 'class="findings hide-pass"' in html
    assert "Перезапустить" in html


def test_run_from_form_stores_pass_findings_but_csv_hides_them(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("## Part 1. Работа с cat\n", encoding="utf-8")
    (project / "README_RUS.md").write_text("# Проект\n", encoding="utf-8")
    (project / "check-list.yml").write_text(
        "sections:\n"
        "  - questions:\n"
        "      - name: Part_1.CAT\n",
        encoding="utf-8",
    )
    report_dir = workspace_tmp_path / "reports"
    state = WebState(default_input=project, report_dir=report_dir, env_values={})

    report = run_from_form({"input_path": str(project)}, state)
    persisted = load_latest_report(report_dir)
    csv_text = (report_dir / "report.csv").read_text(encoding="utf-8-sig")

    assert any(finding.verdict == Verdict.PASS for finding in report.findings)
    assert persisted is not None
    assert any(finding.verdict == Verdict.PASS for finding in persisted.findings)
    assert "Проверено" not in csv_text


def test_run_from_form_always_enables_models_and_network(workspace_tmp_path: Path, monkeypatch) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    captured = {}

    class _FakeRunner:
        def __init__(self, settings):
            captured["settings"] = settings

        def run(self):
            return AuditReport(
                summary=RunSummary(started_at="2026-06-08T00:00:00+00:00", input_path=str(project)),
                units=[],
                entities=[],
                findings=[],
            )

    monkeypatch.setattr("content_audit.web_app.AuditRunner", _FakeRunner)
    state = WebState(
        default_input=None,
        report_dir=workspace_tmp_path / "reports",
        env_values={
            "OPENROUTER_API_KEY": "key",
            "OPENROUTER_MODEL": "openai/general",
            "OPENROUTER_TECH_MODEL": "qwen/tech",
            "OPENROUTER_FACT_MODEL": "perplexity/facts",
        },
    )

    run_from_form(
        {
            "input_path": str(project),
            "model_name": "perplexity/sonar",
        },
        state,
    )

    assert captured["settings"].use_model is True
    assert captured["settings"].allow_network is True
    assert captured["settings"].openrouter_model == "openai/general"
    assert captured["settings"].openrouter_tech_model == "qwen/tech"
    assert captured["settings"].openrouter_fact_model == "perplexity/facts"
