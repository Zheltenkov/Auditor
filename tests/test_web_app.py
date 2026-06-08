from pathlib import Path

from content_audit.domain import AuditReport, Finding, RunSummary, Severity, Verdict, Criterion
from content_audit.web_app import WebState, render_page


def test_render_page_contains_project_input(workspace_tmp_path: Path) -> None:
    state = WebState(default_input=workspace_tmp_path, report_dir=workspace_tmp_path / "reports", env_values={})

    html = render_page(None, state)

    assert "Проверка локального проекта" in html
    assert "Путь к проекту" in html
    assert str(workspace_tmp_path) in html


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
