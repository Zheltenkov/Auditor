from pathlib import Path

from content_audit.domain import AuditReport, AuditSettings, Criterion, Finding, RunSummary, Severity, Verdict
from content_audit.exporters import write_report
from content_audit.orchestrator import AuditRunner


def test_runner_writes_reports(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    output = workspace_tmp_path / "reports"
    project.mkdir()
    (project / "README_RUS.md").write_text("[link](https://example.com)\nUse Java 21.\n", encoding="utf-8")
    (project / "check-list.yml").write_text("sections: []\n", encoding="utf-8")

    settings = AuditSettings(input_path=project, output_path=output, allow_network=False)
    report = AuditRunner(settings).run()
    write_report(report, output)

    assert report.summary.units_total == 1
    assert report.summary.files_total == 2
    assert report.summary.affected_units_total >= 1
    assert report.summary.by_unit
    assert report.summary.by_branch
    assert [step.name for step in report.summary.steps] == [
        "Загрузка файлов",
        "Подготовка проверок",
        "Извлечение и проверки",
        "Сборка отчёта",
    ]
    assert (output / "report.json").exists()
    assert (output / "report.csv").exists()
    assert (output / "run_summary.json").exists()
    csv_text = (output / "report.csv").read_text(encoding="utf-8-sig")
    assert "Источник" in csv_text
    assert "Дата проверки" in csv_text
    assert "Статус поддержки" in csv_text
    assert "Последняя версия" in csv_text
    assert "Рекомендуемая версия" in csv_text


def test_exporter_does_not_write_pass_findings(workspace_tmp_path: Path) -> None:
    output = workspace_tmp_path / "reports"
    report = AuditReport(
        summary=RunSummary(started_at="2026-06-08T00:00:00+00:00", input_path=str(workspace_tmp_path)),
        units=[],
        entities=[],
        findings=[
            Finding(
                finding_id="pass",
                unit_id="unit",
                branch=None,
                criterion=Criterion.CHECKLIST_ALIGNMENT,
                severity=Severity.INFO,
                verdict=Verdict.PASS,
                confidence=0.9,
                recommendation="Ничего не делать.",
                checker_name="checklist_checker",
            )
        ],
    )

    write_report(report, output)

    assert "Проверено" not in (output / "report.csv").read_text(encoding="utf-8-sig")
    assert '"findings": []' in (output / "report.json").read_text(encoding="utf-8")
