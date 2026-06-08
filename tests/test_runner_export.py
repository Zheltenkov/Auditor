from pathlib import Path

from content_audit.domain import AuditSettings
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
    assert (output / "report.json").exists()
    assert (output / "report.csv").exists()
    assert (output / "run_summary.json").exists()
    csv_text = (output / "report.csv").read_text(encoding="utf-8-sig")
    assert "Источник" in csv_text
    assert "Дата проверки" in csv_text
    assert "Статус поддержки" in csv_text
    assert "Последняя версия" in csv_text
    assert "Рекомендуемая версия" in csv_text
