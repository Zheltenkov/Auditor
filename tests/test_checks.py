from pathlib import Path

from content_audit.checks import CheckContext, ChecklistChecker, LanguageCoverageChecker, TechnologyFreshnessChecker
from content_audit.domain import AuditSettings, Criterion, Verdict
from content_audit.extraction import extract_entities
from content_audit.ingestion import discover_content_units, load_unit_files


def _settings(tmp_path: Path, project: Path) -> AuditSettings:
    return AuditSettings(input_path=project, output_path=tmp_path / "out", allow_network=False)


def test_checklist_checker_accepts_part_names(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("## Part 1. Работа с утилитой cat\n", encoding="utf-8")
    (project / "check-list.yml").write_text(
        "sections:\n"
        "  - questions:\n"
        "      - name: Part_1.CAT\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)

    findings = ChecklistChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings[0].criterion == Criterion.CHECKLIST_ALIGNMENT
    assert findings[0].verdict == Verdict.PASS


def test_language_checker_flags_single_language(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README_RUS.md").write_text("# Проект\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)

    findings = LanguageCoverageChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings[0].verdict == Verdict.WARNING
    assert findings[0].extra["languages"] == ["RUS"]


def test_technology_checker_creates_actuality_candidate(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("Use Alpine 3.20.\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    entities = extract_entities(unit)

    findings = TechnologyFreshnessChecker().check(unit, entities, CheckContext(_settings(workspace_tmp_path, project)))

    assert any(finding.criterion == Criterion.ACTUALITY for finding in findings)
