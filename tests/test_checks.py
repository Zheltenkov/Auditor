from pathlib import Path

from content_audit.cache import AuditCache
from content_audit.checks import (
    CheckContext,
    ChecklistChecker,
    FactCheckerPerplexity,
    LanguageCoverageChecker,
    TechFreshnessChecker,
    TechnologyFreshnessChecker,
)
from content_audit.domain import AuditSettings, Criterion, Verdict
from content_audit.extraction import extract_entities
from content_audit.ingestion import discover_content_units, load_unit_files


def _settings(tmp_path: Path, project: Path) -> AuditSettings:
    return AuditSettings(input_path=project, output_path=tmp_path / "out", allow_network=False)


class _FakeJsonClient:
    def __init__(self, response):
        self.response = response
        self.model = "fake-model"
        self.calls = 0

    def complete_json(self, system_prompt: str, user_prompt: str, max_retries: int = 2):
        del system_prompt, user_prompt, max_retries
        self.calls += 1
        return self.response


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


def test_tech_freshness_checker_uses_sources_and_cache(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("Use Alpine 3.20 for the build image.\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    entities = extract_entities(unit)
    fake_client = _FakeJsonClient(
        {
            "verdict": "warning",
            "severity": "minor",
            "confidence": 0.8,
            "support_status": "устарело",
            "latest_version": "3.22",
            "recommended_version": "3.22",
            "evidence": "Alpine 3.20 уже не последняя стабильная ветка.",
            "sources": [{"title": "Alpine releases", "url": "https://alpinelinux.org/releases/"}],
            "recommendation": "Проверить образ и обновить версию в материалах.",
        }
    )
    cache = AuditCache.load(workspace_tmp_path / "cache.json")
    context = CheckContext(_settings(workspace_tmp_path, project), tech_model_client=fake_client, cache=cache)

    first = TechFreshnessChecker().check(unit, entities, context)
    second = TechFreshnessChecker().check(unit, entities, context)

    assert fake_client.calls == 1
    assert first[0].support_status == "устарело"
    assert first[0].latest_version == "3.22"
    assert first[0].recommended_version == "3.22"
    assert first[0].source == "https://alpinelinux.org/releases/"
    assert second[0].extra["cache_hit"] is True


def test_fact_checker_perplexity_uses_sources_and_cache(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text(
        "Python 3.10 supports structural pattern matching since the 2021 release.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    fake_client = _FakeJsonClient(
        {
            "verdict": "pass",
            "confidence": 0.9,
            "evidence": "Утверждение подтверждается документацией Python.",
            "sources": [{"title": "Python docs", "url": "https://docs.python.org/3/whatsnew/3.10.html"}],
            "recommendation": "Действий не требуется.",
        }
    )
    cache = AuditCache.load(workspace_tmp_path / "fact_cache.json")
    context = CheckContext(_settings(workspace_tmp_path, project), fact_model_client=fake_client, cache=cache)

    first = FactCheckerPerplexity().check(unit, [], context)
    second = FactCheckerPerplexity().check(unit, [], context)

    assert fake_client.calls == 1
    assert first[0].verdict == Verdict.PASS
    assert first[0].source == "https://docs.python.org/3/whatsnew/3.10.html"
    assert second[0].extra["cache_hit"] is True
