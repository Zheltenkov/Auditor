from pathlib import Path

from content_audit import checks as checks_module
from content_audit.cache import AuditCache
from content_audit.checks import (
    CheckContext,
    ChecklistChecker,
    FactCheckerPerplexity,
    ImageQualityChecker,
    LanguageCoverageChecker,
    LinkChecker,
    MarketFitChecker,
    ReadabilityChecker,
    RightsAndOriginalityChecker,
    RightsChecker,
    TechFreshnessChecker,
    TechnologyFreshnessChecker,
)
from content_audit.domain import AuditSettings, Criterion, Severity, Verdict
from content_audit.extraction import extract_entities
from content_audit.ingestion import discover_content_units, load_unit_files


def _settings(tmp_path: Path, project: Path) -> AuditSettings:
    return AuditSettings(input_path=project, output_path=tmp_path / "out", allow_network=False)


class _FakeJsonClient:
    def __init__(self, response):
        self.response = response
        self.model = "fake-model"
        self.calls = 0
        self.last_call_usage = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15, "cost_usd": 0.001}

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


def test_language_checker_cross_checks_suffix_with_content(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README_RUS.md").write_text(
        "This project explains how to build and test command line utilities. "
        "Students should read the instructions carefully before starting the task.",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)

    findings = LanguageCoverageChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert any(finding.evidence[0].title == "Несовпадение языка" for finding in findings)
    assert findings[0].extra["mismatches"][0]["expected"] == "RUS"
    assert findings[0].extra["mismatches"][0]["detected"] == "ENG"


def test_readability_checker_does_not_flag_long_lines_without_model(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text(f"{'Очень длинный учебный абзац. ' * 20}\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=2000)

    findings = ReadabilityChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings == []


def test_readability_checker_lets_model_decide_long_line_warning(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text(f"{'Очень длинный учебный абзац с несколькими мыслями. ' * 16}\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=2000)
    fake_client = _FakeJsonClient(
        {
            "verdict": "warning",
            "severity": "minor",
            "confidence": 0.82,
            "problem_lines": [1],
            "evidence": "Абзац перегружен несколькими действиями и плохо сканируется.",
            "recommendation": "Разбить абзац на короткие пункты.",
        }
    )
    cache = AuditCache.load(workspace_tmp_path / "readability_cache.json")
    context = CheckContext(_settings(workspace_tmp_path, project), model_client=fake_client, cache=cache)

    first = ReadabilityChecker().check(unit, [], context)
    second = ReadabilityChecker().check(unit, [], context)

    assert fake_client.calls == 1
    assert first[0].criterion == Criterion.READABILITY
    assert first[0].verdict == Verdict.WARNING
    assert first[0].location is not None
    assert first[0].location.line_start == 1
    assert first[0].prompt_version == "readability_checker:v2"
    assert second[0].extra["cache_hit"] is True
    assert context.model_usage["calls_total"] == 1
    assert context.model_usage["cache_hits"] == 1


def test_technology_checker_creates_actuality_candidate(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("Use Alpine 3.20.\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    entities = extract_entities(unit)

    findings = TechnologyFreshnessChecker().check(unit, entities, CheckContext(_settings(workspace_tmp_path, project)))

    assert any(finding.criterion == Criterion.ACTUALITY for finding in findings)


def test_market_fit_checker_passes_when_all_business_signals_exist(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    data_dir = project / "data"
    data_dir.mkdir()
    (data_dir / "customers.csv").write_text("id,churn\n1,0\n", encoding="utf-8")
    (project / "README.md").write_text(
        "Проект работает с реальными данными клиентов.\n"
        "Бизнес-задача: снизить отток клиентов банка.\n"
        "Метрика успеха: уменьшить churn и повысить retention.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=2000)

    findings = MarketFitChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings[0].criterion == Criterion.MARKET_FIT
    assert findings[0].verdict == Verdict.PASS
    assert findings[0].extra["market_fit_score"] == 3
    assert findings[0].needs_human_review is False


def test_market_fit_checker_flags_missing_success_metrics(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text(
        "Используется датасет продаж.\n"
        "Бизнес-проблема: заказчик хочет лучше понимать спрос.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=2000)

    findings = MarketFitChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings[0].verdict == Verdict.WARNING
    assert findings[0].severity == Severity.MINOR
    assert findings[0].extra["sub_checks"]["success_metrics"]["present"] is False


def test_market_fit_checker_does_not_count_generic_technical_data_as_market_fit(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text(
        "Autotests compare correct output data with expected results.\n"
        "The service exports CSV reports for manual review.\n"
        "Наша игра — многопользовательская.\n"
        "Интеграционные тесты сравнивают результат со стандартным выводом.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=2000)

    findings = MarketFitChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings[0].extra["market_fit_score"] == 0
    assert findings[0].severity == Severity.MAJOR
    assert findings[0].verdict == Verdict.WARNING


def test_market_fit_checker_uses_model_to_refine_weak_signals(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("Проект помогает аналитикам принимать решения по заявкам.\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=2000)
    fake_client = _FakeJsonClient(
        {
            "verdict": "pass",
            "severity": "info",
            "confidence": 0.8,
            "real_data": True,
            "business_context": True,
            "success_metrics": True,
            "evidence": "В тексте есть прикладной сценарий, а данные и критерии успеха заданы другими словами.",
            "recommendation": "Действий не требуется.",
        }
    )
    cache = AuditCache.load(workspace_tmp_path / "market_cache.json")
    context = CheckContext(_settings(workspace_tmp_path, project), model_client=fake_client, cache=cache)

    first = MarketFitChecker().check(unit, [], context)
    second = MarketFitChecker().check(unit, [], context)

    assert fake_client.calls == 1
    assert first[0].verdict == Verdict.PASS
    assert first[0].extra["market_fit_score"] == 3
    assert first[0].prompt_version == "market_fit_checker:v1"
    assert second[0].extra["cache_hit"] is True


def test_rights_checker_treats_missing_license_as_advisory(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("# Проект\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)

    findings = RightsChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings[0].criterion == Criterion.RIGHTS
    assert findings[0].severity == Severity.INFO
    assert findings[0].verdict == Verdict.WARNING
    assert findings[0].needs_human_review is False


def test_rights_checker_flags_significant_image_without_source(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("![architecture](diagram.png)\n", encoding="utf-8")
    (project / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (project / "diagram.png").write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\rIHDR"
        + (480).to_bytes(4, "big")
        + (320).to_bytes(4, "big")
        + b"\x08\x06\x00\x00\x00"
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    entities = extract_entities(unit)

    findings = RightsAndOriginalityChecker().check(unit, entities, CheckContext(_settings(workspace_tmp_path, project)))

    assert len(findings) == 1
    assert findings[0].severity == Severity.MINOR
    assert findings[0].verdict == Verdict.WARNING
    assert findings[0].needs_human_review is True
    assert findings[0].extra["kind"] == "image_provenance"


def test_rights_checker_ignores_decorative_image(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("![logo](logo.png)\n", encoding="utf-8")
    (project / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (project / "logo.png").write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\rIHDR"
        + (48).to_bytes(4, "big")
        + (48).to_bytes(4, "big")
        + b"\x08\x06\x00\x00\x00"
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    entities = extract_entities(unit)

    findings = RightsAndOriginalityChecker().check(unit, entities, CheckContext(_settings(workspace_tmp_path, project)))

    assert findings == []


def test_rights_checker_flags_dataset_without_license_terms(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (project / "README.md").write_text(
        "Используется датасет продаж с Kaggle: https://kaggle.com/datasets/example/sales.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)

    findings = RightsAndOriginalityChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert len(findings) == 1
    assert findings[0].extra["kind"] == "dataset_rights"
    assert findings[0].severity == Severity.MINOR
    assert findings[0].needs_human_review is True


def test_image_quality_checker_ignores_decorative_small_icons(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("![icon](icon.png)\n", encoding="utf-8")
    (project / "icon.png").write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\rIHDR"
        + (32).to_bytes(4, "big")
        + (32).to_bytes(4, "big")
        + b"\x08\x06\x00\x00\x00"
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    entities = extract_entities(unit)

    findings = ImageQualityChecker().check(unit, entities, CheckContext(_settings(workspace_tmp_path, project)))

    assert findings == []


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
    assert (workspace_tmp_path / "cache.json").exists()
    assert first[0].support_status == "устарело"
    assert first[0].latest_version == "3.22"
    assert first[0].recommended_version == "3.22"
    assert first[0].source == "https://alpinelinux.org/releases/"
    assert first[0].prompt_version == "tech_freshness_checker:v1"
    assert second[0].extra["cache_hit"] is True
    assert context.model_usage["calls_total"] == 1
    assert context.model_usage["cache_hits"] == 1
    assert context.model_usage["total_tokens"] == 15


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
    assert first[0].prompt_version == "fact_checker_perplexity:v1"
    assert second[0].extra["cache_hit"] is True


def test_link_checker_blocks_private_ip_before_network(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("[internal](http://127.0.0.1:9999/secret)\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    entities = extract_entities(unit)
    settings = _settings(workspace_tmp_path, project).model_copy(update={"allow_network": True})

    findings = LinkChecker().check(unit, entities, CheckContext(settings))

    assert findings[0].verdict == Verdict.UNKNOWN
    assert "Локальные адреса" in findings[0].evidence[0].detail or "Внутренние IP" in findings[0].evidence[0].detail


def test_link_checker_treats_transient_status_as_recheck(workspace_tmp_path: Path, monkeypatch) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("[slow](https://example.com/slow)\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    entities = extract_entities(unit)
    settings = _settings(workspace_tmp_path, project).model_copy(update={"allow_network": True})
    monkeypatch.setattr(checks_module, "_check_url", lambda *_args: (503, "https://example.com/slow", None))

    findings = LinkChecker().check(unit, entities, CheckContext(settings))

    assert findings[0].severity == Severity.INFO
    assert findings[0].verdict == Verdict.UNKNOWN
    assert "Повторить проверку позже" in findings[0].recommendation


def test_link_checker_does_not_make_first_404_critical(workspace_tmp_path: Path, monkeypatch) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("[missing](https://example.com/missing)\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    entities = extract_entities(unit)
    settings = _settings(workspace_tmp_path, project).model_copy(update={"allow_network": True})
    monkeypatch.setattr(checks_module, "_check_url", lambda *_args: (404, "https://example.com/missing", None))

    findings = LinkChecker().check(unit, entities, CheckContext(settings))

    assert findings[0].severity == Severity.MAJOR
    assert findings[0].verdict == Verdict.FAIL
