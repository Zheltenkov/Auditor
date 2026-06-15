from datetime import datetime, timezone
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
    ModelRubricChecker,
    ReadmeFactActualityChecker,
    ReadabilityChecker,
    RegionalAvailabilityChecker,
    RightsAndOriginalityChecker,
    RightsChecker,
    TechFreshnessChecker,
    TechnologyFreshnessChecker,
    default_checkers,
)
from content_audit.dependencies import DependencyCandidate, DependencyMetadata, DependencyRegistryClient
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
        del system_prompt, max_retries
        self.calls += 1
        self.user_prompt = user_prompt
        self.user_prompts = getattr(self, "user_prompts", [])
        self.user_prompts.append(user_prompt)
        return self.response


def test_checklist_checker_accepts_part_names(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("## Part 1. Работа с утилитой cat\n", encoding="utf-8")
    (project / "check-list.yml").write_text(
        "sections:\n"
        "  - questions:\n"
        "      - name: Part_1.CAT\n"
        "        description: Must check src/cat.c, expected stdout and error handling. Example input is provided.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)

    findings = ChecklistChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings[0].criterion == Criterion.CHECKLIST_ALIGNMENT
    assert findings[0].verdict == Verdict.PASS


def test_checklist_checker_matches_number_and_keyword_across_language(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README_UZB.md").write_text("## 1-qism. cat utilitasi bilan ishlash\n", encoding="utf-8")
    (project / "check-list.yml").write_text(
        "sections:\n"
        "  - questions:\n"
        "      - name: Part_1.CAT\n"
        "        description: Must check src/cat.c, expected stdout and error handling. Example input is provided.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)

    findings = ChecklistChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings[0].verdict == Verdict.PASS


def test_checklist_checker_keeps_lexical_weak_match_minor(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("## Part 4. Log generator\n", encoding="utf-8")
    (project / "check-list.yml").write_text(
        "sections:\n"
        "  - questions:\n"
        "      - name: Part_4.File_generator\n"
        "        description: Must check src/log_generator.c, expected output and error handling. Example input is provided.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)

    findings = ChecklistChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings[0].criterion == Criterion.CHECKLIST_ALIGNMENT
    assert findings[0].verdict == Verdict.WARNING
    assert findings[0].severity == Severity.MINOR
    assert findings[0].extra["strong_matched"] == 0
    assert findings[0].extra["weak_matched"] == 1


def test_checklist_checker_flags_missing_expanded_descriptions_as_major(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("## Part 1. Работа с cat\n", encoding="utf-8")
    (project / "check-list.yml").write_text(
        "sections:\n"
        "  - questions:\n"
        "      - name: Part_1.CAT\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)

    findings = ChecklistChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings[0].verdict == Verdict.WARNING
    assert findings[0].severity == Severity.MAJOR
    assert findings[0].extra["description_ratio"] == 0.0
    assert findings[0].extra["incomplete_questions"] == ["Part_1.CAT"]


def test_checklist_checker_keeps_partial_descriptions_minor(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text(
        "## Exercise 00 - Terminology\n"
        "## Exercise 01 - Data Preparation\n"
        "## Exercise 02 - UC Update\n",
        encoding="utf-8",
    )
    (project / "check-list.yml").write_text(
        "sections:\n"
        "  - questions:\n"
        "      - name: Exercise 00 - Terminology\n"
        "        description: Terms are compared.\n"
        "      - name: Exercise 01 - Data Preparation\n"
        "        description: Ported from previous projects.\n"
        "      - name: Exercise 02 - UC Update\n"
        "        description: UC is analyzed. The response set must contain request.json, at least 2 responses, expected output and an example.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=3000)

    findings = ChecklistChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings[0].verdict == Verdict.WARNING
    assert findings[0].severity == Severity.MINOR
    assert 0.0 < findings[0].extra["description_ratio"] < 0.8


def test_language_checker_flags_single_language(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README_RUS.md").write_text("# Проект\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)

    findings = LanguageCoverageChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings[0].verdict == Verdict.INFO
    assert findings[0].severity == Severity.INFO
    assert findings[0].extra["languages"] == ["RUS"]
    assert findings[0].extra["expected_languages"] == ["RUS", "ENG", "UZ", "TG"]
    assert findings[0].extra["missing_languages"] == ["ENG", "UZ", "TG"]
    assert findings[0].needs_human_review is False


def test_language_checker_passes_when_expected_languages_are_present(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README_RUS.md").write_text("# Проект\n", encoding="utf-8")
    (project / "README.md").write_text("# Project\nThis project explains the task for students.\n", encoding="utf-8")
    settings = _settings(workspace_tmp_path, project).model_copy(update={"expected_languages": ("RUS", "ENG")})
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)

    findings = LanguageCoverageChecker().check(unit, [], CheckContext(settings))

    assert findings[0].verdict == Verdict.PASS
    assert findings[0].extra["coverage_ratio"] == 1.0
    assert findings[0].extra["missing_languages"] == []


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


def test_readability_checker_does_not_flag_normal_here_will_be_phrase(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("В этом разделе здесь будет описан порядок настройки сервиса.\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)

    findings = ReadabilityChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings == []


def test_readability_checker_flags_real_placeholder_phrase(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("Здесь будет описание проекта.\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)

    findings = ReadabilityChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings[0].severity == Severity.MAJOR
    assert findings[0].verdict == Verdict.FAIL


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


def test_technology_checker_ignores_makefile_target_instruction(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "check-list.yml").write_text(
        "- The program is built with Makefile with target s21_cat.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    entities = extract_entities(unit)

    findings = TechnologyFreshnessChecker().check(unit, entities, CheckContext(_settings(workspace_tmp_path, project)))

    assert findings == []


def test_tech_freshness_checker_ignores_exercise_numbers_and_turn_in_labels(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text(
        "10.1. [Exercise 06. Sorting a dictionary](#exercise-06-sorting-a-dictionary)\n"
        "- Turn-in directory: `ex00/`.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    entities = extract_entities(unit)
    fake_client = _FakeJsonClient(
        {
            "verdict": "unknown",
            "severity": "info",
            "confidence": 0.1,
            "support_status": "неизвестно",
            "evidence": "Нет проверяемой версии технологии.",
        }
    )
    context = CheckContext(_settings(workspace_tmp_path, project), tech_model_client=fake_client)

    findings = TechFreshnessChecker().check(unit, entities, context)

    assert findings == []
    assert fake_client.calls == 0


def test_technology_checker_skips_unknown_without_evidence(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("Use Alpine 3.20.\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    entities = extract_entities(unit)
    context = CheckContext(
        _settings(workspace_tmp_path, project),
        tech_model_client=_FakeJsonClient({"verdict": "unknown", "severity": "info"}),
    )

    findings = TechnologyFreshnessChecker().check(unit, entities, context)

    assert findings == []


def test_technology_checker_skips_low_confidence_unknown_without_sources(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("Use Alpine 3.20.\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    entities = extract_entities(unit)
    context = CheckContext(
        _settings(workspace_tmp_path, project),
        tech_model_client=_FakeJsonClient(
            {
                "verdict": "unknown",
                "severity": "info",
                "confidence": 0.1,
                "support_status": "неизвестно",
                "evidence": "Недостаточно источников для проверки.",
                "recommendation": "Проверить вручную.",
            }
        ),
    )

    findings = TechnologyFreshnessChecker().check(unit, entities, context)

    assert findings == []


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


def test_market_fit_checker_accepts_target_audience_and_business_requirements(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    data_dir = project / "datasets"
    data_dir.mkdir()
    (data_dir / "orders.parquet").write_text("id,total\n1,100\n", encoding="utf-8")
    (project / "README.md").write_text(
        "Целевая аудитория: менеджеры интернет-магазина, которые планируют закупки.\n"
        "Пользовательский сценарий: прогнозировать спрос по историческим данным заказов.\n"
        "Бизнес-требование: сократить время обработки заявок и контролировать SLA.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=2000)

    findings = MarketFitChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings[0].verdict == Verdict.PASS
    assert findings[0].extra["sub_checks"]["real_data"]["present"] is True
    assert findings[0].extra["sub_checks"]["business_context"]["present"] is True
    assert findings[0].extra["sub_checks"]["success_metrics"]["present"] is True


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


def test_market_fit_checker_detects_service_business_context_without_dataset(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text(
        "The management of a chain of barbershops decided to implement an online booking system.\n"
        "The objective is to expand the customer base and reduce employee labour costs and manual labour.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=2000)

    findings = MarketFitChecker().check(unit, [], CheckContext(_settings(workspace_tmp_path, project)))

    assert findings[0].verdict == Verdict.WARNING
    assert findings[0].severity == Severity.MINOR
    assert findings[0].extra["market_fit_score"] == 1
    assert findings[0].extra["sub_checks"]["business_context"]["present"] is True
    assert findings[0].extra["sub_checks"]["real_data"]["present"] is False
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
    (project / "reports.csv").write_text("metric,value\ncoverage,90\n", encoding="utf-8")
    tests_dir = project / "tests" / "fixtures"
    tests_dir.mkdir(parents=True)
    (tests_dir / "expected.csv").write_text("value\n42\n", encoding="utf-8")
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


def test_rights_checker_uses_registry_dependency_license(workspace_tmp_path: Path, monkeypatch) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("# Проект\n", encoding="utf-8")
    (project / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (project / "package.json").write_text('{"dependencies":{"copyleft-lib":"1.0.0"}}', encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=5000)

    def fake_fetch(self, candidate: DependencyCandidate) -> DependencyMetadata:
        del self
        return DependencyMetadata(
            ecosystem=candidate.ecosystem,
            name=candidate.name,
            latest_version="1.0.0",
            source_url=f"https://registry.npmjs.org/{candidate.name}",
            checked_at=datetime.now(timezone.utc),
            license_spdx="GPL-3.0-only",
        )

    monkeypatch.setattr(DependencyRegistryClient, "fetch", fake_fetch)
    context = CheckContext(AuditSettings(input_path=project, output_path=workspace_tmp_path / "out", allow_network=True))

    findings = RightsAndOriginalityChecker().check(unit, [], context)

    license_findings = [finding for finding in findings if finding.extra["kind"] == "dependency_license"]
    assert len(license_findings) == 1
    assert license_findings[0].criterion == Criterion.RIGHTS
    assert license_findings[0].severity == Severity.CRITICAL
    assert license_findings[0].verdict == Verdict.FAIL
    assert license_findings[0].source == "GPL-3.0-only"
    assert license_findings[0].evidence[0].url == "https://registry.npmjs.org/copyleft-lib"


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


def test_fact_checker_skips_navigation_and_course_requirements(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text(
        "- [Python 3.10 supports structural pattern matching since the 2021 release](#python-310)\n"
        "Python scripts should be placed in src according to the project rules.\n"
        "Python 3.10 supports structural pattern matching since the 2021 release.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=2000)
    fake_client = _FakeJsonClient(
        {
            "verdict": "pass",
            "confidence": 0.9,
            "evidence": "Утверждение подтверждается документацией Python.",
            "sources": [{"title": "Python docs", "url": "https://docs.python.org/3/whatsnew/3.10.html"}],
            "recommendation": "Действий не требуется.",
        }
    )
    context = CheckContext(_settings(workspace_tmp_path, project), fact_model_client=fake_client)

    findings = FactCheckerPerplexity().check(unit, [], context)

    assert fake_client.calls == 1
    assert len(findings) == 1
    assert "structural pattern matching" in findings[0].quote


def test_readme_fact_actuality_checker_only_reads_main_and_russian_readme(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text(
        "Python 3.10 was released in October 2021 and introduced structural pattern matching.\n",
        encoding="utf-8",
    )
    (project / "README_RUS.md").write_text(
        "Python 3.10 поддерживает структурное сопоставление pattern matching с релиза 2021 года.\n",
        encoding="utf-8",
    )
    (project / "README_UZB.md").write_text("Bu fayl maxsus fakt tekshiruviga kirmaydi.\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=2000)
    fake_client = _FakeJsonClient(
        {
            "findings": [
                {
                    "claim": "Python 3.10 поддерживает структурное сопоставление pattern matching с релиза 2021 года.",
                    "criterion": "actuality",
                    "verdict": "warning",
                    "severity": "minor",
                    "confidence": 0.82,
                    "file_path": "README_RUS.md",
                    "line_start": 1,
                    "evidence": "Утверждение требует уточнения по версии.",
                    "sources": [{"title": "Python docs", "url": "https://docs.python.org/3/whatsnew/3.10.html"}],
                    "support_status": "поддерживается",
                    "latest_version": "3.14",
                    "recommended_version": "3.14",
                    "recommendation": "Уточнить актуальную версию Python.",
                }
            ]
        }
    )
    context = CheckContext(_settings(workspace_tmp_path, project), fact_model_client=fake_client)

    findings = ReadmeFactActualityChecker().check(unit, [], context)

    assert fake_client.calls == 2
    assert "README.md" in fake_client.user_prompts[0]
    assert "README_RUS.md" in fake_client.user_prompts[1]
    assert all("README_UZB.md" not in prompt for prompt in fake_client.user_prompts)
    assert findings[0].criterion == Criterion.CORRECTNESS
    assert findings[0].source == "https://docs.python.org/3/whatsnew/3.10.html"
    assert findings[0].latest_version == "3.14"


def test_readme_fact_actuality_checker_skips_exercise_options_and_task_requirements(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text(
        "## Chapter III\n"
        "REST is an architectural style for distributed systems.\n"
        "## Chapter V\n"
        "### Exercise 00 — Terminology\n"
        "1) The ability of a system to increase performance without adding resources.\n"
        "The system should notify clients through Telegram and SMS.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=2000)
    fake_client = _FakeJsonClient({"findings": []})
    context = CheckContext(_settings(workspace_tmp_path, project), fact_model_client=fake_client)

    findings = ReadmeFactActualityChecker().check(unit, [], context)

    assert findings == []
    assert fake_client.calls == 1
    assert "REST is an architectural style" in fake_client.user_prompt
    assert "without adding resources" not in fake_client.user_prompt
    assert "notify clients" not in fake_client.user_prompt


def test_full_model_audit_includes_readme_fact_checker() -> None:
    checker_names = [checker.name for checker in default_checkers(use_model=True)]

    assert "readme_fact_actuality_checker" in checker_names
    assert "fact_checker_perplexity" in checker_names


def test_model_rubric_checker_only_keeps_workload_findings(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("# Проект\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    fake_client = _FakeJsonClient(
        {
            "findings": [
                {
                    "criterion": "checklist_alignment",
                    "severity": "critical",
                    "verdict": "fail",
                    "confidence": 0.9,
                    "quote": "Проверьте, что ни одно вредоносное ПО не использовалось.",
                    "file_path": "check-list.yml",
                    "line_start": 13,
                    "evidence": "Ложный дубль специализированной проверки.",
                    "recommendation": "Не должно попасть в отчёт.",
                },
                {
                    "criterion": "workload",
                    "severity": "info",
                    "verdict": "unknown",
                    "confidence": 0.5,
                    "evidence": "Нет данных о реальном времени прохождения.",
                    "recommendation": "Собрать данные платформы о трудозатратах.",
                },
            ]
        }
    )
    context = CheckContext(_settings(workspace_tmp_path, project), model_client=fake_client)

    findings = ModelRubricChecker().check(unit, [], context)

    assert len(findings) == 1
    assert findings[0].criterion == Criterion.WORKLOAD


def test_regional_availability_checker_uses_curated_ru_rules(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text(
        "The task uses https://blocked.example/api and the ExampleCloud SDK.\n",
        encoding="utf-8",
    )
    (project / "requirements.txt").write_text("examplecloud==1.0.0\n", encoding="utf-8")
    (project / "regional_availability_ru.yml").write_text(
        "rules:\n"
        "  - pattern: blocked.example\n"
        "    target: service\n"
        "    status: unavailable\n"
        "    reason: Сервис недоступен из РФ по кураторской базе.\n"
        "    source: https://kb.example/blocked\n"
        "    updated_at: 2026-06-01\n"
        "  - pattern: examplecloud\n"
        "    target: package\n"
        "    status: limited\n"
        "    reason: SDK требует проверки доступности из РФ.\n",
        encoding="utf-8",
    )
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=5000)
    entities = extract_entities(unit)
    context = CheckContext(_settings(workspace_tmp_path, project))

    findings = RegionalAvailabilityChecker().check(unit, entities, context)

    assert {finding.support_status for finding in findings} == {"недоступно в РФ", "ограничено в РФ"}
    assert all(finding.criterion == Criterion.ACTUALITY for finding in findings)
    assert any(finding.severity == Severity.MAJOR for finding in findings)
    assert any(finding.source == "https://kb.example/blocked" for finding in findings)


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


def test_link_checker_accepts_oprosso_short_link_redirect(workspace_tmp_path: Path, monkeypatch) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("[survey](http://opros.so/kAnXy)\n", encoding="utf-8")
    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    entities = extract_entities(unit)
    settings = _settings(workspace_tmp_path, project).model_copy(update={"allow_network": True})
    monkeypatch.setattr(
        checks_module,
        "_check_url",
        lambda *_args: (200, "https://oprosso.ru/p/4cb31ec3f47a4596bc758ea1861fb624", None),
    )

    findings = LinkChecker().check(unit, entities, CheckContext(settings))

    assert findings == []
