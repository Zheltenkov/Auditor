"""Проверяющие модули для критериев аудита."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urldefrag, urljoin, urlparse

import requests
import yaml

from content_audit.cache import AuditCache
from content_audit.checklist_matching import (
    assess_checklist_description_quality,
    extract_checklist_questions,
    match_checklist_to_readme,
)
from content_audit.dependencies import (
    CompatibilityIssue,
    DependencyCandidate,
    DependencyMetadata,
    DependencyRegistryClient,
    DependencyRegistryError,
    dependency_cache_key,
    dependency_identity,
    extract_dependency_candidates,
    find_compatibility_issues,
    is_pinned_outdated,
    is_unbounded_spec,
    metadata_from_record,
    metadata_to_record,
)
from content_audit.domain import (
    CRITERION_LABELS,
    AuditSettings,
    ContentUnit,
    Criterion,
    EntityType,
    Evidence,
    ExtractedEntity,
    Finding,
    Severity,
    TextLocation,
    Verdict,
)
from content_audit.image_rights import (
    image_evidence_queries,
    image_rights_signals,
    is_decorative_image,
    read_image_dimensions,
)
from content_audit.openrouter import OpenRouterClient, OpenRouterError
from content_audit.regional_availability import (
    RegionalAvailabilityMatch,
    load_regional_availability_rules,
    match_regional_availability,
)
from content_audit.rights import (
    DATASET_RE,
    MANIFEST_NAMES,
    CodeMatch,
    RightsSignal,
    grade_rights_signal,
    license_policy,
    resolve_dependency_licenses,
    scan_project_licenses,
)
from content_audit.text_utils import normalize_for_match


TECH_KEYWORDS = {
    "alpine",
    "bash",
    "busybox",
    "c11",
    "docker",
    "gcc",
    "github",
    "gitlab",
    "gnu",
    "java",
    "node",
    "node.js",
    "pcre2",
    "posix",
    "python",
    "ubuntu",
}
NON_TECH_VERSION_LABEL_RE = re.compile(
    r"(?i)\b(?:chapter|exercise|section|part|task|step|lesson|module|unit|turn-in|files?\s+to\s+turn\s+in)\b"
)
LOW_CONFIDENCE_UNKNOWN_THRESHOLD = 0.3

TRUSTED_REDIRECT_HOST_GROUPS = (
    frozenset({"opros.so", "oprosso.ru", "oprosso.net", "new.oprosso.net"}),
)

FACT_MARKER_RE = re.compile(
    r"\b("
    r"deprecated|latest|lts|release|standard|style|support|supported|"
    r"актуаль|устар|поддерж|стандарт|релиз|верси|используется|является|входит|доступ"
    r")\b",
    re.IGNORECASE,
)
FACT_DATE_RE = re.compile(r"\b(?:19|20)\d{2}(?:[-./](?:0?[1-9]|1[0-2])(?:[-./](?:0?[1-9]|[12]\d|3[01]))?)?\b")
INTERNAL_MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(\s*#[^)]+\)")
MARKDOWN_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
README_FACT_FILE_RE = re.compile(r"^readme(?:_rus)?\.md$", re.IGNORECASE)
README_TASK_SECTION_RE = re.compile(
    r"(?i)^\s*#{2,6}\s*(?:chapter\s+iv|chapter\s+v|description\s+of\s+tasks|task\s+\d+|exercise\s+\d+|"
    r"задач[а-я]*\s+\d+|упражнен[а-я]*\s+\d+)"
)
README_THEORY_SECTION_RE = re.compile(
    r"(?i)^\s*#{2,6}\s*(?:chapter\s+iii|theory|general\s+concepts|documentation|mapping|error\s+handling|"
    r"теори[яи]|основные\s+понятия|документаци[яи]|маппинг|обработка\s+ошибок)"
)
README_DEFINITION_LINE_RE = re.compile(r"^\s*(?:\*\*)?[A-ZА-ЯЁ][^:\n]{1,90}(?:\*\*)?\s*[:—-]\s+\S")
README_EXERCISE_OPTION_RE = re.compile(r"^\s*(?:\d+[).]|[A-ZА-ЯЁ][).])\s+")
README_FEEDBACK_LINE_RE = re.compile(r"(?i)(feedback|опрос|educational experience|оставить отзыв|leave your feedback)")
REQUIREMENT_CLAIM_MARKERS = (
    " must ",
    " should ",
    " need to ",
    " needs to ",
    " required ",
    " requirement ",
    " have to ",
    "должен",
    "должна",
    "должны",
    "нужно",
    "необходимо",
    "требуется",
    "следует",
    "обязательно",
)
MODEL_RUBRIC_ALLOWED_CRITERIA = {Criterion.WORKLOAD}


class CheckContext:
    """Контекст, общий для всех проверяющих модулей."""

    def __init__(
        self,
        settings: AuditSettings,
        model_client: OpenRouterClient | None = None,
        fact_model_client: OpenRouterClient | None = None,
        tech_model_client: OpenRouterClient | None = None,
        cache: AuditCache | None = None,
    ) -> None:
        self.settings = settings
        self.model_client = model_client
        self.fact_model_client = fact_model_client
        self.tech_model_client = tech_model_client
        self.cache = cache
        self.model_usage: dict[str, Any] = {
            "calls_total": 0,
            "cache_hits": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "cost_usd": 0.0,
            "by_model": {},
        }
        self.prompt_versions: dict[str, str] = {}

    def record_model_result(self, client: OpenRouterClient, cache_hit: bool, prompt_version: str) -> None:
        """Собираем учёт вызовов модели и используемых версий промптов."""

        self.prompt_versions[prompt_version.split(":", 1)[0]] = prompt_version
        if cache_hit:
            self.model_usage["cache_hits"] += 1
            return

        usage = getattr(client, "last_call_usage", {}) or {}
        self.model_usage["calls_total"] += 1
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            self.model_usage[key] += int(usage.get(key, 0) or 0)
        self.model_usage["cost_usd"] += float(usage.get("cost_usd", 0.0) or 0.0)

        by_model = self.model_usage["by_model"]
        model_stats = by_model.setdefault(
            client.model,
            {"calls_total": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "cost_usd": 0.0},
        )
        model_stats["calls_total"] += 1
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            model_stats[key] += int(usage.get(key, 0) or 0)
        model_stats["cost_usd"] += float(usage.get("cost_usd", 0.0) or 0.0)


class BaseChecker(ABC):
    """Базовый интерфейс проверяющего модуля."""

    name: str

    @abstractmethod
    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        """Возвращает найденные случаи по единице контента."""


class StructureChecker(BaseChecker):
    """Проверяет наличие минимальной структуры учебного проекта."""

    name = "structure_checker"

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        del entities, context
        findings: list[Finding] = []
        file_names = {file.relative_path.lower() for file in unit.files}
        has_readme = any(path.startswith("readme") and path.endswith(".md") for path in file_names)
        has_checklist = any(path.startswith("check-list") and path.endswith((".yml", ".yaml")) for path in file_names)
        if not has_readme:
            findings.append(
                _finding(
                    unit,
                    self.name,
                    Criterion.READABILITY,
                    Severity.MAJOR,
                    Verdict.FAIL,
                    0.95,
                    None,
                    None,
                    [Evidence(title="Структура", detail="В единице контента не найден README*.md.")],
                    "Добавить основной README или проверить, что на вход передана корректная папка проекта.",
                    True,
                )
            )
        if not has_checklist:
            findings.append(
                _finding(
                    unit,
                    self.name,
                    Criterion.CHECKLIST_ALIGNMENT,
                    Severity.MAJOR,
                    Verdict.FAIL,
                    0.95,
                    None,
                    None,
                    [Evidence(title="Структура", detail="В единице контента не найден check-list.yml или check-list.yaml.")],
                    "Добавить чек-лист проверки или исключить критерий соответствия чек-листу для этой единицы.",
                    True,
                )
            )
        return findings


class LinkChecker(BaseChecker):
    """Проверяет ссылки: локальные сразу, внешние при разрешённой сети."""

    name = "link_checker"

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        for entity in _entities_of_type(entities, EntityType.LINK):
            parsed = urlparse(entity.value)
            if parsed.scheme not in {"http", "https"}:
                continue
            policy_error = _url_policy_error(entity.value)
            if policy_error is not None:
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.ACTUALITY,
                        Severity.INFO,
                        Verdict.UNKNOWN,
                        0.65,
                        entity.quote,
                        entity.location,
                        [Evidence(title="Политика проверки ссылок", detail=policy_error, url=entity.value)],
                        "Проверить ссылку вручную.",
                        True,
                    )
                )
                continue
            if not context.settings.allow_network:
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.ACTUALITY,
                        Severity.INFO,
                        Verdict.UNKNOWN,
                        0.5,
                        entity.quote,
                        entity.location,
                        [Evidence(title="Сеть отключена", detail=f"Ссылка не проверялась: {entity.value}", url=entity.value)],
                        "Запустить проверку с доступом к сети, чтобы подтвердить доступность ссылки.",
                        True,
                    )
                )
                continue

            status_code, final_url, error = _check_url(entity.value, context.settings.link_timeout_seconds)
            if error is not None:
                severity = Severity.MINOR if _is_redirect_chain_error(error) else Severity.INFO
                verdict = Verdict.WARNING if _is_redirect_chain_error(error) else Verdict.UNKNOWN
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.ACTUALITY,
                        severity,
                        verdict,
                        0.65,
                        entity.quote,
                        entity.location,
                        [Evidence(title="Ошибка запроса", detail=error, url=entity.value)],
                        "Перепроверить ссылку: ошибка может быть временной, сетевой или связанной с перенаправлениями.",
                        True,
                    )
                )
            elif _is_transient_http_status(status_code):
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.ACTUALITY,
                        Severity.INFO,
                        Verdict.UNKNOWN,
                        0.65,
                        entity.quote,
                        entity.location,
                        [Evidence(title="Временный HTTP-статус", detail=f"Получен статус {status_code}.", url=final_url or entity.value)],
                        "Повторить проверку позже: статус похож на временную недоступность или ограничение запросов.",
                        True,
                    )
                )
            elif status_code >= 400:
                severity = Severity.MAJOR
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.ACTUALITY,
                        severity,
                        Verdict.FAIL,
                        0.9,
                        entity.quote,
                        entity.location,
                        [Evidence(title="HTTP-статус", detail=f"Получен статус {status_code}.", url=final_url or entity.value)],
                        "Заменить ссылку на актуальную или удалить зависимость от недоступного ресурса.",
                        True,
                    )
                )
            elif _redirect_smells_like_rot(entity.value, final_url):
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.ACTUALITY,
                        Severity.MINOR,
                        Verdict.WARNING,
                        0.7,
                        entity.quote,
                        entity.location,
                        [Evidence(title="Подозрительный редирект", detail=f"Финальный адрес: {final_url}.", url=final_url or entity.value)],
                        "Проверить, ведёт ли ссылка на нужный материал, а не на главную страницу или другой домен.",
                        True,
                    )
                )
        return findings


class LocalLinkChecker(BaseChecker):
    """Проверяет локальные Markdown-ссылки на файлы и изображения."""

    name = "local_link_checker"

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        del context
        findings: list[Finding] = []
        for entity in [*list(_entities_of_type(entities, EntityType.IMAGE))]:
            target, _fragment = urldefrag(entity.value)
            parsed = urlparse(target)
            if parsed.scheme in {"http", "https"} or not target:
                continue
            source_file = unit.root_path / entity.location.file_path
            target_path = (source_file.parent / target).resolve()
            if not _is_inside(target_path, unit.root_path) or not target_path.exists():
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.ACTUALITY,
                        Severity.MAJOR,
                        Verdict.FAIL,
                        0.95,
                        entity.quote,
                        entity.location,
                        [Evidence(title="Локальный файл", detail=f"Файл не найден: {entity.value}")],
                        "Исправить путь к локальному ресурсу или добавить отсутствующий файл.",
                        True,
                    )
                )
        return findings


class ChecklistChecker(BaseChecker):
    """Проверяет наличие и базовое соответствие чек-листа README."""

    name = "checklist_checker"

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        del entities, context
        checklist_files = [file for file in unit.files if file.kind == "checklist"]
        if not checklist_files:
            return []

        findings: list[Finding] = []
        readme_text = "\n".join(file.text for file in unit.files if file.kind == "readme")
        for checklist_file in checklist_files:
            try:
                payload = yaml.safe_load(checklist_file.text) or {}
            except yaml.YAMLError as exc:
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.CHECKLIST_ALIGNMENT,
                        Severity.CRITICAL,
                        Verdict.FAIL,
                        0.95,
                        None,
                        TextLocation(file_path=checklist_file.relative_path),
                        [Evidence(title="YAML", detail=f"Чек-лист не разбирается: {exc}")],
                        "Исправить структуру YAML, иначе чек-лист нельзя использовать для проверки.",
                        True,
                    )
                )
                continue

            questions = extract_checklist_questions(payload)
            question_names = [question.name for question in questions]
            if not question_names:
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.CHECKLIST_ALIGNMENT,
                        Severity.MAJOR,
                        Verdict.FAIL,
                        0.9,
                        None,
                        TextLocation(file_path=checklist_file.relative_path),
                        [Evidence(title="Чек-лист", detail="Не найдены вопросы проверки в sections[].questions[].")],
                        "Проверить формат чек-листа: пункты должны быть представлены в sections[].questions[].",
                        True,
                    )
                )
                continue

            match_result = match_checklist_to_readme(question_names, readme_text)
            description_result = assess_checklist_description_quality(questions)
            evidence_detail = (
                f"Сильных совпадений: {match_result.strong_matched} из {match_result.total}; "
                f"слабых совпадений: {match_result.weak_matched} из {match_result.total}; "
                f"не сопоставлено: {len(match_result.unmatched_names)} из {match_result.total}. "
                f"Развёрнутых описаний: {description_result.complete} из {description_result.total}."
            )
            if match_result.unmatched_names:
                evidence_detail += f" Не сопоставлены: {', '.join(match_result.unmatched_names[:8])}."
            if description_result.incomplete_names:
                evidence_detail += f" Недостаточно описаны: {', '.join(description_result.incomplete_names[:8])}."

            severity = Severity.INFO
            verdict = Verdict.PASS
            recommendation_parts: list[str] = []
            confidence = 0.78
            if match_result.strong_ratio < 0.5:
                severity = Severity.MINOR
                verdict = Verdict.WARNING
                confidence = min(confidence, 0.65)
                recommendation_parts.append(
                    "Проверить связь пунктов чек-листа с требованиями README; текущий сигнал основан на лексическом сопоставлении."
                )
            if description_result.ratio == 0:
                severity = Severity.MAJOR
                verdict = Verdict.WARNING
                confidence = max(confidence, 0.82)
                recommendation_parts.append(
                    "Добавить развёрнутые описания пунктов: критерии приёмки, ожидаемые артефакты и примеры."
                )
            elif description_result.ratio < 0.8:
                if severity == Severity.INFO:
                    severity = Severity.MINOR
                    verdict = Verdict.WARNING
                    confidence = min(confidence, 0.72)
                recommendation_parts.append(
                    "Доработать пункты без критериев приёмки, ожидаемых артефактов или примеров."
                )

            if verdict != Verdict.PASS:
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.CHECKLIST_ALIGNMENT,
                        severity,
                        verdict,
                        confidence,
                        None,
                        TextLocation(file_path=checklist_file.relative_path),
                        [
                            Evidence(
                                title="Связность README и чек-листа",
                                detail=evidence_detail,
                            )
                        ],
                        " ".join(recommendation_parts),
                        True,
                        extra={
                            "matched_ratio": match_result.ratio,
                            "strong_matched": match_result.strong_matched,
                            "weak_matched": match_result.weak_matched,
                            "strong_matched_questions": list(match_result.strong_matched_names),
                            "weak_matched_questions": list(match_result.weak_matched_names),
                            "unmatched_questions": list(match_result.unmatched_names),
                            "description_ratio": description_result.ratio,
                            "complete_description_questions": list(description_result.complete_names),
                            "incomplete_questions": list(description_result.incomplete_names),
                        },
                    )
                )
            else:
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.CHECKLIST_ALIGNMENT,
                        Severity.INFO,
                        Verdict.PASS,
                        0.75,
                        None,
                        TextLocation(file_path=checklist_file.relative_path),
                        [
                            Evidence(
                                title="Чек-лист",
                                detail=evidence_detail,
                            )
                        ],
                        "Действий не требуется; структура чек-листа и базовая связность с README выглядят достаточными.",
                        False,
                        extra={
                            "matched_ratio": match_result.ratio,
                            "strong_matched": match_result.strong_matched,
                            "weak_matched": match_result.weak_matched,
                            "strong_matched_questions": list(match_result.strong_matched_names),
                            "weak_matched_questions": list(match_result.weak_matched_names),
                            "unmatched_questions": list(match_result.unmatched_names),
                            "description_ratio": description_result.ratio,
                            "complete_description_questions": list(description_result.complete_names),
                            "incomplete_questions": list(description_result.incomplete_names),
                        },
                    )
                )
        return findings


class LanguageCoverageChecker(BaseChecker):
    """Определяет наличие языковых версий RUS/ENG/UZ/TG."""

    name = "language_coverage_checker"

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        del entities
        languages, mismatches = _detect_language_profile(unit)
        expected_languages = tuple(context.settings.expected_languages)
        missing_languages = tuple(language for language in expected_languages if language not in languages)
        coverage_ratio = (
            (len(expected_languages) - len(missing_languages)) / len(expected_languages)
            if expected_languages
            else None
        )
        verdict = Verdict.INFO if missing_languages or not expected_languages else Verdict.PASS
        detail_parts = [f"Обнаружены: {', '.join(sorted(languages)) or 'не определены'}."]
        if expected_languages:
            detail_parts.append(f"Ожидались: {', '.join(expected_languages)}.")
        if missing_languages:
            detail_parts.append(f"Отсутствуют: {', '.join(missing_languages)}.")
        elif expected_languages:
            detail_parts.append("Ожидаемый набор языков найден.")
        else:
            detail_parts.append("Ожидаемый набор языков не задан; строка носит мониторинговый характер.")
        findings = [
            _finding(
                unit,
                self.name,
                Criterion.LANGUAGE,
                Severity.INFO,
                verdict,
                0.8,
                None,
                None,
                [Evidence(title="Языковые версии", detail=" ".join(detail_parts))],
                "Использовать как мониторинг языкового покрытия; добавлять языковые версии только если это требуется политикой платформы.",
                False,
                extra={
                    "languages": sorted(languages),
                    "expected_languages": list(expected_languages),
                    "missing_languages": list(missing_languages),
                    "coverage_ratio": coverage_ratio,
                    "mismatches": mismatches,
                },
            )
        ]
        for mismatch in mismatches:
            findings.append(
                _finding(
                    unit,
                    self.name,
                    Criterion.LANGUAGE,
                    Severity.MINOR,
                    Verdict.WARNING,
                    0.75,
                    None,
                    TextLocation(file_path=mismatch["file_path"]),
                    [
                        Evidence(
                            title="Несовпадение языка",
                            detail=f"В имени файла ожидается {mismatch['expected']}, по тексту похоже на {mismatch['detected']}.",
                        )
                    ],
                    "Проверить имя файла или содержимое языковой версии.",
                    True,
                    extra=mismatch,
                )
            )
        return findings


class ExamPresenceChecker(BaseChecker):
    """Ищет признаки финальной проверки или экзамена в единице контента."""

    name = "exam_presence_checker"

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        del entities, context
        markers = ("exam", "final", "экзамен", "финаль", "итогов")
        matched_paths = [file.relative_path for file in unit.files if any(marker in file.relative_path.lower() for marker in markers)]
        if matched_paths:
            return [
                _finding(
                    unit,
                    self.name,
                    Criterion.EXAM,
                    Severity.INFO,
                    Verdict.PASS,
                    0.8,
                    None,
                    None,
                    [Evidence(title="Финальная проверка", detail=f"Найдены признаки: {', '.join(matched_paths[:5])}.")],
                    "Действий не требуется; признак финальной проверки найден.",
                    False,
                )
            ]
        return [
            _finding(
                unit,
                self.name,
                Criterion.EXAM,
                Severity.INFO,
                Verdict.UNKNOWN,
                0.55,
                None,
                None,
                [Evidence(title="Финальная проверка", detail="В локальной папке нет явных признаков экзамена или финальной проверки.")],
                "Если наличие экзамена определяется платформой, добавить внешний источник данных или поле в выгрузке.",
                True,
            )
        ]


class ImageQualityChecker(BaseChecker):
    """Проверяет размеры локальных изображений, на которые ссылается Markdown."""

    name = "image_quality_checker"

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        for entity in _entities_of_type(entities, EntityType.IMAGE):
            target, _fragment = urldefrag(entity.value)
            parsed = urlparse(target)
            if parsed.scheme in {"http", "https"} or not target:
                continue
            source_file = unit.root_path / entity.location.file_path
            target_path = (source_file.parent / target).resolve()
            if not target_path.exists() or not _is_inside(target_path, unit.root_path):
                continue
            dimensions = read_image_dimensions(target_path)
            if dimensions is None:
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.IMAGE_QUALITY,
                        Severity.INFO,
                        Verdict.UNKNOWN,
                        0.45,
                        entity.quote,
                        entity.location,
                        [Evidence(title="Изображение", detail=f"Не удалось определить размер: {entity.value}")],
                        "Проверить изображение вручную или добавить поддержку его формата.",
                        True,
                    )
                )
                continue
            width, height = dimensions
            if width < context.settings.min_image_width or height < context.settings.min_image_height:
                if is_decorative_image(entity.value, entity.quote, width, height):
                    continue
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.IMAGE_QUALITY,
                        Severity.MINOR,
                        Verdict.WARNING,
                        0.85,
                        entity.quote,
                        entity.location,
                        [Evidence(title="Размер изображения", detail=f"{width}x{height}, минимум {context.settings.min_image_width}x{context.settings.min_image_height}.")],
                        "Заменить изображение на более качественное или подтвердить, что малый размер допустим.",
                        True,
                    )
                )
        return findings


class ReadabilityChecker(BaseChecker):
    """Ищет незавершённые фрагменты и грубые проблемы читаемости."""

    name = "readability_checker"
    prompt_version = "readability_checker:v2"
    long_line_candidate_threshold = 260
    max_long_line_candidates = 8
    SYSTEM_PROMPT = """Ты проверяешь читаемость учебного материала.
Тебе дадут строки-кандидаты, которые технически длинные. Не считай длину строки самостоятельной ошибкой.
Оцени, мешает ли фрагмент методической читаемости: перегружен ли он несколькими мыслями,
списками без структуры, длинной инструкцией без разбивки.
Если длинная строка является таблицей, кодом, ссылкой, командой, цитатой, YAML/JSON или нормально читаемым абзацем, верни verdict='pass'.
Верни только JSON: {"verdict":"pass|warning|fail|unknown","severity":"info|minor|major","confidence":0.0,
"problem_lines":[1],"evidence":"","recommendation":""}.
verdict='warning' ставь только когда текст реально стоит разбить или переписать для учебной читаемости.
verdict='fail' используй только для грубой проблемы, которая серьёзно мешает понять задание.
verdict='unknown' используй, если контекста недостаточно.
Все пояснения и рекомендации пиши на русском языке."""

    PLACEHOLDER_RE = re.compile(
        r"\b(TODO|TBD|FIXME|lorem ipsum)\b|"
        r"\bздесь\s+будет\s+(?:текст|описание|картинка|изображение|пример|раздел|таблица|ссылка)\b|"
        r"\b(?:дописать|заглушка)\b",
        re.IGNORECASE,
    )

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        del entities
        findings: list[Finding] = []
        for file in unit.files:
            check_long_lines = file.kind in {"readme", "material"}
            long_lines: list[tuple[int, int, str]] = []
            for index, line in enumerate(file.text.splitlines(), start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                placeholder = self.PLACEHOLDER_RE.search(stripped)
                if placeholder:
                    findings.append(
                        _finding(
                            unit,
                            self.name,
                            Criterion.READABILITY,
                            Severity.MAJOR,
                            Verdict.FAIL,
                            0.9,
                            stripped[:320],
                            TextLocation(file_path=file.relative_path, line_start=index, line_end=index),
                            [Evidence(title="Незавершённый фрагмент", detail=f"Найден маркер: {placeholder.group(0)}")],
                            "Заменить заглушку на финальный текст или удалить незавершённый фрагмент.",
                            True,
                        )
                    )
                if check_long_lines and len(stripped) > self.long_line_candidate_threshold:
                    long_lines.append((index, len(stripped), stripped[:700]))
            if long_lines:
                finding = self._model_long_line_finding(unit, file.relative_path, long_lines, context)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _model_long_line_finding(
        self,
        unit: ContentUnit,
        file_path: str,
        long_lines: list[tuple[int, int, str]],
        context: CheckContext,
    ) -> Finding | None:
        """Передаём длинные строки модели: сама длина строки не является вердиктом."""

        if context.model_client is None:
            return None

        candidates = [
            {"line": line, "length": length, "text": text}
            for line, length, text in long_lines[: self.max_long_line_candidates]
        ]
        prompt_payload = {
            "file_path": file_path,
            "candidate_rule": (
                f"Строки длиннее {self.long_line_candidate_threshold} символов "
                "отправлены только как кандидаты."
            ),
            "candidates": candidates,
        }
        prompt = json.dumps(prompt_payload, ensure_ascii=False, indent=2)
        cache_key = _hash_cache_key("readability", f"{file_path}|{prompt}")
        try:
            record, cache_hit = _cached_model_json(
                context,
                "readability",
                cache_key,
                context.model_client,
                self.SYSTEM_PROMPT,
                prompt,
                self.prompt_version,
            )
        except OpenRouterError as exc:
            return _external_check_error(unit, self.name, Criterion.READABILITY, exc)

        item = _first_result_item(record.get("response"))
        if item is None:
            return None
        verdict = _enum_or_default(Verdict, item.get("verdict"), Verdict.UNKNOWN)
        if verdict not in {Verdict.WARNING, Verdict.FAIL}:
            return None

        severity = _enum_or_default(Severity, item.get("severity"), Severity.MINOR)
        problem_lines = _readability_problem_lines(item.get("problem_lines"))
        location = (
            TextLocation(file_path=file_path, line_start=problem_lines[0], line_end=problem_lines[-1])
            if problem_lines
            else TextLocation(file_path=file_path)
        )
        evidence_text = _model_text(
            item,
            ("evidence", "reason", "explanation"),
            "Модель оценила длинные строки как проблему читаемости.",
        )
        recommendation = _model_text(
            item,
            ("recommendation", "fix", "action"),
            "Разбить перегруженный фрагмент на короткие абзацы или пункты.",
        )
        return _finding(
            unit,
            self.name,
            Criterion.READABILITY,
            severity,
            verdict,
            _parse_confidence(item.get("confidence")),
            None,
            location,
            [Evidence(title="Оценка читаемости LLM", detail=evidence_text)],
            recommendation,
            True,
            extra={
                "candidate_count": len(long_lines),
                "problem_lines": problem_lines,
                "cache_hit": cache_hit,
                "examples": [candidate["text"] for candidate in candidates[:5]],
            },
            checked_at=_checked_at_from_record(record),
            prompt_version=self.prompt_version,
        )


class RightsAndOriginalityChecker(BaseChecker):
    """Проверяет права на материалы и признаки заимствований."""

    name = "rights_originality_checker"
    prompt_version = "rights_originality_checker:v1"
    max_external_lookups = 6
    PROVENANCE_SYSTEM_PROMPT = """Ты собираешь доказательства о происхождении и правах на ресурс из учебного контента.
Верни только JSON: {"likely_source":"","license":"","confidence":0.0,"sources":[{"title":"","url":""}],"note":""}.
Не делай вывод о нарушении: укажи вероятный источник и лицензию, если нашёл.
Если источников нет, оставь sources пустым и confidence низким. Пиши пояснения на русском."""

    def __init__(self, code_similarity_index: dict[str, list[CodeMatch]] | None = None) -> None:
        self.code_similarity_index = code_similarity_index or {}

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        signals: list[RightsSignal] = []
        signals.extend(self._project_license_signals(unit))
        signals.extend(self._dependency_license_signals(unit, context))
        signals.extend(image_rights_signals(unit, entities))
        signals.extend(self._dataset_rights_signals(unit))
        signals.extend(self._code_similarity_signals(unit))
        signals.extend(self._external_evidence_signals(unit, entities, context))

        findings: list[Finding] = []
        for signal in signals:
            severity, verdict, needs_review = grade_rights_signal(signal)
            findings.append(
                _finding(
                    unit,
                    self.name,
                    Criterion.RIGHTS,
                    severity,
                    verdict,
                    signal.confidence,
                    signal.quote,
                    signal.location,
                    [Evidence(title=signal.title, detail=signal.detail, url=signal.url)],
                    signal.recommendation,
                    needs_review,
                    extra={
                        "kind": signal.kind,
                        "risk": signal.risk,
                        "deterministic": signal.deterministic,
                    },
                    source=signal.source,
                )
            )
        return findings

    def _project_license_signals(self, unit: ContentUnit) -> list[RightsSignal]:
        has_license_file = any(
            Path(file.relative_path).name.lower().startswith(("license", "notice"))
            for file in unit.files
        )
        readme_mentions_license = any(
            ("license" in file.text.lower() or "лицензи" in file.text.lower())
            for file in unit.files
            if file.kind == "readme"
        )
        scan = scan_project_licenses(unit.root_path)
        if has_license_file or readme_mentions_license or (scan is not None and scan.spdx):
            return []
        return [
            RightsSignal(
                kind="project_license",
                risk="no_license_only",
                deterministic=True,
                title="Лицензия проекта",
                detail="Не найден LICENSE/NOTICE и нет упоминания лицензии в README.",
                recommendation="Проверить, нужна ли лицензия для материалов и кода этой единицы.",
                confidence=0.6,
            )
        ]

    def _dependency_license_signals(self, unit: ContentUnit, context: CheckContext) -> list[RightsSignal]:
        manifests = [file for file in unit.files if Path(file.relative_path).name.lower() in MANIFEST_NAMES]
        signals: list[RightsSignal] = []
        seen: set[tuple[str, str, str]] = set()
        if context.settings.allow_network:
            registry_client = DependencyRegistryClient(context.settings.link_timeout_seconds)
            for candidate in extract_dependency_candidates(unit):
                if candidate.group in {"engine", "runtime"}:
                    continue
                metadata = _dependency_registry_metadata(candidate, registry_client, context)
                if metadata is None or not metadata.license_spdx:
                    continue
                signal = _dependency_license_signal(candidate.name, metadata.license_spdx, metadata.source_url, candidate.location)
                if signal is None:
                    continue
                key = (candidate.ecosystem, candidate.name.lower(), metadata.license_spdx)
                if key in seen:
                    continue
                seen.add(key)
                signals.append(signal)

        for package, spdx in resolve_dependency_licenses(manifests):
            signal = _dependency_license_signal(package, spdx, None, None)
            if signal is not None:
                key = ("local", package.lower(), spdx or "")
                if key not in seen:
                    seen.add(key)
                    signals.append(signal)
        return signals

    def _dataset_rights_signals(self, unit: ContentUnit) -> list[RightsSignal]:
        signals: list[RightsSignal] = []
        for file in unit.files:
            if file.kind not in {"readme", "material", "text"}:
                continue
            for line_number, line in enumerate(file.text.splitlines(), start=1):
                if not DATASET_RE.search(line):
                    continue
                if self._has_license_terms_near(file.text, line.strip()):
                    continue
                signals.append(
                    RightsSignal(
                        kind="dataset_rights",
                        risk="no_source",
                        deterministic=True,
                        title="Датасет без условий использования",
                        detail=f"Упоминание датасета без источника или лицензии: {line.strip()[:240]}",
                        recommendation="Добавить ссылку на датасет, его лицензию и условия использования.",
                        quote=line.strip()[:500],
                        location=TextLocation(file_path=file.relative_path, line_start=line_number, line_end=line_number),
                        confidence=0.7,
                    )
                )
        return signals[:5]

    def _code_similarity_signals(self, unit: ContentUnit) -> list[RightsSignal]:
        signals: list[RightsSignal] = []
        for match in self.code_similarity_index.get(unit.unit_id, []):
            if match.similarity < 0.8 or match.attributed:
                continue
            signals.append(
                RightsSignal(
                    kind="code_similarity",
                    risk="no_source",
                    deterministic=True,
                    title="Похожий код без атрибуции",
                    detail=f"Совпадение {match.similarity:.0%} с единицей {match.other_unit_id} без ссылки на источник.",
                    recommendation="Проверить заимствование между сдачами и добавить атрибуцию либо переработать код.",
                    source=match.other_unit_id,
                    confidence=min(1.0, max(0.0, match.similarity)),
                )
            )
        return signals

    def _external_evidence_signals(
        self,
        unit: ContentUnit,
        entities: list[ExtractedEntity],
        context: CheckContext,
    ) -> list[RightsSignal]:
        if not context.settings.allow_network or context.fact_model_client is None:
            return []

        signals: list[RightsSignal] = []
        for query in self._evidence_queries(unit, entities)[: self.max_external_lookups]:
            prompt = json.dumps(query, ensure_ascii=False, indent=2)
            try:
                record, _cache_hit = _cached_model_json(
                    context,
                    "rights",
                    _hash_cache_key("rights", prompt),
                    context.fact_model_client,
                    self.PROVENANCE_SYSTEM_PROMPT,
                    prompt,
                    self.prompt_version,
                )
            except OpenRouterError:
                continue
            item = _first_result_item(record.get("response")) or {}
            sources = _sources_from_item(item)
            if not sources:
                continue
            note = _model_text(item, ("note", "likely_source", "license"), "Поиск нашёл возможный источник ресурса.")
            signals.append(
                RightsSignal(
                    kind=str(query["kind"]),
                    risk="no_source",
                    deterministic=False,
                    title=str(query["title"]),
                    detail=note,
                    recommendation="Передать методологу: подтвердить источник и права по найденным ссылкам.",
                    quote=query.get("quote"),
                    location=query.get("location"),
                    source=_source_summary(sources),
                    url=_first_source_url(sources),
                    confidence=_parse_confidence(item.get("confidence")),
                )
            )
        return signals

    def _evidence_queries(self, unit: ContentUnit, entities: list[ExtractedEntity]) -> list[dict[str, object]]:
        queries: list[dict[str, object]] = []
        for file in unit.files:
            if file.kind not in {"readme", "material", "text"}:
                continue
            for line_number, line in enumerate(file.text.splitlines(), start=1):
                if DATASET_RE.search(line) and not self._has_license_terms_near(file.text, line.strip()):
                    queries.append(
                        {
                            "kind": "dataset_rights",
                            "title": "Возможный источник датасета",
                            "text": f"Найди источник, лицензию и условия использования датасета из фрагмента: {line.strip()}",
                            "quote": line.strip()[:500],
                            "location": TextLocation(file_path=file.relative_path, line_start=line_number, line_end=line_number),
                        }
                    )
        queries.extend(image_evidence_queries(entities))
        return queries

    def _has_license_terms_near(self, text: str, needle: str) -> bool:
        position = text.lower().find(needle.lower())
        if position < 0:
            return False
        fragment = text[max(0, position - 300) : position + len(needle) + 300]
        return bool(re.search(r"license|licence|terms|rights|лицензи|услови|права|cc-by|mit|apache", fragment, flags=re.IGNORECASE))


RightsChecker = RightsAndOriginalityChecker


class MarketFitChecker(BaseChecker):
    """Проверяет наличие прикладного бизнес-контекста в учебном проекте."""

    name = "market_fit_checker"
    prompt_version = "market_fit_checker:v1"
    signal_labels = {
        "real_data": "Работа с реальными данными",
        "business_context": "Бизнес-контекст",
        "success_metrics": "Бизнес-метрики или требования",
    }
    signal_patterns = {
        "real_data": (
            r"\b(dataset|datasets|real data|production data|historical data|customer data|sales data|transaction data|"
            r"kaggle|open data|huggingface datasets|uci repository|data source)\b",
            r"(датасет\w*|выборк\w*|реальн\w*\s+данн\w*|историческ\w*\s+данн\w*|открыт\w*\s+данн\w*|"
            r"обезличенн\w*\s+данн\w*|данн\w*\s+(?:клиент\w*|пользовател\w*|продаж\w*|транзакц\w*|заказ\w*|заявк\w*)|"
            r"набор\s+данн\w*)",
        ),
        "business_context": (
            r"\b(business problem|business case|customer problem|stakeholder|user persona|target audience|use case|client need|"
            r"business process|market segment|customer base|online booking|manual labour|manual labor|employee labour costs|"
            r"employee labor costs|barbershop|barbershops|booking system)\b",
            r"(бизнес[-\s]?задач\w*|бизнес[-\s]?контекст\w*|проблем\w*\s+бизнес\w*|заказчик\w*|"
            r"целев\w*\s+аудитори\w*|пользовательск\w*\s+сценари\w*|потребност\w*\s+(?:клиент\w*|пользовател\w*)|"
            r"бизнес[-\s]?процесс\w*|сегмент\w*\s+рынк\w*|клиентск\w*\s+баз\w*|онлайн[-\s]?запис\w*|"
            r"ручн\w*\s+труд\w*|трудозатрат\w*|барбершоп\w*)",
        ),
        "success_metrics": (
            r"\b(kpi|conversion|revenue|retention|churn|nps|ltv|cac|arpu|roi|gmv|mau|dau|sla|"
            r"business metric|business requirement|quality target|service level|time to resolution)\b",
            r"(бизнес[-\s]?метрик\w*|метрик\w*\s+успех\w*|kpi|конверси\w*|выручк\w*|удержан\w*|отток\w*|"
            r"средн\w*\s+чек\w*|стоимост\w*\s+(?:привлечени\w*|обработк\w*)|врем\w*\s+обработк\w*|\bsla\b|"
            r"бизнес[-\s]?требован\w*|требован\w*\s+бизнес\w*|целев\w*\s+показател\w*)",
        ),
    }
    SYSTEM_PROMPT = """Ты проверяешь соответствие учебного проекта прикладной рыночной задаче.
На входе есть результаты правил: наличие реальных данных, бизнес-контекста, бизнес-метрик или требований.
Проверь, не пропустили ли правила перефразированный бизнес-контекст.
Верни только JSON: {"verdict":"pass|warning|unknown","severity":"info|minor|major","confidence":0.0,
"evidence":"","recommendation":"","real_data":true,"business_context":true,"success_metrics":true}.
real_data=true ставь только при реальном, внешнем, публичном, историческом или production-like датасете; тестовые фикстуры, мок-данные и технические отчёты не считаются.
business_context=true ставь только если есть бизнес-проблема, целевая аудитория, заказчик, пользовательский сценарий или бизнес-процесс.
success_metrics=true ставь только если есть бизнес-метрики, бизнес-требования, целевые показатели или ограничения результата.
Не ставь severity='critical'. Если данных мало, ставь verdict='unknown'.
Все пояснения и рекомендации пиши на русском языке."""

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        del entities
        signals = _market_fit_signals(unit, self.signal_patterns)
        finding = self._finding_from_signals(unit, signals, model_item=None, record=None, cache_hit=False)
        if context.model_client is None or finding.verdict == Verdict.PASS:
            return [finding]

        model_result = self._model_refinement(unit, signals, context)
        if model_result is None:
            return [finding]
        item, record, cache_hit = model_result
        return [self._finding_from_signals(unit, signals, model_item=item, record=record, cache_hit=cache_hit)]

    def _model_refinement(
        self,
        unit: ContentUnit,
        signals: dict[str, dict[str, object]],
        context: CheckContext,
    ) -> tuple[dict[str, Any], dict[str, Any], bool] | None:
        """Уточняет слабые эвристические сигналы моделью."""

        payload = {
            "unit": unit.name,
            "signals": signals,
            "context": _compact_unit_context(unit, limit=8000),
        }
        prompt = json.dumps(payload, ensure_ascii=False, indent=2)
        try:
            record, cache_hit = _cached_model_json(
                context,
                "market_fit",
                _hash_cache_key("market_fit", prompt),
                context.model_client,
                self.SYSTEM_PROMPT,
                prompt,
                self.prompt_version,
            )
        except OpenRouterError:
            return None
        item = _first_result_item(record.get("response"))
        return (item, record, cache_hit) if item is not None else None

    def _finding_from_signals(
        self,
        unit: ContentUnit,
        signals: dict[str, dict[str, object]],
        model_item: dict[str, Any] | None,
        record: dict[str, Any] | None,
        cache_hit: bool,
    ) -> Finding:
        """Собирает одну строку отчёта по трём под-оценкам."""

        merged = _merge_market_signals(signals, model_item)
        score = sum(1 for item in merged.values() if item["present"])
        verdict, severity = _market_fit_verdict(score)
        confidence = 0.65 + 0.1 * score
        if model_item is not None:
            verdict = _verdict_from_model_value(model_item.get("verdict"), verdict)
            severity = _enum_or_default(Severity, model_item.get("severity"), severity)
            if severity == Severity.CRITICAL:
                severity = Severity.MAJOR
            confidence = _parse_confidence(model_item.get("confidence"))

        evidence_text = _market_fit_evidence(merged, self.signal_labels)
        if model_item is not None:
            model_evidence = _optional_model_text(model_item.get("evidence"))
            if model_evidence:
                evidence_text = f"{evidence_text} Модель: {model_evidence}"
        recommendation = _market_fit_recommendation(merged, model_item)
        return _finding(
            unit,
            self.name,
            Criterion.MARKET_FIT,
            severity,
            verdict,
            confidence,
            None,
            _first_market_location(merged),
            [Evidence(title="Проверка соответствия рынку", detail=evidence_text)],
            recommendation,
            verdict != Verdict.PASS,
            extra={
                "market_fit_score": score,
                "sub_checks": merged,
                "model_refined": model_item is not None,
                "cache_hit": cache_hit,
            },
            checked_at=_checked_at_from_record(record) if record is not None else None,
            prompt_version=self.prompt_version if model_item is not None else None,
        )


class FactCheckerPerplexity(BaseChecker):
    """Проверяет фактологические утверждения через поисковую модель Perplexity."""

    name = "fact_checker_perplexity"
    prompt_version = "fact_checker_perplexity:v1"
    max_claims = 8
    SYSTEM_PROMPT = """Ты проверяешь фактологическое утверждение из учебного контента через внешние источники.
Верни только JSON: {"verdict":"pass|warning|fail|unknown","confidence":0.0,"evidence":"","sources":[{"title":"","url":""}],"recommendation":""}.
verdict='pass' ставь только если утверждение подтверждено надёжным источником.
verdict='warning' ставь, если утверждение частично устарело, неполное или требует уточнения.
verdict='fail' ставь, если утверждение противоречит актуальным источникам.
verdict='unknown' ставь, если источников недостаточно.
Не придумывай источники; если ссылки нет, оставь sources пустым списком.
Все пояснения и рекомендации пиши на русском языке."""

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        del entities
        if context.fact_model_client is None:
            return []

        claims = _extract_fact_claims(unit, self.max_claims)
        findings: list[Finding] = []
        for claim in claims:
            cache_key = _hash_cache_key("fact", str(claim["claim"]))
            prompt = _fact_check_prompt(claim)
            try:
                record, cache_hit = _cached_model_json(
                    context,
                    "fact",
                    cache_key,
                    context.fact_model_client,
                    self.SYSTEM_PROMPT,
                    prompt,
                    self.prompt_version,
                )
            except OpenRouterError as exc:
                findings.append(_external_check_error(unit, self.name, Criterion.CORRECTNESS, exc))
                break

            item = _first_result_item(record.get("response"))
            if item is None:
                continue
            findings.append(_finding_from_fact_item(unit, self.name, claim, item, record, cache_hit, self.prompt_version))
        return findings


class ReadmeFactActualityChecker(BaseChecker):
    """Проверяет фактологию и актуальность только в README.md и README_RUS.md."""

    name = "readme_fact_actuality_checker"
    prompt_version = "readme_fact_actuality_checker:v1"
    max_lines_per_batch = 90
    max_batches = 8
    SYSTEM_PROMPT = """Ты проверяешь README учебного проекта через внешние источники.
Твоя задача — найти только утверждения, которые требуют внимания методолога:
фактологические ошибки, устаревшие даты, неверные определения, устаревшие или конфликтующие стеки технологий, версии, стандарты, библиотеки и инструменты.
Игнорируй правила выполнения задания, требования курса, навигацию, оглавление, вкусовые оценки и формулировки без проверяемого внешнего факта.
Если во фрагменте нет проблемы, верни пустой список findings.
Верни только JSON: {"findings":[{"claim":"","verdict":"warning|fail|unknown","severity":"info|minor|major|critical","confidence":0.0,"file_path":"","line_start":1,"evidence":"","sources":[{"title":"","url":""}],"recommendation":"","support_status":"","latest_version":"","recommended_version":""}]}.
Все найденные проблемы относятся к критерию «Точность и корректность», включая даты, версии, поддержку технологий, библиотеки, стандарты и стеки.
verdict='fail' ставь, если утверждение противоречит источникам.
verdict='warning' ставь, если утверждение частично устарело, неполное или нуждается в уточнении.
verdict='unknown' ставь только для важного утверждения, которое нельзя подтвердить источниками.
Не придумывай источники; если ссылки нет, оставь sources пустым списком.
Все пояснения и рекомендации пиши на русском языке."""

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        del entities
        if context.fact_model_client is None:
            return []

        findings: list[Finding] = []
        for batch in _extract_readme_fact_batches(unit, self.max_lines_per_batch, self.max_batches):
            cache_key = _hash_cache_key("readme_fact", f"{self.prompt_version}|{batch['file_path']}|{batch['text']}")
            prompt = _readme_fact_check_prompt(batch)
            try:
                record, cache_hit = _cached_model_json(
                    context,
                    "readme_fact",
                    cache_key,
                    context.fact_model_client,
                    self.SYSTEM_PROMPT,
                    prompt,
                    self.prompt_version,
                )
            except OpenRouterError as exc:
                findings.append(_external_check_error(unit, self.name, Criterion.CORRECTNESS, exc))
                break

            for item in _result_items(record.get("response")):
                if _is_uninformative_readme_fact_item(item) or not _is_allowed_readme_fact_item(item, batch):
                    continue
                finding = _finding_from_readme_fact_item(unit, self.name, batch, item, record, cache_hit, self.prompt_version)
                if finding.verdict != Verdict.PASS:
                    findings.append(finding)
        return findings


class TechFreshnessChecker(BaseChecker):
    """Проверяет актуальность технологий и версий с источниками."""

    name = "tech_freshness_checker"
    prompt_version = "tech_freshness_checker:v1"
    max_candidates = 12
    SYSTEM_PROMPT = """Ты проверяешь актуальность технологии, версии или стандарта в учебном контенте.
Верни только JSON: {"verdict":"pass|warning|fail|unknown","severity":"info|minor|major|critical","confidence":0.0,"support_status":"","latest_version":"","recommended_version":"","evidence":"","sources":[{"title":"","url":""}],"recommendation":""}.
support_status пиши коротко на русском: поддерживается, устарело, не поддерживается, окончание поддержки, неизвестно.
latest_version заполняй только когда источник позволяет назвать последнюю стабильную версию.
recommended_version заполняй только когда можно дать практическую рекомендацию по обновлению.
verdict='pass' ставь, если текущая версия поддерживается и подходит для учебного контента.
verdict='warning' ставь, если версия устарела, но ещё допустима.
verdict='fail' ставь, если версия не поддерживается или вводит студентов в заблуждение.
verdict='unknown' ставь, если источников недостаточно.
Не придумывай источники; если ссылки нет, оставь sources пустым списком.
Все пояснения и рекомендации пиши на русском языке."""

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        selected = _select_technology_candidates(entities, self.max_candidates)
        if not selected:
            return []

        if context.tech_model_client is None:
            return [self._fallback_candidate_finding(unit, selected)]

        findings: list[Finding] = []
        for entity in selected:
            cache_key = _hash_cache_key("technology", _normalise_technology_value(entity.value))
            prompt = _technology_check_prompt(entity)
            try:
                record, cache_hit = _cached_model_json(
                    context,
                    "technology",
                    cache_key,
                    context.tech_model_client,
                    self.SYSTEM_PROMPT,
                    prompt,
                    self.prompt_version,
                )
            except OpenRouterError as exc:
                findings.append(_external_check_error(unit, self.name, Criterion.ACTUALITY, exc))
                break

            item = _first_result_item(record.get("response"))
            if item is None:
                continue
            if _is_uninformative_technology_item(item):
                continue
            findings.append(_finding_from_technology_item(unit, self.name, entity, item, record, cache_hit, self.prompt_version))
        return findings

    def _fallback_candidate_finding(self, unit: ContentUnit, selected: list[ExtractedEntity]) -> Finding:
        """Сохраняем прежний режим: без модели показываем кандидатов на ручную проверку."""

        preview = ", ".join(entity.value for entity in selected[:20])
        if len(selected) > 20:
            preview = f"{preview}, ..."
        return _finding(
            unit,
            self.name,
            Criterion.ACTUALITY,
            Severity.INFO,
            Verdict.UNKNOWN,
            0.55,
            None,
            None,
            [Evidence(title="Кандидаты на проверку", detail=f"Найдено {len(selected)} сущностей: {preview}")],
            "Включить модельный контур, чтобы получить источник, статус поддержки и рекомендуемую версию.",
            True,
            extra={"candidate_count": len(selected), "sample_values": [entity.value for entity in selected[:20]]},
            support_status="не проверялось",
        )


TechnologyFreshnessChecker = TechFreshnessChecker


class DependencyFreshnessChecker(BaseChecker):
    """Проверяет зависимости проекта через официальные реестры и запасной поиск."""

    name = "dependency_freshness_checker"
    prompt_version = "dependency_freshness_checker:v1"
    max_candidates = 50
    SYSTEM_PROMPT = """Ты проверяешь актуальность зависимости проекта.
Официальный реестр не дал уверенного ответа, поэтому нужен запасной поиск по открытым источникам.
Верни только JSON: {"verdict":"pass|warning|fail|unknown","severity":"info|minor|major","confidence":0.0,
"support_status":"","latest_version":"","recommended_version":"","evidence":"","sources":[{"title":"","url":""}],"recommendation":""}.
Не придумывай версии и источники. Если источников недостаточно, ставь verdict='unknown'.
Все пояснения и рекомендации пиши на русском языке."""

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        del entities
        candidates = extract_dependency_candidates(unit)[: self.max_candidates]
        if not candidates:
            return []
        registry_candidates = [candidate for candidate in candidates if candidate.group not in {"engine", "runtime"}]
        if not registry_candidates:
            return []
        if not context.settings.allow_network and context.fact_model_client is None:
            return [self._network_required_finding(unit, registry_candidates)]

        findings: list[Finding] = []
        metadata_by_key: dict[tuple[str, str], DependencyMetadata] = {}
        registry_client = DependencyRegistryClient(context.settings.link_timeout_seconds)
        for candidate in registry_candidates:
            metadata = self._registry_metadata(candidate, registry_client, context)
            if metadata is None:
                fallback = self._fallback_model_finding(unit, candidate, context)
                if fallback is not None:
                    findings.append(fallback)
                continue
            metadata_by_key[dependency_identity(candidate)] = metadata
            dependency_finding = self._finding_from_dependency(unit, candidate, metadata)
            if dependency_finding is not None:
                findings.append(dependency_finding)

        findings.extend(self._compatibility_findings(unit, candidates, metadata_by_key))
        return findings

    def _registry_metadata(
        self,
        candidate: DependencyCandidate,
        registry_client: DependencyRegistryClient,
        context: CheckContext,
    ) -> DependencyMetadata | None:
        """Получает метаданные официального реестра с кэшированием."""

        return _dependency_registry_metadata(candidate, registry_client, context)

    def _finding_from_dependency(
        self,
        unit: ContentUnit,
        candidate: DependencyCandidate,
        metadata: DependencyMetadata,
    ) -> Finding | None:
        """Создаёт находку по актуальности одной зависимости."""

        if candidate.ecosystem == "docker" and candidate.spec == "latest":
            return _finding(
                unit,
                self.name,
                Criterion.ACTUALITY,
                Severity.MINOR,
                Verdict.WARNING,
                0.8,
                _dependency_quote(candidate),
                candidate.location,
                [Evidence(title="Docker", detail="Образ использует тег latest.", url=metadata.source_url)],
                "Закрепить конкретный тег образа, чтобы окружение проекта было воспроизводимым.",
                True,
                source=metadata.source_url,
                checked_at=metadata.checked_at,
                support_status="не закреплено",
            )
        if is_unbounded_spec(candidate.spec) and candidate.name.lower() not in {"python", "node"}:
            return _finding(
                unit,
                self.name,
                Criterion.ACTUALITY,
                Severity.INFO,
                Verdict.UNKNOWN,
                0.7,
                _dependency_quote(candidate),
                candidate.location,
                [Evidence(title="Официальный реестр", detail="Версия зависимости не ограничена.", url=metadata.source_url)],
                "Закрепить допустимый диапазон версий или подтвердить, что плавающая версия допустима.",
                True,
                source=metadata.source_url,
                checked_at=metadata.checked_at,
                support_status="не закреплено",
                latest_version=metadata.latest_version,
                recommended_version=metadata.latest_version,
            )
        if is_pinned_outdated(candidate.spec, metadata.latest_version):
            return _finding(
                unit,
                self.name,
                Criterion.ACTUALITY,
                Severity.MINOR,
                Verdict.WARNING,
                0.85,
                _dependency_quote(candidate),
                candidate.location,
                [Evidence(title="Официальный реестр", detail="Закреплённая версия ниже последней.", url=metadata.source_url)],
                "Проверить совместимость и обновить зависимость до поддерживаемой версии.",
                True,
                source=metadata.source_url,
                checked_at=metadata.checked_at,
                support_status="есть новая версия",
                latest_version=metadata.latest_version,
                recommended_version=metadata.latest_version,
            )
        return _finding(
            unit,
            self.name,
            Criterion.ACTUALITY,
            Severity.INFO,
            Verdict.PASS,
            0.75,
            _dependency_quote(candidate),
            candidate.location,
            [Evidence(title="Официальный реестр", detail="Зависимость проверена, явных проблем не найдено.", url=metadata.source_url)],
            "Действий не требуется; при обновлении проекта повторить проверку совместимости.",
            False,
            source=metadata.source_url,
            checked_at=metadata.checked_at,
            support_status="проверено",
            latest_version=metadata.latest_version,
        )

    def _compatibility_findings(
        self,
        unit: ContentUnit,
        candidates: list[DependencyCandidate],
        metadata_by_key: dict[tuple[str, str], DependencyMetadata],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for issue in find_compatibility_issues(candidates, metadata_by_key):
            findings.append(_finding_from_dependency_issue(unit, self.name, issue))
        return findings

    def _fallback_model_finding(
        self,
        unit: ContentUnit,
        candidate: DependencyCandidate,
        context: CheckContext,
    ) -> Finding | None:
        """Использует Perplexity как запасной источник, если официальный реестр не дал ответ."""

        if context.fact_model_client is None:
            return _finding(
                unit,
                self.name,
                Criterion.ACTUALITY,
                Severity.INFO,
                Verdict.UNKNOWN,
                0.45,
                _dependency_quote(candidate),
                candidate.location,
                [Evidence(title="Официальный реестр", detail="Не удалось проверить зависимость через официальный источник.")],
                "Повторить проверку позже или включить модельный контур для запасной проверки.",
                True,
                support_status="не проверялось",
            )

        prompt = json.dumps(
            {
                "ecosystem": candidate.ecosystem,
                "name": candidate.name,
                "declared_version": candidate.spec,
                "file_path": candidate.location.file_path,
                "line_start": candidate.location.line_start,
            },
            ensure_ascii=False,
            indent=2,
        )
        try:
            record, cache_hit = _cached_model_json(
                context,
                "dependency_fallback",
                _hash_cache_key("dependency_fallback", prompt),
                context.fact_model_client,
                self.SYSTEM_PROMPT,
                prompt,
                self.prompt_version,
            )
        except OpenRouterError as exc:
            return _external_check_error(unit, self.name, Criterion.ACTUALITY, exc)

        item = _first_result_item(record.get("response"))
        if item is None:
            return None
        finding = _finding_from_dependency_model_item(unit, self.name, candidate, item, record, cache_hit, self.prompt_version)
        return finding if finding.verdict != Verdict.PASS else None

    def _network_required_finding(self, unit: ContentUnit, candidates: list[DependencyCandidate]) -> Finding:
        """Фиксирует, что зависимости найдены, но внешняя сверка не выполнялась."""

        preview = ", ".join(f"{item.name}{item.spec}" for item in candidates[:12])
        return _finding(
            unit,
            self.name,
            Criterion.ACTUALITY,
            Severity.INFO,
            Verdict.UNKNOWN,
            0.55,
            None,
            None,
            [Evidence(title="Зависимости", detail=f"Найдено зависимостей: {len(candidates)}. Пример: {preview}")],
            "Включить сеть или модельный контур, чтобы сверить версии и совместимость зависимостей.",
            True,
            extra={"candidate_count": len(candidates)},
            support_status="не проверялось",
        )


class RegionalAvailabilityChecker(BaseChecker):
    """Проверяет доступность сервисов и технологий из РФ по кураторской базе."""

    name = "regional_availability_checker"

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        rules = load_regional_availability_rules(context.settings.input_path)
        if not rules:
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str, str, int | None]] = set()
        for entity in entities:
            if entity.entity_type not in {EntityType.LINK, EntityType.TECHNOLOGY, EntityType.VERSION}:
                continue
            match = match_regional_availability(entity.value, rules)
            if match is None:
                continue
            key = (match.rule.pattern.lower(), entity.location.file_path, entity.value.lower(), entity.location.line_start)
            if key in seen:
                continue
            seen.add(key)
            findings.append(_finding_from_regional_availability_match(unit, self.name, match, entity))

        for candidate in extract_dependency_candidates(unit):
            match = match_regional_availability(candidate.name, rules)
            if match is None:
                continue
            key = (match.rule.pattern.lower(), candidate.location.file_path, candidate.name.lower(), candidate.location.line_start)
            if key in seen:
                continue
            seen.add(key)
            findings.append(_finding_from_regional_availability_match(unit, self.name, match, candidate))
        return findings


class ModelRubricChecker(BaseChecker):
    """Модельная проверка критериев, которые трудно закрыть правилами."""

    name = "model_rubric_checker"
    prompt_version = "model_rubric_checker:v1"

    SYSTEM_PROMPT = """Ты проверяешь учебный контент как инженер-методолог.
Верни только JSON: {"findings": [ ... ]}.
Каждый элемент: criterion, severity, verdict, confidence, quote, file_path, line_start, evidence, recommendation.
Критерий только один: workload.
Все текстовые поля ответа пиши на русском языке.
Не используй английский язык в рекомендации, если только цитируешь исходный термин из материала.
Не придумывай источники. Если доказательств мало, ставь verdict='unknown' и needs_human_review=true.
Для workload не ставь severity='critical': это консультационный критерий до калибровки на данных.
Для workload ставь verdict='unknown', если нет данных о реальном времени прохождения или трудозатратах.
Не проверяй фактологию, рынок, чек-лист, ссылки, права, язык, изображения и актуальность технологий: эти зоны закрывают отдельные специализированные модули."""

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        del entities
        if context.model_client is None:
            return []
        compact_context = _compact_unit_context(unit)
        if not compact_context.strip():
            return []
        try:
            response = context.model_client.complete_json(self.SYSTEM_PROMPT, compact_context)
        except OpenRouterError as exc:
            return [
                _finding(
                    unit,
                    self.name,
                    Criterion.CORRECTNESS,
                    Severity.INFO,
                    Verdict.UNKNOWN,
                    0.3,
                    None,
                    None,
                    [Evidence(title="Модельная проверка", detail=str(exc))],
                    "Повторить модельную проверку после устранения ошибки провайдера.",
                    True,
                )
            ]
        context.record_model_result(context.model_client, cache_hit=False, prompt_version=self.prompt_version)

        findings: list[Finding] = []
        for item in response.get("findings", []):
            if not isinstance(item, dict):
                continue
            finding = _finding_from_model_item(unit, self.name, item, self.prompt_version)
            if finding.criterion not in MODEL_RUBRIC_ALLOWED_CRITERIA:
                continue
            findings.append(finding)
        return findings


def default_checkers(
    use_model: bool,
    code_similarity_index: dict[str, list[CodeMatch]] | None = None,
) -> list[BaseChecker]:
    """Возвращает набор проверок для первого рабочего прототипа."""

    checkers: list[BaseChecker] = [
        StructureChecker(),
        LinkChecker(),
        LocalLinkChecker(),
        ChecklistChecker(),
        LanguageCoverageChecker(),
        ExamPresenceChecker(),
        ImageQualityChecker(),
        ReadabilityChecker(),
        RightsAndOriginalityChecker(code_similarity_index=code_similarity_index),
        MarketFitChecker(),
        DependencyFreshnessChecker(),
        RegionalAvailabilityChecker(),
        TechFreshnessChecker(),
    ]
    if use_model:
        checkers.append(ReadmeFactActualityChecker())
        checkers.append(FactCheckerPerplexity())
        checkers.append(ModelRubricChecker())
    return checkers


def _entities_of_type(entities: Iterable[ExtractedEntity], entity_type: EntityType) -> Iterable[ExtractedEntity]:
    """Фильтруем сущности по типу."""

    return (entity for entity in entities if entity.entity_type == entity_type)


def _check_url(url: str, timeout_seconds: float) -> tuple[int, str | None, str | None]:
    """Проверяем внешнюю ссылку через HEAD с ручной проверкой перенаправлений."""

    current_url = url
    headers = {"User-Agent": "ContentAudit/0.1 (+https://github.com/Zheltenkov/Auditor)"}
    try:
        for _redirect_index in range(5):
            policy_error = _url_policy_error(current_url)
            if policy_error is not None:
                return 0, current_url, policy_error
            response = requests.head(current_url, allow_redirects=False, timeout=timeout_seconds, headers=headers)
            if response.status_code in {405, 403}:
                response = requests.get(current_url, allow_redirects=False, timeout=timeout_seconds, stream=True, headers=headers)
            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                if not location:
                    return response.status_code, current_url, None
                current_url = urljoin(current_url, location)
                continue
            return response.status_code, current_url, None
        return 0, current_url, "Слишком длинная цепочка перенаправлений."
    except requests.RequestException as exc:
        return 0, current_url, str(exc)


def _is_transient_http_status(status_code: int) -> bool:
    """Отделяем временную недоступность от устойчиво битой ссылки."""

    return status_code in {408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524}


def _is_redirect_chain_error(error: str) -> bool:
    """Цепочка редиректов чаще похожа на гниение ссылки, чем на сетевой сбой."""

    return "перенаправ" in error.lower() or "redirect" in error.lower()


def _redirect_smells_like_rot(original_url: str, final_url: str | None) -> bool:
    """Ловим редирект на другой домен или главную страницу вместо исходного материала."""

    if not final_url:
        return False
    original = urlparse(original_url)
    final = urlparse(final_url)
    original_host = (original.hostname or "").lower().removeprefix("www.")
    final_host = (final.hostname or "").lower().removeprefix("www.")
    if _same_trusted_redirect_family(original_host, final_host) and (final.path or "/") not in {"", "/"}:
        return False
    if original_host and final_host and original_host != final_host:
        return True
    original_path = original.path or "/"
    final_path = final.path or "/"
    return original_path not in {"", "/"} and final_path in {"", "/"}


def _same_trusted_redirect_family(original_host: str, final_host: str) -> bool:
    """Разрешаем известные пары коротких ссылок и основных доменов платформ."""

    return any(original_host in group and final_host in group for group in TRUSTED_REDIRECT_HOST_GROUPS)


def _url_policy_error(url: str) -> str | None:
    """Проверяем схему, локальные адреса и служебные IP."""

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return f"Неподдерживаемая схема ссылки: {parsed.scheme or 'не указана'}."
    if parsed.username or parsed.password:
        return "Ссылки с учётными данными в адресе не проверяются автоматически."
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return "Не удалось определить домен ссылки."
    if hostname == "localhost" or hostname.endswith(".localhost") or hostname.endswith(".local"):
        return "Локальные адреса не проверяются автоматически."
    try:
        ip_address = ipaddress.ip_address(hostname)
    except ValueError:
        ip_address = None
    if ip_address and (ip_address.is_private or ip_address.is_loopback or ip_address.is_link_local or ip_address.is_reserved):
        return "Внутренние IP-адреса не проверяются автоматически."
    return None


def _is_inside(path: Path, root: Path) -> bool:
    """Защищаемся от ссылок, выходящих за пределы проекта."""

    try:
        path.relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _detect_language_profile(unit: ContentUnit) -> tuple[set[str], list[dict[str, str]]]:
    """Определяем языковые версии и сверяем явные суффиксы с содержимым."""

    languages: set[str] = set()
    mismatches: list[dict[str, str]] = []
    for file in unit.files:
        lower_path = file.relative_path.lower()
        expected = _language_from_path(lower_path)
        detected = _language_from_content(file.text)
        if expected:
            languages.add(expected)
        elif detected:
            languages.add(detected)
        elif file.kind == "readme":
            languages.add("ENG")

        if expected and detected and expected != detected:
            mismatches.append({"file_path": file.relative_path, "expected": expected, "detected": detected})
    return languages, mismatches


def _language_from_path(lower_path: str) -> str | None:
    """Достаём явный язык из имени файла."""

    if "_rus" in lower_path or "рус" in lower_path:
        return "RUS"
    if "_uzb" in lower_path or "_uz" in lower_path:
        return "UZ"
    if "_tg" in lower_path or "taj" in lower_path:
        return "TG"
    if "_eng" in lower_path:
        return "ENG"
    return None


def _language_from_content(text: str) -> str | None:
    """Дешёвый кросс-чек языка по содержимому без внешних зависимостей."""

    sample = text[:6000].lower()
    letters = [char for char in sample if char.isalpha()]
    if len(letters) < 40:
        return None

    cyrillic = sum(1 for char in letters if "а" <= char <= "я" or char == "ё")
    latin = sum(1 for char in letters if "a" <= char <= "z")
    tajik_markers = set("қғӯҳҷӣ")
    if any(char in tajik_markers for char in sample):
        return "TG"

    uzbek_markers = ("o‘", "g‘", "o'", "g'", "bo'lim", "uchun", "kerak", "loyiha", "tekshir")
    if latin > cyrillic * 2 and any(marker in sample for marker in uzbek_markers):
        return "UZ"
    if cyrillic > latin * 2:
        return "RUS"
    if latin > cyrillic * 2:
        return "ENG"
    return None


def _market_fit_signals(unit: ContentUnit, patterns: dict[str, tuple[str, ...]]) -> dict[str, dict[str, object]]:
    """Ищет признаки данных, бизнес-контекста и метрик успеха."""

    signals: dict[str, dict[str, object]] = {
        name: {"present": False, "matches": [], "source": "rules"} for name in patterns
    }
    for file in unit.files:
        if file.kind not in {"readme", "material", "text"}:
            continue
        for line_number, line in enumerate(file.text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            if _is_market_fit_noise_line(stripped):
                continue
            lowered = stripped.lower()
            for signal_name, signal_patterns in patterns.items():
                if signals[signal_name]["present"]:
                    continue
                if any(re.search(pattern, lowered, flags=re.IGNORECASE) for pattern in signal_patterns):
                    signals[signal_name]["present"] = True
                    signals[signal_name]["matches"] = [
                        {
                            "file_path": file.relative_path,
                            "line_start": line_number,
                            "text": stripped[:220],
                        }
                    ]
    if not signals["real_data"]["present"]:
        _mark_dataset_files(unit, signals)
    return signals


def _mark_dataset_files(unit: ContentUnit, signals: dict[str, dict[str, object]]) -> None:
    """Файлы данных тоже считаются признаком работы с реальными данными."""

    for file in unit.files:
        if _looks_like_market_dataset_file(file.relative_path):
            signals["real_data"]["present"] = True
            signals["real_data"]["matches"] = [
                {"file_path": file.relative_path, "line_start": None, "text": "Найден файл или папка данных."}
            ]
            return


def _looks_like_market_dataset_file(relative_path: str) -> bool:
    """Отличает датасет от технических отчётов, фикстур и ожидаемых выходов."""

    lower_path = relative_path.lower()
    data_suffixes = (".csv", ".xlsx", ".parquet", ".jsonl")
    if not lower_path.endswith(data_suffixes):
        return False
    if _is_market_fit_noise_path(lower_path):
        return False
    path_parts = lower_path.split("/")
    if any(part in {"data", "dataset", "datasets"} for part in path_parts):
        return True
    return bool(
        re.search(
            r"(customer|client|sales|transaction|order|churn|bank|retail|market|user|billing|claim|loan|price|product|"
            r"клиент|продаж|транзакц|заказ|отток|банк|рынок|пользовател|заявк|кредит|товар)",
            lower_path,
            flags=re.IGNORECASE,
        )
    )


def _is_market_fit_noise_path(lower_path: str) -> bool:
    """Фильтрует технические данные, которые не доказывают работу с рынком."""

    return bool(
        re.search(
            r"(^|/)(test|tests|fixture|fixtures|mock|mocks|expected|actual|output|outputs|report|reports|coverage|"
            r"autotest|golden)(/|\.|_|-)",
            lower_path,
        )
    )


def _is_market_fit_noise_line(value: str) -> bool:
    """Отсекает строки про тесты, фикстуры и технический вывод."""

    lowered = value.lower()
    technical_markers = (
        "autotest",
        "unit test",
        "integration test",
        "fixture",
        "mock",
        "expected output",
        "correct output",
        "test data",
        "synthetic data",
        "toy dataset",
        "тестов",
        "автотест",
        "фикстур",
        "мок",
        "ожидаем",
        "стандартн",
        "синтетическ",
        "игрушечн",
    )
    if not any(marker in lowered for marker in technical_markers):
        return False
    business_markers = (
        "business",
        "customer",
        "client",
        "market",
        "revenue",
        "retention",
        "churn",
        "бизнес",
        "клиент",
        "заказчик",
        "рынок",
        "выруч",
        "удержан",
        "отток",
    )
    return not any(marker in lowered for marker in business_markers)


def _merge_market_signals(
    signals: dict[str, dict[str, object]],
    model_item: dict[str, Any] | None,
) -> dict[str, dict[str, object]]:
    """Объединяет правила и уточнение модели без потери найденных доказательств."""

    merged = {
        key: {"present": bool(value["present"]), "matches": list(value["matches"]), "source": value["source"]}
        for key, value in signals.items()
    }
    if model_item is None:
        return merged
    for key in ("real_data", "business_context", "success_metrics"):
        value = model_item.get(key)
        if isinstance(value, bool) and value:
            merged[key]["present"] = True
            merged[key]["source"] = "model" if not merged[key]["matches"] else "rules+model"
    return merged


def _market_fit_verdict(score: int) -> tuple[Verdict, Severity]:
    """Назначает базовый вердикт по трём под-оценкам."""

    if score >= 3:
        return Verdict.PASS, Severity.INFO
    if score >= 1:
        return Verdict.WARNING, Severity.MINOR
    return Verdict.WARNING, Severity.MAJOR


def _market_fit_evidence(signals: dict[str, dict[str, object]], labels: dict[str, str]) -> str:
    """Собирает человекочитаемое объяснение по под-оценкам."""

    parts: list[str] = []
    for key, label in labels.items():
        signal = signals[key]
        status = "есть" if signal["present"] else "нет"
        detail = ""
        matches = signal.get("matches")
        if isinstance(matches, list) and matches:
            first = matches[0]
            if isinstance(first, dict):
                location = first.get("file_path") or ""
                line = first.get("line_start")
                text = first.get("text") or ""
                detail = f" ({location}{':' + str(line) if line else ''}: {text})"
        parts.append(f"{label}: {status}{detail}")
    return "; ".join(parts)


def _market_fit_recommendation(signals: dict[str, dict[str, object]], model_item: dict[str, Any] | None) -> str:
    """Формирует рекомендацию по недостающим признакам."""

    if model_item is not None:
        recommendation = _optional_model_text(model_item.get("recommendation"))
        if recommendation:
            return recommendation
    missing = [key for key, value in signals.items() if not value["present"]]
    if not missing:
        return "Действий не требуется: данные, бизнес-контекст и метрики/требования найдены."
    mapping = {
        "real_data": "добавить датасет или ссылку на реальные данные",
        "business_context": "описать бизнес-проблему, заказчика или целевую аудиторию",
        "success_metrics": "зафиксировать бизнес-метрики, ограничения или требования к результату",
    }
    return "Усилить прикладной контекст: " + "; ".join(mapping[key] for key in missing) + "."


def _first_market_location(signals: dict[str, dict[str, object]]) -> TextLocation | None:
    """Берёт первую строку, где найден признак соответствия рынку."""

    for signal in signals.values():
        matches = signal.get("matches")
        if not isinstance(matches, list) or not matches:
            continue
        first = matches[0]
        if not isinstance(first, dict) or not first.get("file_path"):
            continue
        line = first.get("line_start") if isinstance(first.get("line_start"), int) else None
        return TextLocation(file_path=str(first["file_path"]), line_start=line, line_end=line)
    return None


def _select_technology_candidates(entities: list[ExtractedEntity], limit: int) -> list[ExtractedEntity]:
    """Выбираем ограниченный набор сущностей, которые реально похожи на технологии."""

    candidates = [entity for entity in entities if entity.entity_type in {EntityType.VERSION, EntityType.TECHNOLOGY, EntityType.DATE}]
    seen_values: set[str] = set()
    seen_roots: set[str] = set()
    selected: list[ExtractedEntity] = []
    for entity in candidates:
        key = _normalise_technology_value(entity.value)
        root = _technology_root(entity.value)
        if key in seen_values:
            continue
        if entity.entity_type == EntityType.TECHNOLOGY and root and root in seen_roots:
            continue
        seen_values.add(key)
        if not _looks_like_actuality_candidate(entity):
            continue
        if root:
            seen_roots.add(root)
        selected.append(entity)
        if len(selected) >= limit:
            break
    return selected


def _looks_like_actuality_candidate(entity: ExtractedEntity) -> bool:
    """Отсекаем слишком общие слова и оставляем проверяемые версии/даты/технологии."""

    value = entity.value.strip()
    lowered = value.lower()
    context = f"{value} {entity.context or ''}".lower()
    if len(lowered) < 2:
        return False
    if _is_non_technology_version_label(value):
        return False
    if re.fullmatch(r"(19|20)\d{2}", lowered):
        return any(keyword in context for keyword in TECH_KEYWORDS)
    if any(keyword in lowered for keyword in TECH_KEYWORDS):
        return True
    return entity.entity_type == EntityType.VERSION and _has_nearby_technology_context(context)


def _is_non_technology_version_label(value: str) -> bool:
    """Отбрасывает номера упражнений и служебные подписи, похожие на версии."""

    normalized = value.strip().lower()
    if NON_TECH_VERSION_LABEL_RE.search(normalized):
        return True
    if re.fullmatch(r"ex\d{1,3}", normalized):
        return True
    return False


def _has_nearby_technology_context(context: str) -> bool:
    """Проверяет, что версия стоит рядом с настоящей технологической сущностью."""

    if not any(keyword in context for keyword in TECH_KEYWORDS):
        return False
    return any(
        marker in context
        for marker in (
            "version",
            "верси",
            "interpreter",
            "интерпретатор",
            "runtime",
            "image",
            "образ",
            "standard",
            "стандарт",
            "release",
            "lts",
            "support",
            "поддерж",
            "python",
            "java",
            "alpine",
            "ubuntu",
            "gcc",
            "node",
            "posix",
            "c11",
        )
    )


def _normalise_technology_value(value: str) -> str:
    """Нормализуем значение для дедупликации и кэша."""

    return re.sub(r"\s+", " ", value.strip().lower())


def _technology_root(value: str) -> str | None:
    """Определяем базовое имя технологии для подавления дублей вида Java 21 и Java."""

    lowered = value.lower()
    for keyword in sorted(TECH_KEYWORDS, key=len, reverse=True):
        if keyword in lowered:
            return keyword
    return None


def _hash_cache_key(namespace: str, value: str) -> str:
    """Создаём стабильный ключ кэша без хранения длинных утверждений в имени."""

    normalized = normalize_for_match(value)
    digest = hashlib.sha1(f"{namespace}|{normalized}".encode("utf-8")).hexdigest()
    return digest


def _compact_unit_context(unit: ContentUnit, limit: int = 12000) -> str:
    """Собираем компактный контекст для модельной проверки."""

    chunks: list[str] = []
    ordered_files = sorted(unit.files, key=lambda file: _model_context_priority(file.kind, file.relative_path))
    for file in ordered_files:
        if file.kind not in {"readme", "checklist", "material"}:
            continue
        fragment = file.text[:3000]
        chunks.append(f"Файл: {file.relative_path}\n{fragment}")
        if sum(len(chunk) for chunk in chunks) >= limit:
            break
    return "\n\n---\n\n".join(chunks)[:limit]


def _model_context_priority(kind: str, relative_path: str) -> tuple[int, str]:
    """Сначала даём модели README, затем чек-лист, затем дополнительные материалы."""

    order = {"readme": 0, "checklist": 1, "material": 2}
    return order.get(kind, 9), relative_path.lower()


def _extract_fact_claims(unit: ContentUnit, limit: int) -> list[dict[str, Any]]:
    """Достаём короткие фактологические утверждения, которые есть смысл проверять внешним поиском."""

    claims: list[dict[str, Any]] = []
    seen: set[str] = set()
    ordered_files = sorted(unit.files, key=lambda file: _model_context_priority(file.kind, file.relative_path))
    for file in ordered_files:
        if file.kind not in {"readme", "material", "text"}:
            continue
        for line_number, line in enumerate(file.text.splitlines(), start=1):
            for candidate in _split_claim_line(line):
                if _is_markdown_navigation_claim(candidate):
                    continue
                claim = _clean_claim_text(candidate)
                key = normalize_for_match(claim)
                if key in seen or not _looks_like_fact_claim(claim):
                    continue
                seen.add(key)
                claims.append(
                    {
                        "claim": claim,
                        "context": line.strip()[:700],
                        "location": TextLocation(file_path=file.relative_path, line_start=line_number, line_end=line_number),
                    }
                )
                if len(claims) >= limit:
                    return claims
    return claims


def _split_claim_line(line: str) -> list[str]:
    """Разделяем строку на короткие утверждения без тяжёлого лингвистического разбора."""

    return [part.strip() for part in re.split(r"(?<=[.!?])\s+", line) if part.strip()]


def _clean_claim_text(value: str) -> str:
    """Убираем Markdown-маркеры, которые не относятся к смыслу утверждения."""

    cleaned = re.sub(r"^\s*(?:#{1,6}|[-*]|\d+[.)])\s*", "", value.strip())
    cleaned = MARKDOWN_LINK_RE.sub(r"\1", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def _looks_like_fact_claim(value: str) -> bool:
    """Отбираем только утверждения с датами, версиями, стандартами или признаками внешней проверяемости."""

    lowered = value.lower()
    if len(value) < 35 or len(value) > 520:
        return False
    if lowered.startswith(("http://", "https://", "![", "[")):
        return False
    if _is_markdown_navigation_claim(value):
        return False
    if _is_requirement_claim(value):
        return False
    if len(re.findall(r"\w+", value, flags=re.UNICODE)) < 5:
        return False
    return bool(FACT_DATE_RE.search(value) or FACT_MARKER_RE.search(value) or any(keyword in lowered for keyword in TECH_KEYWORDS))


def _is_markdown_navigation_claim(value: str) -> bool:
    """Отсекаем строки оглавления и внутренние якоря, которые не являются фактами."""

    if not INTERNAL_MARKDOWN_LINK_RE.search(value):
        return False
    without_links = INTERNAL_MARKDOWN_LINK_RE.sub("", value)
    return len(re.findall(r"\w+", without_links, flags=re.UNICODE)) <= 3


def _is_requirement_claim(value: str) -> bool:
    """Отсекаем требования курса: их нужно оценивать рубрикой, а не внешним фактчеком."""

    lowered = f" {value.lower()} "
    return any(marker in lowered for marker in REQUIREMENT_CLAIM_MARKERS)


def _fact_check_prompt(claim: dict[str, Any]) -> str:
    """Формируем входной контракт фактологической проверки."""

    location = claim.get("location")
    payload = {
        "check_date": datetime.now(timezone.utc).date().isoformat(),
        "claim": claim.get("claim"),
        "context": claim.get("context"),
        "file_path": location.file_path if isinstance(location, TextLocation) else None,
        "line_start": location.line_start if isinstance(location, TextLocation) else None,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _extract_readme_fact_batches(unit: ContentUnit, max_lines_per_batch: int, max_batches: int) -> list[dict[str, Any]]:
    """Готовит README.md и README_RUS.md к проверке с сохранением номеров строк."""

    batches: list[dict[str, Any]] = []
    for file in sorted(unit.files, key=lambda item: item.relative_path.lower()):
        if not _is_fact_readme_file(file.relative_path):
            continue
        candidates = _readme_fact_candidate_lines(file.text.splitlines())
        for start_index in range(0, len(candidates), max_lines_per_batch):
            chunk = candidates[start_index : start_index + max_lines_per_batch]
            numbered_text = "\n".join(f"{line_number}: {line}" for line_number, line in chunk)
            if not numbered_text.strip():
                continue
            allowed_lines = [line_number for line_number, _line in chunk]
            batches.append(
                {
                    "file_path": file.relative_path,
                    "line_start": min(allowed_lines),
                    "line_end": max(allowed_lines),
                    "text": numbered_text,
                    "allowed_lines": allowed_lines,
                }
            )
            if len(batches) >= max_batches:
                return batches
    return batches


def _readme_fact_candidate_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Оставляет для README-фактчека только определения и внешне проверяемые утверждения."""

    candidates: list[tuple[int, str]] = []
    in_task_section = False
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if README_THEORY_SECTION_RE.search(stripped):
            in_task_section = False
        elif README_TASK_SECTION_RE.search(stripped):
            in_task_section = True
        if not _is_readme_fact_candidate_line(stripped, in_task_section):
            continue
        candidates.append((line_number, line))
    return candidates


def _is_readme_fact_candidate_line(line: str, in_task_section: bool) -> bool:
    """Отсекает учебные инструкции, дистракторы и локальные требования проекта."""

    if not line or in_task_section:
        return False
    if line.startswith("#") or README_FEEDBACK_LINE_RE.search(line):
        return False
    if _is_markdown_navigation_claim(line) or README_EXERCISE_OPTION_RE.match(line):
        return False
    claim = _clean_claim_text(line)
    if _looks_like_fact_claim(claim):
        return True
    return _looks_like_definition_line(claim)


def _looks_like_definition_line(value: str) -> bool:
    """Разрешает проверку терминологических определений из теоретических разделов."""

    if len(value) < 20 or len(value) > 520:
        return False
    if not README_DEFINITION_LINE_RE.search(value):
        return False
    lowered = value.lower()
    return bool(FACT_MARKER_RE.search(value) or any(keyword in lowered for keyword in TECH_KEYWORDS) or ":" in value)


def _is_allowed_readme_fact_item(item: dict[str, Any], batch: dict[str, Any]) -> bool:
    """Не принимает от модели строку, которой не было во входе специального фактчека."""

    file_path = str(item.get("file_path") or batch["file_path"])
    if Path(file_path).name.lower() != Path(str(batch["file_path"])).name.lower():
        return False
    allowed_lines = set(batch.get("allowed_lines") or [])
    if not allowed_lines:
        return True
    line_start = _parse_optional_int(item.get("line_start"))
    if line_start is None:
        return False
    return line_start in allowed_lines


def _is_fact_readme_file(relative_path: str) -> bool:
    """Ограничивает специальную фактологическую проверку двумя README-файлами."""

    return bool(README_FACT_FILE_RE.fullmatch(Path(relative_path).name))


def _readme_fact_check_prompt(batch: dict[str, Any]) -> str:
    """Формирует контракт проверки README-фрагмента."""

    payload = {
        "check_date": datetime.now(timezone.utc).date().isoformat(),
        "file_path": batch["file_path"],
        "line_start": batch["line_start"],
        "line_end": batch["line_end"],
        "numbered_text": batch["text"],
        "scope": [
            "проверяемые определения",
            "даты и временные утверждения",
            "версии и поддержка технологий",
            "стеки технологий, библиотеки, стандарты и инструменты",
            "прочие утверждения о внешнем мире, которые можно подтвердить источниками",
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _technology_check_prompt(entity: ExtractedEntity) -> str:
    """Формируем входной контракт проверки актуальности технологии."""

    payload = {
        "check_date": datetime.now(timezone.utc).date().isoformat(),
        "candidate": entity.value,
        "entity_type": entity.entity_type.value,
        "quote": entity.quote,
        "context": entity.context,
        "file_path": entity.location.file_path,
        "line_start": entity.location.line_start,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _cached_model_json(
    context: CheckContext,
    namespace: str,
    key: str,
    client: OpenRouterClient,
    system_prompt: str,
    user_prompt: str,
    prompt_version: str,
) -> tuple[dict[str, Any], bool]:
    """Берём модельный JSON из кэша или выполняем один внешний запрос."""

    if context.cache is not None:
        cached = context.cache.get(namespace, key)
        if cached is not None and isinstance(cached.get("response"), dict):
            context.record_model_result(client, cache_hit=True, prompt_version=prompt_version)
            return cached, True

    response = client.complete_json(system_prompt, user_prompt)
    context.record_model_result(client, cache_hit=False, prompt_version=prompt_version)
    record = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "model": client.model,
        "prompt_version": prompt_version,
        "usage": getattr(client, "last_call_usage", {}) or {},
        "response": response,
    }
    if context.cache is not None:
        context.cache.set(namespace, key, record)
        context.cache.save()
    return record, False


def _first_result_item(payload: object) -> dict[str, Any] | None:
    """Разбираем разные допустимые формы JSON-ответа модели."""

    if isinstance(payload, list):
        return next((item for item in payload if isinstance(item, dict)), None)
    if not isinstance(payload, dict):
        return None
    for key in ("result", "finding", "check"):
        item = payload.get(key)
        if isinstance(item, dict):
            return item
    findings = payload.get("findings")
    if isinstance(findings, list):
        return next((item for item in findings if isinstance(item, dict)), None)
    return payload


def _result_items(payload: object) -> list[dict[str, Any]]:
    """Разбирает JSON-ответ модели, который может содержать несколько найденных случаев."""

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("findings", "items", "results"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    item = _first_result_item(payload)
    return [item] if item is not None else []


def _dependency_registry_metadata(
    candidate: DependencyCandidate,
    registry_client: DependencyRegistryClient,
    context: CheckContext,
) -> DependencyMetadata | None:
    """Получает метаданные зависимости из реестра через общий кэш аудита."""

    if not context.settings.allow_network:
        return None
    cache_key = dependency_cache_key(candidate)
    if context.cache is not None:
        cached = context.cache.get("dependency_registry", cache_key)
        if cached is not None:
            try:
                return metadata_from_record(cached)
            except (KeyError, ValueError, TypeError):
                pass
    try:
        metadata = registry_client.fetch(candidate)
    except DependencyRegistryError:
        return None
    if context.cache is not None:
        context.cache.set("dependency_registry", cache_key, metadata_to_record(metadata))
        context.cache.save()
    return metadata


def _dependency_license_signal(
    package: str,
    spdx: str | None,
    source_url: str | None,
    location: TextLocation | None,
) -> RightsSignal | None:
    """Преобразует лицензию пакета в сигнал по правам."""

    policy = license_policy(spdx)
    if policy == "deny":
        return RightsSignal(
            kind="dependency_license",
            risk="violation",
            deterministic=True,
            title="Несовместимая лицензия зависимости",
            detail=f"Зависимость {package} указана с лицензией {spdx}, которая требует отдельного согласования.",
            recommendation=f"Заменить {package} на пермиссивный аналог или согласовать использование.",
            location=location,
            source=spdx,
            url=source_url,
            confidence=0.9,
        )
    if policy == "review" and spdx is not None:
        return RightsSignal(
            kind="dependency_license",
            risk="unverifiable",
            deterministic=True,
            title="Лицензия зависимости требует разбора",
            detail=f"{package}: {spdx}. Условия лицензии нужно проверить вручную.",
            recommendation=f"Проверить условия лицензии {package} и допустимость использования в учебном проекте.",
            location=location,
            source=spdx,
            url=source_url,
            confidence=0.55,
        )
    return None


def _finding_from_dependency_issue(unit: ContentUnit, checker_name: str, issue: CompatibilityIssue) -> Finding:
    """Преобразует конфликт зависимостей в строку отчёта."""

    detail = (
        f"{issue.dependency.name}{issue.dependency.spec} требует {issue.related_name}{issue.required_spec}; "
        f"в проекте указано: {_dependency_name_with_spec(issue.related_name, issue.declared_spec)}. {issue.reason}"
    )
    return _finding(
        unit,
        checker_name,
        Criterion.ACTUALITY,
        Severity.MAJOR,
        Verdict.WARNING,
        0.8,
        _dependency_quote(issue.dependency),
        issue.dependency.location,
        [Evidence(title="Совместимость зависимостей", detail=detail)],
        "Согласовать версии зависимостей или явно добавить недостающую peer-зависимость.",
        True,
        extra={
            "dependency": issue.dependency.name,
            "related_dependency": issue.related_name,
            "declared_spec": issue.declared_spec,
            "required_spec": issue.required_spec,
        },
        support_status="конфликт ограничений",
    )


def _finding_from_regional_availability_match(
    unit: ContentUnit,
    checker_name: str,
    match: RegionalAvailabilityMatch,
    source_entity: ExtractedEntity | DependencyCandidate,
) -> Finding:
    """Преобразует правило региональной доступности в строку отчёта."""

    severity = {
        "unavailable": Severity.MAJOR,
        "limited": Severity.MINOR,
        "manual_review": Severity.INFO,
    }.get(match.rule.status, Severity.INFO)
    status_label = {
        "unavailable": "недоступно в РФ",
        "limited": "ограничено в РФ",
        "manual_review": "проверить доступность из РФ",
    }.get(match.rule.status, "проверить доступность из РФ")
    quote = source_entity.quote if isinstance(source_entity, ExtractedEntity) else _dependency_quote(source_entity)
    return _finding(
        unit,
        checker_name,
        Criterion.ACTUALITY,
        severity,
        Verdict.WARNING if match.rule.status in {"unavailable", "limited"} else Verdict.UNKNOWN,
        0.85,
        quote,
        source_entity.location,
        [Evidence(title="Доступность из РФ", detail=match.rule.reason, url=match.rule.source)],
        "Заменить сервис на доступный аналог, добавить зеркало или явно описать обходной вариант для учебного проекта.",
        True,
        extra={
            "regional_profile": "ru",
            "matched_value": match.value,
            "matched_pattern": match.rule.pattern,
            "rule_updated_at": match.rule.updated_at,
        },
        source=match.rule.source,
        support_status=status_label,
    )


def _finding_from_dependency_model_item(
    unit: ContentUnit,
    checker_name: str,
    candidate: DependencyCandidate,
    item: dict[str, Any],
    record: dict[str, Any],
    cache_hit: bool,
    prompt_version: str,
) -> Finding:
    """Преобразует запасную проверку зависимости через Perplexity в строку отчёта."""

    verdict = _verdict_from_model_value(item.get("verdict"), Verdict.UNKNOWN)
    severity = _enum_or_default(Severity, item.get("severity"), _severity_from_verdict(verdict))
    evidence_text = _model_text(item, ("evidence", "reason", "explanation"), "Запасная проверка зависимости без пояснения.")
    sources = _sources_from_item(item)
    return _finding(
        unit,
        checker_name,
        Criterion.ACTUALITY,
        severity,
        verdict,
        _parse_confidence(item.get("confidence")),
        _dependency_quote(candidate),
        candidate.location,
        [Evidence(title="Запасная проверка зависимости", detail=evidence_text, url=_first_source_url(sources))],
        str(item.get("recommendation") or "Проверить зависимость вручную."),
        verdict != Verdict.PASS,
        extra={"cache_hit": cache_hit, "ecosystem": candidate.ecosystem},
        source=_source_summary(sources),
        checked_at=_checked_at_from_record(record),
        support_status=str(item.get("support_status") or _support_status_from_verdict(verdict)),
        latest_version=_optional_model_text(item.get("latest_version")),
        recommended_version=_optional_model_text(item.get("recommended_version")),
        prompt_version=prompt_version,
    )


def _dependency_quote(candidate: DependencyCandidate) -> str:
    """Показывает зависимость в коротком виде для цитаты отчёта."""

    return _dependency_name_with_spec(candidate.name, candidate.spec)


def _dependency_name_with_spec(name: str, spec: str) -> str:
    """Склеивает имя и ограничение версии без лишних пробелов."""

    return f"{name}{spec}" if spec else f"{name}: не указано"


def _finding_from_fact_item(
    unit: ContentUnit,
    checker_name: str,
    claim: dict[str, Any],
    item: dict[str, Any],
    record: dict[str, Any],
    cache_hit: bool,
    prompt_version: str,
) -> Finding:
    """Преобразуем результат фактологической проверки в строку отчёта."""

    verdict = _verdict_from_model_value(item.get("verdict"), Verdict.UNKNOWN)
    evidence_text = _model_text(item, ("evidence", "reason", "explanation"), "Фактологическая проверка без отдельного пояснения.")
    sources = _sources_from_item(item)
    location = claim.get("location")
    return _finding(
        unit,
        checker_name,
        Criterion.CORRECTNESS,
        _severity_from_verdict(verdict),
        verdict,
        _parse_confidence(item.get("confidence")),
        str(claim.get("claim") or "") or None,
        location if isinstance(location, TextLocation) else None,
        [Evidence(title="Фактологическая проверка", detail=evidence_text, url=_first_source_url(sources))],
        _model_text(item, ("recommendation",), "Проверить утверждение вручную и обновить материал при расхождении с источниками."),
        verdict != Verdict.PASS,
        extra={"cache_hit": cache_hit, "model": record.get("model"), "claim": claim.get("claim")},
        source=_source_summary(sources),
        checked_at=_checked_at_from_record(record),
        prompt_version=prompt_version,
    )


def _finding_from_readme_fact_item(
    unit: ContentUnit,
    checker_name: str,
    batch: dict[str, Any],
    item: dict[str, Any],
    record: dict[str, Any],
    cache_hit: bool,
    prompt_version: str,
) -> Finding:
    """Преобразует результат специальной проверки README в строку отчёта."""

    verdict = _verdict_from_model_value(item.get("verdict"), Verdict.UNKNOWN)
    severity = _enum_or_default(Severity, item.get("severity"), _severity_from_verdict(verdict))
    evidence_text = _model_text(item, ("evidence", "reason", "explanation"), "Проверка README без отдельного пояснения.")
    sources = _sources_from_item(item)
    line_start = _parse_optional_int(item.get("line_start")) or int(batch["line_start"])
    location = TextLocation(file_path=str(item.get("file_path") or batch["file_path"]), line_start=line_start, line_end=line_start)
    quote = _model_text(item, ("claim", "quote"), "")
    return _finding(
        unit,
        checker_name,
        Criterion.CORRECTNESS,
        severity,
        verdict,
        _parse_confidence(item.get("confidence")),
        quote or None,
        location,
        [Evidence(title="Проверка README", detail=evidence_text, url=_first_source_url(sources))],
        _model_text(item, ("recommendation",), "Проверить утверждение по источнику и обновить README."),
        verdict != Verdict.PASS,
        extra={"cache_hit": cache_hit, "model": record.get("model"), "claim": quote, "scope": "readme_fact_check"},
        source=_source_summary(sources),
        checked_at=_checked_at_from_record(record),
        support_status=_optional_model_text(item.get("support_status")),
        latest_version=_optional_model_text(item.get("latest_version")),
        recommended_version=_optional_model_text(item.get("recommended_version")),
        prompt_version=prompt_version,
    )


def _is_uninformative_readme_fact_item(item: dict[str, Any]) -> bool:
    """Отбрасывает пустые ответы, чтобы в отчёт не попадали технические заглушки."""

    verdict = _verdict_from_model_value(item.get("verdict"), Verdict.UNKNOWN)
    if verdict == Verdict.PASS:
        return True
    if verdict != Verdict.UNKNOWN:
        return False
    if _sources_from_item(item):
        return False
    return not any(
        _optional_model_text(item.get(key))
        for key in ("claim", "quote", "evidence", "reason", "explanation", "recommendation")
    )


def _finding_from_technology_item(
    unit: ContentUnit,
    checker_name: str,
    entity: ExtractedEntity,
    item: dict[str, Any],
    record: dict[str, Any],
    cache_hit: bool,
    prompt_version: str,
) -> Finding:
    """Преобразуем результат проверки технологии в строку отчёта."""

    verdict = _verdict_from_model_value(item.get("verdict"), Verdict.UNKNOWN)
    severity = _enum_or_default(Severity, item.get("severity"), _severity_from_verdict(verdict))
    evidence_text = _model_text(item, ("evidence", "reason", "explanation"), "Проверка актуальности без отдельного пояснения.")
    sources = _sources_from_item(item)
    support_status = _model_text(item, ("support_status", "status"), _support_status_from_verdict(verdict))
    return _finding(
        unit,
        checker_name,
        Criterion.ACTUALITY,
        severity,
        verdict,
        _parse_confidence(item.get("confidence")),
        entity.quote,
        entity.location,
        [Evidence(title="Актуальность технологии", detail=evidence_text, url=_first_source_url(sources))],
        _model_text(item, ("recommendation",), "Проверить версию технологии вручную и обновить материал при необходимости."),
        verdict != Verdict.PASS,
        extra={"cache_hit": cache_hit, "model": record.get("model"), "candidate": entity.value},
        source=_source_summary(sources),
        checked_at=_checked_at_from_record(record),
        support_status=support_status,
        latest_version=_optional_model_text(item.get("latest_version")),
        recommended_version=_optional_model_text(item.get("recommended_version")),
        prompt_version=prompt_version,
    )


def _is_uninformative_technology_item(item: dict[str, Any]) -> bool:
    """Отбрасываем пустой unknown от модели, чтобы не плодить строки без основания."""

    verdict = _verdict_from_model_value(item.get("verdict"), Verdict.UNKNOWN)
    if verdict != Verdict.UNKNOWN:
        return False
    if _sources_from_item(item):
        return False
    if _optional_model_text(item.get("latest_version")) or _optional_model_text(item.get("recommended_version")):
        return False
    confidence = _parse_confidence(item.get("confidence"))
    support_status = (_optional_model_text(item.get("support_status")) or _optional_model_text(item.get("status")) or "").lower()
    if confidence < LOW_CONFIDENCE_UNKNOWN_THRESHOLD and support_status in {"", "неизвестно", "unknown", "не проверялось"}:
        return True
    informative_keys = (
        "evidence",
        "reason",
        "explanation",
        "recommendation",
        "support_status",
        "status",
        "latest_version",
        "recommended_version",
    )
    return not any(_optional_model_text(item.get(key)) for key in informative_keys)


def _external_check_error(unit: ContentUnit, checker_name: str, criterion: Criterion, exc: OpenRouterError) -> Finding:
    """Фиксируем сбой внешней проверки одной строкой вместо падения всего аудита."""

    return _finding(
        unit,
        checker_name,
        criterion,
        Severity.INFO,
        Verdict.UNKNOWN,
        0.3,
        None,
        None,
        [Evidence(title="Внешняя проверка", detail=str(exc))],
        "Повторить проверку после устранения ошибки провайдера или временно отключить модельный контур.",
        True,
        checked_at=datetime.now(timezone.utc),
        support_status="ошибка проверки" if criterion == Criterion.ACTUALITY else None,
    )


def _model_text(item: dict[str, Any], keys: tuple[str, ...], default: str) -> str:
    """Берём первое непустое текстовое поле из ответа модели."""

    for key in keys:
        value = item.get(key)
        text = _optional_model_text(value)
        if text:
            return text
    return default


def _optional_model_text(value: object) -> str | None:
    """Нормализуем пустые значения модели."""

    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _verdict_from_model_value(value: object, default: Verdict) -> Verdict:
    """Поддерживаем русские и английские синонимы вердиктов."""

    if value is None:
        return default
    normalized = str(value).strip().lower()
    aliases = {
        "ok": Verdict.PASS,
        "true": Verdict.PASS,
        "correct": Verdict.PASS,
        "подтверждено": Verdict.PASS,
        "частично": Verdict.WARNING,
        "partial": Verdict.WARNING,
        "outdated": Verdict.WARNING,
        "устарело": Verdict.WARNING,
        "false": Verdict.FAIL,
        "incorrect": Verdict.FAIL,
        "ошибка": Verdict.FAIL,
        "unknown": Verdict.UNKNOWN,
        "неизвестно": Verdict.UNKNOWN,
    }
    if normalized in aliases:
        return aliases[normalized]
    return _enum_or_default(Verdict, normalized, default)


def _severity_from_verdict(verdict: Verdict) -> Severity:
    """Выбираем критичность по умолчанию, если модель её не вернула."""

    if verdict == Verdict.FAIL:
        return Severity.MAJOR
    if verdict == Verdict.WARNING:
        return Severity.MINOR
    return Severity.INFO


def _support_status_from_verdict(verdict: Verdict) -> str:
    """Заполняем статус поддержки даже при неполном ответе модели."""

    if verdict == Verdict.PASS:
        return "поддерживается"
    if verdict == Verdict.WARNING:
        return "требует уточнения"
    if verdict == Verdict.FAIL:
        return "не поддерживается"
    return "неизвестно"


def _sources_from_item(item: dict[str, Any]) -> list[dict[str, str]]:
    """Нормализуем список источников из ответа модели."""

    raw_sources = item.get("sources") or item.get("source") or []
    if isinstance(raw_sources, str):
        raw_sources = [raw_sources]
    if not isinstance(raw_sources, list):
        return []

    sources: list[dict[str, str]] = []
    for raw_source in raw_sources:
        if isinstance(raw_source, dict):
            title = str(raw_source.get("title") or raw_source.get("name") or "").strip()
            url = str(raw_source.get("url") or raw_source.get("link") or "").strip()
        else:
            title = ""
            url = str(raw_source).strip()
        if not title and not url:
            continue
        sources.append({"title": title, "url": url})
    return sources


def _source_summary(sources: list[dict[str, str]]) -> str | None:
    """Собираем компактное текстовое представление источников для таблицы."""

    parts: list[str] = []
    for source in sources:
        value = source.get("url") or source.get("title")
        if value and value not in parts:
            parts.append(value)
    return " | ".join(parts)[:1200] or None


def _first_source_url(sources: list[dict[str, str]]) -> str | None:
    """Выбираем первую ссылку для поля evidence.url."""

    for source in sources:
        url = source.get("url")
        if url:
            return url
    return None


def _checked_at_from_record(record: dict[str, Any]) -> datetime | None:
    """Разбираем дату проверки из кэша или свежего ответа."""

    value = record.get("checked_at")
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _finding_from_model_item(
    unit: ContentUnit,
    checker_name: str,
    item: dict[str, object],
    prompt_version: str | None = None,
) -> Finding:
    """Преобразуем ответ модели в строгий доменный объект."""

    criterion = _enum_or_default(Criterion, item.get("criterion"), Criterion.CORRECTNESS)
    severity = _enum_or_default(Severity, item.get("severity"), Severity.INFO)
    verdict = _enum_or_default(Verdict, item.get("verdict"), Verdict.UNKNOWN)
    file_path = str(item.get("file_path") or "") or None
    line_start = _parse_optional_int(item.get("line_start"))
    location = TextLocation(file_path=file_path or "", line_start=line_start, line_end=line_start) if file_path and line_start else None
    evidence_text = str(item.get("evidence") or "Модельная проверка без отдельного источника.")
    sources = _sources_from_item(item)
    return _finding(
        unit,
        checker_name,
        criterion,
        severity,
        verdict,
        _parse_confidence(item.get("confidence")),
        str(item.get("quote") or "") or None,
        location,
        [Evidence(title="Модельная проверка", detail=evidence_text)],
        str(item.get("recommendation") or "Проверить случай вручную."),
        True,
        source=_source_summary(sources),
        prompt_version=prompt_version,
    )


def _enum_or_default(enum_class: type, value: object, default: object) -> object:
    """Безопасно разбираем строковое значение перечисления."""

    if value is None:
        return default
    try:
        return enum_class(str(value).strip().lower())
    except Exception:  # noqa: BLE001 - модель может вернуть произвольную строку.
        return default


def _parse_confidence(value: object) -> float:
    """Приводит уверенность модели к числу от 0 до 1."""

    if isinstance(value, int | float):
        return max(0.0, min(1.0, float(value)))
    if value is None:
        return 0.5
    normalized = str(value).strip().lower()
    aliases = {
        "low": 0.35,
        "низкая": 0.35,
        "medium": 0.6,
        "средняя": 0.6,
        "high": 0.85,
        "высокая": 0.85,
    }
    if normalized in aliases:
        return aliases[normalized]
    try:
        return max(0.0, min(1.0, float(normalized)))
    except ValueError:
        return 0.5


def _parse_optional_int(value: object) -> int | None:
    """Безопасно разбирает номер строки из ответа модели."""

    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _readability_problem_lines(value: object) -> list[int]:
    """Нормализуем список строк, которые модель сочла проблемными для чтения."""

    if value is None:
        return []
    raw_values = value if isinstance(value, list) else [value]
    lines: list[int] = []
    for raw_value in raw_values:
        line = _parse_optional_int(raw_value)
        if line is not None and line > 0 and line not in lines:
            lines.append(line)
    return sorted(lines)


def _finding(
    unit: ContentUnit,
    checker_name: str,
    criterion: Criterion,
    severity: Severity,
    verdict: Verdict,
    confidence: float,
    quote: str | None,
    location: TextLocation | None,
    evidence: list[Evidence],
    recommendation: str,
    needs_human_review: bool,
    extra: dict[str, object] | None = None,
    source: str | None = None,
    checked_at: datetime | None = None,
    support_status: str | None = None,
    latest_version: str | None = None,
    recommended_version: str | None = None,
    prompt_version: str | None = None,
) -> Finding:
    """Создаём найденный случай со стабильным идентификатором."""

    raw = "|".join(
        [
            unit.unit_id,
            checker_name,
            criterion.value,
            severity.value,
            quote or "",
            location.file_path if location else "",
            str(location.line_start if location else ""),
        ]
    )
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return Finding(
        finding_id=f"fnd_{digest}",
        unit_id=unit.unit_id,
        branch=unit.branch,
        criterion=criterion,
        severity=severity,
        verdict=verdict,
        confidence=confidence,
        quote=quote,
        location=location,
        evidence=evidence,
        source=source,
        checked_at=checked_at,
        support_status=support_status,
        latest_version=latest_version,
        recommended_version=recommended_version,
        prompt_version=prompt_version,
        recommendation=recommendation,
        needs_human_review=needs_human_review,
        checker_name=checker_name,
        extra=extra or {},
    )
