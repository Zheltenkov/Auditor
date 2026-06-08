"""Проверяющие модули для критериев аудита."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import struct
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urldefrag, urljoin, urlparse

import requests
import yaml

from content_audit.cache import AuditCache
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
from content_audit.openrouter import OpenRouterClient, OpenRouterError
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
    "makefile",
    "node",
    "node.js",
    "pcre2",
    "posix",
    "python",
    "ubuntu",
}

FACT_MARKER_RE = re.compile(
    r"\b("
    r"deprecated|latest|lts|release|standard|style|support|supported|"
    r"актуаль|устар|поддерж|стандарт|релиз|верси|используется|является|входит|доступ"
    r")\b",
    re.IGNORECASE,
)
FACT_DATE_RE = re.compile(r"\b(?:19|20)\d{2}(?:[-./](?:0?[1-9]|1[0-2])(?:[-./](?:0?[1-9]|[12]\d|3[01]))?)?\b")


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
            policy_error = _url_policy_error(entity.value, context.settings.link_allowlist)
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
                        "Проверить ссылку вручную или добавить домен в список разрешённых источников.",
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

            status_code, final_url, error = _check_url(entity.value, context.settings.link_timeout_seconds, context.settings.link_allowlist)
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
        normalized_readme = normalize_for_match(readme_text)
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

            question_names = _extract_checklist_question_names(payload)
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

            matched = sum(1 for name in question_names if _checklist_name_matches_readme(name, normalized_readme))
            ratio = matched / len(question_names)
            if ratio < 0.5:
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.CHECKLIST_ALIGNMENT,
                        Severity.MAJOR,
                        Verdict.WARNING,
                        0.7,
                        None,
                        TextLocation(file_path=checklist_file.relative_path),
                        [
                            Evidence(
                                title="Связность README и чек-листа",
                                detail=f"Сопоставлено {matched} из {len(question_names)} пунктов чек-листа.",
                            )
                        ],
                        "Методологу нужно проверить, что пункты чек-листа однозначно соответствуют заданиям в README.",
                        True,
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
                        [Evidence(title="Чек-лист", detail=f"Найдено {len(question_names)} пунктов, сопоставлено {matched}.")],
                        "Действий не требуется; при пилоте можно заменить грубое сопоставление на модельную проверку смысла.",
                        False,
                    )
                )
        return findings


class LanguageCoverageChecker(BaseChecker):
    """Определяет наличие языковых версий RUS/ENG/UZ/TG."""

    name = "language_coverage_checker"

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        del entities, context
        languages, mismatches = _detect_language_profile(unit)
        severity = Severity.INFO if len(languages) >= 2 else Severity.MINOR
        verdict = Verdict.PASS if len(languages) >= 2 else Verdict.WARNING
        findings = [
            _finding(
                unit,
                self.name,
                Criterion.LANGUAGE,
                severity,
                verdict,
                0.8,
                None,
                None,
                [Evidence(title="Языковые версии", detail=f"Обнаружены: {', '.join(sorted(languages)) or 'не определены'}.")],
                "Если для ветки требуется многоязычность, добавить недостающие версии материалов.",
                len(languages) < 2,
                extra={"languages": sorted(languages), "mismatches": mismatches},
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
            dimensions = _read_image_dimensions(target_path)
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
                if _is_decorative_image(entity.value, entity.quote, width, height):
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

    PLACEHOLDER_RE = re.compile(r"\b(TODO|TBD|FIXME|lorem ipsum)\b|здесь будет|дописать|заглушка", re.IGNORECASE)

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


class RightsChecker(BaseChecker):
    """Проверяет минимальные признаки правовой чистоты материалов."""

    name = "rights_checker"

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        del context
        findings: list[Finding] = []
        has_license = any(Path(file.relative_path).name.lower().startswith("license") for file in unit.files)
        image_count = sum(1 for _ in _entities_of_type(entities, EntityType.IMAGE))
        if not has_license:
            findings.append(
                _finding(
                    unit,
                    self.name,
                    Criterion.RIGHTS,
                    Severity.INFO,
                    Verdict.UNKNOWN,
                    0.55,
                    None,
                    None,
                    [Evidence(title="Лицензия", detail="В единице контента не найден файл LICENSE.")],
                    "Проверить, требуется ли лицензия для материалов, кода и изображений в этой единице.",
                    True,
                )
            )
        if image_count > 0:
            findings.append(
                _finding(
                    unit,
                    self.name,
                    Criterion.RIGHTS,
                    Severity.INFO,
                    Verdict.UNKNOWN,
                    0.45,
                    None,
                    None,
                    [Evidence(title="Изображения", detail=f"Найдено изображений: {image_count}. Права не могут быть подтверждены локально.")],
                    "Для изображений добавить источник/лицензию или подтвердить права вручную.",
                    True,
                )
            )
        return findings


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


class ModelRubricChecker(BaseChecker):
    """Модельная проверка критериев, которые трудно закрыть правилами."""

    name = "model_rubric_checker"
    prompt_version = "model_rubric_checker:v1"

    SYSTEM_PROMPT = """Ты проверяешь учебный контент как инженер-методолог.
Верни только JSON: {"findings": [ ... ]}.
Каждый элемент: criterion, severity, verdict, confidence, quote, file_path, line_start, evidence, recommendation.
Критерии: market_fit, correctness, workload, rights, readability, checklist_alignment, actuality.
Все текстовые поля ответа пиши на русском языке.
Не используй английский язык в рекомендации, если только цитируешь исходный термин из материала.
Не придумывай источники. Если доказательств мало, ставь verdict='unknown' и needs_human_review=true.
Для market_fit и workload не ставь severity='critical': это консультационные критерии до калибровки на данных.
Для workload ставь verdict='unknown', если нет данных о реальном времени прохождения или трудозатратах."""

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

        return [
            _finding_from_model_item(unit, self.name, item, self.prompt_version)
            for item in response.get("findings", [])
            if isinstance(item, dict)
        ]


def default_checkers(use_model: bool) -> list[BaseChecker]:
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
        RightsChecker(),
        DependencyFreshnessChecker(),
        TechFreshnessChecker(),
    ]
    if use_model:
        checkers.append(FactCheckerPerplexity())
        checkers.append(ModelRubricChecker())
    return checkers


def _entities_of_type(entities: Iterable[ExtractedEntity], entity_type: EntityType) -> Iterable[ExtractedEntity]:
    """Фильтруем сущности по типу."""

    return (entity for entity in entities if entity.entity_type == entity_type)


def _check_url(url: str, timeout_seconds: float, allowlist: list[str]) -> tuple[int, str | None, str | None]:
    """Проверяем внешнюю ссылку через HEAD с ручной проверкой перенаправлений."""

    current_url = url
    headers = {"User-Agent": "ContentAudit/0.1 (+https://github.com/Zheltenkov/Auditor)"}
    try:
        for _redirect_index in range(5):
            policy_error = _url_policy_error(current_url, allowlist)
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
    if original_host and final_host and original_host != final_host:
        return True
    original_path = original.path or "/"
    final_path = final.path or "/"
    return original_path not in {"", "/"} and final_path in {"", "/"}


def _url_policy_error(url: str, allowlist: list[str]) -> str | None:
    """Проверяем схему, локальные адреса и список разрешённых доменов."""

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
    normalized_allowlist = [item.lower().lstrip(".") for item in allowlist if item.strip()]
    if normalized_allowlist and not any(hostname == item or hostname.endswith(f".{item}") for item in normalized_allowlist):
        return f"Домен {hostname} не входит в список разрешённых источников."
    return None


def _is_inside(path: Path, root: Path) -> bool:
    """Защищаемся от ссылок, выходящих за пределы проекта."""

    try:
        path.relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _extract_checklist_question_names(payload: object) -> list[str]:
    """Достаём имена вопросов из YAML-чек-листа."""

    if not isinstance(payload, dict):
        return []
    names: list[str] = []
    for section in payload.get("sections", []) or []:
        if not isinstance(section, dict):
            continue
        for question in section.get("questions", []) or []:
            if isinstance(question, dict) and question.get("name"):
                names.append(str(question["name"]))
    return names


def _checklist_name_matches_readme(name: str, normalized_readme: str) -> bool:
    """Грубо сопоставляем Part_1.CAT с заголовками вроде Part 1."""

    normalized = normalize_for_match(name)
    if normalized and normalized in normalized_readme:
        return True
    part_match = re.search(r"part\s+(\d+)", normalized)
    return bool(part_match and f"part {part_match.group(1)}" in normalized_readme)


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


def _read_image_dimensions(path: Path) -> tuple[int, int] | None:
    """Читаем размеры PNG/JPEG без внешних библиотек."""

    try:
        with path.open("rb") as handle:
            header = handle.read(24)
            if header.startswith(b"\x89PNG\r\n\x1a\n") and len(header) >= 24:
                width, height = struct.unpack(">II", header[16:24])
                return int(width), int(height)
            if header.startswith(b"\xff\xd8"):
                return _read_jpeg_dimensions(header + handle.read())
    except OSError:
        return None
    return None


def _is_decorative_image(path: str, quote: str, width: int, height: int) -> bool:
    """Не ругаем маленькие иконки, бейджи и логотипы как содержательные изображения."""

    marker_text = f"{path} {quote}".lower()
    decorative_markers = ("icon", "badge", "logo", "favicon", "avatar", "shield", "икон", "логотип")
    if any(marker in marker_text for marker in decorative_markers):
        return True
    return width <= 128 and height <= 128


def _read_jpeg_dimensions(data: bytes) -> tuple[int, int] | None:
    """Находим SOF-сегмент JPEG и достаём ширину/высоту."""

    index = 2
    while index < len(data) - 9:
        if data[index] != 0xFF:
            index += 1
            continue
        marker = data[index + 1]
        block_length = int.from_bytes(data[index + 2 : index + 4], "big")
        if marker in {0xC0, 0xC1, 0xC2, 0xC3}:
            height = int.from_bytes(data[index + 5 : index + 7], "big")
            width = int.from_bytes(data[index + 7 : index + 9], "big")
            return width, height
        index += 2 + block_length
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
    if re.fullmatch(r"(19|20)\d{2}", lowered):
        return any(keyword in context for keyword in TECH_KEYWORDS)
    if any(keyword in lowered for keyword in TECH_KEYWORDS):
        return True
    return entity.entity_type == EntityType.VERSION and any(keyword in context for keyword in TECH_KEYWORDS)


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
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def _looks_like_fact_claim(value: str) -> bool:
    """Отбираем только утверждения с датами, версиями, стандартами или признаками внешней проверяемости."""

    lowered = value.lower()
    if len(value) < 35 or len(value) > 520:
        return False
    if lowered.startswith(("http://", "https://", "![", "[")):
        return False
    if len(re.findall(r"\w+", value, flags=re.UNICODE)) < 5:
        return False
    return bool(FACT_DATE_RE.search(value) or FACT_MARKER_RE.search(value) or any(keyword in lowered for keyword in TECH_KEYWORDS))


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
