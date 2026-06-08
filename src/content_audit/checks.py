"""Проверяющие модули для критериев аудита."""

from __future__ import annotations

import hashlib
import re
import struct
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable
from urllib.parse import urldefrag, urlparse

import requests
import yaml

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


class CheckContext:
    """Контекст, общий для всех проверяющих модулей."""

    def __init__(self, settings: AuditSettings, model_client: OpenRouterClient | None = None) -> None:
        self.settings = settings
        self.model_client = model_client


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
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.ACTUALITY,
                        Severity.MAJOR,
                        Verdict.WARNING,
                        0.75,
                        entity.quote,
                        entity.location,
                        [Evidence(title="Ошибка запроса", detail=error, url=entity.value)],
                        "Проверить ссылку вручную: возможно, ресурс недоступен, требует авторизации или блокирует автоматические запросы.",
                        True,
                    )
                )
            elif status_code >= 400:
                severity = Severity.CRITICAL if status_code in {404, 410} else Severity.MAJOR
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
        languages = _detect_languages(unit)
        severity = Severity.INFO if len(languages) >= 2 else Severity.MINOR
        verdict = Verdict.PASS if len(languages) >= 2 else Verdict.WARNING
        return [
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
                extra={"languages": sorted(languages)},
            )
        ]


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

    PLACEHOLDER_RE = re.compile(r"\b(TODO|TBD|FIXME|lorem ipsum)\b|здесь будет|дописать|заглушка", re.IGNORECASE)

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        del entities, context
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
                if check_long_lines and len(stripped) > 260:
                    long_lines.append((index, len(stripped), stripped[:180]))
            if long_lines:
                preview = "; ".join(f"строка {line}: {length} симв." for line, length, _text in long_lines[:8])
                findings.append(
                    _finding(
                        unit,
                        self.name,
                        Criterion.READABILITY,
                        Severity.MINOR,
                        Verdict.WARNING,
                        0.7,
                        None,
                        TextLocation(file_path=file.relative_path),
                        [Evidence(title="Длинные строки", detail=f"Найдено {len(long_lines)} длинных строк: {preview}")],
                        "Проверить читаемость файла: при необходимости разбить длинные абзацы на более короткие блоки.",
                        True,
                        extra={"long_line_count": len(long_lines), "examples": [text for _line, _length, text in long_lines[:5]]},
                    )
                )
        return findings


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
                    Severity.MINOR,
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


class TechnologyFreshnessChecker(BaseChecker):
    """Формирует кандидаты на проверку актуальности технологий и версий."""

    name = "technology_freshness_checker"

    def check(self, unit: ContentUnit, entities: list[ExtractedEntity], context: CheckContext) -> list[Finding]:
        del context
        candidates = [entity for entity in entities if entity.entity_type in {EntityType.VERSION, EntityType.TECHNOLOGY, EntityType.DATE}]
        seen_values: set[tuple[str, str]] = set()
        selected: list[ExtractedEntity] = []
        for entity in candidates:
            key = (entity.location.file_path, entity.value.lower())
            if key in seen_values:
                continue
            seen_values.add(key)
            if not _looks_like_actuality_candidate(entity.value):
                continue
            selected.append(entity)

        if not selected:
            return []

        preview = ", ".join(entity.value for entity in selected[:20])
        if len(selected) > 20:
            preview = f"{preview}, ..."
        return [
            _finding(
                unit,
                self.name,
                Criterion.ACTUALITY,
                Severity.INFO,
                Verdict.UNKNOWN,
                0.55,
                None,
                None,
                [Evidence(title="Кандидаты на проверку", detail=f"Найдено {len(selected)} сущностей: {preview}")],
                "Запустить модельную проверку актуальности технологий, версий и дат; извлечённые сущности доступны в report.json.",
                True,
                extra={"candidate_count": len(selected), "sample_values": [entity.value for entity in selected[:20]]},
            )
        ]


class ModelRubricChecker(BaseChecker):
    """Модельная проверка критериев, которые трудно закрыть правилами."""

    name = "model_rubric_checker"

    SYSTEM_PROMPT = """Ты проверяешь учебный контент как инженер-методолог.
Верни только JSON: {"findings": [ ... ]}.
Каждый элемент: criterion, severity, verdict, confidence, quote, file_path, line_start, evidence, recommendation.
Критерии: market_fit, correctness, workload, rights, readability, checklist_alignment, actuality.
Все текстовые поля ответа пиши на русском языке.
Не используй английский язык в рекомендации, если только цитируешь исходный термин из материала.
Не придумывай источники. Если доказательств мало, ставь verdict='unknown' и needs_human_review=true."""

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

        return [_finding_from_model_item(unit, self.name, item) for item in response.get("findings", []) if isinstance(item, dict)]


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
        TechnologyFreshnessChecker(),
    ]
    if use_model:
        checkers.append(ModelRubricChecker())
    return checkers


def _entities_of_type(entities: Iterable[ExtractedEntity], entity_type: EntityType) -> Iterable[ExtractedEntity]:
    """Фильтруем сущности по типу."""

    return (entity for entity in entities if entity.entity_type == entity_type)


def _check_url(url: str, timeout_seconds: float) -> tuple[int, str | None, str | None]:
    """Проверяем внешнюю ссылку через HEAD с запасным GET."""

    try:
        response = requests.head(url, allow_redirects=True, timeout=timeout_seconds)
        if response.status_code in {405, 403}:
            response = requests.get(url, allow_redirects=True, timeout=timeout_seconds, stream=True)
        return response.status_code, response.url, None
    except requests.RequestException as exc:
        return 0, None, str(exc)


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


def _detect_languages(unit: ContentUnit) -> set[str]:
    """Определяем языковые версии по именам файлов и маркерам в тексте."""

    languages: set[str] = set()
    for file in unit.files:
        lower_path = file.relative_path.lower()
        if "_rus" in lower_path or "рус" in lower_path:
            languages.add("RUS")
        if "_uzb" in lower_path or "_uz" in lower_path:
            languages.add("UZ")
        if "_tg" in lower_path or "taj" in lower_path:
            languages.add("TG")
        if file.kind == "readme" and not any(marker in lower_path for marker in ("_rus", "_uzb", "_uz", "_tg")):
            languages.add("ENG")
    return languages


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


def _looks_like_actuality_candidate(value: str) -> bool:
    """Отсекаем слишком общие слова и оставляем проверяемые версии/даты/технологии."""

    lowered = value.lower()
    if len(lowered) < 3:
        return False
    if re.fullmatch(r"(19|20)\d{2}", lowered):
        year = int(lowered)
        return year >= 2000
    return bool(re.search(r"\d", lowered) or lowered in {"java", "python", "docker", "gitlab", "github", "gcc", "pcre2"})


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


def _finding_from_model_item(unit: ContentUnit, checker_name: str, item: dict[str, object]) -> Finding:
    """Преобразуем ответ модели в строгий доменный объект."""

    criterion = _enum_or_default(Criterion, item.get("criterion"), Criterion.CORRECTNESS)
    severity = _enum_or_default(Severity, item.get("severity"), Severity.INFO)
    verdict = _enum_or_default(Verdict, item.get("verdict"), Verdict.UNKNOWN)
    file_path = str(item.get("file_path") or "") or None
    line_start = _parse_optional_int(item.get("line_start"))
    location = TextLocation(file_path=file_path or "", line_start=line_start, line_end=line_start) if file_path and line_start else None
    evidence_text = str(item.get("evidence") or "Модельная проверка без отдельного источника.")
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
        recommendation=recommendation,
        needs_human_review=needs_human_review,
        checker_name=checker_name,
        extra=extra or {},
    )
