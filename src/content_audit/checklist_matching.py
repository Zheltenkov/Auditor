"""Сопоставление пунктов чек-листа с заданиями README."""

from __future__ import annotations

import re
from dataclasses import dataclass

from content_audit.text_utils import normalize_for_match


CHECKLIST_STOP_TOKENS = {
    "part",
    "task",
    "step",
    "section",
    "chapter",
    "module",
    "exercise",
    "project",
    "qism",
    "часть",
    "раздел",
    "задание",
}


@dataclass(frozen=True)
class ChecklistMatchResult:
    """Итог сопоставления чек-листа с README."""

    total: int
    matched: int
    ratio: float
    matched_names: tuple[str, ...]
    unmatched_names: tuple[str, ...]


def extract_checklist_question_names(payload: object) -> list[str]:
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


def match_checklist_to_readme(question_names: list[str], readme_text: str) -> ChecklistMatchResult:
    """Сопоставляет пункты чек-листа с README и возвращает объяснимый результат."""

    normalized_readme = normalize_for_match(readme_text)
    matched_names = []
    unmatched_names = []
    for name in question_names:
        if checklist_name_matches_readme(name, normalized_readme):
            matched_names.append(name)
        else:
            unmatched_names.append(name)
    total = len(question_names)
    matched = len(matched_names)
    ratio = matched / total if total else 0.0
    return ChecklistMatchResult(
        total=total,
        matched=matched,
        ratio=ratio,
        matched_names=tuple(matched_names),
        unmatched_names=tuple(unmatched_names),
    )


def checklist_name_matches_readme(name: str, normalized_readme: str) -> bool:
    """Сопоставляет техническое имя пункта с нормализованным текстом README."""

    normalized = normalize_for_match(name)
    if normalized and normalized in normalized_readme:
        return True
    part_match = re.search(r"part\s+(\d+)", normalized)
    if part_match and f"part {part_match.group(1)}" in normalized_readme:
        return True

    numbers = re.findall(r"\d+", normalized)
    tokens = [
        token
        for token in re.findall(r"[a-zа-яё0-9]+", normalized)
        if token not in CHECKLIST_STOP_TOKENS and not token.isdigit() and len(token) >= 2
    ]
    if not tokens:
        return False

    token_hits = sum(1 for token in tokens if re.search(rf"\b{re.escape(token)}\b", normalized_readme))
    number_hits = sum(1 for number in numbers if re.search(rf"\b{re.escape(number)}\b", normalized_readme))
    if numbers:
        return token_hits == len(tokens) and number_hits > 0
    return token_hits == len(tokens)
