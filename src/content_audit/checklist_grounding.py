"""Проверка, что чек-лист не добавляет требования поверх README."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from content_audit.checklist_matching import ChecklistQuestion
from content_audit.domain import Severity


EXERCISE_HEADING_RE = re.compile(
    r"(?im)^#{1,6}\s*(?:exercise|task|quest|chapter|задани[ея]|упражнени[ея])\s*0*(\d+)\b"
)
QUESTION_NUMBER_RE = re.compile(r"(?i)(?:exercise|task|quest|chapter|задани[ея]|упражнени[ея])\s*0*(\d+)")
SELF_JOIN_ID_ORDER_RE = re.compile(r"\b(?P<left>[a-z]\w*)\.id\s*(?P<op>>|<)\s*(?P<right>[a-z]\w*)\.id\b", re.IGNORECASE)
QUOTED_VALUE_RE = re.compile(r'"([^"\n]{2,120})"')


@dataclass(frozen=True)
class ChecklistGroundingIssue:
    """Конкретное требование чек-листа, не подтверждённое текстом задания."""

    question_name: str
    issue_type: str
    detail: str
    severity: Severity
    evidence: str


def assess_checklist_grounding(
    questions: list[ChecklistQuestion],
    readme_text: str,
) -> list[ChecklistGroundingIssue]:
    """Ищет узкие, но сильные признаки расхождения README и чек-листа."""

    readme_sections = _split_readme_sections(readme_text)
    issues: list[ChecklistGroundingIssue] = []
    for question in questions:
        exercise_number = _extract_question_number(question.name)
        if exercise_number is None:
            continue
        readme_section = readme_sections.get(exercise_number, "")
        if not readme_section:
            continue

        issues.extend(_find_self_join_ordering_issues(question, readme_section))
        issues.extend(_find_duplicate_name_result_issues(question, readme_section))
    return issues


def _find_self_join_ordering_issues(
    question: ChecklistQuestion,
    readme_section: str,
) -> list[ChecklistGroundingIssue]:
    """Ловит скрытое требование к порядку пары через `p1.id > p2.id`."""

    checklist_text = question.description_text
    if not _readme_describes_pair_result(readme_section):
        return []

    compact_readme = _compact_sql_text(readme_section)
    issues: list[ChecklistGroundingIssue] = []
    for match in SELF_JOIN_ID_ORDER_RE.finditer(checklist_text):
        predicate = match.group(0)
        if _compact_sql_text(predicate) in compact_readme:
            continue
        issues.append(
            ChecklistGroundingIssue(
                question_name=question.name,
                issue_type="ungrounded_self_join_order",
                detail=(
                    "Чек-лист фиксирует порядок пары через сравнение идентификаторов, "
                    "но README не описывает это как требование."
                ),
                severity=Severity.MAJOR,
                evidence=predicate,
            )
        )
    return issues


def _find_duplicate_name_result_issues(
    question: ChecklistQuestion,
    readme_section: str,
) -> list[ChecklistGroundingIssue]:
    """Ловит повторяющиеся строки результата, когда README просит список названий."""

    if not _readme_asks_for_pizzeria_names(readme_section):
        return []

    values = [value.strip() for value in QUOTED_VALUE_RE.findall(question.description_text)]
    repeated_values = [(value, count) for value, count in Counter(values).items() if count >= 3]
    if not repeated_values:
        return []

    value, count = sorted(repeated_values, key=lambda item: (-item[1], item[0]))[0]
    return [
        ChecklistGroundingIssue(
            question_name=question.name,
            issue_type="suspicious_duplicate_name_result",
            detail=(
                "Чек-лист ожидает несколько одинаковых строк результата, "
                "хотя README формулирует результат как список названий."
            ),
            severity=Severity.MAJOR,
            evidence=f'{value} × {count}',
        )
    ]


def _split_readme_sections(readme_text: str) -> dict[int, str]:
    """Разбивает README на секции заданий по markdown-заголовкам."""

    matches = list(EXERCISE_HEADING_RE.finditer(readme_text))
    sections: dict[int, str] = {}
    for index, match in enumerate(matches):
        number = int(match.group(1))
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(readme_text)
        sections.setdefault(number, readme_text[start:end])
    return sections


def _extract_question_number(name: str) -> int | None:
    """Достаёт номер задания из имени пункта чек-листа."""

    match = QUESTION_NUMBER_RE.search(name)
    return int(match.group(1)) if match else None


def _readme_describes_pair_result(readme_section: str) -> bool:
    """Понимает, что секция README описывает результат из пар сущностей."""

    lowered = readme_section.lower()
    return (
        ("person_name1" in lowered and "person_name2" in lowered)
        or "pairs of" in lowered
        or "пары" in lowered
        or "парами" in lowered
    )


def _readme_asks_for_pizzeria_names(readme_section: str) -> bool:
    """Понимает формулировку «вернуть названия пиццерий», а не конкретные пиццы."""

    lowered = readme_section.lower()
    asks_for_names = (
        "names of pizzerias" in lowered
        or "name of pizzerias" in lowered
        or "названия пиццерий" in lowered
        or "название пиццерий" in lowered
    )
    asks_for_specific_pizzas = (
        "pizza_name" in lowered
        or "names of pizzas" in lowered
        or bool(re.search(r"\bназвания\s+пицц(?:ы)?\b", lowered))
    )
    return asks_for_names and not asks_for_specific_pizzas


def _compact_sql_text(value: str) -> str:
    """Сжимает SQL-фрагмент для сравнения без влияния пробелов."""

    return re.sub(r"\s+", "", value.lower())
