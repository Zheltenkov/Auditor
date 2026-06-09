"""Экспорт отчётов в JSON и CSV."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from content_audit.domain import CRITERION_LABELS, SEVERITY_LABELS, VERDICT_LABELS, AuditReport, Verdict


def write_report(report: AuditReport, output_path: Path, include_pass: bool = False) -> None:
    """Записываем полный отчёт, таблицу для методологов и краткую сводку."""

    output_path.mkdir(parents=True, exist_ok=True)
    (output_path / "report.json").write_text(
        json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (output_path / "run_summary.json").write_text(
        json.dumps(report.summary.model_dump(mode="json"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    _write_csv(report, output_path / "report.csv", include_pass=include_pass)


def _write_csv(report: AuditReport, path: Path, include_pass: bool) -> None:
    """Формируем таблицу результата в виде, близком к ТЗ."""

    unit_by_id = {unit.unit_id: unit for unit in report.units}
    rows = []
    for finding in report.findings:
        if finding.verdict == Verdict.PASS and not include_pass:
            continue
        unit = unit_by_id.get(finding.unit_id)
        evidence = " | ".join(f"{item.title}: {item.detail}" for item in finding.evidence)
        rows.append(
            {
                "Ветка": finding.branch or "",
                "ID единицы": finding.unit_id,
                "Название единицы": unit.name if unit else "",
                "Критерий": CRITERION_LABELS[finding.criterion],
                "Файл": finding.location.file_path if finding.location else "",
                "Строка": finding.location.line_start if finding.location else "",
                "Цитата": finding.quote or "",
                "Вердикт": VERDICT_LABELS[finding.verdict],
                "Критичность": SEVERITY_LABELS[finding.severity],
                "Уверенность": f"{finding.confidence:.2f}",
                "Обоснование": evidence,
                "Источник": finding.source or "",
                "Дата проверки": _format_checked_at(finding),
                "Статус поддержки": finding.support_status or "",
                "Последняя версия": finding.latest_version or "",
                "Рекомендуемая версия": finding.recommended_version or "",
                "Версия модельного запроса": finding.prompt_version or "",
                "Рекомендация": finding.recommendation,
                "Нужен человек": "да" if finding.needs_human_review else "нет",
                "Проверяющий модуль": finding.checker_name,
            }
        )

    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else _empty_fieldnames())
        writer.writeheader()
        writer.writerows(rows)


def _empty_fieldnames() -> list[str]:
    """Возвращаем заголовки даже для пустого отчёта."""

    return [
        "Ветка",
        "ID единицы",
        "Название единицы",
        "Критерий",
        "Файл",
        "Строка",
        "Цитата",
        "Вердикт",
        "Критичность",
        "Уверенность",
        "Обоснование",
        "Источник",
        "Дата проверки",
        "Статус поддержки",
        "Последняя версия",
        "Рекомендуемая версия",
        "Версия модельного запроса",
        "Рекомендация",
        "Нужен человек",
        "Проверяющий модуль",
    ]


def _format_checked_at(finding) -> str:
    """Форматируем дату проверки для табличной выгрузки."""

    if not finding.checked_at:
        return ""
    return finding.checked_at.isoformat()
