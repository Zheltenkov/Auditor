"""Каркас расчёта метрик качества по размеченной выборке."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from content_audit.domain import AuditReport, Criterion, Severity


class EvaluationItem(BaseModel):
    """Одна эталонная или предсказанная находка для сравнения."""

    unit_id: str
    criterion: str
    severity: str | None = None
    file_path: str | None = None
    line_start: int | None = None

    def key(self, strict_severity: bool = False) -> tuple[object, ...]:
        """Ключ сопоставления с опциональным учётом критичности."""

        base: tuple[object, ...] = (self.unit_id, self.criterion, self.file_path or "", self.line_start or 0)
        if strict_severity:
            return (*base, self.severity or "")
        return base


class EvaluationSummary(BaseModel):
    """Метрики приёмки для текущего отчёта."""

    gold_total: int
    predicted_total: int
    true_positive: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float
    critical_recall: float
    false_positive_rate: float
    notes: list[str] = Field(default_factory=list)


def evaluate_report(report: AuditReport, gold_path: Path) -> EvaluationSummary:
    """Сравниваем отчёт с эталонной JSON/CSV разметкой."""

    gold_items = _load_gold_items(gold_path)
    predicted_items = _items_from_report(report)
    gold_keys = {item.key() for item in gold_items}
    predicted_keys = {item.key() for item in predicted_items}

    true_positive = len(gold_keys & predicted_keys)
    false_positive = len(predicted_keys - gold_keys)
    false_negative = len(gold_keys - predicted_keys)
    critical_gold = {item.key() for item in gold_items if item.severity == Severity.CRITICAL.value}
    critical_found = len(critical_gold & predicted_keys)

    return EvaluationSummary(
        gold_total=len(gold_keys),
        predicted_total=len(predicted_keys),
        true_positive=true_positive,
        false_positive=false_positive,
        false_negative=false_negative,
        precision=_safe_ratio(true_positive, true_positive + false_positive),
        recall=_safe_ratio(true_positive, true_positive + false_negative),
        critical_recall=_safe_ratio(critical_found, len(critical_gold)),
        false_positive_rate=_safe_ratio(false_positive, len(predicted_keys)),
        notes=["Метрики считаются по ключу unit_id + criterion + file_path + line_start."],
    )


def write_evaluation(report: AuditReport, gold_path: Path, output_path: Path) -> EvaluationSummary:
    """Считаем и записываем метрики качества."""

    summary = evaluate_report(report, gold_path)
    output_path.write_text(json.dumps(summary.model_dump(mode="json"), ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def _load_gold_items(path: Path) -> list[EvaluationItem]:
    """Загружаем эталонную выборку из JSON или CSV."""

    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            rows = [dict(row) for row in csv.DictReader(handle)]
    else:
        payload = json.loads(path.read_text(encoding="utf-8"))
        rows = payload.get("items", payload) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        return []
    return [_item_from_row(row) for row in rows if isinstance(row, dict)]


def _items_from_report(report: AuditReport) -> list[EvaluationItem]:
    """Преобразуем находки отчёта к ключам оценки."""

    items: list[EvaluationItem] = []
    for finding in report.findings:
        file_path = finding.location.file_path if finding.location else None
        line_start = finding.location.line_start if finding.location else None
        items.append(
            EvaluationItem(
                unit_id=finding.unit_id,
                criterion=finding.criterion.value,
                severity=finding.severity.value,
                file_path=file_path,
                line_start=line_start,
            )
        )
    return items


def _item_from_row(row: dict[str, Any]) -> EvaluationItem:
    """Поддерживаем русские и технические имена полей в эталонной выборке."""

    return EvaluationItem(
        unit_id=str(_first_value(row, "unit_id", "ID единицы") or ""),
        criterion=_normalise_criterion(_first_value(row, "criterion", "Критерий")),
        severity=_normalise_severity(_first_value(row, "severity", "Критичность")),
        file_path=str(_first_value(row, "file_path", "Файл") or "") or None,
        line_start=_parse_optional_int(_first_value(row, "line_start", "Строка")),
    )


def _first_value(row: dict[str, Any], *keys: str) -> Any:
    """Берём первое имеющееся значение из строки."""

    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return None


def _normalise_criterion(value: Any) -> str:
    """Нормализуем критерий для сравнения."""

    text = str(value or "").strip().lower()
    labels = {
        "актуальность": Criterion.ACTUALITY.value,
        "точность и корректность": Criterion.CORRECTNESS.value,
        "грамотность и читаемость текста": Criterion.READABILITY.value,
        "качество изображений": Criterion.IMAGE_QUALITY.value,
    }
    return labels.get(text, text)


def _normalise_severity(value: Any) -> str | None:
    """Нормализуем критичность для будущих строгих сравнений."""

    text = str(value or "").strip().lower()
    labels = {
        "критическая": Severity.CRITICAL.value,
        "высокая": Severity.MAJOR.value,
        "средняя": Severity.MINOR.value,
        "справочно": Severity.INFO.value,
    }
    return labels.get(text, text or None)


def _parse_optional_int(value: Any) -> int | None:
    """Безопасно разбираем номер строки."""

    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _safe_ratio(numerator: int, denominator: int) -> float:
    """Деление для метрик без исключения на пустом наборе."""

    return round(numerator / denominator, 4) if denominator else 0.0
