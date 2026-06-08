"""Привязка локальных папок к платформенным идентификаторам."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from content_audit.domain import ContentUnit


class UnitManifestRecord(BaseModel):
    """Одна строка манифеста с платформенными метаданными единицы."""

    path: str
    unit_id: str | None = None
    branch: str | None = None
    admin_url: str | None = None
    name: str | None = None


def apply_unit_manifest(
    units: list[ContentUnit],
    input_root: Path,
    manifest_path: Path | None,
    admin_url_template: str | None,
) -> tuple[list[ContentUnit], list[str]]:
    """Накладываем манифест на найденные единицы контента."""

    warnings: list[str] = []
    records = _load_manifest_records(manifest_path, warnings) if manifest_path else {}
    updated: list[ContentUnit] = []
    for unit in units:
        record = _match_record(unit, records, input_root)
        unit_id = record.unit_id if record and record.unit_id else unit.unit_id
        branch = record.branch if record and record.branch else unit.branch
        admin_url = record.admin_url if record and record.admin_url else unit.admin_url
        name = record.name if record and record.name else unit.name
        if not admin_url and admin_url_template:
            admin_url = _render_admin_url(admin_url_template, unit_id, branch, unit.relative_path, name, warnings)
        updated.append(unit.model_copy(update={"unit_id": unit_id, "branch": branch, "admin_url": admin_url, "name": name}))
    return updated, warnings


def _load_manifest_records(manifest_path: Path, warnings: list[str]) -> dict[str, UnitManifestRecord]:
    """Читаем JSON или CSV манифест и индексируем строки по нормализованному пути."""

    if not manifest_path.exists():
        warnings.append(f"Манифест единиц не найден: {manifest_path}")
        return {}

    if manifest_path.suffix.lower() == ".csv":
        rows = _read_csv_rows(manifest_path)
    else:
        rows = _read_json_rows(manifest_path)

    records: dict[str, UnitManifestRecord] = {}
    for row in rows:
        record = _record_from_row(row)
        if not record:
            continue
        records[_normalize_manifest_path(record.path)] = record
    return records


def _read_csv_rows(path: Path) -> list[dict[str, Any]]:
    """Читаем CSV с заголовками."""

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _read_json_rows(path: Path) -> list[dict[str, Any]]:
    """Читаем JSON-манифест в форме списка или объекта с ключом units."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        payload = payload.get("units", [])
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _record_from_row(row: dict[str, Any]) -> UnitManifestRecord | None:
    """Поддерживаем несколько распространённых имён колонок."""

    path = _first_non_empty(row, "path", "relative_path", "unit_path", "folder", "project_path")
    if not path:
        return None
    return UnitManifestRecord(
        path=path,
        unit_id=_first_non_empty(row, "unit_id", "id", "platform_id", "project_id"),
        branch=_first_non_empty(row, "branch", "track", "direction"),
        admin_url=_first_non_empty(row, "admin_url", "url", "platform_url"),
        name=_first_non_empty(row, "name", "title", "unit_name"),
    )


def _first_non_empty(row: dict[str, Any], *keys: str) -> str | None:
    """Возвращаем первое непустое значение из строки манифеста."""

    for key in keys:
        value = row.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _match_record(
    unit: ContentUnit,
    records: dict[str, UnitManifestRecord],
    input_root: Path,
) -> UnitManifestRecord | None:
    """Ищем запись по относительному пути и по пути от входной папки."""

    candidates = {
        _normalize_manifest_path(unit.relative_path),
        _normalize_manifest_path(unit.root_path.name),
    }
    try:
        candidates.add(_normalize_manifest_path(unit.root_path.relative_to(input_root).as_posix()))
    except ValueError:
        pass
    if unit.relative_path == ".":
        candidates.add(".")
    for candidate in candidates:
        if candidate in records:
            return records[candidate]
    return None


def _normalize_manifest_path(value: str) -> str:
    """Приводим путь из манифеста к единому виду."""

    normalized = value.strip().replace("\\", "/").strip("/")
    return normalized or "."


def _render_admin_url(
    template: str,
    unit_id: str,
    branch: str | None,
    relative_path: str,
    name: str,
    warnings: list[str],
) -> str | None:
    """Подставляем идентификаторы в шаблон ссылки админки."""

    try:
        return template.format(id=unit_id, unit_id=unit_id, branch=branch or "", path=relative_path, name=name)
    except KeyError as exc:
        warnings.append(f"В шаблоне ссылки админки неизвестное поле: {exc}")
        return None
