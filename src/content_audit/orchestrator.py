"""Оркестратор запуска аудита."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from content_audit.checks import CheckContext, default_checkers
from content_audit.domain import AuditReport, AuditSettings, ExtractedEntity, Finding, RunSummary, Verdict
from content_audit.extraction import extract_entities
from content_audit.ingestion import discover_content_units, load_unit_files
from content_audit.openrouter import OpenRouterClient


class AuditRunner:
    """Управляет полным прогоном: загрузка, извлечение, проверки, сводка."""

    def __init__(self, settings: AuditSettings) -> None:
        self.settings = settings

    def run(self) -> AuditReport:
        """Выполняем аудит и возвращаем полный отчёт."""

        started_at = datetime.now(timezone.utc)
        warnings: list[str] = []
        units = [load_unit_files(unit, self.settings.max_file_bytes) for unit in discover_content_units(self.settings.input_path)]
        model_client = self._build_model_client(warnings)
        context = CheckContext(settings=self.settings, model_client=model_client)
        checkers = default_checkers(use_model=self.settings.use_model and model_client is not None)

        all_entities: list[ExtractedEntity] = []
        all_findings: list[Finding] = []
        for unit in units:
            # Сначала извлекаем сущности, затем маршрутизируем их по проверяющим модулям.
            entities = extract_entities(unit)
            all_entities.extend(entities)
            for checker in checkers:
                all_findings.extend(checker.check(unit, entities, context))

        findings = self._filter_findings(all_findings)
        summary = self._build_summary(started_at, units, findings, warnings, model_client is not None)
        return AuditReport(summary=summary, units=units, entities=all_entities, findings=findings)

    def _build_model_client(self, warnings: list[str]) -> OpenRouterClient | None:
        """Создаём модельный клиент только при наличии ключа и модели."""

        if not self.settings.use_model:
            return None
        if not self.settings.openrouter_api_key:
            warnings.append("Модельный контур запрошен, но OPENROUTER_API_KEY не задан.")
            return None
        if not self.settings.openrouter_model:
            warnings.append("Модельный контур запрошен, но модель OpenRouter не указана.")
            return None
        return OpenRouterClient(api_key=self.settings.openrouter_api_key, model=self.settings.openrouter_model)

    def _filter_findings(self, findings: list[Finding]) -> list[Finding]:
        """Убираем положительные и неизвестные случаи, если пользователь это запросил."""

        result = findings if self.settings.include_pass else [finding for finding in findings if finding.verdict != Verdict.PASS]
        if self.settings.include_unknown:
            return result
        return [finding for finding in result if finding.verdict != Verdict.UNKNOWN]

    def _build_summary(
        self,
        started_at: datetime,
        units: list,
        findings: list[Finding],
        warnings: list[str],
        model_used: bool,
    ) -> RunSummary:
        """Собираем краткую сводку по прогону."""

        by_severity = Counter(finding.severity.value for finding in findings)
        by_criterion = Counter(finding.criterion.value for finding in findings)
        return RunSummary(
            started_at=started_at,
            finished_at=datetime.now(timezone.utc),
            input_path=str(self.settings.input_path),
            units_total=len(units),
            files_total=sum(len(unit.files) for unit in units),
            findings_total=len(findings),
            by_severity=dict(by_severity),
            by_criterion=dict(by_criterion),
            model_used=model_used,
            network_used=self.settings.allow_network or model_used,
            warnings=warnings,
        )
