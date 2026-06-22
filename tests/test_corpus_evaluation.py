from __future__ import annotations

from datetime import datetime, timezone

from openpyxl import Workbook

from content_audit.corpus_evaluation import evaluate_corpus_report
from content_audit.domain import AuditReport, ContentUnit, Criterion, Finding, RunSummary, Severity, Verdict


def test_corpus_evaluation_matches_projects_and_computes_metrics(workspace_tmp_path) -> None:
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["Проект", "SDP/ревью", "Проблема", "Детали", "Архив"])
    sheet.append(["AP1-Go-T01", "", "неактуальная ссылка\nопечатки", "Сломанная ссылка и опечатка.", ""])
    sheet.append(["SQLB3", "", "несоответствие задания чек-листу", "В чеклисте ожидается другое условие.", ""])
    gold_path = workspace_tmp_path / "gold.xlsx"
    workbook.save(gold_path)

    report = AuditReport(
        summary=RunSummary(started_at=datetime.now(timezone.utc), input_path=str(workspace_tmp_path)),
        units=[
            ContentUnit(
                unit_id="ap1_go_t01__abc",
                name="AP1_Go_T01.ID_1375359-master",
                root_path=workspace_tmp_path,
                relative_path="AP1_Go_T01.ID_1375359-master",
            ),
            ContentUnit(
                unit_id="sqlb3__abc",
                name="SQLB3_Retrieving_data.ID_574089-master (1)",
                root_path=workspace_tmp_path,
                relative_path="SQLB3_Retrieving_data.ID_574089-master (1)",
            ),
        ],
        entities=[],
        findings=[
            Finding(
                finding_id="f1",
                unit_id="ap1_go_t01__abc",
                branch=None,
                criterion=Criterion.ACTUALITY,
                severity=Severity.MAJOR,
                verdict=Verdict.FAIL,
                confidence=0.9,
                recommendation="Исправить ссылку.",
                checker_name="test",
            ),
            Finding(
                finding_id="f2",
                unit_id="sqlb3__abc",
                branch=None,
                criterion=Criterion.CHECKLIST_ALIGNMENT,
                severity=Severity.MAJOR,
                verdict=Verdict.FAIL,
                confidence=0.9,
                recommendation="Синхронизировать чек-лист.",
                checker_name="test",
            ),
            Finding(
                finding_id="f3",
                unit_id="sqlb3__abc",
                branch=None,
                criterion=Criterion.RIGHTS,
                severity=Severity.INFO,
                verdict=Verdict.UNKNOWN,
                confidence=0.4,
                recommendation="Проверить права.",
                checker_name="test",
            ),
        ],
    )

    summary = evaluate_corpus_report(report, gold_path)

    assert summary.gold_total == 3
    assert summary.predicted_total == 3
    assert summary.true_positive == 2
    assert summary.false_positive == 1
    assert summary.false_negative == 1
    assert summary.precision == 0.6667
    assert summary.recall == 0.6667
    assert summary.f1_score == 0.6667
    assert summary.gold_scope_precision == 1.0
    assert summary.gold_scope_recall == 0.6667
    assert summary.gold_scope_f1_score == 0.8
