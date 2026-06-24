"""Anchor pre-screen + LLM-as-judge aligner for corpus evaluation.

This is an optional matching strategy for corpus_evaluation: instead of the
strict line+text matcher it screens candidate pairs cheaply (shared anchors:
url / file / quote / missing-artifact, plus lexical similarity and line
proximity) and asks a judge "same defect?" only for the top-K candidates per
gold case. The judge is pluggable:

  * "offline"    - semantic stand-in (Russian light stemmer + rare-token
                   overlap). No network. Used for local/CI runs.
  * "openrouter" - real model via content_audit.openrouter. Run where
                   OpenRouter is reachable (key from .env).

The module is import-light and is loaded lazily by corpus_evaluation to avoid a
circular import. All Russian marker words and prompt text live in
aligner_markers.json / aligner_prompts.json so this source stays ASCII.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Protocol

from content_audit.corpus_evaluation import (
    CorpusEvaluationMatch,
    GoldCorpusCase,
    PredictedCorpusItem,
    _criterion_label,
    _format_prediction_range,
    _format_range,
    _line_relation,
    _normalize_match_text,
    _same_missing_artifact_signal,
)

_DATA_DIR = Path(__file__).parent
_MARKERS = json.loads((_DATA_DIR / "aligner_markers.json").read_text(encoding="utf-8"))
_PROMPTS = json.loads((_DATA_DIR / "aligner_prompts.json").read_text(encoding="utf-8"))

PLACEHOLDER_MARKERS = tuple(_MARKERS["placeholders"])
OPINION_MARKERS = tuple(_MARKERS["opinions"])
RU_STOP = set(_MARKERS["ru_stop"])
STOPWORDS = set("the a to of in is on are and not".split()) | RU_STOP

PRESCREEN_MIN = 0.10
DEFAULT_TOPK = 6
JUDGE_ACCEPT = 0.55

URL_RE = re.compile(r"https?:[/\\]+[^\s)>\]\"'|]+", re.IGNORECASE)
FILE_RE = re.compile(
    r"[\w\-./]+\.(?:sql|docx?|md|ya?ml|png|jpe?g|pcapng|pcap|py|js|java|go|c|h|sh|txt|xlsx|csv)",
    re.IGNORECASE,
)
QUOTE_RE = re.compile(r"[`«\"']([^`«»\"']{3,80})[`»\"']")

_SUFFIXES = sorted(
    [
        "ами", "ями", "ому", "ему",
        "ого", "его", "ыми", "ими",
        "ая", "яя", "ое", "ее", "ые", "ие",
        "ой", "ей", "ом", "ем", "ах", "ях",
        "ов", "ев", "ам", "ям", "ть", "ся",
        "ия", "ию", "ий", "ла", "ло", "ли",
        "на", "ну", "ет", "ут", "ют", "ат",
        "ят",
        "а", "я", "о", "е", "ы", "и", "у", "ю", "й", "ь",
    ],
    key=len,
    reverse=True,
)

_MIRROR_FAMILY = {
    "readme.md": "readme",
    "readme_rus.md": "readme",
    "readme_eng.md": "readme",
    "check-list.yml": "checklist",
    "check-list_rus.yml": "checklist",
    "check-list_uzb.yml": "checklist",
}


@dataclass(frozen=True)
class Anchors:
    urls: frozenset
    files: frozenset
    phrases: frozenset


def _norm_url(url: str) -> str:
    u = url.lower().strip().rstrip(".,);]>")
    u = re.sub(r"https?:[/\\]+", "https://", u)
    return u.rstrip("/")


def extract_anchors(text: str) -> Anchors:
    urls = {_norm_url(m.group(0)) for m in URL_RE.finditer(text)}
    files = {Path(m.group(0).replace("\\", "/")).name.lower() for m in FILE_RE.finditer(text)}
    phrases = set()
    for m in QUOTE_RE.finditer(text):
        phrase = _normalize_match_text(m.group(1))
        if len(phrase.split()) >= 2:
            phrases.add(phrase)
    return Anchors(frozenset(urls), frozenset(files), frozenset(phrases))


def _content_tokens(text: str) -> set:
    return {t for t in _normalize_match_text(text).split() if len(t) > 2 and t not in STOPWORDS}


def content_similarity(gold_text: str, found_text: str) -> float:
    g = _content_tokens(gold_text)
    f = _content_tokens(found_text)
    if not g or not f:
        return 0.0
    token_score = len(g & f) / min(len(g), len(f))
    seq = SequenceMatcher(a=_normalize_match_text(gold_text), b=_normalize_match_text(found_text)).ratio()
    return max(token_score, seq)


def _phrase_hit(a: Anchors, b: Anchors) -> bool:
    if a.phrases & b.phrases:
        return True
    for p in a.phrases:
        for q in b.phrases:
            if p in q or q in p:
                return True
    return False


def _stem(token: str) -> str:
    for suf in _SUFFIXES:
        if len(token) - len(suf) >= 4 and token.endswith(suf):
            return token[: -len(suf)]
    return token


def _stem_tokens(text: str) -> set:
    return {_stem(t) for t in _content_tokens(text)}


def is_opinion(text: str) -> bool:
    low = (text or "").lower()
    return any(m in low for m in OPINION_MARKERS)


def is_placeholder_prediction(item: PredictedCorpusItem) -> bool:
    low = (item.found_text or "").lower()
    return any(m in low for m in PLACEHOLDER_MARKERS)


def mirror_family(file_path: str | None) -> str:
    base = Path((file_path or "").replace("\\", "/")).name.lower()
    return _MIRROR_FAMILY.get(base, base)


def dedupe_mirror(items: list[PredictedCorpusItem]) -> list[PredictedCorpusItem]:
    """Collapse RU/EN and README<->check-list mirror findings by text core."""

    seen: set = set()
    out: list[PredictedCorpusItem] = []
    for item in items:
        core = " ".join(sorted(_content_tokens(item.found_text)))[:120]
        key = (item.project_id, item.criterion, item.issue_type, mirror_family(item.file_path), core)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def confidence_gate(items: list[PredictedCorpusItem], floor: float) -> list[PredictedCorpusItem]:
    """Drop low-confidence predictions (keeps items without a confidence value)."""

    if floor <= 0.0:
        return items
    return [it for it in items if it.confidence is None or it.confidence >= floor]


# --------------- judge backends ---------------

class Judge(Protocol):
    name: str
    calls: int

    def same_defect(self, gold: GoldCorpusCase, pred: PredictedCorpusItem) -> tuple[bool, float, str]:
        ...


class OfflineJudge:
    name = "offline"

    def __init__(self) -> None:
        self.calls = 0

    def same_defect(self, gold: GoldCorpusCase, pred: PredictedCorpusItem) -> tuple[bool, float, str]:
        self.calls += 1
        ga = extract_anchors(gold.gold_text)
        pa = extract_anchors(pred.found_text + " " + (pred.file_path or ""))
        if ga.urls & pa.urls or ga.files & pa.files or _phrase_hit(ga, pa):
            return True, 0.9, "shared anchor"
        if _same_missing_artifact_signal(gold.gold_text, pred.found_text):
            return True, 0.85, "missing-artifact signal"
        gs, fs = _stem_tokens(gold.gold_text), _stem_tokens(pred.found_text)
        if not gs or not fs:
            return False, 0.0, "empty"
        rare_shared = {t for t in (gs & fs) if len(t) >= 5}
        if len(rare_shared) >= 2:
            return True, 0.72, "shared rare stems"
        if _line_relation(gold.line_start, gold.line_end, pred.line_start, pred.line_end) == "overlap" and (gs & fs):
            return True, 0.7, "line overlap + shared stem"
        jac = len(gs & fs) / len(gs | fs)
        if jac >= 0.34:
            return True, 0.6, "stem jaccard %.2f" % jac
        return False, round(jac, 2), "low overlap"


class OpenRouterJudge:
    name = "openrouter"

    def __init__(self, api_key: str, model: str, cache_path: str | None = None) -> None:
        from content_audit.openrouter import OpenRouterClient

        self.client = OpenRouterClient(api_key=api_key, model=model)
        self.calls = 0
        self.cache_path = Path(cache_path) if cache_path else None
        self.cache: dict = {}
        if self.cache_path and self.cache_path.exists():
            self.cache = json.loads(self.cache_path.read_text(encoding="utf-8"))

    def _key(self, gold: GoldCorpusCase, pred: PredictedCorpusItem) -> str:
        raw = (gold.gold_text + "||" + pred.found_text).encode("utf-8")
        return hashlib.sha1(raw).hexdigest()

    def _save(self) -> None:
        if self.cache_path:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self.cache, ensure_ascii=False, indent=1), encoding="utf-8")

    def same_defect(self, gold: GoldCorpusCase, pred: PredictedCorpusItem) -> tuple[bool, float, str]:
        key = self._key(gold, pred)
        if key in self.cache:
            v = self.cache[key]
            return bool(v["same_defect"]), float(v.get("confidence", 0.6)), v.get("reason", "cache")
        loc = (pred.file_path or "") + (":%s" % pred.line_start if pred.line_start else "")
        user = _PROMPTS["user_template"].format(
            gold_criterion=gold.criterion,
            gold_text=gold.gold_text[:1200],
            pred_criterion=pred.criterion,
            pred_loc=loc,
            pred_text=pred.found_text[:1200],
        )
        self.calls += 1
        try:
            data = self.client.complete_json(_PROMPTS["system"], user)
        except Exception as exc:  # noqa: BLE001 - одиночный сбой судьи не должен валить весь замер.
            reason = f"judge_error: {str(exc)[:180]}"
            self.cache[key] = {"same_defect": False, "confidence": 0.0, "reason": reason}
            self._save()
            return False, 0.0, reason
        same = bool(data.get("same_defect"))
        conf = float(data.get("confidence", 0.6) or 0.6)
        reason = str(data.get("reason", ""))[:200]
        self.cache[key] = {"same_defect": same, "confidence": conf, "reason": reason}
        self._save()
        return same, conf, reason


def build_judge(backend: str, *, api_key: str | None = None, model: str | None = None, cache_path: str | None = None) -> Judge:
    if backend == "offline":
        return OfflineJudge()
    if backend == "openrouter":
        if not api_key:
            raise ValueError("OpenRouter judge requires an API key.")
        return OpenRouterJudge(api_key, model or "qwen/qwen-2.5-coder-32b-instruct", cache_path)
    raise ValueError("Unknown judge backend: %s" % backend)


# --------------- matching ---------------

def _prescreen(gold: GoldCorpusCase, pred: PredictedCorpusItem) -> float:
    ga = extract_anchors(gold.gold_text)
    pa = extract_anchors(pred.found_text + " " + (pred.file_path or ""))
    if ga.urls & pa.urls or ga.files & pa.files or _phrase_hit(ga, pa):
        return 1.0
    if _same_missing_artifact_signal(gold.gold_text, pred.found_text):
        return 0.95
    score = content_similarity(gold.gold_text, pred.found_text)
    if _line_relation(gold.line_start, gold.line_end, pred.line_start, pred.line_end) in ("overlap", "near"):
        score += 0.1
    return score


def _row(gold: GoldCorpusCase, pred: PredictedCorpusItem | None, conf: float, reason: str, counted: bool) -> CorpusEvaluationMatch:
    if pred is None:
        return CorpusEvaluationMatch(
            project=gold.matched_project,
            project_id=gold.project_id,
            criterion=gold.criterion,
            label=_criterion_label(gold.criterion),
            gold_row_number=gold.row_number,
            gold_line_range=_format_range(gold.line_start, gold.line_end),
            gold_text=gold.gold_text,
            found_line_range="",
            found_text="",
            match_type="missed",
            match_score=0.0,
            counted=False,
            reason="Подходящей находки не нашлось: судья не подтвердил совпадение ни по одному кандидату.",
        )
    return CorpusEvaluationMatch(
        project=gold.matched_project,
        project_id=gold.project_id,
        criterion=gold.criterion,
        label=_criterion_label(gold.criterion),
        gold_row_number=gold.row_number,
        gold_line_range=_format_range(gold.line_start, gold.line_end),
        gold_text=gold.gold_text,
        found_finding_id=pred.finding_id,
        found_checker=pred.checker_name,
        found_line_range=_format_prediction_range(pred),
        found_text=pred.found_text,
        match_type="judge_same_criterion" if gold.criterion == pred.criterion else "judge_cross_criterion",
        match_score=round(conf, 4),
        counted=counted,
        reason="Судья подтвердил один и тот же дефект (%s)." % reason,
    )


def match_anchor_judge(
    gold_cases: list[GoldCorpusCase],
    predicted_items: list[PredictedCorpusItem],
    judge: Judge,
    *,
    topk: int = DEFAULT_TOPK,
    accept: float = JUDGE_ACCEPT,
) -> tuple[list[CorpusEvaluationMatch], set]:
    """Returns (match rows aligned to gold_cases order, set of matched prediction ids)."""

    by_project: dict = defaultdict(list)
    for p in predicted_items:
        by_project[p.project_id].append(p)
    predicted_by_id = {p.finding_id: p for p in predicted_items}

    accepted: list[tuple] = []  # (conf, gold_id, pred_id, same_criterion, reason)
    for gold in gold_cases:
        scored = [(s, p) for p in by_project.get(gold.project_id, []) for s in (_prescreen(gold, p),) if s >= PRESCREEN_MIN]
        scored.sort(key=lambda x: x[0], reverse=True)
        for _, pred in scored[:topk]:
            same, conf, reason = judge.same_defect(gold, pred)
            if same and conf >= accept:
                accepted.append((conf, gold.case_id, pred.finding_id, gold.criterion == pred.criterion, reason))

    assigned_g: set = set()
    assigned_p: set = set()
    chosen: dict = {}

    def assign(rows: list[tuple]) -> None:
        for conf, gid, pid, _same, reason in sorted(rows, key=lambda x: x[0], reverse=True):
            if gid in assigned_g or pid in assigned_p:
                continue
            assigned_g.add(gid)
            assigned_p.add(pid)
            chosen[gid] = (pid, conf, reason)

    assign([r for r in accepted if r[3]])       # same-criterion first
    assign([r for r in accepted if not r[3]])   # cross-criterion leftovers

    rows: list[CorpusEvaluationMatch] = []
    for gold in gold_cases:
        if gold.case_id in chosen:
            pid, conf, reason = chosen[gold.case_id]
            rows.append(_row(gold, predicted_by_id.get(pid), conf, reason, True))
        else:
            rows.append(_row(gold, None, 0.0, "", False))
    return rows, assigned_p
