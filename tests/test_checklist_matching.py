from content_audit.checklist_matching import (
    checklist_name_matches_readme,
    extract_checklist_question_names,
    match_checklist_to_readme,
)
from content_audit.text_utils import normalize_for_match


def test_extract_checklist_question_names_reads_yaml_shape() -> None:
    payload = {
        "sections": [
            {"questions": [{"name": "Part_1.CAT"}, {"name": "Part_2.GREP"}]},
            {"questions": [{"title": "without-name"}]},
        ]
    }

    assert extract_checklist_question_names(payload) == ["Part_1.CAT", "Part_2.GREP"]


def test_checklist_name_matches_readme_by_number_and_keyword() -> None:
    normalized_readme = normalize_for_match("## 1-qism. cat utilitasi bilan ishlash")

    assert checklist_name_matches_readme("Part_1.CAT", normalized_readme)


def test_match_checklist_to_readme_returns_explainable_result() -> None:
    result = match_checklist_to_readme(
        ["Part_1.CAT", "Part_2.GREP"],
        "## Part 1. Работа с cat\n\n## Part 2. Работа с grep\n",
    )

    assert result.total == 2
    assert result.matched == 2
    assert result.ratio == 1.0
    assert result.unmatched_names == ()


def test_match_checklist_to_readme_tracks_unmatched_items() -> None:
    result = match_checklist_to_readme(["Part_1.CAT", "Part_2.GREP"], "## Part 1. Работа с cat\n")

    assert result.total == 2
    assert result.matched == 1
    assert result.ratio == 0.5
    assert result.unmatched_names == ("Part_2.GREP",)
