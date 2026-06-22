from content_audit.checklist_grounding import assess_checklist_grounding
from content_audit.checklist_matching import ChecklistQuestion


def test_grounding_flags_self_join_order_missing_from_readme() -> None:
    readme = """
## Exercise 10

Find pairs of people who live at the same address.

| person_name1 | person_name2 | common_address |
"""
    questions = [
        ChecklistQuestion(
            name="Exercise 10 Find persons from one city",
            description_text="""
Checks for the file day02_ex10.sql.
SELECT p1.name, p2.name, p1.address AS common_address
FROM person p1
INNER JOIN person p2 ON p1.id > p2.id
AND p1.address = p2.address
ORDER BY 1, 2, 3
""",
        )
    ]

    issues = assess_checklist_grounding(questions, readme)

    assert len(issues) == 1
    assert issues[0].issue_type == "ungrounded_self_join_order"
    assert issues[0].evidence == "p1.id > p2.id"


def test_grounding_does_not_flag_self_join_order_when_readme_mentions_it() -> None:
    readme = """
## Exercise 10

Find pairs of people who live at the same address. Use `p1.id > p2.id`
to avoid duplicate pairs.

| person_name1 | person_name2 | common_address |
"""
    questions = [
        ChecklistQuestion(
            name="Exercise 10 Find persons from one city",
            description_text="INNER JOIN person p2 ON p1.id > p2.id AND p1.address = p2.address",
        )
    ]

    assert assess_checklist_grounding(questions, readme) == []


def test_grounding_flags_duplicate_pizzeria_names_result() -> None:
    readme = """
## Exercise 06

Please create a function `fnc_person_visits_and_eats_on_date` that will
find the names of pizzerias that a person visited and where he could buy
pizza for less than the given price.
"""
    questions = [
        ChecklistQuestion(
            name="Exercise 06 — Function like a function-wrapper",
            description_text="""
The result of SQL:
"Pizza Hut"
"Pizza Hut"
"Pizza Hut"
"Pizza Hut"
""",
        )
    ]

    issues = assess_checklist_grounding(questions, readme)

    assert len(issues) == 1
    assert issues[0].issue_type == "suspicious_duplicate_name_result"
    assert issues[0].evidence == "Pizza Hut × 4"


def test_grounding_does_not_flag_duplicate_rows_when_readme_asks_for_pizzas() -> None:
    readme = """
## Exercise 06

Return names of pizzas and pizzerias where the user can buy them.
"""
    questions = [
        ChecklistQuestion(
            name="Exercise 06",
            description_text='"Pizza Hut" "Pizza Hut" "Pizza Hut"',
        )
    ]

    assert assess_checklist_grounding(questions, readme) == []
