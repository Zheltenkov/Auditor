from pathlib import Path

from content_audit.web_app import WebState, render_page


def test_render_page_contains_project_input(workspace_tmp_path: Path) -> None:
    state = WebState(default_input=workspace_tmp_path, report_dir=workspace_tmp_path / "reports", env_values={})

    html = render_page(None, state)

    assert "Проверка локального проекта" in html
    assert "Путь к проекту" in html
    assert str(workspace_tmp_path) in html
