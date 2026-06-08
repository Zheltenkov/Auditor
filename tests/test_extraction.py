from pathlib import Path

from content_audit.extraction import extract_entities
from content_audit.ingestion import discover_content_units, load_unit_files


def test_extracts_links_versions_dates_and_images(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text(
        "![pic](misc/image.png)\n"
        "Use Java 21 and POSIX.1-2017.\n"
        "Docs: https://example.com/docs\n",
        encoding="utf-8",
    )

    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    entities = extract_entities(unit)
    values = {entity.value for entity in entities}

    assert "misc/image.png" in values
    assert "Java 21" in values
    assert "POSIX.1-2017" in values
    assert "https://example.com/docs" in values
