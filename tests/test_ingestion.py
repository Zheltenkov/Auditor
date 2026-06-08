from pathlib import Path

from content_audit.ingestion import discover_content_units, load_unit_files


def test_discovers_single_content_unit(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "Simple Bash Utils"
    project.mkdir()
    (project / "README_RUS.md").write_text("# Проект\n", encoding="utf-8")
    (project / "check-list.yml").write_text("sections: []\n", encoding="utf-8")

    units = discover_content_units(project)

    assert len(units) == 1
    assert units[0].unit_id.startswith("simple_bash_utils__")
    assert units[0].relative_path == "."


def test_loads_supported_files_only(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("# Readme\n", encoding="utf-8")
    (project / "binary.bin").write_bytes(b"\x00\x01")

    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)

    assert [file.relative_path for file in unit.files] == ["README.md"]


def test_loads_standard_extensionless_text_files(workspace_tmp_path: Path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("# Readme\n", encoding="utf-8")
    (project / "LICENSE").write_text("MIT\n", encoding="utf-8")

    unit = load_unit_files(discover_content_units(project)[0], max_file_bytes=1000)
    relative_paths = {file.relative_path for file in unit.files}

    assert "LICENSE" in relative_paths
