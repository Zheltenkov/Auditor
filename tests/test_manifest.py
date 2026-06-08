import json

from content_audit.ingestion import discover_content_units
from content_audit.manifest import apply_unit_manifest


def test_manifest_maps_unit_to_platform_fields(workspace_tmp_path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("# Readme\n", encoding="utf-8")
    manifest_path = workspace_tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "units": [
                    {
                        "path": ".",
                        "id": "platform-42",
                        "branch": "C",
                        "admin_url": "https://admin.example.test/projects/platform-42",
                        "name": "Platform Unit",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    units = discover_content_units(project)

    mapped, warnings = apply_unit_manifest(units, project, manifest_path, None)

    assert warnings == []
    assert mapped[0].unit_id == "platform-42"
    assert mapped[0].branch == "C"
    assert mapped[0].admin_url == "https://admin.example.test/projects/platform-42"
    assert mapped[0].name == "Platform Unit"


def test_admin_url_template_fills_missing_url(workspace_tmp_path) -> None:
    project = workspace_tmp_path / "unit"
    project.mkdir()
    (project / "README.md").write_text("# Readme\n", encoding="utf-8")
    units = discover_content_units(project)

    mapped, warnings = apply_unit_manifest(units, project, None, "https://admin.example.test/projects/{unit_id}")

    assert warnings == []
    assert mapped[0].admin_url.endswith(mapped[0].unit_id)
