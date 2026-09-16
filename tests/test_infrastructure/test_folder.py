"""Folder tree tests - old-project port (nested groups, collisions)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pykeepass import PyKeePass, create_database

from app.infrastructure.kdbx.folder import (
    Folder,
    load_folders,
    nested_traverse_insert,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_nested_traverse_insert_builds_hierarchy() -> None:
    root = Folder(None)
    folders = [
        ("1", ["a"]),
        ("2", ["a", "b"]),
        ("3", ["a", "b", "c"]),
        ("4", ["d"]),
    ]
    inserted = {folder_id: Folder(folder_id) for folder_id, _ in folders}
    for folder_id, name_parts in folders:
        nested_traverse_insert(root, name_parts, inserted[folder_id], "/")

    assert root.children == [inserted["1"], inserted["4"]]
    assert inserted["1"].children == [inserted["2"]]
    assert inserted["2"].children == [inserted["3"]]
    assert inserted["2"].name == "b"
    assert inserted["3"].name == "c"


def test_load_folders_creates_nested_groups(tmp_path: Path) -> None:
    db_path = tmp_path / "test.kdbx"
    kp = create_database(str(db_path), password="test")
    groups = load_folders(
        kp,
        [
            {"id": "1", "name": "a"},
            {"id": "2", "name": "a/b"},
            {"id": "3", "name": "a/b/c"},
        ],
    )
    # NOTE: pykeepass `root_group` is a fresh object per access, so
    # compare by name rather than identity.
    assert groups[None].name == kp.root_group.name
    assert groups["1"].name == "a"
    assert groups["2"].name == "b"
    assert groups["3"].name == "c"
    assert kp.root_group.subgroups[0].name == "a"
    assert kp.root_group.subgroups[0].subgroups[0].name == "b"
    assert kp.root_group.subgroups[0].subgroups[0].subgroups[0].name == "c"


def test_load_folders_without_folders_maps_root(tmp_path: Path) -> None:
    kp = create_database(str(tmp_path / "test.kdbx"), password="test")
    groups = load_folders(kp, [])
    assert set(groups) == {None}
    assert groups[None].name == kp.root_group.name


def test_load_folders_skips_folder_without_name(tmp_path: Path) -> None:
    kp = create_database(str(tmp_path / "test.kdbx"), password="test")
    groups = load_folders(kp, [{"id": "broken", "name": None}])
    assert set(groups) == {None}


def test_load_folders_reuses_existing_group_on_name_collision(tmp_path: Path) -> None:
    """Regression: a name collision used to raise and abort the whole export."""
    db_path = tmp_path / "test.kdbx"
    kp = create_database(str(db_path), password="test")
    kp.add_group(kp.root_group, "a")
    groups = load_folders(kp, [{"id": "1", "name": "a"}])

    assert groups["1"].name == "a"
    assert len(kp.root_group.subgroups) == 1

    # Entries for that folder land in the pre-existing group.
    kp.add_entry(groups["1"], "Title", "user", "pass")
    kp.save()
    reloaded = PyKeePass(str(db_path), password="test")
    entry = reloaded.find_entries(title="Title", first=True)
    assert entry.group.name == "a"
