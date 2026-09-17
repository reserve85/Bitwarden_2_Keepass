"""Bitwarden folder tree -> KeePass group mapping.

# ported from bitwarden-to-keepass (src/folder.py) verbatim
"""

from __future__ import annotations

import collections
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from pykeepass import PyKeePass
    from pykeepass.group import Group as KPGroup


class Folder:
    id: str | None
    name: str | None
    children: list[Folder]
    parent: Folder | None
    keepass_group: KPGroup | None

    def __init__(self, id: str | None) -> None:
        self.id = id
        self.name = None
        self.children = []
        self.parent = None
        self.keepass_group = None

    def add_child(self, child: Folder) -> None:
        self.children.append(child)
        child.parent = self


# logic was lifted directly from https://github.com/bitwarden/jslib/blob/ecdd08624f61ccff8128b7cb3241f39e664e1c7f/common/src/misc/serviceUtils.ts#L7
def nested_traverse_insert(
    root: Folder,
    name_parts: list[str],
    new_folder: Folder,
    delimiter: str,
) -> None:
    if len(name_parts) == 0:
        return

    end: bool = len(name_parts) == 1
    part_name: str = name_parts[0]

    for child in root.children:
        if child.name != part_name:
            continue

        if end and child.id != new_folder.id:
            # Another node with the same name.
            new_folder.name = part_name
            root.add_child(new_folder)
            return
        nested_traverse_insert(child, name_parts[1:], new_folder, delimiter)
        return

    if end:
        new_folder.name = part_name
        root.add_child(new_folder)
        return
    new_part_name: str = part_name + delimiter + name_parts[1]
    new_name_parts: list[str] = [new_part_name]
    new_name_parts.extend(name_parts[2:])
    nested_traverse_insert(root, new_name_parts, new_folder, delimiter)


def bfs_traverse_execute(
    kp: PyKeePass,
    root: Folder,
    callback: Callable[[PyKeePass, Folder], None],
) -> None:
    queue: collections.deque[Folder] = collections.deque()
    queue.extend(root.children)
    while queue:
        child: Folder = queue.popleft()
        queue.extend(child.children)
        callback(kp, child)


def load_folders(kp: PyKeePass, folders: list[dict]) -> dict[str | None, KPGroup]:
    # Guard against malformed records (missing or empty name) so a single
    # broken folder cannot crash the whole export. Bitwarden usually never
    # sends these, but the error handling must not be the exported data.
    folders = sorted(
        (folder for folder in folders if folder.get("name")),
        # sort folders so that in the case of nested folders
        # the parents would be guaranteed to show up before the children
        key=lambda folder: folder["name"],
    )

    # dict to store mapping of Bitwarden folder id to keepass group
    groups_by_id: dict[str | None, KPGroup] = {}

    # build up folder tree
    folder_root: Folder = Folder(None)
    folder_root.keepass_group = kp.root_group
    groups_by_id[None] = kp.root_group

    for folder in folders:
        if folder.get("id") is not None:
            new_folder: Folder = Folder(folder["id"])
            # regex lifted from https://github.com/bitwarden/jslib/blob/ecdd08624f61ccff8128b7cb3241f39e664e1c7f/common/src/services/folder.service.ts#L108
            folder_name_parts: list[str] = re.sub(
                r"^\/+|\/+$",
                "",
                folder["name"],
            ).split("/")
            nested_traverse_insert(
                folder_root,
                folder_name_parts,
                new_folder,
                "/",
            )

    # create keepass groups based off folder tree
    def add_keepass_group(kp: PyKeePass, folder: Folder) -> None:
        parent_group: KPGroup = folder.parent.keepass_group
        # Reuse an existing subgroup with the same name instead of raising:
        # pykeepass rejects duplicate group names, and a single collision
        # (importing into a database that already has a group called e.g. "a")
        # would otherwise abort the whole export. This also folds two Bitwarden
        # folders onto the same name into one group, mirroring the jslib logic
        # this module was lifted from.
        existing = [group for group in parent_group.subgroups if group.name == folder.name]
        if existing:
            new_group: KPGroup = existing[0]
        else:
            new_group = kp.add_group(parent_group, folder.name)
        folder.keepass_group = new_group
        groups_by_id[folder.id] = new_group

    bfs_traverse_execute(kp, folder_root, add_keepass_group)

    return groups_by_id
