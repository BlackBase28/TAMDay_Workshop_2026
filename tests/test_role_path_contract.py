#!/usr/bin/env python3
"""Verify that every static local role reference resolves through ansible.cfg."""

from __future__ import annotations

import configparser
import os
import unittest
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE_TASK_KEYS = {
    "include_role",
    "import_role",
    "ansible.builtin.include_role",
    "ansible.builtin.import_role",
}


def configured_role_paths(root: Path) -> list[Path]:
    parser = configparser.ConfigParser(interpolation=None)
    loaded = parser.read(root / "ansible.cfg", encoding="utf-8")
    if not loaded:
        raise AssertionError("ansible.cfg was not found")

    raw = parser.get("defaults", "roles_path", fallback="")
    paths: list[Path] = []
    for item in raw.split(os.pathsep):
        item = os.path.expandvars(os.path.expanduser(item.strip()))
        if not item:
            continue
        candidate = Path(item)
        if not candidate.is_absolute():
            candidate = root / candidate
        paths.append(candidate.resolve(strict=False))
    return paths


def _add_role(value: Any, found: set[str]) -> None:
    role = ""
    if isinstance(value, str):
        role = value.strip()
    elif isinstance(value, dict):
        role = str(value.get("role") or value.get("name") or "").strip()

    # Dynamic/Jinja names cannot be checked statically. FQCN roles are supplied
    # by collections and are not expected under the repository's roles_path.
    if not role or "{{" in role or "{%" in role or role.count(".") >= 2:
        return
    found.add(role)


def _walk_yaml(node: Any, found: set[str]) -> None:
    if isinstance(node, list):
        for item in node:
            _walk_yaml(item, found)
        return

    if not isinstance(node, dict):
        return

    for key, value in node.items():
        if key == "roles" and isinstance(value, list):
            for item in value:
                _add_role(item, found)
        elif key in ROLE_TASK_KEYS:
            _add_role(value, found)

        _walk_yaml(value, found)


def static_local_role_references(root: Path) -> dict[str, set[str]]:
    references: dict[str, set[str]] = {}
    playbook_dir = root / "playbooks"
    for pattern in ("*.yml", "*.yaml"):
        for playbook in sorted(playbook_dir.glob(pattern)):
            data = yaml.safe_load(playbook.read_text(encoding="utf-8"))
            found: set[str] = set()
            _walk_yaml(data, found)
            for role in found:
                references.setdefault(role, set()).add(
                    str(playbook.relative_to(root))
                )
    return references


def role_exists(role: str, role_paths: list[Path]) -> bool:
    for base in role_paths:
        role_dir = base / role
        if role_dir.is_dir() and (
            (role_dir / "tasks/main.yml").is_file()
            or (role_dir / "tasks/main.yaml").is_file()
        ):
            return True
    return False


class RolePathContractTests(unittest.TestCase):
    def test_ansible_cfg_searches_both_repository_role_roots(self) -> None:
        role_paths = configured_role_paths(ROOT)
        normalized = {path.as_posix() for path in role_paths}
        self.assertIn((ROOT / "roles").resolve().as_posix(), normalized)
        self.assertIn((ROOT / "playbooks/roles").resolve().as_posix(), normalized)

    def test_all_static_local_role_references_resolve(self) -> None:
        role_paths = configured_role_paths(ROOT)
        references = static_local_role_references(ROOT)
        self.assertTrue(references, "No static local role references were found")

        missing = {
            role: sorted(playbooks)
            for role, playbooks in references.items()
            if not role_exists(role, role_paths)
        }
        self.assertFalse(
            missing,
            "Static role references are missing from configured roles_path: "
            f"{missing}; configured paths={[str(path) for path in role_paths]}",
        )


if __name__ == "__main__":
    unittest.main()
