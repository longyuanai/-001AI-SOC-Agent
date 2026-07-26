"""Keep the declared plugin entry points consistent with the real rules.

``pyproject.toml`` advertises every SOC pattern under the
``longyuanai.soc_patterns`` group, but nothing inside this project reads that
group — the consumer is outside the repo. That makes the declarations easy to
break silently: rename a rule class or add a sixth pattern and whoever *does*
load the group finds out at runtime, in production. These tests fail instead.
"""

from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

import pytest

from ai_soc_agent.patterns import ENTRY_POINT_GROUP, PATTERN_TYPES, SOCPattern

PYPROJECT = Path(__file__).parents[1] / "pyproject.toml"


def _declared() -> dict[str, str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    plugins = data["tool"]["poetry"]["plugins"]
    assert ENTRY_POINT_GROUP in plugins, (
        f"{ENTRY_POINT_GROUP!r} is the group this project names in code, "
        f"but pyproject declares {sorted(plugins)}"
    )
    return plugins[ENTRY_POINT_GROUP]


def _resolve(target: str) -> type:
    module_name, _, attribute = target.partition(":")
    return getattr(importlib.import_module(module_name), attribute)


@pytest.mark.parametrize("name", sorted(_declared()))
def test_declared_entry_point_resolves_to_a_soc_pattern(name: str):
    resolved = _resolve(_declared()[name])

    assert isinstance(resolved, type)
    assert issubclass(resolved, SOCPattern)


def test_every_builtin_pattern_is_declared():
    """A new rule that nobody declared would never reach the suite registry."""
    declared = {_resolve(target) for target in _declared().values()}

    assert declared == set(PATTERN_TYPES)


def test_entry_point_names_are_namespaced_to_this_product():
    assert all(name.startswith("001.") for name in _declared())
