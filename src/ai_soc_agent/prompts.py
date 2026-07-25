"""Loader for the versioned prompt templates under ``prompts/``.

The system prompt used to be duplicated: once in ``prompts/incident_triage/v1.yml``
and once as a literal in :mod:`ai_soc_agent.analyzer`. Nothing loaded the YAML, so
the two drifted and editing the obvious file had no effect. The YAML is now the
only copy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

import yaml

#: Where to look for the prompt library, in order: alongside the installed
#: package (wheel layout, see the ``include`` in pyproject.toml), then the repo
#: checkout layout.
PROMPT_ROOTS = (
    Path(__file__).resolve().parents[1] / "prompts",
    Path(__file__).resolve().parents[2] / "prompts",
)

_PLACEHOLDER = re.compile(r"\{\{\s*(\w+)\s*\}\}")


class PromptError(RuntimeError):
    """Raised when a prompt template is missing or malformed."""


@dataclass(frozen=True)
class PromptTemplate:
    """One prompt version: a system message plus a parameterized user message."""

    name: str
    version: str
    description: str
    system: str
    user: str

    def render_user(self, **values: Any) -> str:
        """Substitute ``{{ placeholder }}`` slots, rejecting unknown names."""
        missing: list[str] = []

        def replace(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in values:
                missing.append(key)
                return match.group(0)
            return str(values[key])

        rendered = _PLACEHOLDER.sub(replace, self.user)
        if missing:
            raise PromptError(
                f"{self.name}/{self.version} needs values for: {', '.join(sorted(set(missing)))}"
            )
        return rendered


def _locate(name: str, version: str, root: Path | None) -> Path:
    candidates = (root / name / f"{version}.yml",) if root else tuple(
        base / name / f"{version}.yml" for base in PROMPT_ROOTS
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    searched = ", ".join(str(candidate) for candidate in candidates)
    raise PromptError(f"prompt template {name}/{version} not found; looked in {searched}")


@cache
def load_prompt(name: str, version: str = "v1", *, root: Path | None = None) -> PromptTemplate:
    """Load and validate one prompt template, caching the parsed result."""
    path = _locate(name, version, root)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PromptError(f"prompt template is not valid YAML: {path}") from exc
    if not isinstance(data, dict):
        raise PromptError(f"prompt template must be a mapping: {path}")
    for key in ("system", "user"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise PromptError(f"prompt template {path} is missing a non-empty '{key}'")
    return PromptTemplate(
        name=name,
        version=version,
        description=str(data.get("description", "")),
        system=data["system"].strip(),
        user=data["user"].strip(),
    )
