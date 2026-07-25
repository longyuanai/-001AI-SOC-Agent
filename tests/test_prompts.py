"""Tests for the versioned prompt loader.

The analyzer used to carry a hardcoded copy of the system prompt while
``prompts/incident_triage/v1.yml`` sat unread, so the two drifted apart.
"""

from __future__ import annotations

import pytest

from ai_soc_agent.analyzer import PROMPT_NAME, PROMPT_VERSION
from ai_soc_agent.prompts import PromptError, load_prompt


def test_incident_triage_v1_is_loadable():
    template = load_prompt(PROMPT_NAME, PROMPT_VERSION)

    assert template.name == "incident_triage"
    assert template.version == "v1"
    assert "SOC analyst" in template.system
    assert template.description


def test_shipped_prompt_declares_the_json_contract():
    template = load_prompt(PROMPT_NAME, PROMPT_VERSION)

    for field in ("summary", "severity", "confidence", "attack_pattern"):
        assert field in template.system


def test_user_template_substitutes_events_json():
    template = load_prompt(PROMPT_NAME, PROMPT_VERSION)

    rendered = template.render_user(events_json='[{"actor": "1.2.3.4"}]')

    assert '"actor": "1.2.3.4"' in rendered
    assert "{{" not in rendered


def test_render_user_rejects_missing_values():
    template = load_prompt(PROMPT_NAME, PROMPT_VERSION)

    with pytest.raises(PromptError, match="events_json"):
        template.render_user()


def test_missing_template_names_the_paths_searched():
    with pytest.raises(PromptError, match="looked in"):
        load_prompt("no_such_prompt", "v9")


def test_malformed_template_is_rejected(tmp_path):
    directory = tmp_path / "broken"
    directory.mkdir()
    (directory / "v1.yml").write_text("system: |\n  only a system prompt\n", encoding="utf-8")

    with pytest.raises(PromptError, match="missing a non-empty 'user'"):
        load_prompt("broken", "v1", root=tmp_path)


def test_non_mapping_template_is_rejected(tmp_path):
    directory = tmp_path / "listy"
    directory.mkdir()
    (directory / "v1.yml").write_text("- a\n- b\n", encoding="utf-8")

    with pytest.raises(PromptError, match="must be a mapping"):
        load_prompt("listy", "v1", root=tmp_path)
