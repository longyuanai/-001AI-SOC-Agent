"""Test double for ``shared_llm_core.rule_engine`` (v0.5 §8).

Only the subset consumed by 001AI-SOC-Agent is reproduced. See
``tests/_contract_stub/README.md`` before touching anything here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

from shared_llm_core.finding import Finding


@dataclass(frozen=True)
class RuleContext:
    """Immutable evaluation input handed to every rule."""

    subject: str
    facts: Mapping[str, Any] = field(default_factory=dict)
    window: tuple[datetime, datetime] | None = None


class Rule(ABC):
    """Pure, side-effect-free detection rule."""

    id: str = ""

    @abstractmethod
    def match(self, ctx: RuleContext) -> bool:
        """Return whether this rule recognizes the supplied context."""

    @abstractmethod
    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        """Return the Findings this rule produces for the supplied context."""


class RuleRegistry:
    """Ordered, id-unique collection of rules."""

    def __init__(self, rules: Iterable[Rule] = ()) -> None:
        self._rules: dict[str, Rule] = {}
        for rule in rules:
            self.register(rule)

    def register(self, rule: Rule) -> None:
        """Add one rule; duplicate ids are rejected."""
        if not rule.id:
            raise ValueError("rule id must not be empty")
        if rule.id in self._rules:
            raise ValueError(f"duplicate rule id: {rule.id}")
        self._rules[rule.id] = rule

    def all(self) -> list[Rule]:
        """Return every registered rule in registration order."""
        return list(self._rules.values())

    def get(self, rule_id: str) -> Rule | None:
        """Return one rule by id, or None."""
        return self._rules.get(rule_id)


class RuleEngine:
    """Evaluate a registry against one context."""

    def __init__(self, registry: RuleRegistry) -> None:
        self._registry = registry

    def evaluate(
        self, ctx: RuleContext, rule_ids: Sequence[str] | None = None
    ) -> list[Finding]:
        """Run every (or the selected) rule and concatenate their Findings."""
        selected = (
            self._registry.all()
            if rule_ids is None
            else [rule for rule in self._registry.all() if rule.id in set(rule_ids)]
        )
        findings: list[Finding] = []
        for rule in selected:
            findings.extend(rule.evaluate(ctx))
        return findings
