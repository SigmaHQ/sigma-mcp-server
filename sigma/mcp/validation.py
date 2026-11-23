"""Pure helpers for running pySigma rule validators."""

from __future__ import annotations

import dataclasses
from typing import Any

from sigma.validators.base import SigmaRuleValidator, SigmaValidationIssue
from sigma.validators.core import validators as _raw_validators

# Typed reference to the core validator registry
all_validators: dict[str, type[SigmaRuleValidator]] = dict(_raw_validators)


def issue_to_dict(validator_name: str, issue: SigmaValidationIssue) -> dict[str, Any]:
    """Convert a SigmaValidationIssue to a JSON-serialisable dict.

    The returned dict always contains the keys ``validator``, ``type``,
    ``severity``, ``description`` and ``rules``.  Any extra instance fields
    defined on the concrete issue subclass (e.g. ``identifier`` for UUID
    collision issues) are included as additional string-valued keys.
    """
    rule_refs: list[str] = [str(r.id) if r.id else str(r.title) for r in issue.rules]
    extra: dict[str, Any] = {
        f.name: str(getattr(issue, f.name))
        for f in dataclasses.fields(issue)
        if f.name != "rules"
    }
    return {
        "validator": validator_name,
        "type": type(issue).__name__,
        "severity": issue.severity.name.lower(),
        "description": issue.description,
        "rules": rule_refs,
        **extra,
    }


def get_active_validators(
    validator_names: list[str] | None,
    exclusions: list[str],
) -> dict[str, type[SigmaRuleValidator]]:
    """Return the set of validators that should be applied for a validation run.

    Args:
        validator_names: Explicit allow-list of validator identifiers. ``None``
            means *all* registered validators are included before exclusions are
            applied.
        exclusions: Validator identifiers to remove from the active set.

    Returns:
        Ordered dict mapping identifier → validator class for every validator
        that should be instantiated and executed.
    """
    if validator_names is not None:
        selected: dict[str, type[SigmaRuleValidator]] = {
            n: all_validators[n] for n in validator_names if n in all_validators
        }
    else:
        selected = dict(all_validators)
    return {n: cls for n, cls in selected.items() if n not in exclusions}
