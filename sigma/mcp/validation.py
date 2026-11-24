"""Pure helpers for parsing Sigma rules and running pySigma rule validators."""

from __future__ import annotations

import dataclasses
from typing import Any

import yaml
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError, SigmaRuleNotFoundError
from sigma.rule import SigmaRule
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


PARSE_ISSUE_TYPE = "SigmaParseError"
"""``type`` of every issue reporting that a rule could not be parsed.

Kept constant for clients that test for it; ``error_class`` names the
actual pySigma exception.
"""

_MISSING_REFERENCE_HINT = (
    " Put the referenced rules into the same YAML, separated by '---', to "
    "validate the correlation completely."
)


def parse_issue(
    message: str, rules: list[str] | None = None, error_class: str | None = None
) -> dict[str, Any]:
    """Return an issue dict for a rule that could not be parsed."""
    return {
        "validator": "parser",
        "type": PARSE_ISSUE_TYPE,
        "severity": "high",
        "description": message,
        "rules": rules or [],
        "error_class": error_class or PARSE_ISSUE_TYPE,
    }


def _rule_ref(rule: SigmaRule | SigmaCorrelationRule) -> str:
    return str(rule.id) if rule.id else str(rule.title)


def parse_rules(
    rule_yaml: str,
) -> tuple[list[SigmaRule | SigmaCorrelationRule], list[dict[str, Any]]]:
    """Parse one or more rules (YAML documents separated by ``---``).

    Errors in individual rules are collected instead of stopping the parse.
    A correlation rule referencing a rule that is not part of *rule_yaml* is
    reported, and the remaining rules are still returned.

    Returns:
        The rules that parsed without errors, and issue dicts (see
        :func:`parse_issue`) for everything that went wrong.
    """
    issues: list[dict[str, Any]] = []
    try:
        try:
            collection = SigmaCollection.from_yaml(rule_yaml, collect_errors=True)
        except SigmaRuleNotFoundError as exc:
            issues.append(
                parse_issue(
                    str(exc) + _MISSING_REFERENCE_HINT,
                    error_class=type(exc).__name__,
                )
            )
            collection = SigmaCollection.from_yaml(
                rule_yaml, collect_errors=True, resolve_references=False
            )
    except yaml.YAMLError as exc:
        return [], [parse_issue(f"Invalid YAML: {exc}", error_class="YAMLError")]
    except Exception as exc:  # noqa: BLE001 - pySigma raises many types here
        message = str(exc) if isinstance(exc, SigmaError) else repr(exc)
        return [], [parse_issue(message, error_class=type(exc).__name__)]

    valid: list[SigmaRule | SigmaCorrelationRule] = []
    reported: set[int] = set()
    for rule in collection.rules:
        if not isinstance(rule, (SigmaRule, SigmaCorrelationRule)):
            continue
        for error in rule.errors:
            reported.add(id(error))
            issues.append(
                parse_issue(str(error), [_rule_ref(rule)], type(error).__name__)
            )
        if not rule.errors:
            valid.append(rule)
    for error in collection.errors:
        if id(error) not in reported:
            issues.append(parse_issue(str(error), error_class=type(error).__name__))
    if not collection.rules and not issues:
        issues.append(parse_issue("The YAML contains no Sigma rule."))
    return valid, issues


def run_validators(
    rules: list[SigmaRule | SigmaCorrelationRule],
    active: dict[str, type[SigmaRuleValidator]],
) -> list[dict[str, Any]]:
    """Run each active validator over all *rules* and finalize it.

    One validator instance checks all rules, so collection-wide checks such
    as ID uniqueness work across the rules of one call.  A validator that
    crashes on a rule is reported as an issue instead of aborting.
    """
    issues: list[dict[str, Any]] = []
    for name, validator_cls in active.items():
        validator: SigmaRuleValidator = validator_cls()
        for rule in rules:
            try:
                found = validator.validate(rule)
            except Exception as exc:  # noqa: BLE001 - reported to the client
                issues.append(
                    {
                        "validator": name,
                        "type": "ValidatorError",
                        "severity": "low",
                        "description": (
                            f"The validator could not run ({exc!r}). This is "
                            "not a problem with the rule; it usually means "
                            "reference data (e.g. MITRE ATT&CK) could not be "
                            "downloaded. Exclude the validator with "
                            "configure_validators if it keeps failing."
                        ),
                        "rules": [_rule_ref(rule)],
                    }
                )
                continue
            issues.extend(issue_to_dict(name, issue) for issue in found)
        issues.extend(issue_to_dict(name, issue) for issue in validator.finalize())
    return issues
