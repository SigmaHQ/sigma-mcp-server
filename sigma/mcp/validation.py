"""Pure helpers for parsing Sigma rules and running pySigma rule validators."""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable
from typing import Any

import yaml
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError, SigmaRuleNotFoundError
from sigma.rule import SigmaRule
from sigma.rule.base import check_alias_expansion
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


# ---------------------------------------------------------------------------
# Size limit
# ---------------------------------------------------------------------------

MAX_EXPANDED_VALUES = 50_000
"""Most detection values the rules of one call may expand to.

pySigma turns each value with the ``windash`` modifier into up to 125
strings (and ``base64offset`` into 3) while parsing, at roughly 15 µs and
several kilobytes each.  Without a limit, a 500 KiB request kept the server
busy for most of a minute and needed more than 1 GiB of memory.  Real rules
stay far below this limit.
"""

_WINDASH_DASH = re.compile(r"\B[-/]\b")
"""The dash pattern pySigma's ``windash`` modifier expands."""
_WINDASH_VARIANTS = 5
_WINDASH_MAX_DASHES = 3
_BASE64OFFSET_VARIANTS = 3
_NON_DETECTION_KEYS = {"condition", "timeframe"}
_Loader: Any = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def _value_weight(value: object, modifiers: list[str]) -> int:
    """How many values pySigma makes of *value* with *modifiers*."""
    weight = 1
    if "windash" in modifiers and isinstance(value, str):
        dashes = min(len(_WINDASH_DASH.findall(value)), _WINDASH_MAX_DASHES)
        weight *= _WINDASH_VARIANTS**dashes
    if "base64offset" in modifiers:
        weight *= _BASE64OFFSET_VARIANTS
    return weight


def _values(values: object) -> list[object]:
    return values if isinstance(values, list) else [values]


def _item_weight(item: object) -> int:
    """Weight of one detection item: a field mapping or a keyword."""
    if not isinstance(item, dict):
        return 1
    total = 0
    for key, values in item.items():
        modifiers = str(key).split("|")[1:]
        total += sum(_value_weight(value, modifiers) for value in _values(values))
    return total


def expanded_value_count(documents: Iterable[object]) -> int:
    """Estimate how many detection values pySigma creates for *documents*.

    Only the shapes a Sigma detection may have are walked (detection →
    mapping or list of mappings/keywords → field → value or list of values),
    so the walk never recurses into deeper client-controlled nesting.
    """
    total = 0
    for document in documents:
        if not isinstance(document, dict):
            continue
        detection = document.get("detection")
        if not isinstance(detection, dict):
            continue
        for name, value in detection.items():
            if name in _NON_DETECTION_KEYS:
                continue
            total += sum(_item_weight(item) for item in _values(value))
    return total


def _too_many_values(rule_yaml: str) -> dict[str, Any] | None:
    """Return a parse issue if *rule_yaml* expands to too many values.

    YAML that cannot be loaded here is left to pySigma, which reports it.
    """
    try:
        documents = list(yaml.load_all(rule_yaml, Loader=_Loader))
        check_alias_expansion(documents)
    except Exception:  # noqa: BLE001 - pySigma reports the problem itself
        return None
    count = expanded_value_count(documents)
    if count <= MAX_EXPANDED_VALUES:
        return None
    return parse_issue(
        f"The rules expand to about {count} detection values (modifiers such "
        f"as windash multiply them); at most {MAX_EXPANDED_VALUES} are "
        "accepted per call. Validate fewer rules or values at once.",
        error_class="TooManyValues",
    )


def parse_rules(
    rule_yaml: str,
) -> tuple[list[SigmaRule | SigmaCorrelationRule], list[dict[str, Any]]]:
    """Parse one or more rules (YAML documents separated by ``---``).

    Errors in individual rules are collected instead of stopping the parse.
    A correlation rule referencing a rule that is not part of *rule_yaml* is
    reported, and the remaining rules are still returned.

    Returns:
        The rules that parsed without errors, and issue dicts (see
        :func:`parse_issue`) for everything that went wrong.  Input that
        expands to more than :data:`MAX_EXPANDED_VALUES` values is not
        parsed at all.
    """
    too_many = _too_many_values(rule_yaml)
    if too_many is not None:
        return [], [too_many]
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
