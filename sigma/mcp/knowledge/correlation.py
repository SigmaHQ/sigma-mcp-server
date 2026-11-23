"""Offline reference for Sigma correlation rules.

The ``sigma://specification/correlation`` resource serves the official
specification from the sigma-specification repository.  This condensed
reference is returned instead when that document cannot be fetched, so
rule authors always get the syntax, examples and common mistakes.
"""

from __future__ import annotations

CORRELATION_RULES_SPEC = """
# Sigma Correlation Rules – Specification Reference (v2.1.0)

## Key Concept
Correlation rules are **separate YAML documents** (using `---` separators) that reference
base Sigma detection rules. They do NOT use `detection:` + pipe condition syntax.
The deprecated pipe/aggregation syntax (e.g. `| count() by ...`) must never be used.

## File Structure
Use multi-document YAML in one file with `---` between documents.
Recommended filename prefix: `mr_` (meta-rule).

The outermost (first) document is the final correlation and is the only one that
carries meta-fields such as `status`, `level`, `falsepositives`, `author`, `date`.

## Base Rule Name Registration
Any rule referenced by name in a correlation must declare a `name:` field:
```yaml
name: failed_login   # unique human-readable name used in correlation rules
logsource: ...
detection: ...
```

## Correlation Section Fields
```yaml
correlation:
  type: <event_count|value_count|temporal|temporal_ordered|value_sum|value_avg|value_percentile>
  rules:
    - <rule_id_or_name>    # rule UUID or the value of the `name:` field
  aliases:                 # optional – map field aliases across rules
    <alias>:
      <rule_name>: <field_in_that_rule>
  group-by:                # mandatory – fields to partition counts/windows by
    - FieldName
  timespan: 10m            # mandatory – Xs/Xm/Xh/Xd
  condition:               # mandatory for count types
    gte: 10                # gt / gte / lt / lte / eq / neq
    field: FieldName       # mandatory for value_count, value_sum, value_avg, value_percentile
```

## Correlation Types

### event_count
Count matching events per group in the time window.
```yaml
correlation:
  type: event_count
  rules:
    - failed_login
  group-by:
    - User
    - ComputerName
  timespan: 10m
  condition:
    gte: 10
```

### value_count
Count **distinct values** of a field per group.
```yaml
correlation:
  type: value_count
  rules:
    - failed_login
  group-by:
    - ComputerName
  timespan: 1d
  condition:
    field: User
    gte: 100
```

### temporal
All referenced rules must fire within the time window for the same group (any order).
No `condition:` key needed (the requirement is simply that all rules fire).
```yaml
correlation:
  type: temporal
  rules:
    - recon_cmd_a
    - recon_cmd_b
    - recon_cmd_c
  group-by:
    - ComputerName
    - User
  timespan: 5m
```

### temporal_ordered
⚠️ **WARNING: Use with caution – requires explicit user request**

Like `temporal` but events must appear **in the listed order**.

**Drawbacks:**
- **Strict ordering**: Any deviation in log event sequence causes false negatives
- **Log arrival timing**: Events may be logged out of order due to clock skew or buffering
- **Higher false negatives**: Legitimate attacks that occur in slightly different order go undetected
- **Difficult to tune**: Hard to select appropriate timespan that accommodates log delays
- **MITRE ATT&CK limitations**: Most attack chains are not strictly time-ordered

**Recommendation**: Prefer `temporal` (unordered) in most cases. Only use `temporal_ordered` if:
1. The user explicitly requests strict ordering detection
2. The attack chain has a documented, enforced sequence (rare)
3. You understand the false negative trade-off

**DO NOT suggest this type unless the user specifically asks for ordered event detection.**

```yaml
correlation:
  type: temporal_ordered
  rules:
    - many_failed_logins
    - successful_login
  group-by:
    - User
  timespan: 1h
```

### value_sum
Sum of a numeric field per group.
```yaml
correlation:
  type: value_sum
  rules:
    - web_access
  group-by:
    - SourceIP
  timespan: 1h
  condition:
    field: bytes_sent
    gt: 1000000
```

### value_avg
Average of a numeric field per group.
```yaml
correlation:
  type: value_avg
  rules:
    - network_traffic
  group-by:
    - SourceIP
  timespan: 24h
  condition:
    field: BytesOut
    gt: 500
```

### value_percentile
Match when a field value falls at or below a given percentile of observed values.
```yaml
correlation:
  type: value_percentile
  rules:
    - process_creation
  group-by:
    - ComputerName
  timespan: 24h
  condition:
    field: Image
    lte: 1
```

## Field Name Aliases
Use when the same logical entity maps to different field names in different rules:
```yaml
aliases:
  internal_ip:
    internal_error: destination.ip
    new_network_connection: source.ip
  remote_ip:
    internal_error: source.ip
    new_network_connection: destination.ip
```
The alias names are then used in `group-by`.

## Complete Example – Brute-Force Detection

```yaml
title: Multiple Failed Logins Followed by Successful Login
id: b180ead8-d58f-40b2-ae54-c8940995b9b6
status: experimental
description: Detects multiple failed logins by a single user followed by a successful login
references:
    - https://example.com
author: Sigma AI
date: 2026-10-13
correlation:
    type: temporal_ordered
    rules:
        - multiple_failed_logins
        - successful_login
    group-by:
        - User
    timespan: 10m
falsepositives:
    - Unlikely
level: high
---
title: Multiple Failed Logins
id: a8418a5a-5fc4-46b5-b23b-6c73beb19d41
name: multiple_failed_logins
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - User
    timespan: 10m
    condition:
        gte: 10
---
title: Single Failed Login
id: 53ba33fd-3a50-4468-a5ef-c583635cfa92
name: failed_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4625
    condition: selection
---
title: Successful Login
id: 4d0a2c83-c62c-4ed4-b475-c7e23a9269b8
name: successful_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4624
    condition: selection
```

## Rules
- The top-level correlation document is the only one that carries `status`, `level`,
  `falsepositives`, `author`, `date`, `tags`.
- Intermediate correlation rules (e.g. `multiple_failed_logins` above) have no meta fields.
- Base Sigma rules within the same file must declare `name:` if referenced by name.
- Never use `detection:` inside a document that has `correlation:`.
- Never use pipe/aggregation syntax (`| count() by ...`). That syntax is deprecated.
- Use `generate: true` on the outer correlation if the backend should also emit standalone
  queries for the referenced base rules.
""".strip()
