# sigma-mcp-server

An [MCP](https://modelcontextprotocol.io/) server that exposes
[pySigma](https://github.com/SigmaHQ/pySigma) functionality to AI assistants
and other MCP clients.

## Features

| Capability | Details |
|---|---|
| **Tool** `validate_rule` | Validate a Sigma rule (YAML) against all configured validators |
| **Tool** `configure_validators` | Persist a custom validator allow-list / exclusion-list for the current MCP session |
| **Resource** `sigma://validators` | JSON dict of available validator identifiers → descriptions |
| **Resource** `sigma://modifiers` | JSON list of available Sigma value modifier names |

## Requirements

- Python ≥ 3.10
- [Poetry](https://python-poetry.org/) (for development / installation)

## Installation

```bash
git clone <repo-url>
cd sigma-mcp-server
poetry install
```

## Usage

### Running the server

```bash
poetry run sigma-mcp-server
# or, after installation:
sigma-mcp-server
```

The server listens on **stdio** by default (standard MCP transport).

### Configuring in VS Code / Claude Desktop

Add the following entry to your MCP client configuration (e.g.
`~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "sigma": {
      "command": "sigma-mcp-server"
    }
  }
}
```

Adjust the `command` path to the installed binary if it is not on `PATH`.

---

## Tool Reference

### `validate_rule`

Validate a single Sigma rule.

**Arguments**

| Name | Type | Description |
|---|---|---|
| `rule_yaml` | `string` | Complete Sigma rule in YAML format |

**Returns**

A JSON array of validation issue objects.  Each object contains:

| Key | Type | Description |
|---|---|---|
| `validator` | `string` | Validator identifier that produced the issue |
| `type` | `string` | Issue class name (e.g. `IdentifierExistenceIssue`) |
| `severity` | `string` | `low`, `medium`, or `high` |
| `description` | `string` | Human-readable description of the issue class |
| `rules` | `array[string]` | Rule IDs / titles affected by the issue |

Additional subclass-specific fields (e.g. `identifier`) may also be present.

An **empty array** means the rule passed all active validators.

---

### `configure_validators`

Persist a custom validator configuration for the current MCP session.
All subsequent `validate_rule` calls within the same session will use this
configuration.

**Arguments**

| Name | Type | Default | Description |
|---|---|---|---|
| `validator_names` | `array[string] \| null` | `null` | Explicit allow-list of validator identifiers. `null` = use all. |
| `exclusions` | `array[string] \| null` | `null` (= `[]`) | Validator identifiers to exclude after the allow-list is applied. |

**Returns**

On success: `{"validator_names": ..., "exclusions": [...]}` confirming the stored config.  
On error: `{"error": "<description>"}` when an unknown identifier is supplied.

**Example – exclude a single validator:**

```json
{"exclusions": ["identifier_existence"]}
```

**Example – use only two validators:**

```json
{"validator_names": ["identifier_existence", "identifier_uniqueness"]}
```

---

## Resource Reference

### `sigma://validators`

Returns a JSON object mapping validator identifier strings to their
human-readable descriptions.  Validator identifiers are used with
`configure_validators`.

**Example response (truncated):**

```json
{
  "identifier_existence": "Checks if rule has identifier.",
  "identifier_uniqueness": "Check rule UUID uniqueness.",
  ...
}
```

### `sigma://modifiers`

Returns a sorted JSON array of Sigma value modifier names that can be used in
detection conditions (e.g. `contains`, `startswith`, `re`, `base64`).

---

## Development

```bash
# Install dev dependencies
poetry install

# Run tests
poetry run pytest

# Run tests with coverage report
poetry run pytest --cov=sigma/mcp --cov-report=term-missing

# Type checking
poetry run mypy sigma/mcp/ tests/

# Code formatting
poetry run black sigma/ tests/ conftest.py
```

Test coverage must remain ≥ 95 %.  All code must pass `mypy --strict` and be
formatted with `black` in its default configuration.

## License

MIT
