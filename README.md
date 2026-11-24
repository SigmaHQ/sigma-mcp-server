# Sigma MCP Server

An [MCP](https://modelcontextprotocol.io/) server that exposes
[pySigma](https://github.com/SigmaHQ/pySigma) functionality to AI assistants
and other MCP clients.

## Features

### Tools

| Tool | Description |
|---|---|
| `validate_rule` | Validate Sigma rules (YAML, several documents and correlation rules allowed) against all configured validators; returns detailed issue reports with severity levels |
| `configure_validators` | Persist a custom validator allow-list / exclusion-list for the current MCP session |
| `generate_uuid` | Generate a UUID v4 for a rule's `id` field |
| `get_logsource_info` | Suggest logsources for an activity, with fields, event IDs, tips and how SigmaHQ rules use them |
| `suggest_rule_filename` | Suggest a file name following the SigmaHQ conventions (logsource prefix, length, characters) and check it against existing SigmaHQ rules |
| `search_rules` | Search the SigmaHQ rule repository for rules similar to a detection idea |
| `get_rule` | Return the full YAML of a SigmaHQ rule by ID or path |
| `get_logsource_statistics` | Show how many SigmaHQ rules use each logsource and which fields they use most |
| `update_sigma_repository` | Download the latest SigmaHQ rules and rebuild the rule index in the background |
| `get_index_status` | Report the state of the SigmaHQ rule index |
| `validate_pipeline` | Validate a processing pipeline (YAML); returns errors, style warnings and a summary of its transformations |
| `apply_pipeline` | Apply one or more processing pipelines to a rule and show the result: field mappings, failures, state and the transformed detections |
| `analyze_pipeline_coverage` | Measure which SigmaHQ logsources and fields a processing pipeline supports, maps, rejects or leaves untouched |
| `list_resources` / `read_resource` | List and read every resource below, for clients that support tools but not resources |

### Resources

| Resource | Description |
|---|---|
| `sigma://validators` | JSON dict mapping validator identifiers → human-readable descriptions |
| `sigma://modifiers` | JSON dict mapping modifier names (e.g. `contains`, `re`, `base64`) → descriptions |
| `sigma://logsources` | JSON array of valid Sigma log source combinations from the official specification |
| `sigma://fields/{category}` | JSON array of known field names for a Sigma log source category (e.g. `process_creation`) |
| `sigma://tags` | JSON dict mapping tag namespaces (e.g. `attack`, `cve`, `detection`) → descriptions |
| `sigma://specification` | Full Sigma Rules Specification document as Markdown |
| `sigma://specification/correlation` | Sigma Correlation Rules Specification as Markdown (offline reference if it cannot be fetched) |
| `sigma://events/windows` | JSON dict of documented Windows Security Auditing events grouped by log channel |
| `sigma://events/windows/{channel}/{event_id}` | Full Microsoft documentation for a specific Windows event as Markdown |
| `sigma://statistics/logsources` | JSON statistics of all logsources in the SigmaHQ rules: rule counts and field usage |
| `sigma://pipelines/transformations` | All processing pipeline transformations, conditions, postprocessing steps and finalizers with descriptions |

### Prompts

| Prompt | Description |
|---|---|
| `create_sigma_rules` | Interactive workflow for creating Sigma rules: hypotheses, check SigmaHQ for existing rules, choose logsource and fields, draft, validate, save. Optional `task` argument |
| `create_processing_pipeline` | Interactive workflow for creating a processing pipeline: gather the environment, draft, validate, test with SigmaHQ rules, analyse coverage. Optional `task` argument |
| `create_sigma_rule_from_description` | Guide an LLM to create and validate a Sigma detection rule from a natural language description |
| `create_sigma_rules_from_url` | Guide an LLM to extract and validate Sigma rules from a blog post or threat report URL |

## Requirements

- Python ≥ 3.11

## Installation

The server is published on [PyPI](https://pypi.org/project/sigma-mcp-server/).
Run it without installing with [uv](https://docs.astral.sh/uv/):

```bash
uvx sigma-mcp-server
```

or install it with [pipx](https://pipx.pypa.io/) (or pip):

```bash
pipx install sigma-mcp-server
```

For development, see [Development](#development).

## Usage

### Running the server

```bash
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

### Using with Claude Code

Register the server with Claude Code; `uvx` downloads and runs it:

```bash
claude mcp add sigma -- uvx sigma-mcp-server
```

If you installed it with pipx, use `claude mcp add sigma -- sigma-mcp-server`.

The workflows are available as commands in Claude Code:

- `/mcp__sigma__create_sigma_rules` creates Sigma rules from a description
  or a threat report URL.
- `/mcp__sigma__create_processing_pipeline` builds a processing pipeline for
  your SIEM.

Claude Code then uses the server's tools to search SigmaHQ, validate rules
and pipelines, test pipelines against SigmaHQ rules and measure coverage,
and its own tools to read URLs and write files.

### Using the workflows in your own agent

The workflow prompts double as system prompts: fetch `create_sigma_rules` or
`create_processing_pipeline` without arguments and use the text as the
agent's instructions.  Agents that cannot read MCP resources use the
`list_resources` and `read_resource` tools instead.

### SigmaHQ rule index

`search_rules`, `get_rule`, `get_logsource_statistics` and
`sigma://statistics/logsources` work on a local index of the
[SigmaHQ rule repository](https://github.com/SigmaHQ/sigma).

When the server starts, it loads the index saved by an earlier run.  If
there is none, or it is older than the maximum age, the server downloads the
rules from GitHub (all `rules*` directories) and rebuilds the index **in the
background**.  The server answers requests at once: until the index is ready,
the index tools return an `index_status` and a `message` instead of results,
and `get_index_status` shows the progress.  While an update runs, the
previous index stays in use.  Several server processes share the data
directory; a lock file makes sure only one of them downloads at a time.

| Environment variable | Default | Description |
|---|---|---|
| `SIGMA_MCP_DATA_DIR` | user cache dir (`~/.cache/sigma-mcp-server`, `~/Library/Caches/sigma-mcp-server`, `%LOCALAPPDATA%\sigma-mcp-server`) | Where the downloaded rules (`sigma-rules/`) and the index (`index.json`) are stored |
| `SIGMA_MCP_INDEX_MAX_AGE_DAYS` | `7` | Rebuild the index at startup when it is older than this; `0` disables automatic updates |
| `SIGMA_MCP_NO_WARMUP` | unset | Set to `1` to skip loading/building the index at startup; a saved index is then loaded on first use, and `update_sigma_repository` builds one on demand |

The first download needs access to `codeload.github.com`.

### MITRE ATT&CK and D3FEND data

The validators `attacktag` and `d3_fendtag` need the MITRE ATT&CK and D3FEND
data, which pySigma downloads once and caches (in `~/.cache/pysigma`).  The
server loads it in the background at startup.  Until it is available,
`validate_rule` skips these validators and reports a `ValidatorSkipped`
issue; after a failed download it tries again at most every 10 minutes.
`ValidatorSkipped` and `ValidatorError` issues are not problems with the
rule.

### Processing pipelines

`validate_pipeline`, `apply_pipeline` and `analyze_pipeline_coverage` parse
pipelines with pySigma's safe policy: regular expressions use RE2, template
directories and external sources are refused.  Template `vars` files, which
make pySigma execute Python code, are always refused, even when
`PYSIGMA_ALLOW_VARS_EXECUTION` is set.

`analyze_pipeline_coverage` runs the pipeline with pySigma on probe rules for
every logsource in the SigmaHQ rule index, and for every field used by at
least 5 % of that logsource's rules.  It reports logsources as `covered`,
`uncovered` or `unsupported` (rejected by a `rule_failure`) and fields as
`mapped`, `unmapped`, `unsupported` (rejected by a `detection_item_failure`)
or `dropped`.

---

## Tool Reference

### `validate_rule`

Validate one or more Sigma rules.  Several rules go into one YAML string,
separated by `---`; a correlation rule should be accompanied by the rules it
references.

**Arguments**

| Name | Type | Description |
|---|---|---|
| `rule_yaml` | `string` | Complete Sigma rule(s) in YAML format |

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

Rules that cannot be parsed are reported with `validator: "parser"`,
`type: "SigmaParseError"` and the pySigma exception class in `error_class`;
they are not run through the validators.

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

Development uses [Poetry](https://python-poetry.org/):

```bash
git clone https://github.com/SigmaHQ/sigma-mcp-server
cd sigma-mcp-server
poetry install

# Run the server from the checkout
poetry run sigma-mcp-server

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

The GitHub workflow `tests.yml` runs these checks on Python 3.11, 3.12 and
3.13 for every pull request.

### Releasing

Releases have two stages, as in pySigma:

1. Set the new version in `pyproject.toml` (`poetry version <version>`) and
   merge it into `main`.
2. Push the tag `v<version>` (e.g. `git tag v0.2.0 && git push origin v0.2.0`).
   The workflow `release.yml` checks that the tag matches the package
   version, runs the checks, builds the package and publishes it to
   [TestPyPI](https://test.pypi.org/project/sigma-mcp-server/).  Try it in a
   fresh virtual environment (dependencies come from PyPI):

   ```bash
   python -m venv /tmp/sigma-mcp-test
   /tmp/sigma-mcp-test/bin/pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ sigma-mcp-server==<version>
   ```

3. Create and publish a GitHub release for that tag.  The workflow builds
   the package again and publishes it to [PyPI](https://pypi.org/project/sigma-mcp-server/).

Creating a GitHub release together with a new tag runs both stages at the
same time; push the tag first to test the package before releasing it.

Uploads use [trusted publishing](https://docs.pypi.org/trusted-publishers/),
so no API token is stored.  One-time setup:

- on test.pypi.org and on pypi.org, add a trusted publisher for the
  repository `SigmaHQ/sigma-mcp-server` with the workflow `release.yml` and
  the environment `testpypi` or `pypi` respectively;
- in the repository settings, create the environments `testpypi` and `pypi`
  (optionally with required reviewers for `pypi`).

## License

MIT
