# Copilot Instructions for sigma-mcp-server

## Project Overview

This project is an MCP (Model Context Protocol) server built with
[FastMCP](https://github.com/jlowin/fastmcp) that exposes
[pySigma](https://github.com/SigmaHQ/pySigma) functionality.

The package lives in the `sigma.mcp` Python namespace (a sub-namespace of the
pySigma `sigma` namespace package).  The entry-point for running the server is
`sigma.mcp.main:main`.

---

## Architecture

```
sigma/mcp/
    __init__.py            # empty namespace marker
    server.py              # the shared FastMCP instance `mcp`
    main.py                # imports all component modules (registration), main()
    config.py              # settings from environment variables (data dir, warm-up)
    validation.py          # pure validator helpers (registry, issue → dict)
    repo.py                # download + extract the SigmaHQ rules (GitHub ZIP)
    index.py               # rule index: search entries, logsource statistics, JSON
    index_manager.py       # background refresh, states, inter-process file lock
    pipelines.py           # parse (safe policy), validate, apply + render pipelines
    coverage.py            # pipeline coverage via probe rules per logsource/field
    resources.py           # @mcp.resource handlers
    prompts.py             # @mcp.prompt handlers
    tools/
        rules.py           # @mcp.tool handlers for Sigma rules + session state
        index.py           # @mcp.tool handlers for search and statistics
        pipelines.py       # @mcp.tool handlers for processing pipelines
    knowledge/
        specification.py   # fetch + parse the Sigma specification documents
        windows_events.py  # Windows event index + on-demand event docs
    data/
        windows_event_index.json
tests/
    __init__.py
    test_main.py  # validation, specification, Windows event and prompt tests
    test_config.py, test_repo.py, test_index.py, test_index_manager.py
    test_index_tools.py  # index tools end-to-end through Client(mcp)
    test_pipelines.py, test_coverage.py, test_pipeline_tools.py
    data/sigma-repo/ # miniature SigmaHQ repository used by the index tests
conftest.py       # fixtures: anyio backend, isolated index data dir, fake downloader
```

---

## Key Requirements

### Code Style
- All code **must** be formatted with **black** in its default configuration.
  Run: `poetry run black sigma/ tests/ conftest.py`
- All code **must** be fully typed and pass **mypy strict** mode.
  Run: `poetry run mypy sigma/mcp/ tests/`

### Testing
- Tests use **pytest** with the **anyio** pytest plugin (auto-registered as a
  transitive dependency of FastMCP).
- Async tests are marked with `@pytest.mark.anyio`.  The `anyio_backend`
  fixture in `conftest.py` fixes the backend to `asyncio`.
- Integration tests use `async with Client(mcp) as client:` (in-memory FastMCP
  transport) to test tools and resources end-to-end, including session state.
- Test coverage **must remain ≥ 95 %**.
  Run: `poetry run pytest --cov=sigma/mcp --cov-report=term-missing`

### MCP Server (FastMCP)
- The `FastMCP` instance is `mcp`, defined in `sigma/mcp/server.py` and
  re-exported by `sigma/mcp/main.py`.
- Component modules import `mcp` from `sigma.mcp.server` and register tools
  with `@mcp.tool()`, resources with `@mcp.resource(uri)` and prompts with
  `@mcp.prompt`.  A new component module must be imported in `main.py`,
  otherwise its components are never registered.
- Keep domain logic (fetching, parsing, validation) in plain functions outside
  the decorated handlers, so it can be unit-tested without an MCP client.
- Tools must never block on long-running work.  The SigmaHQ rule index is
  built in a background thread by `index_manager`; tools return its
  `index_status` plus a `message` while no index is available.
- Pipelines from clients are untrusted.  Always parse them with
  `sigma.mcp.pipelines.parse_pipeline`, which applies `PIPELINE_POLICY`
  (pySigma's `SafePolicy`) and refuses template `vars` files.  Never call
  `ProcessingPipeline.from_yaml` / `from_dict` on client input directly.
- Do not report transformed rules with `SigmaRule.to_dict()`: after field
  mappings to several fields it prints an OR as an AND.  Use
  `render_detection` instead.
- The `isolated_index` autouse fixture gives each test its own
  `SIGMA_MCP_DATA_DIR` and sets `SIGMA_MCP_NO_WARMUP=1`, because connecting a
  `Client(mcp)` runs the server lifespan.  Tests must never download from the
  network; use the `fake_downloader` fixture or `httpx.MockTransport`.
- The `Context` parameter (type-annotated as `Context`) is injected by FastMCP
  and must **not** be passed by callers.
- Session state is persisted via `await ctx.set_state(key, value)` /
  `await ctx.get_state(key)`.  All state stored in a session is visible to
  subsequent tool calls within the **same** MCP session.

### pySigma Validators
- The registry of all available validators is `sigma.validators.core.validators`
  (a `dict[str, type[SigmaRuleValidator]]`).  Identifiers follow the pattern
  `snake_case` derived from the class name (e.g. `IdentifierExistenceValidator`
  → `identifier_existence`).
- A **fresh validator instance** must be created for each `validate_rule` call.
- `SigmaRule.from_yaml(yaml_str)` parses a rule; it raises `sigma.exceptions.SigmaError`
  on parse failure.
- `SigmaValidationIssue` is the base dataclass for all issues.  Concrete
  subclasses may add extra instance fields (accessible via `dataclasses.fields`).
  `description` and `severity` are `ClassVar` on the class, not instance fields.

### Session State Keys
- `"validator_names"` – `list[str] | None` – explicit allow-list of validator
  identifiers, or `None` to use all validators.
- `"excluded_validators"` – `list[str]` – validator identifiers to exclude
  after the allow-list is applied.

### Resources
- `sigma://validators` – returns `dict[str, str]` (identifier → docstring).
- `sigma://modifiers` – returns `list[str]` (sorted modifier names from
  `sigma.modifiers.modifier_mapping`).

---

## Dependency Management

Dependencies are managed with **Poetry 2.x** using the PEP 621 `[project]`
format.  The `sigma.mcp` namespace package is declared under `[tool.poetry]`:

```toml
[tool.poetry]
packages = [{include = "sigma"}]
```

Dev dependencies live in `[dependency-groups] dev`.

No `sigma/__init__.py` must exist; `sigma` is a namespace package shared with
pySigma.

---

## Extending the Server

To add a new **tool**:
1. Define an `async def` function with appropriate type annotations.
2. Decorate it with `@mcp.tool()`.
3. If session state is needed, add a `ctx: Context` parameter (injected by
   FastMCP; must come before any parameters with defaults to satisfy Python
   syntax rules).
4. Add tests in the matching `tests/test_*.py` file using `async with Client(mcp) as client:`.

To add a new **resource**:
1. Define a (sync or async) function returning `str`, `bytes`, `dict`, or `list`.
2. Decorate it with `@mcp.resource("sigma://your-resource")`.
3. Add tests reading the resource via `await client.read_resource(uri)` and
   parsing the text content with `json.loads(contents[0].text)`.
