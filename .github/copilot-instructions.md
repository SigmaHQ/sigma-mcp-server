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
    __init__.py   # empty namespace marker
    main.py       # FastMCP server definition, tools, resources, main()
tests/
    __init__.py
    test_main.py  # pytest tests (anyio async tests via the anyio pytest plugin)
conftest.py       # anyio_backend fixture ("asyncio")
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
- The `FastMCP` instance is `mcp` (module-level) in `sigma/mcp/main.py`.
- Tools are registered with `@mcp.tool()`, resources with `@mcp.resource(uri)`.
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
4. Add tests in `tests/test_main.py` using `async with Client(mcp) as client:`.

To add a new **resource**:
1. Define a (sync or async) function returning `str`, `bytes`, `dict`, or `list`.
2. Decorate it with `@mcp.resource("sigma://your-resource")`.
3. Add tests reading the resource via `await client.read_resource(uri)` and
   parsing the text content with `json.loads(contents[0].text)`.
