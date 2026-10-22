# Security Policy

## Supported versions

This project has no tagged release yet. Security fixes are made on the `main` branch.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub: **Security → Advisories → "Report a vulnerability"** on this repository (<https://github.com/SigmaHQ/sigma-mcp-server/security/advisories/new>).
If you cannot use GitHub, contact one of the maintainers listed in `pyproject.toml` privately.

Please include:

- the version or commit, the tool name and arguments, and the observed and expected result;
- the impact you see (see the scope below) and, if you have one, a proposed fix.

## What we treat as a vulnerability

The Sigma MCP server exposes Sigma tooling (for example rule validation and conversion) as Model Context Protocol tools to LLM clients. Tool arguments come from a language model and may be shaped by untrusted content such as prompts, documents or rules. The following are in scope:

- **Server-side request forgery or path traversal:** tool arguments that make the server fetch, read or write resources other than the ones the tool is meant to access.
- **Code execution:** tool input that leads to code execution, unsafe deserialisation or template evaluation on the server.
- **Denial of service:** small tool inputs that exhaust CPU or memory or make the server unavailable.
- **Information disclosure:** tool responses that leak server files, environment variables, credentials or other clients' data.
- **Transport and exposure:** insecure defaults that expose the server beyond the local machine without authentication.

**Out of scope (report publicly as bugs):**

- Incorrect validation or conversion results without a security impact.
- Behaviour that only occurs when the operator deliberately exposes the server to untrusted networks against the documented setup, unless the documentation or defaults encourage it.

Report problems whose root cause is in pySigma itself (rule parsing, modifiers, processing pipeline machinery, conversion base classes) to [SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma). Report problems specific to this repository here.

## Our process

| Step                                                                          | Target                                        |
| ----------------------------------------------------------------------------- | --------------------------------------------- |
| Acknowledge the report                                                        | within 5 working days                         |
| Initial assessment and severity (CVSS 3.1)                                    | within 14 days                                |
| Fix developed in the advisory's temporary private fork                        | as soon as practical, normally within 90 days |
| Coordinated release, then GitHub Security Advisory published (CVE via GitHub) | at the fix release                            |

- We credit reporters in the advisory unless they ask not to be credited.
- When a fix affects other SigmaHQ projects, we may coordinate their releases.
- We ask reporters to keep details private until the advisory is published or 90 days have passed, whichever comes first, unless agreed otherwise.
