"""Sigma MCP server exposing pySigma functionality via FastMCP.

This module assembles the server: importing the tool, resource and prompt
modules registers their components on the shared :data:`mcp` instance.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

# Imported for their side effect of registering components on ``mcp``.
import sigma.mcp.prompts  # noqa: F401
import sigma.mcp.resources  # noqa: F401
import sigma.mcp.tools.index  # noqa: F401
import sigma.mcp.tools.matching  # noqa: F401
import sigma.mcp.tools.pipelines  # noqa: F401
import sigma.mcp.tools.rules  # noqa: F401
from sigma.mcp import config
from sigma.mcp.index_manager import IndexStatus, index_manager
from sigma.mcp.public import STATELESS_HTTP, apply_public_mode
from sigma.mcp.reference_data import reference_data
from sigma.mcp.server import mcp

__all__ = ["main", "mcp", "parse_args", "prepare"]


# Hosting platforms that import ``mcp`` instead of calling main() (e.g.
# ``fastmcp run sigma/mcp/main.py:mcp``) get the public mode from the
# environment as well.
if config.public_mode():
    apply_public_mode(mcp)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the command line; defaults come from the environment variables."""
    parser = argparse.ArgumentParser(
        prog="sigma-mcp-server",
        description="MCP server for Sigma detection engineering.",
    )
    parser.add_argument(
        "--transport",
        choices=config.TRANSPORTS,
        default=config.transport(),
        help=f"MCP transport (default: stdio, env {config.ENV_TRANSPORT})",
    )
    parser.add_argument(
        "--host",
        default=config.host(),
        help=f"HTTP interface to bind to (default: 127.0.0.1, env {config.ENV_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=config.port(),
        help=f"HTTP port (default: 8000, env {config.ENV_PORT} or PORT)",
    )
    parser.add_argument(
        "--public",
        action="store_true",
        default=config.public_mode(),
        help=(
            "Harden the server for public access: rate and size limits, no "
            f"repository updates by clients (env {config.ENV_PUBLIC})"
        ),
    )
    parser.add_argument(
        "--prepare",
        action="store_true",
        help=(
            "Download the SigmaHQ rules, build the rule index and load the MITRE "
            "data, then exit (e.g. while building a container image)"
        ),
    )
    return parser.parse_args(argv)


def prepare() -> int:
    """Build the rule index and cache the MITRE data in the foreground.

    Returns:
        The process exit code: ``0`` on success, ``1`` if the index could
        not be built.  Missing MITRE data is only a warning, as the server
        loads it again at startup.
    """
    index_manager.start_refresh()
    reference_data.start_loading()
    index_manager.wait()
    reference_data.wait()
    for dataset in reference_data.describe():
        if dataset.get("status") != "ready":
            print(f"Warning: {dataset}", file=sys.stderr)
    info = index_manager.describe()
    if index_manager.status is not IndexStatus.READY:
        print(f"Building the rule index failed: {info}", file=sys.stderr)
        return 1
    print(
        f"Rule index ready: {info.get('rule_count')} rules from commit "
        f"{info.get('source_commit')} in {info.get('data_dir')}"
    )
    return 0


def main(argv: Sequence[str] | None = None) -> None:
    """Entry point for the sigma-mcp-server command."""
    args = parse_args(argv)
    if args.prepare:
        sys.exit(prepare())
    if args.public:
        apply_public_mode(mcp)
    if args.transport == "http":
        # The banner goes to stdout and would only clutter hosting logs.
        mcp.run(
            transport="http",
            host=args.host,
            port=args.port,
            show_banner=False,
            # Public servers run without sessions (see sigma.mcp.public);
            # None keeps FastMCP's default otherwise.
            stateless_http=STATELESS_HTTP if args.public else None,
            # Behind a reverse proxy, take the client address from
            # X-Forwarded-For (for the proxies in FORWARDED_ALLOW_IPS).
            uvicorn_config={
                "proxy_headers": True,
                "forwarded_allow_ips": os.environ.get("FORWARDED_ALLOW_IPS", "*"),
            },
        )
    else:
        mcp.run()
