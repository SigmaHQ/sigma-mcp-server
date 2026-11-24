"""File names for Sigma rules following the SigmaHQ conventions.

SigmaHQ's rule tests require file names matching ``[a-z0-9_]{10,90}\\.yml``
that are 14 to 90 characters long, contain an underscore and start with a
prefix derived from the logsource, for example ``proc_creation_win_`` for
Windows process creation or ``win_security_`` for the Windows Security log.
The prefixes below mirror those tests.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

MAX_FILENAME_LENGTH = 90
MIN_FILENAME_LENGTH = 14
EXTENSION = ".yml"

OS_INFIXES = {"windows": "win_", "macos": "macos_", "linux": "lnx_"}
"""Inserted after category prefixes marked as OS-specific below."""

PRODUCT_PREFIXES = {
    "aws": "aws_",
    "azure": "azure_",
    "gcp": "gcp_",
    "m365": "microsoft365_",
    "okta": "okta_",
    "onelogin": "onelogin_",
    "github": "github_",
    "fortinet": "fortinet_",
}

CATEGORY_PREFIXES: dict[str, tuple[str, bool]] = {
    # category: (prefix, followed by the OS infix)
    "process_creation": ("proc_creation_", True),
    "image_load": ("image_load_", False),
    "file_event": ("file_event_", True),
    "registry_set": ("registry_set_", False),
    "registry_add": ("registry_add_", False),
    "registry_event": ("registry_event_", False),
    "registry_delete": ("registry_delete_", False),
    "registry_rename": ("registry_rename_", False),
    "process_access": ("proc_access_", True),
    "driver_load": ("driver_load_", True),
    "dns_query": ("dns_query_", True),
    "ps_script": ("posh_ps_", False),
    "ps_module": ("posh_pm_", False),
    "ps_classic_start": ("posh_pc_", False),
    "pipe_created": ("pipe_created_", False),
    "network_connection": ("net_connection_", True),
    "file_rename": ("file_rename_", True),
    "file_delete": ("file_delete_", True),
    "file_change": ("file_change_", True),
    "file_access": ("file_access_", True),
    "create_stream_hash": ("create_stream_hash_", False),
    "create_remote_thread": ("create_remote_thread_win_", False),
    "dns": ("net_dns_", False),
    "firewall": ("net_firewall_", False),
    "webserver": ("web_", False),
}

SERVICE_PREFIXES = {
    "auditd": "lnx_auditd_",
    "modsecurity": "modsec_",
    "diagnosis-scripted": "win_diagnosis_scripted_",
    "firewall-as": "win_firewall_as_",
    "msexchange-management": "win_exchange_",
    "security": "win_security_",
    "system": "win_system_",
    "taskscheduler": "win_taskscheduler_",
    "terminalservices-localsessionmanager": "win_terminalservices_",
    "windefend": "win_defender_",
    "wmi": "win_wmi_",
    "codeintegrity-operational": "win_codeintegrity_",
    "bits-client": "win_bits_client_",
    "applocker": "win_applocker_",
    "dns-server-analytic": "win_dns_analytic_",
    "bitlocker": "win_bitlocker_",
    "capi2": "win_capi2_",
    "certificateservicesclient-lifecycle-system": (
        "win_certificateservicesclient_lifecycle_system_"
    ),
    "pim": "azure_pim_",
}

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def filename_prefix(logsource: Mapping[str, str]) -> str:
    """Return the SigmaHQ file name prefix for a logsource (may be empty)."""
    product = logsource.get("product", "")
    category = logsource.get("category", "")
    service = logsource.get("service", "")
    if service in SERVICE_PREFIXES:
        return SERVICE_PREFIXES[service]
    if category in CATEGORY_PREFIXES:
        prefix, with_os = CATEGORY_PREFIXES[category]
        return prefix + (OS_INFIXES.get(product, "") if with_os else "")
    return PRODUCT_PREFIXES.get(product, "")


def slugify(text: str) -> str:
    """Lower-case *text* and join its alphanumeric runs with underscores."""
    return _NON_ALNUM.sub("_", text.lower()).strip("_")


def build_filename(title: str, logsource: Mapping[str, str]) -> tuple[str, str]:
    """Return ``(filename, prefix)`` for a rule title and logsource.

    A title that already starts with the prefix words is not prefixed twice.
    Long names are shortened at a word boundary to at most
    :data:`MAX_FILENAME_LENGTH` characters.
    """
    prefix = filename_prefix(logsource)
    slug = slugify(title)
    if prefix and slug.startswith(prefix):
        slug = slug[len(prefix) :]
    budget = MAX_FILENAME_LENGTH - len(EXTENSION) - len(prefix)
    if len(slug) > budget:
        cut = slug[:budget]
        slug = cut.rsplit("_", 1)[0] if "_" in cut else cut
    return f"{prefix}{slug}{EXTENSION}", prefix


def filename_issues(filename: str) -> list[str]:
    """Return the SigmaHQ naming rules that *filename* violates."""
    issues: list[str] = []
    if len(filename) < MIN_FILENAME_LENGTH:
        issues.append(
            f"The file name is shorter than {MIN_FILENAME_LENGTH} characters. "
            "Use a more descriptive title."
        )
    if "_" not in filename:
        issues.append("The file name must contain at least one underscore.")
    if not re.fullmatch(r"[a-z0-9_]+\.yml", filename):
        issues.append("The file name may only contain a-z, 0-9 and underscores.")
    return issues
