"""MCP prompts guiding an LLM through Sigma rule creation workflows."""

from __future__ import annotations

from fastmcp.prompts import Message

from sigma.mcp.server import mcp
from sigma.mcp.workflows import PIPELINE_WORKFLOW, SIGMA_RULE_WORKFLOW


def _workflow(instructions: str, task: str) -> list[Message]:
    text = instructions
    if task.strip():
        text += f"\n---\n\n## Task\n\n{task.strip()}\n"
    return [Message(text)]


@mcp.prompt
def create_sigma_rules(task: str = "") -> list[Message]:
    """Interactive workflow for creating validated Sigma rules.

    Covers understanding the source, proposing detection hypotheses,
    checking SigmaHQ for existing rules, letting the user choose, picking
    logsource and fields, drafting, validating and saving.  Without *task*
    the text serves as system prompt for an agent.

    Args:
        task: Optional description of what to detect, or a URL of a threat
            report to create rules from.
    """
    return _workflow(SIGMA_RULE_WORKFLOW, task)


@mcp.prompt
def create_processing_pipeline(task: str = "") -> list[Message]:
    """Interactive workflow for creating a Sigma processing pipeline.

    Covers gathering the target environment, drafting, validating, testing
    with SigmaHQ rules, analysing coverage and iterating.  Without *task*
    the text serves as system prompt for an agent.

    Args:
        task: Optional description of the target environment, e.g.
            ``"Elastic with ECS, Windows Security and Sysmon logs"``.
    """
    return _workflow(PIPELINE_WORKFLOW, task)


@mcp.prompt
def create_sigma_rule_from_description(description: str) -> list[Message]:
    """Guide an LLM to create and validate a Sigma detection rule from a description.

    The prompt instructs the LLM to draft a Sigma rule for the described threat
    or behaviour and then use the ``validate_rule`` MCP tool — not pytest or any
    shell command — to validate it, iterating until all issues are resolved.

    Args:
        description: Natural language description of the threat or behaviour to detect.
    """
    return [
        Message(
            f"Create a Sigma detection rule for the following threat or behaviour:\n\n"
            f"{description}\n\n"
            f"Follow these steps:\n"
            f"1. Use the **generate_uuid** MCP tool to create a unique UUID for the "
            f"rule's ``id`` field.\n"
            f"2. Read the **sigma://logsources** resource to find valid product/"
            f"category/service combinations, then choose the most appropriate log "
            f"source for the threat described. "
            f"If the log source uses ``product: windows, service: security``, "
            f"also read **sigma://events/windows** to identify relevant event "
            f"IDs, then read **sigma://events/windows/security/{{event_id}}** "
            f"(substituting the event ID) for detailed field descriptions.\n"
            f"3. Read the **sigma://fields/{{category}}** resource (substituting the "
            f"chosen category) to discover the correct field names for that log source. "
            f"Read **sigma://modifiers** for valid field-value modifiers. "
            f"Read **sigma://tags** to select appropriate rule tags. "
            f"Read **sigma://specification** to get a full understanding of the Sigma rule format.\n"
            f"4. Draft a complete Sigma rule in YAML format. Include the generated UUID "
            f"from step 1 as the ``id`` field.\n"
            f"5. Use the **validate_rule** MCP tool to validate the rule — "
            f"do NOT use pytest, shell commands, or any external test runner. "
            f"Pass the complete YAML as the `rule_yaml` argument.\n"
            f"6. If validate_rule returns any issues, fix them in the YAML and call "
            f"validate_rule again.\n"
            f"7. Repeat step 6 until validate_rule returns no issues other "
            f"than `ValidatorError` or `ValidatorSkipped`, which are not "
            f"problems with the rule.\n"
            f"8. Use the **suggest_rule_filename** MCP tool to get a file name "
            f"that follows the SigmaHQ conventions "
            f"(e.g. `proc_creation_win_lateral_movement_via_psexec.yml`). "
            f"If it reports issues, adjust the title and ask again.\n"
            f"9. Save the final validated rule YAML to that file using your "
            f"available file-writing tools."
        )
    ]


@mcp.prompt
def create_sigma_rules_from_url(url: str) -> list[Message]:
    """Guide an LLM to create and validate Sigma rules from a blog post or threat report URL.

    The prompt instructs the LLM to fetch the URL using its own tools, extract
    every distinct detection opportunity, and then use the ``validate_rule`` MCP
    tool — not pytest or any shell command — to validate each rule.

    Args:
        url: URL of the blog post or threat intelligence report to process.
    """
    return [
        Message(
            f"Create Sigma detection rules based on the content at this URL:\n\n"
            f"{url}\n\n"
            f"Follow these steps:\n"
            f"1. Fetch the URL using your available tools (web browser, fetch, etc.).\n"
            f"2. Analyse the content to identify every distinct detection opportunity "
            f"(TTPs, attacker behaviours, malicious commands, IOCs expressible as "
            f"log-based detections).\n"
            f"3. Read the **sigma://logsources** resource once to understand valid "
            f"product/category/service combinations. Read **sigma://modifiers** for "
            f"valid field-value modifiers and **sigma://tags** for tag namespaces.\n"
            f"Read **sigma://specification** to get a full understanding of the Sigma rule format.\n"
            f"If any detection targets Windows Security logs "
            f"(``product: windows, service: security``), read "
            f"**sigma://events/windows** to identify relevant event IDs, then "
            f"read **sigma://events/windows/security/{{event_id}}** (substituting "
            f"the event ID) for detailed field descriptions.\n"
            f"4. For each detection opportunity:\n"
            f"   a. Use the **generate_uuid** MCP tool to create a unique UUID for "
            f"the rule's ``id`` field.\n"
            f"   b. Choose an appropriate Sigma log source from **sigma://logsources**.\n"
            f"   c. Read **sigma://fields/{{category}}** (substituting the chosen "
            f"category) to use the correct field names.\n"
            f"   d. Draft a complete Sigma rule in YAML format. Include the generated "
            f"UUID from step 4a as the ``id`` field.\n"
            f"   e. Use the **validate_rule** MCP tool to validate the rule — "
            f"do NOT use pytest, shell commands, or any external test runner. "
            f"Pass the complete YAML as the `rule_yaml` argument.\n"
            f"   f. If validate_rule returns any issues, fix them and call "
            f"validate_rule again.\n"
            f"   g. Repeat until validate_rule returns no issues other than "
            f"`ValidatorError` or `ValidatorSkipped`, which are not problems "
            f"with the rule.\n"
            f"   h. Use the **suggest_rule_filename** MCP tool to get a file "
            f"name that follows the SigmaHQ conventions "
            f"(e.g. `proc_creation_win_lateral_movement_via_psexec.yml`).\n"
            f"   i. Save the validated rule YAML to that file using your "
            f"available file-writing tools.\n"
            f"5. After all rules are saved, summarise the files that were written."
        )
    ]
