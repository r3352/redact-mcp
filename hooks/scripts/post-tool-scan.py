#!/usr/bin/env python3
"""
PostToolUse hook — scans tool output for leaked sensitive data.
Triggers when Claude uses raw Bash/Read/Grep/WebFetch instead of redact tools.
Checks if any known real values from the mapping table appear in the output.
"""

import json
import os
import sys


def load_mappings():
    """Load the persisted mapping table."""
    data_dir = os.environ.get("REDACT_DATA_DIR") or os.environ.get("CLAUDE_PLUGIN_DATA", "")
    if not data_dir:
        return []

    mappings_file = os.path.join(data_dir, "mappings.json")
    try:
        with open(mappings_file, "r") as f:
            state = json.load(f)
            return state.get("mappings", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def main():
    # Read the tool output from stdin
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        # No valid input, nothing to scan
        return

    tool_output = input_data.get("tool_output", "") or input_data.get("output", "") or str(input_data)

    mappings = load_mappings()
    if not mappings:
        return

    # Check for leaked real values
    leaked = []
    for mapping in mappings:
        real_value = mapping.get("real", "")
        if len(real_value) >= 4 and real_value in tool_output:
            leaked.append({
                "value": real_value,
                "type": mapping.get("type", "unknown"),
                "fake": mapping.get("fake", ""),
            })

    if leaked:
        # Emit warning as systemMessage
        types = ", ".join(set(l["type"] for l in leaked))
        count = len(leaked)
        warning = (
            f"WARNING: {count} known sensitive value(s) detected in raw tool output "
            f"(types: {types}). This data was NOT redacted because a raw tool was used "
            f"instead of redact_proxy_request or redact_read_file. "
            f"Re-process this output through redact_obfuscate before including it in your response."
        )
        # Output the warning for Claude to see
        print(warning, file=sys.stderr)


if __name__ == "__main__":
    main()
