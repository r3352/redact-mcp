---
name: add
description: Manually add a real→fake redaction mapping
user_invocable: true
args: "<real_value> <fake_value>"
---

# Redact Add Mapping

The user wants to manually add a redaction mapping. Parse the arguments to extract the real value and fake replacement value, then call `redact_add_mapping` from the redact-server MCP.

If the user provided arguments like `clientcorp.com target.example.com`, use the first value as `real` and the second as `fake`.

If the user only provided one value, ask them for the replacement value, or suggest a sensible default like `target-N.example.com` for hostnames.

Confirm the mapping was added successfully.
