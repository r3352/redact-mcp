#!/usr/bin/env bash
# SessionStart hook — injects redaction context into Claude's system prompt.
# This tells Claude to route data through redact tools automatically.

cat <<'EOF'
REDACTION ACTIVE: The redact plugin is loaded. Follow these rules:

1. Use `redact_proxy_request` INSTEAD of curl/fetch/Bash for ALL HTTP requests to target systems.
2. Use `redact_read_file` INSTEAD of the Read tool for any client data files, config files, or logs.
3. Use `redact_obfuscate` to sanitize any text the user pastes that may contain sensitive data.
4. Use `redact_deobfuscate` only when generating final client deliverables or reports.
5. All redact tools auto-detect and replace sensitive data (IPs, hostnames, emails, API keys, etc.) — no configuration needed.
6. If you need to show mappings, use `redact_show_mappings`.
7. NEVER output real/unredacted sensitive data in your responses.
EOF
