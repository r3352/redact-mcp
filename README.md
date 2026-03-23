# Redact — Claude Code Plugin for Sensitive Data Obfuscation

A Claude Code plugin that automatically detects and obfuscates sensitive data (IPs, hostnames, emails, API keys, PII) before Claude ever sees it. Designed for penetration testers who want to use Claude's analysis capabilities without exposing client data to a third party.

## How It Works

```
You paste raw data ──► Redact auto-detects PII ──► Claude sees only fake values
                                                          │
Claude's analysis ◄── Real values restored ◄── You run /redact:export
```

The plugin maintains a bidirectional mapping table. Every sensitive value gets a consistent fake replacement:

| Real Value | Obfuscated As |
|---|---|
| `10.50.1.100` | `198.51.100.1` |
| `api.clientcorp.com` | `target-1.example.com` |
| `john.smith@clientcorp.com` | `user-1@example.com` |
| `AKIA...` | `[REDACTED_AWS_KEY_1]` |
| `John Smith` | `Person_A` |

Same real value always maps to the same fake value across the entire session.

## Install

```bash
# Clone the repo
git clone <repo-url> redact
cd redact

# Build the MCP server
cd server && npm install && npm run build && cd ..

# Load as a Claude Code plugin
claude --plugin-dir ./redact
```

## What Gets Detected

Zero configuration required. The plugin auto-detects:

- **Network:** IPv4 (private + public), IPv6, hostnames with valid TLDs
- **Identity:** Emails, person names (in JSON context), US phone numbers, SSNs
- **Secrets:** AWS access keys, JWTs, Bearer tokens, API keys (context-aware)
- **Financial:** Credit card numbers (with Luhn validation)

### Smart Passthrough

These are never obfuscated:
- `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`
- RFC documentation ranges (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`, `2001:db8::`)
- `example.com`, `example.org`, `example.net`
- Common dev domains (`github.com`, `npmjs.com`, etc.)
- `burpcollaborator.net`, `oastify.com` (Burp OOB testing)
- Code patterns (`package.json`, `console.log`, `process.env`, etc.)

## MCP Tools

The plugin registers 7 tools via MCP:

| Tool | What It Does |
|---|---|
| `redact_obfuscate` | Auto-detect and replace all PII in text |
| `redact_deobfuscate` | Reverse all replacements (for final reports) |
| `redact_proxy_request` | HTTP request proxy — real request out, obfuscated response back |
| `redact_read_file` | Read a file and return obfuscated content |
| `redact_add_mapping` | Manually add a real-to-fake mapping |
| `redact_remove_mapping` | Remove a mapping (fix false positives) |
| `redact_show_mappings` | Show all current mappings grouped by type |

### `redact_proxy_request` — The Key Tool

For pentest workflows, this is the critical tool. Claude calls it instead of curl:

1. Claude provides URL/headers/body (may contain already-obfuscated values)
2. Plugin **deobfuscates** the request (restores real hostnames/IPs)
3. Makes the **real HTTP request** to the target
4. **Obfuscates** the entire response
5. Returns sanitized response to Claude

Claude never sees the real response data.

## Skills

| Command | What It Does |
|---|---|
| `/redact:status` | Show current redaction mappings |
| `/redact:add clientcorp.com target.example.com` | Manually add a mapping |
| `/redact:export ./report.md` | Deobfuscate a file for client delivery |

## Hooks

The plugin uses two hooks (no user interaction needed):

- **SessionStart** — Injects instructions telling Claude to route data through redact tools
- **PostToolUse** — Warns if Claude uses raw Bash/Read/Grep and the output contains known sensitive values

## Architecture

```
redact/
├── .claude-plugin/plugin.json     # Plugin manifest
├── .mcp.json                      # MCP server config (stdio)
├── hooks/
│   ├── hooks.json                 # Hook definitions
│   └── scripts/
│       ├── session-start.sh       # Injects redaction context
│       └── post-tool-scan.py      # Leak detection on raw tool output
├── skills/
│   ├── status/SKILL.md
│   ├── add/SKILL.md
│   └── export/SKILL.md
└── server/
    ├── package.json
    ├── tsconfig.json
    └── src/
        ├── index.ts               # MCP server — 7 tools
        ├── mapping-engine.ts      # Bidirectional mapping + obfuscate/deobfuscate
        ├── pattern-detector.ts    # Regex auto-detection for 12 PII types
        ├── fake-generator.ts      # Deterministic counter-based replacements
        └── persistence.ts         # JSON state file with debounced writes
```

## How Replacements Work

1. **Detection** — Regex patterns scan input text for all PII types
2. **Mapping** — Each unique real value gets a fake replacement (counter-based, deterministic)
3. **Longest-first replacement** — `10.50.1.100` is replaced before `10.50.1.10` to prevent corruption
4. **Persistence** — Mappings saved to disk (debounced 500ms), survive across tool calls
5. **Round-trip** — `obfuscate(text) → deobfuscate(result) === text` is guaranteed

## Development

```bash
cd server

# Build
npm run build

# Rebuild after changes
npm run build

# Test manually (MCP stdio)
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}' | node dist/index.js
```

## License

MIT
