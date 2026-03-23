# Redact MCP — Automatic PII Obfuscation for Claude Code

An MCP server (and Claude Code plugin) that automatically detects and obfuscates sensitive data before Claude ever sees it. Uses **regex pattern matching** and **AI-powered Named Entity Recognition (NER)** to catch IPs, hostnames, emails, API keys, person names, organization names, locations, private keys, connection strings, and more.

Built for penetration testers who need Claude's analysis capabilities without exposing client data to a third party.

## How It Works

```
Raw data with real PII ──► Regex + NER detection ──► Claude sees only fake values
                                                              │
Final report for client ◄── Real values restored ◄── /redact:export
```

The server maintains a **bidirectional mapping table**. Every sensitive value gets a consistent, deterministic fake replacement that persists across the entire session:

| Real Value | Obfuscated As | Detection |
|---|---|---|
| `10.50.1.100` | `198.51.100.1` | regex |
| `api.clientcorp.com` | `target-1.example.com` | regex |
| `john.smith@clientcorp.com` | `user-1@example.com` | regex |
| `AKIA3EXAMPLE...` | `[REDACTED_AWS_KEY_1]` | regex |
| `James Wilson` | `Person_A Person_B` | NER |
| `Microsoft` | `Org_A` | NER |
| `Seattle` | `City_A` | NER |
| `postgres://admin:pw@host/db` | `[REDACTED_CONN_STRING_1]` | regex |
| `-----BEGIN RSA PRIVATE KEY...` | `[REDACTED_PRIVATE_KEY_1]` | regex |

Same real value always maps to the same fake value. `obfuscate(text) -> deobfuscate(result) === text` is guaranteed.

## Install

### Quick install via npx (recommended)

```bash
claude mcp add redact-mcp -- npx redact-mcp
```

That's it. Claude Code will launch the server via npx on each session. The NER model (~110MB) downloads automatically on first use and is cached for subsequent runs.

To enable audit logging:

```bash
claude mcp add redact-mcp -e REDACT_AUDIT_LOG=true -- npx redact-mcp
```

### As a Claude Code plugin (full features: hooks + skills)

```bash
git clone https://github.com/r3352/redact-mcp.git redact
cd redact/server
npm install
npm run build
cd ../..

# Load as a plugin (includes hooks for leak detection + slash commands)
claude --plugin-dir ./redact
```

The plugin mode adds **hooks** (automatic leak detection on raw tool output) and **skills** (`/redact:status`, `/redact:add`, `/redact:export`) on top of the MCP server.

### Manual MCP configuration

Add to your Claude Code MCP config (`~/.claude/mcp.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "redact-server": {
      "command": "npx",
      "args": ["redact-mcp"],
      "env": {
        "REDACT_DATA_DIR": "/path/to/data/directory",
        "REDACT_AUDIT_LOG": "true"
      }
    }
  }
}
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `REDACT_DATA_DIR` | `./data` | Directory for mapping state and audit logs |
| `REDACT_AUDIT_LOG` | `false` | Set to `true` to enable JSONL audit logging |

## What Gets Detected

### Regex Patterns (19 types)

Zero configuration required. Detected automatically:

| Category | Types |
|---|---|
| **Network** | IPv4 (private + public), IPv6, hostnames with valid TLDs, MAC addresses |
| **Identity** | Emails, person names (JSON context), phone numbers (US + international), SSNs |
| **Secrets** | AWS access keys, JWTs, Bearer tokens, API keys (context-aware), generic secrets (`password=`, `secret=`), private keys (PEM format), connection strings (postgres/mysql/redis/mongodb/amqp/mssql URIs) |
| **Financial** | Credit card numbers (Luhn-validated) |
| **Physical** | Street addresses (`123 Main Street`, `456 Oak Ave`, etc.) |

### NER Detection (AI-powered)

When `@huggingface/transformers` is installed (included by default), the server loads `Xenova/bert-base-NER` (~110MB ONNX model, downloaded on first use) to detect:

| Entity Type | Example | Obfuscated As |
|---|---|---|
| Person names | `James Wilson` | `Person_A Person_B` |
| Organizations | `Microsoft`, `Acme Corp` | `Org_A`, `Org_B` |
| Locations | `Seattle`, `New York` | `City_A`, `City_B` |

NER catches entities that regex misses — names and organizations outside of JSON context, arbitrary location names, etc. Regex results always take priority when both detect the same span (regex is more precise for structured patterns).

**Graceful fallback:** If the model fails to load or the package is missing, the server continues in regex-only mode with no errors.

### Smart Passthrough

These values are never obfuscated:

- **Loopback/reserved:** `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`
- **RFC documentation ranges:** `192.0.2.x` (TEST-NET-1), `198.51.100.x` (TEST-NET-2), `203.0.113.x` (TEST-NET-3), `2001:db8::` (IPv6 docs)
- **Example domains:** `example.com`, `example.org`, `example.net`
- **Dev domains:** `github.com`, `npmjs.com`, `nodejs.org`, `googleapis.com`, etc.
- **Security testing:** `burpcollaborator.net`, `oastify.com`
- **Code patterns:** `console.log`, `process.env`, `package.json`, `webpack.config`, `jest.config`, `tailwind.config`, and 30+ other common false positives
- **Broadcast MACs:** `FF:FF:FF:FF:FF:FF`, `00:00:00:00:00:00`

## MCP Tools

The server registers **8 tools** via MCP:

| Tool | Description |
|---|---|
| `redact_obfuscate` | Auto-detect and replace all PII in text (regex + NER) |
| `redact_deobfuscate` | Reverse all replacements back to real values |
| `redact_proxy_request` | HTTP proxy — deobfuscates request, makes real call, obfuscates response |
| `redact_read_file` | Read a file and return obfuscated content |
| `redact_add_mapping` | Manually add a real-to-fake mapping |
| `redact_remove_mapping` | Remove a mapping (fix false positives) |
| `redact_show_mappings` | Show all current mappings grouped by type |
| `redact_audit_log` | View recent audit log entries (requires `REDACT_AUDIT_LOG=true`) |

### `redact_proxy_request` — The Key Tool

For pentest workflows, this is the critical tool. Claude calls it instead of curl/fetch:

1. Claude provides URL/headers/body (may contain already-obfuscated values)
2. Server **deobfuscates** the request (restores real hostnames/IPs/tokens)
3. Makes the **real HTTP request** to the target
4. **Obfuscates** the entire response (headers + body)
5. Returns sanitized response to Claude

Claude never sees the real response data. All deobfuscation and obfuscation steps are audit-logged.

### `redact_audit_log` — Compliance Audit Trail

When `REDACT_AUDIT_LOG=true`, every obfuscation and deobfuscation operation is logged to `${REDACT_DATA_DIR}/audit.jsonl`. Each entry records:

- **Timestamp** and **operation type** (`obfuscate`, `deobfuscate`, `proxy_request`, `file_read`)
- **Full input text** (raw data before transformation)
- **All detections** with type, real value, fake replacement, and source (`regex` or `ner`)
- **Full output text** (transformed result)

This provides a complete audit trail: what went in, what was modified, and what came out.

View entries via the `redact_audit_log` tool or read `audit.jsonl` directly:

```bash
# Last 5 entries, pretty-printed
tail -5 data/audit.jsonl | python3 -m json.tool
```

**Security note:** The audit log contains real sensitive data by design (that's its purpose — proving what was redacted). Protect it accordingly.

## Skills (Slash Commands)

| Command | Description |
|---|---|
| `/redact:status` | Show current redaction mappings grouped by type |
| `/redact:add <real> <fake>` | Manually add a mapping (e.g., `/redact:add clientcorp.com target.example.com`) |
| `/redact:export <file> [output]` | Deobfuscate a file for client delivery (defaults to `~/Desktop/`) |

## Hooks

The plugin uses two hooks (automatic, no user interaction):

- **SessionStart** — Injects instructions telling Claude to route all data through redact tools
- **PostToolUse** — Warns if Claude uses raw `Bash`/`Read`/`Grep`/`WebFetch` and the output contains known sensitive values (leak detection)

## How the Pipeline Works

### Detection

1. **Regex pass** — 19 pattern types scanned synchronously via compiled RegExp
2. **NER pass** — `Xenova/bert-base-NER` runs in parallel (async), catches person/org/location entities
3. **Merge** — Results combined; regex matches win on overlapping spans (more precise for structured data)
4. **Deduplication** — Overlapping NER results that cover the same span as a regex match are dropped

### Mapping

1. Each unique real value gets a **deterministic fake** via counter-based generation
2. Fake values use **safe ranges**: TEST-NET-2 for IPv4, RFC 3849 for IPv6, `example.com` for domains, `555` prefix for phones, locally-administered range for MACs
3. Mappings persist to `${REDACT_DATA_DIR}/mappings.json` with debounced writes (500ms)
4. **Longest-first replacement** prevents partial match corruption (e.g., `10.50.1.100` before `10.50.1.10`)

### Round-trip Guarantee

`deobfuscate(obfuscate(text)) === text` for all inputs. The bidirectional mapping table ensures lossless restoration.

## Architecture

```
redact/
├── .claude-plugin/plugin.json     # Plugin manifest
├── .mcp.json                      # MCP server config (stdio transport)
├── hooks/
│   ├── hooks.json                 # Hook definitions
│   └── scripts/
│       ├── session-start.sh       # Injects redaction context on session start
│       └── post-tool-scan.py      # Leak detection on raw tool output
├── skills/
│   ├── status/SKILL.md            # /redact:status
│   ├── add/SKILL.md               # /redact:add
│   └── export/SKILL.md            # /redact:export
└── server/
    ├── package.json               # v2.0.0, deps: @modelcontextprotocol/sdk, @huggingface/transformers
    ├── tsconfig.json              # ES2022, Node16 modules, strict
    └── src/
        ├── index.ts               # MCP server — 8 tools, server instructions
        ├── mapping-engine.ts      # Bidirectional mapping, async obfuscate/deobfuscate, audit integration
        ├── pattern-detector.ts    # 19 regex patterns + async NER merge
        ├── fake-generator.ts      # Deterministic counter-based fake value generation
        ├── ner-detector.ts        # Lazy-loaded HuggingFace NER with graceful fallback
        ├── audit-logger.ts        # JSONL append logger, serialized write queue
        └── persistence.ts         # JSON state file with debounced writes
```

### Runtime Flow

```
Claude Code ──stdio──► MCP Server (index.ts)
                            │
                     CallToolRequest
                            │
                    ┌───────┴───────┐
                    │ MappingEngine │
                    └───────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
        detectPatterns   NER detect   AuditLogger
        (regex, sync)   (async)      (JSONL, async)
              │             │             │
              └─────────────┼─────────────┘
                            │
                     merge + dedupe
                            │
                     apply mappings
                     (longest-first)
                            │
                     return to Claude
```

## Development

```bash
cd server

# Install dependencies (~110MB for NER model on first run)
npm install

# Build TypeScript
npm run build

# Test MCP server starts and lists tools
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | node dist/index.js

# Quick obfuscation test
node -e '
const { MappingEngine } = await import("./dist/mapping-engine.js");
const engine = new MappingEngine("/tmp/redact-dev");
await engine.init();
console.log(await engine.obfuscate("Email john@acme.com from 10.0.0.1"));
'
```

## Changelog

### v2.0.0

- **NER detection** — AI-powered entity recognition via `@huggingface/transformers` + `Xenova/bert-base-NER`. Catches person names, organizations, and locations outside structured JSON context.
- **Audit logging** — Opt-in JSONL audit trail (`REDACT_AUDIT_LOG=true`) records full input/output text, all detections with sources, and timestamps for every obfuscation and deobfuscation operation.
- **7 new pattern types** — `organization`, `location`, `private_key`, `connection_string`, `generic_secret`, `mac_address`, `street_address`
- **8th tool** — `redact_audit_log` for viewing audit entries
- **Improved phone detection** — International format support (`+CC-XXXX-XXXX`)
- **Expanded false positive list** — `webpack.config`, `jest.config`, `tailwind.config`, and 9 other config file patterns

### v1.0.0

- Initial release with regex-only detection (12 pattern types), 7 MCP tools, bidirectional mapping, persistence, hooks, and skills.

## License

MIT
