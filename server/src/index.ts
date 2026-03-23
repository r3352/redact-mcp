#!/usr/bin/env node
/**
 * Redact MCP Server
 * Auto-obfuscates sensitive client data during pentesting.
 * Registers 7 tools for obfuscation, deobfuscation, proxy requests, file reading, and mapping management.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { readFile } from 'node:fs/promises';
import { MappingEngine } from './mapping-engine.js';
import type { MappingType } from './fake-generator.js';

const DATA_DIR = process.env.REDACT_DATA_DIR || process.env.CLAUDE_PLUGIN_DATA || './data';

const engine = new MappingEngine(DATA_DIR);

const server = new Server(
  { name: 'redact-server', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

// ─── List Tools ────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'redact_obfuscate',
      description: 'Takes raw text and returns an obfuscated version with all detected PII replaced by consistent fake values. Use this to sanitize any pasted text, command output, or data before analysis.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          text: { type: 'string', description: 'Raw text to obfuscate' },
        },
        required: ['text'],
      },
    },
    {
      name: 'redact_deobfuscate',
      description: 'Reverses obfuscation — replaces all fake values back with the original real values. Use this when generating final reports or deliverables for the client.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          text: { type: 'string', description: 'Obfuscated text to restore' },
        },
        required: ['text'],
      },
    },
    {
      name: 'redact_proxy_request',
      description: 'Makes a real HTTP request to the target, then obfuscates the entire response before returning it. Use this INSTEAD of curl/fetch for all pentest HTTP requests. The URL, headers, and body are deobfuscated first (in case you\'re using already-obfuscated values), then the real request is made, and the response is fully sanitized.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          url: { type: 'string', description: 'Target URL (can contain obfuscated or real values)' },
          method: { type: 'string', description: 'HTTP method (GET, POST, PUT, DELETE, etc.)', default: 'GET' },
          headers: {
            type: 'object',
            description: 'Request headers as key-value pairs',
            additionalProperties: { type: 'string' },
          },
          body: { type: 'string', description: 'Request body (for POST/PUT/PATCH)' },
          followRedirects: { type: 'boolean', description: 'Follow HTTP redirects', default: true },
        },
        required: ['url'],
      },
    },
    {
      name: 'redact_read_file',
      description: 'Reads a file from disk and returns its content with all detected PII obfuscated. Use this INSTEAD of the Read tool for any client data files, config files, or logs that may contain sensitive information.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          path: { type: 'string', description: 'Absolute path to the file to read' },
          encoding: { type: 'string', description: 'File encoding', default: 'utf-8' },
        },
        required: ['path'],
      },
    },
    {
      name: 'redact_add_mapping',
      description: 'Manually add a specific real→fake mapping. Use this when you know a specific value should be redacted (e.g., a client company name, internal hostname).',
      inputSchema: {
        type: 'object' as const,
        properties: {
          real: { type: 'string', description: 'The real/sensitive value to map' },
          fake: { type: 'string', description: 'The fake replacement value' },
          type: {
            type: 'string',
            description: 'Category of the value',
            enum: ['hostname', 'ipv4', 'ipv6', 'email', 'person_name', 'phone', 'ssn', 'credit_card', 'api_key', 'jwt', 'bearer', 'aws_key', 'custom'],
            default: 'custom',
          },
        },
        required: ['real', 'fake'],
      },
    },
    {
      name: 'redact_remove_mapping',
      description: 'Remove a mapping by its real value. Use this to undo a false positive detection.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          real: { type: 'string', description: 'The real value whose mapping should be removed' },
        },
        required: ['real'],
      },
    },
    {
      name: 'redact_show_mappings',
      description: 'Display all current real→fake mappings, grouped by type. Shows what is currently being redacted.',
      inputSchema: {
        type: 'object' as const,
        properties: {},
      },
    },
  ],
}));

// ─── Call Tool ──────────────────────────────────────────────────

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case 'redact_obfuscate': {
      const text = args?.text as string;
      if (!text) return { content: [{ type: 'text', text: 'Error: text parameter is required' }] };
      const result = engine.obfuscate(text);
      return { content: [{ type: 'text', text: result }] };
    }

    case 'redact_deobfuscate': {
      const text = args?.text as string;
      if (!text) return { content: [{ type: 'text', text: 'Error: text parameter is required' }] };
      const result = engine.deobfuscate(text);
      return { content: [{ type: 'text', text: result }] };
    }

    case 'redact_proxy_request': {
      const rawUrl = args?.url as string;
      if (!rawUrl) return { content: [{ type: 'text', text: 'Error: url parameter is required' }] };

      const method = (args?.method as string || 'GET').toUpperCase();
      const rawHeaders = (args?.headers as Record<string, string>) || {};
      const rawBody = args?.body as string | undefined;
      const followRedirects = args?.followRedirects !== false;

      // Deobfuscate inputs (in case Claude is using already-obfuscated values)
      const url = engine.deobfuscate(rawUrl);
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(rawHeaders)) {
        headers[engine.deobfuscate(k)] = engine.deobfuscate(v);
      }
      const body = rawBody ? engine.deobfuscate(rawBody) : undefined;

      try {
        const fetchOptions: RequestInit = {
          method,
          headers,
          redirect: followRedirects ? 'follow' : 'manual',
        };
        if (body && !['GET', 'HEAD'].includes(method)) {
          fetchOptions.body = body;
        }

        const response = await fetch(url, fetchOptions);
        const responseBody = await response.text();

        // Build raw-ish response representation
        const responseHeaders: string[] = [];
        response.headers.forEach((value, key) => {
          responseHeaders.push(`${key}: ${value}`);
        });

        const rawResponse = [
          `HTTP/${response.status} ${response.statusText}`,
          ...responseHeaders,
          '',
          responseBody,
        ].join('\n');

        // Obfuscate the entire response
        const obfuscatedResponse = engine.obfuscate(rawResponse);

        return { content: [{ type: 'text', text: obfuscatedResponse }] };
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: `Error making request: ${engine.obfuscate(errorMsg)}` }] };
      }
    }

    case 'redact_read_file': {
      const path = args?.path as string;
      if (!path) return { content: [{ type: 'text', text: 'Error: path parameter is required' }] };

      const encoding = (args?.encoding as BufferEncoding) || 'utf-8';

      try {
        const content = await readFile(path, encoding);
        const obfuscated = engine.obfuscate(content);
        return { content: [{ type: 'text', text: obfuscated }] };
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: `Error reading file: ${errorMsg}` }] };
      }
    }

    case 'redact_add_mapping': {
      const real = args?.real as string;
      const fake = args?.fake as string;
      if (!real || !fake) return { content: [{ type: 'text', text: 'Error: real and fake parameters are required' }] };

      const type = (args?.type as MappingType) || 'custom';
      const mapping = engine.addManualMapping(real, fake, type);
      return { content: [{ type: 'text', text: `Mapping added: "${mapping.real}" → "${mapping.fake}" (type: ${mapping.type})` }] };
    }

    case 'redact_remove_mapping': {
      const real = args?.real as string;
      if (!real) return { content: [{ type: 'text', text: 'Error: real parameter is required' }] };

      const removed = engine.removeMapping(real);
      if (removed) {
        return { content: [{ type: 'text', text: `Mapping removed for: "${real}"` }] };
      }
      return { content: [{ type: 'text', text: `No mapping found for: "${real}"` }] };
    }

    case 'redact_show_mappings': {
      const mappings = engine.getMappings();
      if (mappings.length === 0) {
        return { content: [{ type: 'text', text: 'No mappings registered yet.' }] };
      }

      // Group by type
      const grouped = new Map<string, Array<{ real: string; fake: string; source: string }>>();
      for (const m of mappings) {
        const group = grouped.get(m.type) || [];
        group.push({ real: m.real, fake: m.fake, source: m.source });
        grouped.set(m.type, group);
      }

      const lines: string[] = [`## Redaction Mappings (${mappings.length} total)\n`];
      for (const [type, items] of grouped) {
        lines.push(`### ${type} (${items.length})`);
        for (const item of items) {
          const sourceTag = item.source === 'manual' ? ' [manual]' : '';
          lines.push(`  ${item.real} → ${item.fake}${sourceTag}`);
        }
        lines.push('');
      }

      return { content: [{ type: 'text', text: lines.join('\n') }] };
    }

    default:
      return { content: [{ type: 'text', text: `Unknown tool: ${name}` }] };
  }
});

// ─── Start Server ──────────────────────────────────────────────

async function main() {
  await engine.init();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[redact] MCP server started');
}

main().catch((err) => {
  console.error('[redact] Fatal error:', err);
  process.exit(1);
});
