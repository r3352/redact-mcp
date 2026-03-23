#!/usr/bin/env node
/**
 * Redact MCP v2 — End-to-End Test Suite
 * Spawns the server as a child process and sends MCP JSON-RPC messages.
 */

import { spawn } from 'node:child_process';
import { readFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const DATA_DIR = join(tmpdir(), `redact-test-${Date.now()}`);
let passed = 0;
let failed = 0;
const failures = [];

function assert(condition, name, detail) {
  if (condition) {
    console.log(`  ✓ ${name}`);
    passed++;
  } else {
    console.log(`  ✗ ${name}`);
    if (detail) console.log(`    ${detail}`);
    failed++;
    failures.push(name);
  }
}

async function callServer(messages, env = {}) {
  return new Promise((resolve, reject) => {
    const proc = spawn('node', ['dist/index.js'], {
      cwd: new URL('.', import.meta.url).pathname,
      env: { ...process.env, REDACT_DATA_DIR: DATA_DIR, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', d => stdout += d);
    proc.stderr.on('data', d => stderr += d);

    // Send all messages
    const init = { jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '1.0' } } };
    const notif = { jsonrpc: '2.0', method: 'notifications/initialized', params: {} };
    proc.stdin.write(JSON.stringify(init) + '\n');
    proc.stdin.write(JSON.stringify(notif) + '\n');

    let id = 1;
    for (const msg of messages) {
      proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: id++, ...msg }) + '\n');
    }

    setTimeout(() => {
      proc.kill();
    }, 15000);

    proc.on('close', () => {
      const responses = stdout.trim().split('\n').filter(l => l.startsWith('{')).map(l => {
        try { return JSON.parse(l); } catch { return null; }
      }).filter(Boolean);
      resolve({ responses, stderr });
    });
  });
}

function getToolResult(responses, id) {
  const resp = responses.find(r => r.id === id);
  return resp?.result?.content?.[0]?.text ?? '';
}

// ──────────────────────────────────────────────────────────────
// Test Groups
// ──────────────────────────────────────────────────────────────

async function testServerStartup() {
  console.log('\n── Server Startup ──');
  const { responses, stderr } = await callServer([
    { method: 'tools/list', params: {} },
  ]);

  const initResp = responses.find(r => r.id === 0);
  assert(initResp?.result?.serverInfo?.version === '2.0.0', 'Server version is 2.0.0');
  assert(initResp?.result?.serverInfo?.name === 'redact-server', 'Server name is redact-server');

  const toolsResp = responses.find(r => r.id === 1);
  const toolNames = (toolsResp?.result?.tools || []).map(t => t.name);
  assert(toolNames.length === 8, `Lists 8 tools (got ${toolNames.length})`);
  assert(toolNames.includes('redact_audit_log'), 'Includes redact_audit_log tool');
  assert(stderr.includes('MCP server v2 started'), 'Startup log message present');

  const instructions = initResp?.result?.instructions || '';
  assert(instructions.includes('NER'), 'Instructions mention NER detection');
  assert(instructions.includes('REDACT_AUDIT_LOG'), 'Instructions mention audit logging');
}

async function testIPv4Obfuscation() {
  console.log('\n── IPv4 Obfuscation ──');
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'Server at 10.50.1.100 and 172.16.0.5' } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(!result.includes('10.50.1.100'), 'Real IP 10.50.1.100 removed');
  assert(!result.includes('172.16.0.5'), 'Real IP 172.16.0.5 removed');
  assert(result.includes('198.51.100.'), 'Replaced with TEST-NET-2 range');
}

async function testIPv4Passthrough() {
  console.log('\n── IPv4 Passthrough ──');
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'localhost at 127.0.0.1 and docs 192.0.2.1 and 198.51.100.5' } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(result.includes('127.0.0.1'), '127.0.0.1 preserved (loopback)');
  assert(result.includes('192.0.2.1'), '192.0.2.1 preserved (TEST-NET-1)');
  assert(result.includes('198.51.100.5'), '198.51.100.5 preserved (TEST-NET-2)');
}

async function testEmailObfuscation() {
  console.log('\n── Email Obfuscation ──');
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'Contact john.doe@acmecorp.com and admin@internal.io' } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(!result.includes('john.doe@acmecorp.com'), 'Real email removed');
  assert(!result.includes('admin@internal.io'), 'Second email removed');
  assert(result.includes('@example.com'), 'Replaced with @example.com');
}

async function testHostnameObfuscation() {
  console.log('\n── Hostname Obfuscation ──');
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'API at api.clientcorp.com and db.internal.net' } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(!result.includes('clientcorp.com'), 'Real hostname removed');
  assert(!result.includes('internal.net'), 'Second hostname removed');
  assert(result.includes('example.com'), 'Replaced with example.com domain');
}

async function testHostnamePassthrough() {
  console.log('\n── Hostname Passthrough ──');
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'Use github.com and console.log and webpack.config and example.com' } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(result.includes('github.com'), 'github.com preserved');
  assert(result.includes('console.log'), 'console.log preserved');
  assert(result.includes('webpack.config'), 'webpack.config preserved');
  assert(result.includes('example.com'), 'example.com preserved');
}

async function testJWTObfuscation() {
  console.log('\n── JWT Obfuscation ──');
  const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: `Token: ${jwt}` } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(!result.includes('eyJhbGci'), 'JWT removed');
  assert(result.includes('[REDACTED_JWT_'), 'Replaced with REDACTED_JWT');
}

async function testAWSKeyObfuscation() {
  console.log('\n── AWS Key Obfuscation ──');
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'Key: AKIAIOSFODNN7EXAMPLE1' } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(!result.includes('AKIAIOSFODNN7EXAMPLE1'), 'AWS key removed');
  assert(result.includes('[REDACTED_AWS_KEY_'), 'Replaced with REDACTED_AWS_KEY');
}

async function testSSNObfuscation() {
  console.log('\n── SSN Obfuscation ──');
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'SSN: 123-45-6789' } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(!result.includes('123-45-6789'), 'SSN removed');
  assert(result.includes('[REDACTED_SSN_'), 'Replaced with REDACTED_SSN');
}

async function testPrivateKeyObfuscation() {
  console.log('\n── Private Key Obfuscation (v2) ──');
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAH\n-----END RSA PRIVATE KEY-----';
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: `Key:\n${pem}` } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(!result.includes('BEGIN RSA PRIVATE KEY'), 'PEM block removed');
  assert(result.includes('[REDACTED_PRIVATE_KEY_'), 'Replaced with REDACTED_PRIVATE_KEY');
}

async function testConnectionStringObfuscation() {
  console.log('\n── Connection String Obfuscation (v2) ──');
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'DB: postgres://admin:s3cret@db.prod.internal:5432/myapp' } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(!result.includes('postgres://'), 'Connection string removed');
  assert(result.includes('[REDACTED_CONN_STRING_'), 'Replaced with REDACTED_CONN_STRING');
}

async function testGenericSecretObfuscation() {
  console.log('\n── Generic Secret Obfuscation (v2) ──');
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'password=SuperSecret123 and secret: MyTopSecret99' } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(!result.includes('SuperSecret123'), 'Password value removed');
  assert(!result.includes('MyTopSecret99'), 'Secret value removed');
  assert(result.includes('[REDACTED_SECRET_'), 'Replaced with REDACTED_SECRET');
}

async function testMACAddressObfuscation() {
  console.log('\n── MAC Address Obfuscation (v2) ──');
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'NIC: AA:BB:CC:DD:EE:FF and broadcast FF:FF:FF:FF:FF:FF' } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(!result.includes('AA:BB:CC:DD:EE:FF'), 'Real MAC removed');
  assert(result.includes('02:00:00:00:00:'), 'Replaced with locally-administered MAC');
  assert(result.includes('FF:FF:FF:FF:FF:FF'), 'Broadcast MAC preserved');
}

async function testStreetAddressObfuscation() {
  console.log('\n── Street Address Obfuscation (v2) ──');
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'Office at 1234 Oak Tree Boulevard' } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(!result.includes('1234 Oak Tree Boulevard'), 'Street address removed');
  assert(result.includes('Redacted Street'), 'Replaced with Redacted Street');
}

async function testNERDetection() {
  console.log('\n── NER Entity Detection (v2) ──');
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'I met James Wilson from Microsoft in Seattle last week.' } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(!result.includes('James'), 'Person name "James" removed by NER');
  assert(!result.includes('Wilson'), 'Person name "Wilson" removed by NER');
  assert(!result.includes('Microsoft'), 'Organization "Microsoft" removed by NER');
  assert(!result.includes('Seattle'), 'Location "Seattle" removed by NER');
  assert(result.includes('Person_'), 'Person replaced with Person_X');
  assert(result.includes('Org_'), 'Organization replaced with Org_X');
  assert(result.includes('City_'), 'Location replaced with City_X');
}

async function testDeobfuscateRoundTrip() {
  console.log('\n── Deobfuscate Round-Trip ──');
  const original = 'Email admin@clientcorp.com at 10.99.1.50';
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: original } } },
  ]);
  const obfuscated = getToolResult(responses, 1);
  assert(!obfuscated.includes('clientcorp.com'), 'Obfuscation works');

  // Second call to deobfuscate (fresh server, but same data dir = same mappings)
  const { responses: r2 } = await callServer([
    { method: 'tools/call', params: { name: 'redact_deobfuscate', arguments: { text: obfuscated } } },
  ]);
  const restored = getToolResult(r2, 1);
  assert(restored === original, `Round-trip preserves original text`,
    `Expected: "${original}"\nGot:      "${restored}"`);
}

async function testManualMapping() {
  console.log('\n── Manual Mapping ──');
  // Step 1: Add mapping, obfuscate, and show (no remove yet — remove is sync
  // and would race with the async obfuscate via concurrent MCP dispatch)
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_add_mapping', arguments: { real: 'PROJ-FALCON', fake: 'PROJ-REDACTED', type: 'custom' } } },
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'Working on PROJ-FALCON today' } } },
    { method: 'tools/call', params: { name: 'redact_show_mappings', arguments: {} } },
  ]);
  const addResult = getToolResult(responses, 1);
  assert(addResult.includes('Mapping added'), 'Manual mapping added');

  const obfResult = getToolResult(responses, 2);
  assert(obfResult.includes('PROJ-REDACTED'), 'Manual mapping applied during obfuscation');
  assert(!obfResult.includes('PROJ-FALCON'), 'Real value replaced');

  const showResult = getToolResult(responses, 3);
  assert(showResult.includes('PROJ-FALCON') && showResult.includes('PROJ-REDACTED'), 'Show mappings displays manual entry');

  // Step 2: Remove in a separate server session (loads persisted mappings)
  const { responses: r2 } = await callServer([
    { method: 'tools/call', params: { name: 'redact_remove_mapping', arguments: { real: 'PROJ-FALCON' } } },
  ]);
  const removeResult = getToolResult(r2, 1);
  assert(removeResult.includes('Mapping removed'), 'Manual mapping removed');
}

async function testAuditLogDisabled() {
  console.log('\n── Audit Log (disabled) ──');
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_audit_log', arguments: { count: 5 } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(result.includes('disabled'), 'Audit log reports disabled when env var not set');
}

async function testAuditLogEnabled() {
  console.log('\n── Audit Log (enabled, v2) ──');
  const auditDir = join(tmpdir(), `redact-audit-test-${Date.now()}`);
  await mkdir(auditDir, { recursive: true });

  // First: obfuscate something with audit on
  await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'Email test@corp.com from 10.0.0.5' } } },
  ], { REDACT_AUDIT_LOG: 'true', REDACT_DATA_DIR: auditDir });

  // Small delay for fire-and-forget write
  await new Promise(r => setTimeout(r, 1000));

  // Read the JSONL file directly
  let auditContent = '';
  try {
    auditContent = await readFile(join(auditDir, 'audit.jsonl'), 'utf-8');
  } catch { /* may not exist yet */ }

  assert(auditContent.length > 0, 'Audit JSONL file was written');

  if (auditContent.length > 0) {
    const entry = JSON.parse(auditContent.trim().split('\n')[0]);
    assert(entry.timestamp !== undefined, 'Audit entry has timestamp');
    assert(entry.operation === 'obfuscate', 'Audit entry has operation=obfuscate');
    assert(entry.inputText !== undefined, 'Audit entry has inputText (full input logged)');
    assert(entry.outputText !== undefined, 'Audit entry has outputText (full output logged)');
    assert(entry.inputText.includes('test@corp.com'), 'inputText contains real data');
    assert(!entry.outputText.includes('test@corp.com'), 'outputText has obfuscated data');
    assert(entry.detections.length > 0, 'Audit entry has detections array');
    assert(entry.detections.some(d => d.source === 'regex'), 'Detections include source field');
    assert(entry.detections.some(d => d.type === 'email'), 'Detections include email type');
  }

  // Now test the audit tool reads them back
  const { responses: r2 } = await callServer([
    { method: 'tools/call', params: { name: 'redact_audit_log', arguments: { count: 5 } } },
  ], { REDACT_AUDIT_LOG: 'true', REDACT_DATA_DIR: auditDir });
  const toolResult = getToolResult(r2, 1);
  assert(toolResult.includes('Audit Log'), 'redact_audit_log tool returns formatted entries');
  assert(toolResult.includes('obfuscate'), 'Audit tool output shows operation type');

  await rm(auditDir, { recursive: true, force: true });
}

async function testDeobfuscateAuditLogged() {
  console.log('\n── Deobfuscate Audit Logging (v2) ──');
  const auditDir = join(tmpdir(), `redact-deobf-audit-${Date.now()}`);
  await mkdir(auditDir, { recursive: true });

  // Obfuscate first to create mappings
  await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'User alice@test.corp at 10.1.2.3' } } },
  ], { REDACT_AUDIT_LOG: 'true', REDACT_DATA_DIR: auditDir });

  await new Promise(r => setTimeout(r, 500));

  // Now deobfuscate
  await callServer([
    { method: 'tools/call', params: { name: 'redact_deobfuscate', arguments: { text: 'User user-1@example.com at 198.51.100.1' } } },
  ], { REDACT_AUDIT_LOG: 'true', REDACT_DATA_DIR: auditDir });

  await new Promise(r => setTimeout(r, 1000));

  let auditContent = '';
  try {
    auditContent = await readFile(join(auditDir, 'audit.jsonl'), 'utf-8');
  } catch { /* */ }

  const lines = auditContent.trim().split('\n').filter(l => l.length > 0);
  const deobfEntry = lines.map(l => JSON.parse(l)).find(e => e.operation === 'deobfuscate');

  assert(deobfEntry !== undefined, 'Deobfuscation operation is audit logged');
  if (deobfEntry) {
    assert(deobfEntry.inputText !== undefined, 'Deobf audit has inputText');
    assert(deobfEntry.outputText !== undefined, 'Deobf audit has outputText');
    assert(deobfEntry.detections.length > 0, 'Deobf audit has restorations logged');
  }

  await rm(auditDir, { recursive: true, force: true });
}

async function testAPIKeyObfuscation() {
  console.log('\n── API Key Obfuscation ──');
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: 'api_key: sk_live_abcdefghij1234567890xyz' } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(!result.includes('sk_live_abcdefghij1234567890xyz'), 'API key value removed');
  assert(result.includes('[REDACTED_KEY_'), 'Replaced with REDACTED_KEY');
}

async function testPersonNameInJSON() {
  console.log('\n── Person Name in JSON Context ──');
  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: '{"name": "John Smith", "email": "john@corp.com"}' } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(!result.includes('John Smith'), 'JSON person name removed');
  assert(result.includes('Person_'), 'Replaced with Person_X');
}

async function testMixedContent() {
  console.log('\n── Mixed Content (all types) ──');
  const input = [
    'Server: 10.20.30.40',
    'Host: api.secret-client.com',
    'User: admin@secret-client.com',
    'Key: AKIAIOSFODNN7EXAMPLE2',
    'DB: mysql://root:pass123@db.secret-client.com:3306/prod',
    'MAC: DE:AD:BE:EF:CA:FE',
    'Office: 500 Corporate Drive',
    'password=hunter2hunter2',
    'SSN: 987-65-4321',
  ].join('\n');

  const { responses } = await callServer([
    { method: 'tools/call', params: { name: 'redact_obfuscate', arguments: { text: input } } },
  ]);
  const result = getToolResult(responses, 1);
  assert(!result.includes('10.20.30.40'), 'IPv4 redacted');
  assert(!result.includes('secret-client.com'), 'Hostname redacted');
  assert(!result.includes('admin@'), 'Email redacted');
  assert(!result.includes('AKIAIOSFODNN7EXAMPLE2'), 'AWS key redacted');
  assert(!result.includes('mysql://'), 'Connection string redacted');
  assert(!result.includes('DE:AD:BE:EF:CA:FE'), 'MAC redacted');
  assert(!result.includes('500 Corporate Drive'), 'Street address redacted');
  assert(!result.includes('hunter2hunter2'), 'Password redacted');
  assert(!result.includes('987-65-4321'), 'SSN redacted');
}

// ──────────────────────────────────────────────────────────────
// Run all tests
// ──────────────────────────────────────────────────────────────

async function main() {
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║   Redact MCP v2 — End-to-End Test Suite     ║');
  console.log('╚══════════════════════════════════════════════╝');
  console.log(`Data dir: ${DATA_DIR}`);

  await mkdir(DATA_DIR, { recursive: true });

  await testServerStartup();
  await testIPv4Obfuscation();
  await testIPv4Passthrough();
  await testEmailObfuscation();
  await testHostnameObfuscation();
  await testHostnamePassthrough();
  await testJWTObfuscation();
  await testAWSKeyObfuscation();
  await testSSNObfuscation();
  await testAPIKeyObfuscation();
  await testPersonNameInJSON();
  await testPrivateKeyObfuscation();
  await testConnectionStringObfuscation();
  await testGenericSecretObfuscation();
  await testMACAddressObfuscation();
  await testStreetAddressObfuscation();
  await testNERDetection();
  await testDeobfuscateRoundTrip();
  await testManualMapping();
  await testMixedContent();
  await testAuditLogDisabled();
  await testAuditLogEnabled();
  await testDeobfuscateAuditLogged();

  // Cleanup
  await rm(DATA_DIR, { recursive: true, force: true });

  console.log('\n══════════════════════════════════════════════');
  console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
  if (failures.length > 0) {
    console.log('\nFailed tests:');
    for (const f of failures) console.log(`  ✗ ${f}`);
  }
  console.log('══════════════════════════════════════════════');

  process.exit(failed > 0 ? 1 : 0);
}

main();
