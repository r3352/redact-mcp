/**
 * Regex-based auto-detection of sensitive data patterns.
 * Returns match positions and types for the mapping engine.
 */

export type PatternType =
  | 'hostname'
  | 'ipv4'
  | 'ipv6'
  | 'email'
  | 'person_name'
  | 'phone'
  | 'ssn'
  | 'credit_card'
  | 'api_key'
  | 'jwt'
  | 'bearer'
  | 'aws_key';

export interface PatternMatch {
  value: string;
  type: PatternType;
  index: number;
}

// Never obfuscate these values
const PASSTHROUGH_EXACT = new Set([
  'localhost',
  '127.0.0.1',
  '::1',
  '0.0.0.0',
  'example.com',
  'example.org',
  'example.net',
  'test.com',
  'test.net',
  'test.org',
  'invalid',
  'localhost.localdomain',
]);

const PASSTHROUGH_DOMAINS = new Set([
  'example.com',
  'example.org',
  'example.net',
  'github.com',
  'stackoverflow.com',
  'npmjs.com',
  'npmjs.org',
  'nodejs.org',
  'typescriptlang.org',
  'mozilla.org',
  'w3.org',
  'google.com',
  'googleapis.com',
  'cloudflare.com',
  'burpcollaborator.net',
  'oastify.com',
]);

// RFC 5737 documentation ranges + loopback
const PASSTHROUGH_IP_PREFIXES = [
  '192.0.2.',     // TEST-NET-1
  '198.51.100.',  // TEST-NET-2 (we use this for fakes)
  '203.0.113.',   // TEST-NET-3
  '127.',         // loopback
];

const PASSTHROUGH_IPV6_PREFIXES = [
  '2001:db8:',    // RFC 3849 documentation
];

// Common false-positive "hostnames" that are actually code/filenames
const HOSTNAME_FALSE_POSITIVES = new Set([
  'package.json',
  'tsconfig.json',
  'node_modules',
  'console.log',
  'console.error',
  'console.warn',
  'console.info',
  'console.debug',
  'process.env',
  'process.exit',
  'module.exports',
  'require.resolve',
  'path.join',
  'path.resolve',
  'fs.readFileSync',
  'fs.writeFileSync',
  'JSON.parse',
  'JSON.stringify',
  'Object.keys',
  'Object.assign',
  'Array.from',
  'Promise.all',
  'Promise.resolve',
  'Buffer.from',
  'Date.now',
  'Math.random',
  'Math.floor',
  'Math.ceil',
  'Error.captureStackTrace',
  'Symbol.iterator',
  'RegExp.prototype',
  'String.prototype',
  'Number.parseInt',
  'Number.parseFloat',
  'content.length',
  'response.status',
  'request.url',
  'headers.set',
  'headers.get',
  'text.split',
  'text.replace',
  'text.match',
  'e.g',
  'i.e',
  'vs.code',
]);

// Valid TLDs for hostname detection (common ones)
const VALID_TLDS = new Set([
  'com', 'org', 'net', 'io', 'dev', 'app', 'co', 'us', 'uk', 'de', 'fr',
  'jp', 'cn', 'ru', 'br', 'in', 'au', 'ca', 'eu', 'gov', 'edu', 'mil',
  'int', 'info', 'biz', 'name', 'pro', 'museum', 'coop', 'aero', 'xyz',
  'online', 'site', 'tech', 'store', 'cloud', 'ai', 'me', 'tv', 'cc',
  'ly', 'to', 'sh', 'is', 'it', 'nl', 'be', 'at', 'ch', 'se', 'no',
  'fi', 'dk', 'pl', 'cz', 'sk', 'hu', 'ro', 'bg', 'hr', 'si', 'rs',
  'ua', 'lt', 'lv', 'ee', 'pt', 'es', 'ie', 'gr', 'tr', 'za', 'mx',
  'ar', 'cl', 'pe', 've', 'ec', 'uy', 'py', 'bo', 'cr', 'pa', 'do',
  'gt', 'hn', 'sv', 'ni', 'cu', 'jm', 'tt', 'bb', 'bs', 'ky', 'bm',
  'internal', 'local', 'corp', 'lan', 'home', 'test',
]);

function isPassthroughIP(ip: string): boolean {
  return PASSTHROUGH_IP_PREFIXES.some(prefix => ip.startsWith(prefix));
}

function isPassthroughIPv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  return lower === '::1' || PASSTHROUGH_IPV6_PREFIXES.some(prefix => lower.startsWith(prefix));
}

function isPassthroughHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (PASSTHROUGH_EXACT.has(lower)) return true;
  if (HOSTNAME_FALSE_POSITIVES.has(lower)) return true;
  // Check if it ends with a passthrough domain
  for (const domain of PASSTHROUGH_DOMAINS) {
    if (lower === domain || lower.endsWith('.' + domain)) return true;
  }
  return false;
}

function luhnCheck(num: string): boolean {
  const digits = num.replace(/\D/g, '');
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

// Pattern definitions with regexes
const PATTERNS: Array<{ type: PatternType; regex: RegExp; validate?: (match: string) => boolean }> = [
  // AWS Access Key IDs
  {
    type: 'aws_key',
    regex: /AKIA[0-9A-Z]{16,}/g,
  },
  // JWT tokens (3 base64url segments)
  {
    type: 'jwt',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  },
  // Bearer tokens
  {
    type: 'bearer',
    regex: /Bearer\s+[A-Za-z0-9_\-.~+/]{20,}/g,
  },
  // SSN
  {
    type: 'ssn',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  // Credit card (16 digits with optional separators)
  {
    type: 'credit_card',
    regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    validate: (match: string) => luhnCheck(match),
  },
  // IPv6 (full and compressed)
  {
    type: 'ipv6',
    regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b::(?:[fF]{4}:)?(?:\d{1,3}\.){3}\d{1,3}\b/g,
    validate: (match: string) => !isPassthroughIPv6(match),
  },
  // Email
  {
    type: 'email',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    validate: (match: string) => {
      const domain = match.split('@')[1].toLowerCase();
      return domain !== 'example.com' && domain !== 'example.org' && domain !== 'example.net';
    },
  },
  // Phone (US formats)
  {
    type: 'phone',
    regex: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    validate: (match: string) => {
      const digits = match.replace(/\D/g, '');
      // Must have 10 or 11 digits, not start with 555 area code (test numbers)
      return (digits.length === 10 || digits.length === 11) && !digits.startsWith('555') && !(digits.length === 11 && digits.startsWith('1555'));
    },
  },
  // IPv4
  {
    type: 'ipv4',
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g,
    validate: (match: string) => {
      if (isPassthroughIP(match)) return false;
      if (match === '0.0.0.0' || match === '255.255.255.255') return false;
      // Skip common version-like patterns (e.g., 1.0.0, 2.1.0)
      const parts = match.split('.').map(Number);
      if (parts[2] === 0 && parts[3] === 0) return false; // likely a version like x.y.0.0
      return true;
    },
  },
  // Hostname (word.word.tld)
  {
    type: 'hostname',
    regex: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g,
    validate: (match: string) => {
      if (isPassthroughHostname(match)) return false;
      // Must have a valid TLD
      const parts = match.split('.');
      const tld = parts[parts.length - 1].toLowerCase();
      if (!VALID_TLDS.has(tld)) return false;
      // Skip if looks like a file extension pattern (e.g., file.js, file.ts)
      if (parts.length === 2 && parts[1].length <= 4 && /^[a-z]+$/.test(parts[1])) {
        const codeExtensions = new Set(['js', 'ts', 'py', 'rb', 'go', 'rs', 'md', 'sh', 'yml', 'yaml', 'xml', 'css', 'html', 'jsx', 'tsx', 'vue', 'svelte', 'json', 'toml', 'ini', 'cfg', 'conf', 'log', 'txt', 'csv', 'sql', 'env', 'lock', 'map']);
        if (codeExtensions.has(parts[1].toLowerCase())) return false;
      }
      return true;
    },
  },
  // API keys (long alphanumeric near context keywords)
  {
    type: 'api_key',
    regex: /(?:api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret)["'\s:=]+([A-Za-z0-9_\-./+]{20,})/gi,
  },
  // Person names in JSON context: "name": "First Last"
  {
    type: 'person_name',
    regex: /(?:"(?:name|full_?name|first_?name|last_?name|customer|owner|author|user(?:name)?|contact|employee|manager|admin|recipient|sender)"\s*:\s*")([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)"/g,
  },
];

export function detectPatterns(text: string): PatternMatch[] {
  const matches: PatternMatch[] = [];
  const seen = new Set<string>(); // avoid duplicate matches at same position

  for (const pattern of PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      // For patterns with capture groups (api_key, person_name), use group 1
      const value = match[1] ?? match[0];
      const index = match[1] ? match.index + match[0].indexOf(match[1]) : match.index;

      const key = `${value}@${index}`;
      if (seen.has(key)) continue;

      if (pattern.validate && !pattern.validate(value)) continue;

      seen.add(key);
      matches.push({ value, type: pattern.type, index });
    }
  }

  return matches;
}
