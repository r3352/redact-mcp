/**
 * Generates context-appropriate fake replacement values.
 * Uses deterministic counters per type to ensure uniqueness.
 */

import type { PatternType } from './pattern-detector.js';

export type MappingType = PatternType | 'custom';

export interface Counters {
  [key: string]: number;
}

export function generateFake(type: MappingType, counters: Counters): string {
  const key = type;
  const n = (counters[key] ?? 0) + 1;
  counters[key] = n;

  switch (type) {
    case 'ipv4':
      // Use TEST-NET-2 range: 198.51.100.0/24
      // Wrap around if >254
      return `198.51.100.${((n - 1) % 254) + 1}`;

    case 'ipv6':
      // Use RFC 3849 documentation prefix
      return `2001:db8::${n}`;

    case 'hostname':
      return `target-${n}.example.com`;

    case 'email':
      return `user-${n}@example.com`;

    case 'person_name': {
      // Generate letter-based names: Person_A, Person_B, ... Person_Z, Person_AA, ...
      let label = '';
      let remaining = n;
      while (remaining > 0) {
        remaining--;
        label = String.fromCharCode(65 + (remaining % 26)) + label;
        remaining = Math.floor(remaining / 26);
      }
      return `Person_${label}`;
    }

    case 'phone':
      // Use 555 prefix (reserved for fictional use)
      return `(555) 555-${String(n).padStart(4, '0')}`;

    case 'ssn':
      return `[REDACTED_SSN_${n}]`;

    case 'credit_card':
      return `[REDACTED_CC_${n}]`;

    case 'api_key':
      return `[REDACTED_KEY_${n}]`;

    case 'jwt':
      return `[REDACTED_JWT_${n}]`;

    case 'bearer':
      return `Bearer [REDACTED_TOKEN_${n}]`;

    case 'aws_key':
      return `[REDACTED_AWS_KEY_${n}]`;

    case 'organization': {
      let label = '';
      let remaining = n;
      while (remaining > 0) {
        remaining--;
        label = String.fromCharCode(65 + (remaining % 26)) + label;
        remaining = Math.floor(remaining / 26);
      }
      return `Org_${label}`;
    }

    case 'location': {
      let label = '';
      let remaining = n;
      while (remaining > 0) {
        remaining--;
        label = String.fromCharCode(65 + (remaining % 26)) + label;
        remaining = Math.floor(remaining / 26);
      }
      return `City_${label}`;
    }

    case 'private_key':
      return `[REDACTED_PRIVATE_KEY_${n}]`;

    case 'connection_string':
      return `[REDACTED_CONN_STRING_${n}]`;

    case 'generic_secret':
      return `[REDACTED_SECRET_${n}]`;

    case 'mac_address':
      return `02:00:00:00:00:${String(n).padStart(2, '0')}`;

    case 'street_address':
      return `${n} Redacted Street`;

    case 'custom':
      return `[REDACTED_CUSTOM_${n}]`;

    default:
      return `[REDACTED_${n}]`;
  }
}
