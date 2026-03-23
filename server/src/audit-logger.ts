/**
 * JSONL audit logger for redaction operations.
 * Opt-in via REDACT_AUDIT_LOG=true environment variable.
 * Writes to ${REDACT_DATA_DIR}/audit.jsonl.
 */

import { appendFile, readFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

export interface AuditDetection {
  type: string;
  value: string;
  fake: string;
  source: 'regex' | 'ner' | 'manual';
}

export interface AuditEntry {
  timestamp: string;
  operation: string;
  inputLength: number;
  inputText: string;
  detections: AuditDetection[];
  outputLength: number;
  outputText: string;
}

export class AuditLogger {
  private filePath: string;
  private enabled: boolean;
  private writeQueue: Promise<void> = Promise.resolve();
  private dirEnsured = false;

  constructor(dataDir: string) {
    this.filePath = `${dataDir}/audit.jsonl`;
    this.enabled = process.env.REDACT_AUDIT_LOG === 'true';
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Log an audit entry. Fire-and-forget — errors are swallowed to avoid
   * slowing the obfuscation pipeline.
   */
  log(entry: AuditEntry): void {
    if (!this.enabled) return;

    // Serialize writes to prevent interleaving
    this.writeQueue = this.writeQueue.then(async () => {
      try {
        if (!this.dirEnsured) {
          await mkdir(dirname(this.filePath), { recursive: true });
          this.dirEnsured = true;
        }
        const line = JSON.stringify(entry) + '\n';
        await appendFile(this.filePath, line, 'utf-8');
      } catch (err) {
        console.error(`[redact] Audit log write failed: ${err}`);
      }
    });
  }

  /**
   * Read the last N entries from the audit log.
   */
  async getRecentEntries(count: number): Promise<AuditEntry[]> {
    if (!this.enabled) {
      return [];
    }

    try {
      const content = await readFile(this.filePath, 'utf-8');
      const lines = content.trim().split('\n').filter(l => l.length > 0);
      const recent = lines.slice(-count);
      return recent.map(line => JSON.parse(line) as AuditEntry);
    } catch {
      return [];
    }
  }

  /**
   * Wait for all pending writes to complete.
   */
  async flush(): Promise<void> {
    await this.writeQueue;
  }
}
