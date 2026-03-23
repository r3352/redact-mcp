/**
 * Persistence layer for mapping state.
 * Saves/loads mappings and counters to a JSON file.
 * Debounces writes to avoid excessive disk I/O.
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { Mapping } from './mapping-engine.js';
import type { Counters } from './fake-generator.js';

export interface PersistedState {
  mappings: Mapping[];
  counters: Counters;
  lastModified: string;
}

export class Persistence {
  private filePath: string;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private pendingState: PersistedState | null = null;

  constructor(dataDir: string) {
    this.filePath = `${dataDir}/mappings.json`;
  }

  async load(): Promise<PersistedState> {
    try {
      const raw = await readFile(this.filePath, 'utf-8');
      return JSON.parse(raw) as PersistedState;
    } catch {
      return { mappings: [], counters: {}, lastModified: new Date().toISOString() };
    }
  }

  save(state: PersistedState): void {
    this.pendingState = { ...state, lastModified: new Date().toISOString() };

    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }

    this.debounceTimer = setTimeout(() => {
      this.flush();
    }, 500);
  }

  async flush(): Promise<void> {
    if (!this.pendingState) return;

    const state = this.pendingState;
    this.pendingState = null;

    try {
      await mkdir(dirname(this.filePath), { recursive: true });
      await writeFile(this.filePath, JSON.stringify(state, null, 2), 'utf-8');
    } catch (err) {
      console.error(`[redact] Failed to save mappings: ${err}`);
    }
  }
}
