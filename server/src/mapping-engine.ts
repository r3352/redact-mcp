/**
 * Bidirectional mapping engine.
 * Maintains real↔fake mappings, handles obfuscation/deobfuscation
 * with longest-first replacement to prevent partial match corruption.
 */

import { detectPatterns, type PatternType } from './pattern-detector.js';
import { generateFake, type Counters, type MappingType } from './fake-generator.js';
import { Persistence, type PersistedState } from './persistence.js';

export interface Mapping {
  real: string;
  fake: string;
  type: MappingType;
  source: 'auto' | 'manual';
}

export class MappingEngine {
  private mappings: Mapping[] = [];
  private counters: Counters = {};
  private realToFake = new Map<string, Mapping>();
  private fakeToReal = new Map<string, Mapping>();
  private persistence: Persistence;

  constructor(dataDir: string) {
    this.persistence = new Persistence(dataDir);
  }

  async init(): Promise<void> {
    const state = await this.persistence.load();
    this.mappings = state.mappings;
    this.counters = state.counters;
    this.rebuildIndex();
  }

  private rebuildIndex(): void {
    this.realToFake.clear();
    this.fakeToReal.clear();
    for (const m of this.mappings) {
      this.realToFake.set(m.real, m);
      this.fakeToReal.set(m.fake, m);
    }
  }

  private persist(): void {
    this.persistence.save({
      mappings: this.mappings,
      counters: this.counters,
      lastModified: new Date().toISOString(),
    });
  }

  /**
   * Get or create a fake value for a real value.
   */
  private getOrCreateMapping(real: string, type: PatternType, source: 'auto' | 'manual' = 'auto'): Mapping {
    const existing = this.realToFake.get(real);
    if (existing) return existing;

    const fake = generateFake(type, this.counters);
    const mapping: Mapping = { real, fake, type, source };
    this.mappings.push(mapping);
    this.realToFake.set(real, mapping);
    this.fakeToReal.set(fake, mapping);
    this.persist();
    return mapping;
  }

  /**
   * Obfuscate text by detecting and replacing all sensitive patterns.
   */
  obfuscate(text: string): string {
    // 1. Detect patterns
    const matches = detectPatterns(text);

    // 2. Ensure mappings exist for each match
    for (const match of matches) {
      this.getOrCreateMapping(match.value, match.type, 'auto');
    }

    // 3. Sort all mappings by real value length descending (longest first)
    //    This prevents partial match corruption, e.g., 10.50.1.100 before 10.50.1.1
    const sortedMappings = [...this.realToFake.values()]
      .sort((a, b) => b.real.length - a.real.length);

    // 4. Apply replacements
    let result = text;
    for (const mapping of sortedMappings) {
      if (result.includes(mapping.real)) {
        result = result.split(mapping.real).join(mapping.fake);
      }
    }

    return result;
  }

  /**
   * Deobfuscate text by reversing all fake values back to real values.
   */
  deobfuscate(text: string): string {
    // Sort by fake value length descending
    const sortedMappings = [...this.fakeToReal.values()]
      .sort((a, b) => b.fake.length - a.fake.length);

    let result = text;
    for (const mapping of sortedMappings) {
      if (result.includes(mapping.fake)) {
        result = result.split(mapping.fake).join(mapping.real);
      }
    }

    return result;
  }

  /**
   * Manually add a real→fake mapping.
   */
  addManualMapping(real: string, fake: string, type: MappingType = 'custom'): Mapping {
    // Check if already mapped
    const existing = this.realToFake.get(real);
    if (existing) {
      // Update the fake value
      this.fakeToReal.delete(existing.fake);
      existing.fake = fake;
      existing.source = 'manual';
      this.fakeToReal.set(fake, existing);
      this.persist();
      return existing;
    }

    const mapping: Mapping = { real, fake, type, source: 'manual' };
    this.mappings.push(mapping);
    this.realToFake.set(real, mapping);
    this.fakeToReal.set(fake, mapping);
    this.persist();
    return mapping;
  }

  /**
   * Remove a mapping by its real value.
   */
  removeMapping(real: string): boolean {
    const mapping = this.realToFake.get(real);
    if (!mapping) return false;

    this.mappings = this.mappings.filter(m => m.real !== real);
    this.realToFake.delete(real);
    this.fakeToReal.delete(mapping.fake);
    this.persist();
    return true;
  }

  /**
   * Get all current mappings.
   */
  getMappings(): Mapping[] {
    return [...this.mappings];
  }

  /**
   * Get all known real values (for leak detection in hooks).
   */
  getRealValues(): string[] {
    return this.mappings.map(m => m.real);
  }

  /**
   * Flush pending writes to disk.
   */
  async flush(): Promise<void> {
    await this.persistence.flush();
  }
}
