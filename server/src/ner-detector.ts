/**
 * NER (Named Entity Recognition) detector using @huggingface/transformers.
 * Lazy-loads the model on first use. Falls back gracefully if package
 * is missing or model download fails.
 */

import type { PatternMatch, PatternType } from './pattern-detector.js';

// Maps HuggingFace NER entity groups to our PatternType
const ENTITY_MAP: Record<string, PatternType> = {
  PER: 'person_name',
  ORG: 'organization',
  LOC: 'location',
};

// Minimum confidence threshold for NER results
const DEFAULT_THRESHOLD = 0.85;

// Minimum entity length (skip single-char detections)
const MIN_ENTITY_LENGTH = 2;

let classifierPromise: Promise<any> | null = null;
let classifierFailed = false;

/**
 * Lazy-load the NER pipeline. Shares a single promise so concurrent
 * callers don't trigger multiple model loads.
 */
async function getClassifier(): Promise<any> {
  if (classifierFailed) return null;

  if (!classifierPromise) {
    classifierPromise = (async () => {
      try {
        const { pipeline } = await import('@huggingface/transformers');
        const classifier = await pipeline(
          'token-classification',
          'Xenova/bert-base-NER',
          { dtype: 'fp32' },
        );
        console.error('[redact] NER model loaded successfully');
        return classifier;
      } catch (err) {
        classifierFailed = true;
        classifierPromise = null;
        console.error(`[redact] NER model failed to load, falling back to regex-only: ${err}`);
        return null;
      }
    })();
  }

  return classifierPromise;
}

/**
 * Detect named entities using the NER model.
 * Returns PatternMatch[] compatible with the regex detector output.
 */
export async function detectNEREntities(
  text: string,
  threshold: number = DEFAULT_THRESHOLD,
): Promise<PatternMatch[]> {
  const classifier = await getClassifier();
  if (!classifier) return [];

  try {
    const results = await classifier(text, { aggregation_strategy: 'simple' });
    const matches: PatternMatch[] = [];

    for (const entity of results) {
      // Map entity group (strip B-/I- prefixes if present)
      const group = (entity.entity_group ?? entity.entity ?? '').replace(/^[BI]-/, '');
      const patternType = ENTITY_MAP[group];

      // Skip MISC and unmapped entity types
      if (!patternType) continue;

      // Apply confidence threshold
      if ((entity.score ?? 0) < threshold) continue;

      const word = (entity.word ?? '').trim();

      // Skip entities that are too short
      if (word.length < MIN_ENTITY_LENGTH) continue;

      // Find the actual position in the text
      const index = text.indexOf(word, entity.start ?? 0);
      if (index === -1) continue;

      matches.push({
        value: word,
        type: patternType,
        index,
        source: 'ner',
      });
    }

    return matches;
  } catch (err) {
    console.error(`[redact] NER detection error: ${err}`);
    return [];
  }
}

/**
 * Check if the NER model is available and loaded.
 */
export function isNERAvailable(): boolean {
  return !classifierFailed && classifierPromise !== null;
}
