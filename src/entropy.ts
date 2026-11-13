export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

export interface EntropyCandidate {
  value: string;
  index: number;
}

const CANDIDATE = /["'`]([A-Za-z0-9+/=_-]{16,})["'`]/g;

export function findHighEntropyCandidates(line: string, minimumLength: number, threshold: number): EntropyCandidate[] {
  const results: EntropyCandidate[] = [];
  CANDIDATE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = CANDIDATE.exec(line)) !== null) {
    const value = match[1];
    if (value === undefined || value.length < minimumLength) continue;
    if (!/[A-Za-z]/.test(value) || !/\d/.test(value)) continue;
    if (/^[0-9a-f]+$/i.test(value)) continue;
    const entropy = shannonEntropy(value);
    if (entropy >= threshold) {
      results.push({ value, index: match.index + 1 });
    }
  }
  return results;
}
