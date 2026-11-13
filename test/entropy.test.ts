import { describe, expect, it } from 'vitest';
import { findHighEntropyCandidates, shannonEntropy } from '../src/entropy.js';

const BLOB = 'Qm9vay1vZi1z' + 'ZWNyZXRzLWFyZS1u' + 'b3QtaGVyZS0xMjM0NTY3ODkw';

describe('shannonEntropy', () => {
  it('returns zero for a single repeated character', () => {
    expect(shannonEntropy('aaaaaaaa')).toBe(0);
  });

  it('returns one bit for two equally likely characters', () => {
    expect(shannonEntropy('abababab')).toBeCloseTo(1, 5);
  });

  it('returns two bits for four equally likely characters', () => {
    expect(shannonEntropy('abcdabcd')).toBeCloseTo(2, 5);
  });
});

describe('findHighEntropyCandidates', () => {
  it('finds a base64-like quoted value', () => {
    const value = BLOB;
    const results = findHighEntropyCandidates(`const key = "${value}";`, 32, 4.5);
    expect(results).toHaveLength(1);
    expect(results[0]?.value).toBe(value);
  });

  it('skips long hexadecimal strings', () => {
    const value = 'a3f5c9d1b7e24f68a0c3d5e7f9b1a2c4d6e8f0a1b3c5d7e9f1a2b3c4d5e6f7a8';
    expect(findHighEntropyCandidates(`"${value}"`, 32, 4.5)).toEqual([]);
  });

  it('skips values without digits, which are usually words or identifiers', () => {
    const value = 'thisisaverylongidentifierwithoutdigits';
    expect(findHighEntropyCandidates(`"${value}"`, 32, 4.5)).toEqual([]);
  });

  it('skips values shorter than the minimum length', () => {
    expect(findHighEntropyCandidates('"abc123XYZ456"', 32, 4.5)).toEqual([]);
  });
});
