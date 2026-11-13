import { describe, expect, it } from 'vitest';
import { buildSarif } from '../src/sarif.js';
import type { Finding, ScanSummary } from '../src/types.js';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'github-token',
    ruleName: 'GitHub token',
    severity: 'critical',
    file: 'src/config.ts',
    line: 12,
    column: 16,
    match: 'ghp_****abcd',
    message: 'A GitHub token is present.',
    ...overrides
  };
}

function summary(findings: Finding[]): ScanSummary {
  return {
    filesScanned: 4,
    filesSkipped: 1,
    findings,
    durationMs: 42,
    root: '/repo',
    mode: 'tree'
  };
}

describe('buildSarif', () => {
  it('produces a SARIF 2.1.0 run', () => {
    const sarif = buildSarif(summary([finding()]), '1.0.0') as {
      version: string;
      runs: Array<{
        tool: { driver: { name: string; semanticVersion: string; rules: Array<{ id: string }> } };
        results: Array<{
          ruleId: string;
          ruleIndex: number;
          level: string;
          locations: Array<{ physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number; startColumn: number } } }>;
          partialFingerprints: Record<string, string>;
          properties: Record<string, string>;
        }>;
      }>;
    };

    expect(sarif.version).toBe('2.1.0');
    const run = sarif.runs[0];
    expect(run?.tool.driver.name).toBe('NoxaPlus EnvSentinel');
    expect(run?.tool.driver.semanticVersion).toBe('1.0.0');
    expect(run?.tool.driver.rules).toHaveLength(27);
    expect(run?.tool.driver.rules[run.results[0]?.ruleIndex ?? -1]?.id).toBe('github-token');

    const result = run?.results[0];
    expect(result?.level).toBe('error');
    expect(result?.locations[0]?.physicalLocation.artifactLocation.uri).toBe('src/config.ts');
    expect(result?.locations[0]?.physicalLocation.region).toEqual({ startLine: 12, startColumn: 16 });
    expect(result?.partialFingerprints['envSentinel/v1']).toMatch(/^[a-f0-9]{32}$/);
  });

  it('maps severity to SARIF levels', () => {
    const sarif = buildSarif(
      summary([
        finding({ severity: 'critical' }),
        finding({ ruleId: 'jwt', severity: 'medium', match: 'eyJ****abcd' }),
        finding({ ruleId: 'high-entropy', severity: 'low', match: 'Qm9****ODkw' })
      ]),
      '1.0.0'
    ) as { runs: Array<{ results: Array<{ level: string }> }> };
    expect(sarif.runs[0]?.results.map(result => result.level)).toEqual(['error', 'warning', 'note']);
  });

  it('keeps only masked values', () => {
    const sarif = JSON.stringify(buildSarif(summary([finding()]), '1.0.0'));
    expect(sarif).toContain('ghp_****abcd');
    expect(sarif).not.toContain('ghp_realSecretValue');
  });

  it('uses a stable fingerprint for the same finding', () => {
    const first = buildSarif(summary([finding()]), '1.0.0') as {
      runs: Array<{ results: Array<{ partialFingerprints: Record<string, string> }> }>;
    };
    const second = buildSarif(summary([finding()]), '1.0.0') as {
      runs: Array<{ results: Array<{ partialFingerprints: Record<string, string> }> }>;
    };
    expect(first.runs[0]?.results[0]?.partialFingerprints).toEqual(second.runs[0]?.results[0]?.partialFingerprints);
  });
});
