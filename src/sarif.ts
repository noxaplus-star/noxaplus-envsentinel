import { createHash } from 'node:crypto';
import { FILE_RULES, RULES } from './rules.js';
import type { Finding, ScanSummary, Severity } from './types.js';

interface RuleMetadata {
  id: string;
  name: string;
  severity: Severity;
  description: string;
}

const HIGH_ENTROPY_RULE: RuleMetadata = {
  id: 'high-entropy',
  name: 'High-entropy string',
  severity: 'low',
  description: 'A quoted string has high character entropy and may be an encoded credential.'
};

const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0'
};

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note'
};

function ruleMetadata(): RuleMetadata[] {
  const content = RULES.map(rule => ({
    id: rule.id,
    name: rule.name,
    severity: rule.severity,
    description: rule.description
  }));
  const files = FILE_RULES.map(rule => ({
    id: rule.id,
    name: rule.name,
    severity: rule.severity,
    description: rule.description
  }));
  return [...content, ...files, HIGH_ENTROPY_RULE];
}

function fingerprint(finding: Finding): string {
  return createHash('sha256')
    .update(`${finding.ruleId}\0${finding.file}\0${finding.line}\0${finding.match}`)
    .digest('hex')
    .slice(0, 32);
}

export function buildSarif(summary: ScanSummary, version: string): Record<string, unknown> {
  const metadata = ruleMetadata();
  const index = new Map(metadata.map((rule, position) => [rule.id, position]));

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'NoxaPlus EnvSentinel',
            semanticVersion: version,
            informationUri: 'https://github.com/noxaplus-star/noxaplus-envsentinel',
            rules: metadata.map(rule => ({
              id: rule.id,
              name: rule.name,
              shortDescription: { text: rule.name },
              fullDescription: { text: rule.description },
              help: {
                text: `Remove the value from the file and from git history. If it was a real credential, rotate it. Rule: ${rule.id}.`
              },
              defaultConfiguration: { level: LEVEL[rule.severity] },
              properties: {
                tags: ['security', 'secret'],
                'security-severity': SECURITY_SEVERITY[rule.severity]
              }
            }))
          }
        },
        results: summary.findings.map(finding => ({
          ruleId: finding.ruleId,
          ruleIndex: index.get(finding.ruleId) ?? 0,
          level: LEVEL[finding.severity],
          message: { text: finding.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.file },
                region: { startLine: finding.line, startColumn: finding.column }
              }
            }
          ],
          partialFingerprints: { 'envSentinel/v1': fingerprint(finding) },
          properties: {
            severity: finding.severity,
            maskedValue: finding.match
          }
        }))
      }
    ]
  };
}
