import type { Finding, ScanSummary, Severity } from './types.js';
import { SEVERITY_ORDER } from './types.js';

const COLORS: Record<Severity, string> = {
  critical: '\u001b[1;31m',
  high: '\u001b[1;35m',
  medium: '\u001b[1;33m',
  low: '\u001b[1;36m'
};

const RESET = '\u001b[0m';
const DIM = '\u001b[2m';

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

function label(severity: Severity, color: boolean): string {
  const text = severity.toUpperCase().padEnd(8);
  return color ? `${COLORS[severity]}${text}${RESET}` : text;
}

export interface TextReportOptions {
  version: string;
  color: boolean;
}

export function renderText(summary: ScanSummary, options: TextReportOptions): string {
  const lines: string[] = [];
  lines.push(`NoxaPlus EnvSentinel ${options.version}`);
  const where = summary.mode === 'staged' ? 'staged changes' : summary.root;
  lines.push(`Scanning ${where}`);
  lines.push(
    `Scanned ${summary.filesScanned} ${summary.filesScanned === 1 ? 'file' : 'files'} · skipped ${summary.filesSkipped} · ${summary.durationMs} ms`
  );
  lines.push('');

  if (summary.findings.length === 0) {
    lines.push('No leaked secrets or risky config found.');
    return `${lines.join('\n')}\n`;
  }

  const counts = countBySeverity(summary.findings);
  const byFile = new Map<string, Finding[]>();
  for (const finding of summary.findings) {
    const list = byFile.get(finding.file) ?? [];
    list.push(finding);
    byFile.set(finding.file, list);
  }

  for (const [file, findings] of byFile) {
    lines.push(file);
    for (const finding of findings) {
      const location = `${finding.line}:${finding.column}`.padEnd(8);
      const rule = options.color ? `${DIM}(${finding.ruleId})${RESET}` : `(${finding.ruleId})`;
      lines.push(`  ${label(finding.severity, options.color)} ${location}  ${finding.message}  ${rule}`);
      if (finding.match.length > 0) {
        lines.push(`  ${' '.repeat(19)}value: ${finding.match}`);
      }
    }
    lines.push('');
  }

  const parts = (Object.keys(counts) as Severity[])
    .filter(severity => counts[severity] > 0)
    .sort((left, right) => SEVERITY_ORDER[right] - SEVERITY_ORDER[left])
    .map(severity => `${counts[severity]} ${severity}`);
  lines.push(`${summary.findings.length} ${summary.findings.length === 1 ? 'finding' : 'findings'}: ${parts.join(' · ')}`);
  lines.push('');
  lines.push('Rotate any value that was real, then remove it from the commit and from git history.');
  lines.push('EnvSentinel reads files only; it cannot revoke a key for you.');
  return `${lines.join('\n')}\n`;
}

export interface JsonReport {
  tool: string;
  name: string;
  version: string;
  scannedAt: string;
  mode: 'tree' | 'staged';
  root: string;
  summary: {
    filesScanned: number;
    filesSkipped: number;
    durationMs: number;
    counts: Record<Severity, number>;
    total: number;
  };
  findings: Finding[];
}

export function renderJson(summary: ScanSummary, version: string): string {
  const report: JsonReport = {
    tool: 'envsentinel',
    name: 'NoxaPlus EnvSentinel',
    version,
    scannedAt: new Date().toISOString(),
    mode: summary.mode,
    root: summary.root,
    summary: {
      filesScanned: summary.filesScanned,
      filesSkipped: summary.filesSkipped,
      durationMs: summary.durationMs,
      counts: countBySeverity(summary.findings),
      total: summary.findings.length
    },
    findings: summary.findings
  };
  return `${JSON.stringify(report, null, 2)}\n`;
}
