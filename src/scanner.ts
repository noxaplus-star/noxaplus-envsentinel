import { readdir, readFile, stat } from 'node:fs/promises';
import { basename, isAbsolute, relative, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { isIgnored, normalizePath } from './config.js';
import { findHighEntropyCandidates, shannonEntropy } from './entropy.js';
import { isGitRepository, listStagedFiles, listTrackedFiles, readStagedFile, repositoryRoot } from './git.js';
import { FILE_RULES, RULES } from './rules.js';
import type { Finding, Rule, ScanOptions, ScanSummary, ScannerConfig, Severity } from './types.js';
import { SEVERITY_ORDER } from './types.js';

export class ScanError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScanError';
  }
}

const PLACEHOLDER_PATTERNS = [
  /^(?:x{4,}|\*{4,}|\.{3,}|-{4,}|_{4,})$/i,
  /^(?:changeme|change_me|example|sample|dummy|placeholder|redacted|secret|password|token|test|fake|none|null|undefined|todo|foo|bar)$/i,
  /(?:\$\{|\{\{|%[A-Z0-9_]+%|<[^>]{1,40}>|process\.env|os\.environ|import\.meta\.env)/i,
  /^(?:your|my)[_-]/i,
  /^(?:replace|insert|enter)[_-]/i,
  /x{6,}$/i
];

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERNS.some(pattern => pattern.test(value));
}

export function maskValue(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0) return '********';
  if (trimmed.length <= 8) return '*'.repeat(Math.max(4, trimmed.length));
  const visible = trimmed.length > 16 ? 4 : 3;
  const hidden = Math.min(16, Math.max(4, trimmed.length - visible * 2));
  return `${trimmed.slice(0, visible)}${'*'.repeat(hidden)}${trimmed.slice(-visible)}`;
}

function compileRules(config: ScannerConfig): Array<{ rule: Rule; regex: RegExp }> {
  const ignored = new Set(config.ignoreRules);
  return RULES.filter(rule => !ignored.has(rule.id)).map(rule => {
    const flags = new Set(rule.pattern.flags.split(''));
    flags.add('g');
    flags.add('d');
    return { rule, regex: new RegExp(rule.pattern.source, [...flags].join('')) };
  });
}

function inlineIgnore(line: string, nextLine: boolean): Set<string> | 'all' | null {
  const pattern = nextLine
    ? /envsentinel:\s*ignore-next-line(?:\s+([a-z0-9_,-]+))?/i
    : /envsentinel:\s*(?:ignore(?!-next-line)|allow)(?:\s+([a-z0-9_,-]+))?/i;
  const match = pattern.exec(line);
  if (!match) return null;
  const tokens = match[1]
    ?.split(',')
    .map(token => token.trim())
    .filter(token => token.length > 0);
  return tokens && tokens.length > 0 ? new Set(tokens) : 'all';
}

function isRuleIgnored(
  ignored: Set<string> | 'all' | null,
  ruleId: string
): boolean {
  if (ignored === null) return false;
  if (ignored === 'all') return true;
  return ignored.has(ruleId);
}

interface Candidate extends Finding {
  start: number;
  end: number;
}

function dedupeLine(candidates: Candidate[]): Candidate[] {
  const sorted = [...candidates].sort((left, right) => {
    const leftGeneric = left.ruleId === 'generic-assignment';
    const rightGeneric = right.ruleId === 'generic-assignment';
    if (leftGeneric !== rightGeneric) return leftGeneric ? 1 : -1;
    const severity = SEVERITY_ORDER[right.severity] - SEVERITY_ORDER[left.severity];
    return severity !== 0 ? severity : left.start - right.start;
  });
  const kept: Candidate[] = [];
  for (const candidate of sorted) {
    const overlaps = kept.some(other => candidate.start < other.end && other.start < candidate.end);
    if (!overlaps) kept.push(candidate);
  }
  return kept.sort((left, right) => left.start - right.start);
}

export interface ContentScanOptions {
  includeFileRules?: boolean;
  entropy?: boolean;
}

export function scanContent(
  file: string,
  content: string,
  config: ScannerConfig,
  options: ContentScanOptions = {}
): Finding[] {
  const findings: Candidate[] = [];
  const allowPatterns = config.allowPatterns.map(pattern => new RegExp(pattern));
  const rules = compileRules(config);
  const normalizedFile = normalizePath(file);
  const base = basename(normalizedFile);

  if (options.includeFileRules === true) {
    const ignoredRules = new Set(config.ignoreRules);
    for (const fileRule of FILE_RULES) {
      if (ignoredRules.has(fileRule.id)) continue;
      if (!fileRule.matches(base)) continue;
      findings.push({
        ruleId: fileRule.id,
        ruleName: fileRule.name,
        severity: fileRule.severity,
        file: normalizedFile,
        line: 1,
        column: 1,
        match: base,
        message: fileRule.message,
        start: 0,
        end: Math.max(1, base.length)
      });
    }
  }

  const lines = content.split(/\r?\n/);
  const perLine: Candidate[][] = lines.map(() => []);
  const skipAll = new Set<number>();
  const skipRules = new Map<number, Set<string>>();

  lines.forEach((line, index) => {
    const ignore = inlineIgnore(line, false);
    if (ignore === 'all') skipAll.add(index);
    else if (ignore !== null) skipRules.set(index, ignore);

    const next = inlineIgnore(line, true);
    if (index + 1 < lines.length && next !== null) {
      if (next === 'all') skipAll.add(index + 1);
      else {
        const existing = skipRules.get(index + 1);
        skipRules.set(index + 1, existing ? new Set([...existing, ...next]) : next);
      }
    }
  });

  const entropyEnabled = options.entropy !== false;
  for (let index = 0; index < lines.length; index += 1) {
    if (skipAll.has(index)) continue;
    const line = lines[index] ?? '';
    const ignored = skipRules.get(index) ?? null;
    const lineFindings = perLine[index];

    for (const { rule, regex } of rules) {
      if (isRuleIgnored(ignored, rule.id)) continue;
      regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = regex.exec(line)) !== null) {
        if (match[0].length === 0) {
          regex.lastIndex += 1;
          continue;
        }
        const group = rule.secretGroup ?? 0;
        const raw = match[group];
        if (raw === undefined) continue;
        if (rule.id === 'generic-assignment' && isPlaceholder(raw)) continue;
        if (allowPatterns.some(pattern => pattern.test(raw))) continue;
        const indices = match.indices?.[group];
        const start = indices?.[0] ?? match.index;
        lineFindings?.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          file: normalizedFile,
          line: index + 1,
          column: start + 1,
          match: rule.hideMatch === true ? raw : maskValue(raw),
          message: rule.description,
          start,
          end: indices?.[1] ?? start + Math.max(1, raw.length)
        });
      }
    }

    if (lineFindings !== undefined && lineFindings.length === 0 && entropyEnabled) {
      const candidates = findHighEntropyCandidates(line, config.entropyMinLength, config.entropyThreshold);
      for (const candidate of candidates) {
        if (isPlaceholder(candidate.value)) continue;
        if (allowPatterns.some(pattern => pattern.test(candidate.value))) continue;
        const entropy = shannonEntropy(candidate.value);
        lineFindings.push({
          ruleId: 'high-entropy',
          ruleName: 'High-entropy string',
          severity: 'low',
          file: normalizedFile,
          line: index + 1,
          column: candidate.index + 1,
          match: maskValue(candidate.value),
          message: `High-entropy string may be a secret (entropy ${entropy.toFixed(2)}).`,
          entropy,
          start: candidate.index,
          end: candidate.index + candidate.value.length
        });
      }
    }
  }

  for (const candidates of perLine) {
    if (candidates.length === 0) continue;
    findings.push(...dedupeLine(candidates));
  }

  return findings
    .map(({ start: _start, end: _end, ...finding }) => finding)
    .sort((left, right) => {
      if (left.file !== right.file) return left.file.localeCompare(right.file);
      if (left.line !== right.line) return left.line - right.line;
      if (left.column !== right.column) return left.column - right.column;
      return SEVERITY_ORDER[right.severity] - SEVERITY_ORDER[left.severity];
    });
}

function severityRank(severity: Severity): number {
  return SEVERITY_ORDER[severity];
}

export function highestSeverity(findings: Finding[]): Severity | null {
  let highest: Severity | null = null;
  for (const finding of findings) {
    if (highest === null || severityRank(finding.severity) > severityRank(highest)) {
      highest = finding.severity;
    }
  }
  return highest;
}

function isBinary(buffer: Buffer): boolean {
  const sample = buffer.subarray(0, 8192);
  return sample.includes(0);
}

function displayPath(absolutePath: string, baseDir: string, repoRoot: string | null): string {
  if (repoRoot !== null) {
    const fromRoot = normalizePath(relative(repoRoot, absolutePath));
    if (!fromRoot.startsWith('..') && !isAbsolute(fromRoot)) return fromRoot;
  }
  const fromBase = normalizePath(relative(baseDir, absolutePath));
  if (!fromBase.startsWith('..') && !isAbsolute(fromBase)) return fromBase;
  return normalizePath(absolutePath);
}

interface CollectedFile {
  absolute: string;
  display: string;
  relativeToRepo: string | null;
}

async function collectFromDirectory(
  directory: string,
  baseDir: string,
  repoRoot: string | null,
  patterns: string[],
  files: CollectedFile[],
  skipped: { count: number },
  seen: Set<string>
): Promise<void> {
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const absolute = resolve(directory, entry.name);
    const display = displayPath(absolute, baseDir, repoRoot);
    if (entry.isDirectory()) {
      if (isIgnored(display, patterns)) continue;
      await collectFromDirectory(absolute, baseDir, repoRoot, patterns, files, skipped, seen);
    } else if (entry.isFile()) {
      if (isIgnored(display, patterns)) {
        skipped.count += 1;
        continue;
      }
      if (seen.has(absolute)) continue;
      seen.add(absolute);
      files.push({
        absolute,
        display,
        relativeToRepo: repoRoot === null ? null : normalizePath(relative(repoRoot, absolute))
      });
    }
  }
}

async function readScannable(
  file: CollectedFile,
  config: ScannerConfig,
  skipped: { count: number }
): Promise<{ file: CollectedFile; content: string } | null> {
  let info;
  try {
    info = await stat(file.absolute);
  } catch {
    throw new ScanError(`Could not read ${file.display}.`);
  }
  if (info.size > config.maxFileSize) {
    skipped.count += 1;
    return null;
  }
  let buffer: Buffer;
  try {
    buffer = await readFile(file.absolute);
  } catch {
    throw new ScanError(`Could not read ${file.display}.`);
  }
  if (isBinary(buffer)) {
    skipped.count += 1;
    return null;
  }
  return { file, content: buffer.toString('utf8') };
}

export async function scanPaths(options: ScanOptions): Promise<ScanSummary> {
  const started = performance.now();
  const cwd = resolve(options.cwd);
  const patterns = [...options.config.ignorePaths, ...(options.excludePatterns ?? [])];
  const skipped = { count: 0 };
  const files: CollectedFile[] = [];
  const seen = new Set<string>();
  const repoRoot = isGitRepository(cwd) ? repositoryRoot(cwd) : null;
  const tracked = repoRoot !== null && !options.staged ? listTrackedFiles(repoRoot) : null;

  if (options.staged) {
    if (repoRoot === null) {
      throw new ScanError('--staged requires a git repository. Run this command inside one.');
    }
    const staged = listStagedFiles(repoRoot);
    const inputs = options.paths.length > 0 ? options.paths : ['.'];
    const resolvedInputs = inputs.map(input => {
      const resolved = normalizePath(relative(repoRoot, resolve(cwd, input)));
      return resolved.length === 0 ? '.' : resolved;
    });
    for (const stagedFile of staged) {
      if (isIgnored(stagedFile, patterns)) {
        skipped.count += 1;
        continue;
      }
      const matchesInput = resolvedInputs.some(input => input === '.' || stagedFile === input || stagedFile.startsWith(`${input.replace(/\/+$/, '')}/`));
      if (!matchesInput) continue;
      const buffer = readStagedFile(repoRoot, stagedFile);
      if (buffer.byteLength > options.config.maxFileSize || isBinary(buffer)) {
        skipped.count += 1;
        continue;
      }
      files.push({ absolute: stagedFile, display: stagedFile, relativeToRepo: stagedFile });
    }

    const findings: Finding[] = [];
    let scanned = 0;
    for (const file of files) {
      const buffer = readStagedFile(repoRoot, file.relativeToRepo ?? file.display);
      const content = buffer.toString('utf8');
      findings.push(...scanContent(file.display, content, options.config, { includeFileRules: true, entropy: options.entropy ?? true }));
      scanned += 1;
    }
    return {
      filesScanned: scanned,
      filesSkipped: skipped.count,
      findings,
      durationMs: Math.round(performance.now() - started),
      root: repoRoot,
      mode: 'staged'
    };
  }

  const inputs = options.paths.length > 0 ? options.paths : ['.'];
  for (const input of inputs) {
    const absolute = resolve(cwd, input);
    let info;
    try {
      info = await stat(absolute);
    } catch {
      throw new ScanError(`Path not found: ${input}`);
    }
    if (info.isDirectory()) {
      await collectFromDirectory(absolute, cwd, repoRoot, patterns, files, skipped, seen);
    } else if (info.isFile()) {
      if (seen.has(absolute)) continue;
      seen.add(absolute);
      files.push({
        absolute,
        display: displayPath(absolute, cwd, repoRoot),
        relativeToRepo: repoRoot === null ? null : normalizePath(relative(repoRoot, absolute))
      });
    } else {
      throw new ScanError(`Unsupported path type: ${input}`);
    }
  }

  const findings: Finding[] = [];
  let scanned = 0;
  for (const file of files) {
    const readable = await readScannable(file, options.config, skipped);
    if (readable === null) continue;
    const trackedFile =
      tracked !== null &&
      file.relativeToRepo !== null &&
      tracked.has(file.relativeToRepo);
    findings.push(
      ...scanContent(readable.file.display, readable.content, options.config, {
        includeFileRules: trackedFile,
        entropy: options.entropy ?? true
      })
    );
    scanned += 1;
  }

  return {
    filesScanned: scanned,
    filesSkipped: skipped.count,
    findings,
    durationMs: Math.round(performance.now() - started),
    root: repoRoot ?? cwd,
    mode: 'tree'
  };
}
