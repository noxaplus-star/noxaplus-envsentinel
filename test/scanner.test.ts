import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG } from '../src/config.js';
import { scanContent, scanPaths, ScanError } from '../src/scanner.js';
import type { ScannerConfig } from '../src/types.js';

let workspace: string;

const WEAK = 'hunter2' + 'hunter2';
const AWS_KEY = `AKIA${'IOSFODNN7EXAMPLQ'}`;
const EXAMPLE_KEY = `AKIA${'EXAMPLETHISISFAKE'}`;
const DATABASE_URL = `postgres${'://'}app:${'s3cr3t'}@db:5432/x`;
const BLOB = 'Qm9vay1vZi1z' + 'ZWNyZXRzLWFyZS1u' + 'b3QtaGVyZS0xMjM0NTY3ODkw';

beforeEach(async () => {
  workspace = await mkdtemp(join(tmpdir(), 'envsentinel-'));
});

afterEach(async () => {
  await rm(workspace, { recursive: true, force: true });
});

function config(overrides: Partial<ScannerConfig> = {}): ScannerConfig {
  return {
    ...DEFAULT_CONFIG,
    ignorePaths: [...DEFAULT_CONFIG.ignorePaths],
    ...overrides
  };
}

describe('scanContent', () => {
  it('reports line, column, rule, and a masked value', () => {
    const token = `ghp_${'a1'.repeat(18)}`;
    const findings = scanContent('src/app.ts', `const token = "${token}";`, config(), { entropy: false });
    expect(findings).toHaveLength(1);
    const finding = findings[0];
    expect(finding?.ruleId).toBe('github-token');
    expect(finding?.severity).toBe('critical');
    expect(finding?.line).toBe(1);
    expect(finding?.column).toBe(16);
    expect(finding?.match).not.toContain(token);
  });

  it('ignores a line marked with envsentinel:ignore', () => {
    const content = `const password = "${WEAK}"; // envsentinel:ignore`;
    expect(scanContent('a.ts', content, config(), { entropy: false })).toEqual([]);
  });

  it('ignores the line after envsentinel:ignore-next-line', () => {
    const content = `// envsentinel:ignore-next-line\nconst password = "${WEAK}";`;
    expect(scanContent('a.ts', content, config(), { entropy: false })).toEqual([]);
  });

  it('ignores only the listed rules', () => {
    const token = `ghp_${'a1'.repeat(18)}`;
    const content = `const token = "${token}"; // envsentinel:ignore generic-assignment`;
    const findings = scanContent('a.ts', content, config(), { entropy: false });
    expect(findings.map(finding => finding.ruleId)).toEqual(['github-token']);
  });

  it('honors ignored rules from config', () => {
    const findings = scanContent('a.ts', `const password = "${WEAK}";`, config({ ignoreRules: ['generic-assignment'] }), {
      entropy: false
    });
    expect(findings).toEqual([]);
  });

  it('honors allowPatterns against the captured value', () => {
    const content = `const key = "${EXAMPLE_KEY}";`;
    const findings = scanContent('a.ts', content, config({ allowPatterns: ['^AKIAEXAMPLE'] }), { entropy: false });
    expect(findings).toEqual([]);
  });

  it('finds high-entropy strings only when no rule matched the line', () => {
    const findings = scanContent(
      'a.ts',
      `const value = "${BLOB}";`,
      config(),
      {}
    );
    expect(findings.map(finding => finding.ruleId)).toEqual(['high-entropy']);
    expect(findings[0]?.entropy).toBeGreaterThan(4.5);
  });

  it('can disable entropy detection', () => {
    const findings = scanContent(
      'a.ts',
      `const value = "${BLOB}";`,
      config(),
      { entropy: false }
    );
    expect(findings).toEqual([]);
  });

  it('detects committed environment files only when file rules are enabled', () => {
    expect(scanContent('.env', 'A=1', config(), { includeFileRules: true }).map(finding => finding.ruleId)).toEqual(['env-file']);
    expect(scanContent('.env', 'A=1', config(), {})).toEqual([]);
    expect(scanContent('.env.example', 'A=1', config(), { includeFileRules: true })).toEqual([]);
  });

  it('detects credentials and key files', () => {
    expect(scanContent('id_rsa', 'x', config(), { includeFileRules: true }).map(finding => finding.ruleId)).toContain(
      'private-key-file'
    );
    expect(scanContent('credentials.json', '{}', config(), { includeFileRules: true }).map(finding => finding.ruleId)).toContain(
      'credentials-file'
    );
    expect(scanContent('.npmrc', 'x', config(), { includeFileRules: true }).map(finding => finding.ruleId)).toContain('npmrc-file');
  });

  it('keeps multiple distinct secrets on one line', () => {
    const content = `const aws = "${AWS_KEY}"; const db = "${DATABASE_URL}";`;
    const findings = scanContent('a.ts', content, config(), { entropy: false });
    expect(new Set(findings.map(finding => finding.ruleId))).toEqual(new Set(['aws-access-key-id', 'database-url']));
  });

  it('counts lines correctly with CRLF content', () => {
    const content = `const ok = 1;\r\nconst password = "${WEAK}";\r\n`;
    const findings = scanContent('a.ts', content, config(), { entropy: false });
    expect(findings[0]?.line).toBe(2);
  });
});

describe('scanPaths', () => {
  it('walks a tree, ignores defaults, and skips binary files', async () => {
    await mkdir(join(workspace, 'src'), { recursive: true });
    await mkdir(join(workspace, 'node_modules', 'pkg'), { recursive: true });
    await writeFile(join(workspace, 'src', 'app.ts'), `const token = "ghp_${'a1'.repeat(18)}";\n`, 'utf8');
    await writeFile(join(workspace, 'README.md'), '# clean\n', 'utf8');
    await writeFile(join(workspace, 'node_modules', 'pkg', 'index.js'), `const key = "${AWS_KEY}";\n`, 'utf8');
    await writeFile(join(workspace, 'image.bin'), Buffer.from([0, 1, 2, 3]));

    const summary = await scanPaths({ cwd: workspace, paths: [], staged: false, config: config() });
    expect(summary.mode).toBe('tree');
    expect(summary.filesScanned).toBe(2);
    expect(summary.filesSkipped).toBe(1);
    expect(summary.findings.map(finding => finding.file)).toEqual(['src/app.ts']);
  });

  it('scans an explicitly named ignored file', async () => {
    await mkdir(join(workspace, 'node_modules', 'pkg'), { recursive: true });
    const file = join(workspace, 'node_modules', 'pkg', 'index.js');
    await writeFile(file, `const key = "${AWS_KEY}";\n`, 'utf8');

    const summary = await scanPaths({ cwd: workspace, paths: ['node_modules/pkg/index.js'], staged: false, config: config() });
    expect(summary.findings.map(finding => finding.ruleId)).toContain('aws-access-key-id');
  });

  it('skips files larger than the configured limit', async () => {
    await writeFile(join(workspace, 'big.txt'), 'a'.repeat(64), 'utf8');
    const summary = await scanPaths({
      cwd: workspace,
      paths: [],
      staged: false,
      config: config({ maxFileSize: 16 })
    });
    expect(summary.filesScanned).toBe(0);
    expect(summary.filesSkipped).toBe(1);
  });

  it('throws a ScanError for a missing path', async () => {
    await expect(scanPaths({ cwd: workspace, paths: ['missing'], staged: false, config: config() })).rejects.toBeInstanceOf(
      ScanError
    );
  });
});
