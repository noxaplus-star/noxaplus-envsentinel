import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { parseArgs, runCli, VERSION, type CliIo } from '../src/cli.js';

let workspace: string;
const WEAK = 'hunter2' + 'hunter2';
const BLOB = 'Qm9vay1vZi1z' + 'ZWNyZXRzLWFyZS1u' + 'b3QtaGVyZS0xMjM0NTY3ODkw';

beforeEach(async () => {
  workspace = await mkdtemp(join(tmpdir(), 'envsentinel-cli-'));
});

afterEach(async () => {
  await rm(workspace, { recursive: true, force: true });
});

interface Capture extends CliIo {
  output: () => string;
  errors: () => string;
}

function capture(cwd: string): Capture {
  const out: string[] = [];
  const err: string[] = [];
  return {
    cwd,
    env: {},
    isTTY: false,
    stdout: text => out.push(text),
    stderr: text => err.push(text),
    output: () => out.join(''),
    errors: () => err.join('')
  };
}

describe('parseArgs', () => {
  it('defaults to a tree scan of the current directory', () => {
    const options = parseArgs([]);
    expect(options.command).toBe('scan');
    expect(options.paths).toEqual([]);
    expect(options.format).toBe('text');
    expect(options.failOn).toBe('high');
    expect(options.entropy).toBe(true);
  });

  it('treats the first token as a path when it is not a command', () => {
    expect(parseArgs(['src', '.env']).paths).toEqual(['src', '.env']);
  });

  it('supports --flag=value syntax', () => {
    const options = parseArgs(['scan', '--format=json', '--fail-on=medium']);
    expect(options.format).toBe('json');
    expect(options.failOn).toBe('medium');
  });

  it('collects repeated exclusions', () => {
    const options = parseArgs(['scan', '--exclude', 'fixtures/**', '--exclude=*.snap']);
    expect(options.excludePatterns).toEqual(['fixtures/**', '*.snap']);
  });

  it('stops option parsing after --', () => {
    const options = parseArgs(['scan', '--', '--weird-file']);
    expect(options.paths).toEqual(['--weird-file']);
  });

  it('rejects invalid formats and fail levels', () => {
    expect(() => parseArgs(['--format', 'xml'])).toThrow();
    expect(() => parseArgs(['--fail-on', 'severe'])).toThrow();
  });

  it('parses install-hook --force', () => {
    expect(parseArgs(['install-hook', '--force']).force).toBe(true);
  });

  it('rejects arguments for rules', () => {
    expect(() => parseArgs(['rules', 'extra'])).toThrow();
  });
});

describe('runCli', () => {
  it('prints the version', async () => {
    const io = capture(workspace);
    expect(await runCli(['--version'], io)).toBe(0);
    expect(io.output()).toBe(`${VERSION}\n`);
  });

  it('prints help', async () => {
    const io = capture(workspace);
    expect(await runCli(['--help'], io)).toBe(0);
    expect(io.output()).toContain('Scan options');
    expect(io.output()).toContain('--staged');
  });

  it('lists rules', async () => {
    const io = capture(workspace);
    expect(await runCli(['rules'], io)).toBe(0);
    expect(io.output()).toContain('github-token');
    expect(io.output()).toContain('high-entropy');
  });

  it('returns zero for a clean directory', async () => {
    await writeFile(join(workspace, 'app.ts'), 'const value = process.env.API_KEY;\n', 'utf8');
    const io = capture(workspace);
    expect(await runCli([], io)).toBe(0);
    expect(io.output()).toContain('No leaked secrets');
  });

  it('returns one when a finding meets the default threshold', async () => {
    await writeFile(join(workspace, 'app.ts'), `const token = "ghp_${'a1'.repeat(18)}";\n`, 'utf8');
    const io = capture(workspace);
    expect(await runCli([], io)).toBe(1);
    expect(io.output()).toContain('CRITICAL');
    expect(io.output()).not.toContain('ghp_a1a1a1');
  });

  it('respects --fail-on', async () => {
    await writeFile(join(workspace, 'app.ts'), `const password = "${WEAK}";\n`, 'utf8');
    expect(await runCli(['--fail-on', 'critical'], capture(workspace))).toBe(0);
    expect(await runCli(['--fail-on', 'none'], capture(workspace))).toBe(0);
    expect(await runCli(['--fail-on', 'high'], capture(workspace))).toBe(1);
  });

  it('writes JSON reports', async () => {
    await writeFile(join(workspace, 'app.ts'), `const token = "ghp_${'a1'.repeat(18)}";\n`, 'utf8');
    const io = capture(workspace);
    expect(await runCli(['--format', 'json'], io)).toBe(1);
    const parsed = JSON.parse(io.output()) as { tool: string; summary: { total: number }; findings: Array<{ ruleId: string }> };
    expect(parsed.tool).toBe('envsentinel');
    expect(parsed.summary.total).toBe(1);
    expect(parsed.findings[0]?.ruleId).toBe('github-token');
  });

  it('writes SARIF reports', async () => {
    await writeFile(join(workspace, 'app.ts'), `const password = "${WEAK}";\n`, 'utf8');
    const io = capture(workspace);
    expect(await runCli(['--format', 'sarif'], io)).toBe(1);
    const parsed = JSON.parse(io.output()) as { version: string; runs: Array<{ results: unknown[] }> };
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs[0]?.results).toHaveLength(1);
  });

  it('writes report files and prints a status line', async () => {
    await writeFile(join(workspace, 'app.ts'), `const token = "ghp_${'a1'.repeat(18)}";\n`, 'utf8');
    const io = capture(workspace);
    expect(await runCli(['--format', 'json', '--out', 'reports/scan.json'], io)).toBe(1);
    expect(existsSync(join(workspace, 'reports', 'scan.json'))).toBe(true);
    expect(io.output()).toContain('Wrote reports/scan.json (1 finding)');
  });

  it('honors --no-entropy', async () => {
    await writeFile(
      join(workspace, 'app.ts'),
      `const value = "${BLOB}";\n`,
      'utf8'
    );
    const withEntropy = capture(workspace);
    expect(await runCli([], withEntropy)).toBe(0);
    expect(withEntropy.output()).toContain('high-entropy');

    const withoutEntropy = capture(workspace);
    expect(await runCli(['--no-entropy'], withoutEntropy)).toBe(0);
    expect(withoutEntropy.output()).toContain('No leaked secrets');
  });

  it('returns two for invalid usage and missing paths', async () => {
    expect(await runCli(['--nope'], capture(workspace))).toBe(2);
    const io = capture(workspace);
    expect(await runCli(['scan', 'missing'], io)).toBe(2);
    expect(io.errors()).toContain('Path not found');
  });

  it('returns two for a missing config file', async () => {
    const io = capture(workspace);
    expect(await runCli(['--config', 'missing.json'], io)).toBe(2);
    expect(io.errors()).toContain('Could not read config');
  });

  it('returns two for --staged outside a repository', async () => {
    const io = capture(workspace);
    expect(await runCli(['--staged'], io)).toBe(2);
    expect(io.errors()).toContain('requires a git repository');
  });

  it('installs a pre-commit hook', async () => {
    execFileSync('git', ['init', '-q'], { cwd: workspace });
    const io = capture(workspace);
    expect(await runCli(['install-hook'], io)).toBe(0);
    expect(io.output()).toContain('Installed pre-commit hook');
    expect(existsSync(join(workspace, '.git', 'hooks', 'pre-commit'))).toBe(true);
  });
});
