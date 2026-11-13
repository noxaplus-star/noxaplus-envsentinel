#!/usr/bin/env node
import { mkdir, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { loadConfig, normalizePath } from './config.js';
import { GitError, installHook } from './git.js';
import { renderJson, renderText } from './report.js';
import { FILE_RULES, RULES } from './rules.js';
import { buildSarif } from './sarif.js';
import { scanPaths, ScanError } from './scanner.js';
import type { CliOptions, FailLevel, Finding, OutputFormat } from './types.js';
import { SEVERITY_ORDER } from './types.js';

class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

const FORMATS: OutputFormat[] = ['text', 'json', 'sarif'];
const FAIL_LEVELS: FailLevel[] = ['low', 'medium', 'high', 'critical', 'none'];
const COMMANDS = new Set(['scan', 'install-hook', 'rules', 'help', 'version']);

function readVersion(): string {
  try {
    const raw = readFileSync(new URL('../package.json', import.meta.url), 'utf8');
    const parsed = JSON.parse(raw) as { version?: unknown };
    return typeof parsed.version === 'string' ? parsed.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export const VERSION = readVersion();

const HELP = `NoxaPlus EnvSentinel ${VERSION} — find leaked secrets before they reach git.

Usage
  envsentinel [scan] [paths...] [options]
  envsentinel install-hook [--force]
  envsentinel rules
  envsentinel --help
  envsentinel --version

Scan options
  --staged                    Scan files staged for commit instead of the working tree
  --format <text|json|sarif>  Report format (default: text)
  --out <path>                Write the report to a file instead of stdout
  --fail-on <level>           Exit 1 at or above low|medium|high|critical (default: high)
  --config <path>             Config file (default: .envsentinel.json if it exists)
  --exclude <glob>            Additional ignore pattern (repeatable)
  --no-entropy                Disable high-entropy detection
  --no-color                  Disable ANSI colors
  --quiet                     Suppress the "report written" status line

Inline suppression
  Add "envsentinel:ignore" to a line to skip it.
  Add "envsentinel:ignore-next-line" to skip the following line.
  Add rule IDs after the marker to skip only those rules, for example:
  "envsentinel:ignore generic-assignment,jwt".

Exit codes
  0  No findings at or above --fail-on
  1  Findings at or above --fail-on
  2  Invalid usage, config, path, or git error

Examples
  envsentinel
  envsentinel scan src .env
  envsentinel scan --staged --format sarif --out envsentinel.sarif
  envsentinel install-hook
`;

function valueFor(argv: string[], index: number, flag: string, inline: string | undefined): { value: string; next: number } {
  if (inline !== undefined) {
    if (inline.length === 0) throw new UsageError(`${flag} requires a value.`);
    return { value: inline, next: index };
  }
  const value = argv[index + 1];
  if (value === undefined || value.startsWith('--')) throw new UsageError(`${flag} requires a value.`);
  return { value, next: index + 1 };
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    command: 'scan',
    paths: [],
    staged: false,
    format: 'text',
    failOn: 'high',
    noColor: false,
    quiet: false,
    force: false,
    entropy: true,
    excludePatterns: []
  };

  if (argv.includes('--help') || argv.includes('-h') || argv[0] === 'help') {
    options.command = 'help';
    return options;
  }
  if (argv.includes('--version') || argv.includes('-v') || argv[0] === 'version') {
    options.command = 'version';
    return options;
  }

  let index = 0;
  const first = argv[0];
  if (first !== undefined && COMMANDS.has(first)) {
    options.command = first as CliOptions['command'];
    index = 1;
  }

  if (options.command === 'rules') {
    if (argv.length > 1) throw new UsageError('The "rules" command does not accept arguments.');
    return options;
  }

  if (options.command === 'install-hook') {
    for (let position = index; position < argv.length; position += 1) {
      const token = argv[position] ?? '';
      if (token === '--force') options.force = true;
      else throw new UsageError(`Unknown option for install-hook: ${token}`);
    }
    return options;
  }

  let literal = false;
  for (; index < argv.length; index += 1) {
    const token = argv[index] ?? '';
    if (literal) {
      options.paths.push(token);
      continue;
    }
    if (token === '--') {
      literal = true;
      continue;
    }
    if (!token.startsWith('-') || token === '-') {
      options.paths.push(token);
      continue;
    }

    const equals = token.indexOf('=');
    const flag = equals === -1 ? token : token.slice(0, equals);
    const inline = equals === -1 ? undefined : token.slice(equals + 1);

    switch (flag) {
      case '--staged':
        options.staged = true;
        break;
      case '--format': {
        const result = valueFor(argv, index, '--format', inline);
        if (!FORMATS.includes(result.value as OutputFormat)) {
          throw new UsageError(`--format must be one of: ${FORMATS.join(', ')}.`);
        }
        options.format = result.value as OutputFormat;
        index = result.next;
        break;
      }
      case '--out': {
        const result = valueFor(argv, index, '--out', inline);
        options.out = result.value;
        index = result.next;
        break;
      }
      case '--fail-on': {
        const result = valueFor(argv, index, '--fail-on', inline);
        if (!FAIL_LEVELS.includes(result.value as FailLevel)) {
          throw new UsageError(`--fail-on must be one of: ${FAIL_LEVELS.join(', ')}.`);
        }
        options.failOn = result.value as FailLevel;
        index = result.next;
        break;
      }
      case '--config': {
        const result = valueFor(argv, index, '--config', inline);
        options.configPath = result.value;
        index = result.next;
        break;
      }
      case '--exclude': {
        const result = valueFor(argv, index, '--exclude', inline);
        options.excludePatterns.push(result.value);
        index = result.next;
        break;
      }
      case '--no-color':
        options.noColor = true;
        break;
      case '--no-entropy':
        options.entropy = false;
        break;
      case '--quiet':
        options.quiet = true;
        break;
      default:
        throw new UsageError(`Unknown option: ${token}`);
    }
  }

  return options;
}

function severityColor(severity: string, color: boolean): string {
  if (!color) return severity.padEnd(8);
  const codes: Record<string, string> = {
    critical: '\u001b[1;31m',
    high: '\u001b[1;35m',
    medium: '\u001b[1;33m',
    low: '\u001b[1;36m'
  };
  return `${codes[severity] ?? ''}${severity.padEnd(8)}\u001b[0m`;
}

function renderRules(color: boolean): string {
  const rows: Array<{ id: string; severity: string; name: string }> = [
    ...RULES.map(rule => ({ id: rule.id, severity: rule.severity, name: rule.name })),
    ...FILE_RULES.map(rule => ({ id: rule.id, severity: rule.severity, name: rule.name })),
    { id: 'high-entropy', severity: 'low', name: 'High-entropy string' }
  ];
  const idWidth = Math.max(...rows.map(row => row.id.length)) + 2;
  const lines = [`${'ID'.padEnd(idWidth)}SEVERITY  NAME`];
  for (const row of rows) {
    lines.push(`${row.id.padEnd(idWidth)}${severityColor(row.severity, color)}  ${row.name}`);
  }
  const counts = rows.reduce<Record<string, number>>((accumulator, row) => {
    accumulator[row.severity] = (accumulator[row.severity] ?? 0) + 1;
    return accumulator;
  }, {});
  lines.push('');
  lines.push(
    `${rows.length} rules: ${(Object.keys(counts) as Array<keyof typeof counts>)
      .map(severity => `${counts[severity]} ${severity}`)
      .join(' · ')}`
  );
  return `${lines.join('\n')}\n`;
}

function shouldFail(findings: Finding[], level: FailLevel): boolean {
  if (level === 'none') return false;
  const threshold = SEVERITY_ORDER[level];
  return findings.some(finding => SEVERITY_ORDER[finding.severity] >= threshold);
}

export interface CliIo {
  cwd: string;
  env: NodeJS.ProcessEnv;
  isTTY: boolean;
  stdout: (text: string) => void;
  stderr: (text: string) => void;
}

export async function runCli(argv: string[], io: CliIo): Promise<number> {
  let options: CliOptions;
  try {
    options = parseArgs(argv);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    io.stderr(`envsentinel: ${message}\n`);
    io.stderr('Run "envsentinel --help" for usage.\n');
    return 2;
  }

  const color = !options.noColor && io.env.NO_COLOR === undefined && io.isTTY;

  if (options.command === 'help') {
    io.stdout(HELP);
    return 0;
  }
  if (options.command === 'version') {
    io.stdout(`${VERSION}\n`);
    return 0;
  }
  if (options.command === 'rules') {
    io.stdout(renderRules(color));
    return 0;
  }

  try {
    if (options.command === 'install-hook') {
      const result = await installHook(io.cwd, options.force);
      const verb = result.replaced ? 'Replaced' : 'Installed';
      io.stdout(`${verb} pre-commit hook at ${result.path}\n`);
      io.stdout('The hook runs "envsentinel scan --staged --fail-on high" before each commit.\n');
      return 0;
    }

    const config = await loadConfig(io.cwd, options.configPath);
    const summary = await scanPaths({
      cwd: io.cwd,
      paths: options.paths,
      staged: options.staged,
      config,
      excludePatterns: options.excludePatterns,
      entropy: options.entropy
    });

    let report: string;
    if (options.format === 'json') report = renderJson(summary, VERSION);
    else if (options.format === 'sarif') report = `${JSON.stringify(buildSarif(summary, VERSION), null, 2)}\n`;
    else report = renderText(summary, { version: VERSION, color: color && options.out === undefined });

    if (options.out === undefined || options.out === '-') {
      io.stdout(report);
    } else {
      const target = resolve(io.cwd, options.out);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, report, 'utf8');
      if (!options.quiet) {
        const shown = normalizePath(relative(io.cwd, target)) || target;
        const count = summary.findings.length;
        io.stdout(`Wrote ${shown} (${count} ${count === 1 ? 'finding' : 'findings'}).\n`);
      }
    }

    return shouldFail(summary.findings, options.failOn) ? 1 : 0;
  } catch (error) {
    if (error instanceof ScanError || error instanceof GitError) {
      io.stderr(`envsentinel: ${error.message}\n`);
      return 2;
    }
    const message = error instanceof Error ? error.message : String(error);
    io.stderr(`envsentinel: ${message}\n`);
    return 2;
  }
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(resolve(entry)).href) {
  void runCli(process.argv.slice(2), {
    cwd: process.cwd(),
    env: process.env,
    isTTY: process.stdout.isTTY === true,
    stdout: text => process.stdout.write(text),
    stderr: text => process.stderr.write(text)
  }).then(code => {
    process.exitCode = code;
  });
}

export { parseArgs };
