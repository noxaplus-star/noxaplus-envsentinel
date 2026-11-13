import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  ConfigError,
  DEFAULT_CONFIG,
  DEFAULT_IGNORE_PATHS,
  globToRegExp,
  isIgnored,
  loadConfig,
  matchesGlob,
  parseConfig
} from '../src/config.js';

let workspace: string;

beforeEach(async () => {
  workspace = await mkdtemp(join(tmpdir(), 'envsentinel-config-'));
});

afterEach(async () => {
  await rm(workspace, { recursive: true, force: true });
});

describe('parseConfig', () => {
  it('returns defaults for an empty object', () => {
    const config = parseConfig('{}', '.envsentinel.json');
    expect(config.ignorePaths).toEqual(DEFAULT_IGNORE_PATHS);
    expect(config.entropyThreshold).toBe(DEFAULT_CONFIG.entropyThreshold);
    expect(config.maxFileSize).toBe(DEFAULT_CONFIG.maxFileSize);
  });

  it('merges custom ignore paths after the defaults', () => {
    const config = parseConfig(JSON.stringify({ ignorePaths: ['fixtures/**'] }), 'config.json');
    expect(config.ignorePaths).toContain('node_modules');
    expect(config.ignorePaths).toContain('fixtures/**');
  });

  it('converts maxFileSizeKb into bytes', () => {
    expect(parseConfig(JSON.stringify({ maxFileSizeKb: 2 }), 'c.json').maxFileSize).toBe(2048);
  });

  it('rejects invalid JSON', () => {
    expect(() => parseConfig('{oops', 'c.json')).toThrow(ConfigError);
  });

  it('rejects non-array ignore paths', () => {
    expect(() => parseConfig(JSON.stringify({ ignorePaths: 'dist' }), 'c.json')).toThrow(ConfigError);
  });

  it('rejects invalid allow patterns', () => {
    expect(() => parseConfig(JSON.stringify({ allowPatterns: ['('] }), 'c.json')).toThrow(ConfigError);
  });

  it('rejects invalid numbers', () => {
    expect(() => parseConfig(JSON.stringify({ entropyThreshold: -1 }), 'c.json')).toThrow(ConfigError);
  });
});

describe('loadConfig', () => {
  it('returns defaults when the default file is absent', async () => {
    const config = await loadConfig(workspace);
    expect(config.ignorePaths).toEqual(DEFAULT_IGNORE_PATHS);
  });

  it('reads .envsentinel.json from the working directory', async () => {
    await writeFile(join(workspace, '.envsentinel.json'), JSON.stringify({ ignoreRules: ['jwt'] }), 'utf8');
    const config = await loadConfig(workspace);
    expect(config.ignoreRules).toEqual(['jwt']);
  });

  it('reads an explicit relative path', async () => {
    await writeFile(join(workspace, 'sentinel.json'), JSON.stringify({ entropyMinLength: 40 }), 'utf8');
    const config = await loadConfig(workspace, 'sentinel.json');
    expect(config.entropyMinLength).toBe(40);
  });

  it('fails when an explicit path is missing', async () => {
    await expect(loadConfig(workspace, 'missing.json')).rejects.toBeInstanceOf(ConfigError);
  });
});

describe('path matching', () => {
  it('builds glob expressions with double-star support', () => {
    const regex = globToRegExp('dist/**/*.js');
    expect(regex.test('dist/a/b.js')).toBe(true);
    expect(regex.test('src/a/b.js')).toBe(false);
  });

  it('matches basenames for patterns without slashes', () => {
    expect(matchesGlob('*.min.js', 'assets/app.min.js')).toBe(true);
    expect(matchesGlob('*.min.js', 'assets/app.js')).toBe(false);
  });

  it('ignores a directory anywhere in the path', () => {
    expect(isIgnored('packages/app/node_modules/pkg/index.js', ['node_modules'])).toBe(true);
    expect(isIgnored('src/node_modules.ts', ['node_modules'])).toBe(false);
  });

  it('ignores exact paths and globs', () => {
    expect(isIgnored('dist/bundle.js', ['dist/**'])).toBe(true);
    expect(isIgnored('package-lock.json', ['package-lock.json'])).toBe(true);
    expect(isIgnored('src/app.ts', ['*.png'])).toBe(false);
  });
});
