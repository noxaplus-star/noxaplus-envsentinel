import { readFile } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';
import type { ScannerConfig } from './types.js';

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

export const DEFAULT_IGNORE_PATHS = [
  '.git',
  'node_modules',
  'dist',
  'build',
  'coverage',
  'vendor',
  '.next',
  '.nuxt',
  '.cache',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  '*.min.js',
  '*.min.css',
  '*.map',
  '*.png',
  '*.jpg',
  '*.jpeg',
  '*.gif',
  '*.webp',
  '*.ico',
  '*.pdf',
  '*.zip',
  '*.gz',
  '*.tgz',
  '*.tar',
  '*.7z',
  '*.woff',
  '*.woff2',
  '*.ttf',
  '*.eot',
  '*.mp3',
  '*.mp4',
  '*.mov',
  '*.wasm',
  '*.class',
  '*.jar',
  '*.exe',
  '*.dll',
  '*.so',
  '*.dylib'
];

export const DEFAULT_CONFIG: ScannerConfig = {
  ignorePaths: [...DEFAULT_IGNORE_PATHS],
  ignoreRules: [],
  allowPatterns: [],
  entropyThreshold: 4.5,
  entropyMinLength: 32,
  maxFileSize: 1024 * 1024
};

export function normalizePath(value: string): string {
  return value.replace(/\\/g, '/').replace(/^\.\//, '');
}

export function globToRegExp(pattern: string): RegExp {
  let source = '';
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index] ?? '';
    if (character === '*') {
      if (pattern[index + 1] === '*') {
        if (pattern[index + 2] === '/') {
          source += '(?:.*/)?';
          index += 2;
        } else {
          source += '.*';
          index += 1;
        }
      } else {
        source += '[^/]*';
      }
    } else if (character === '?') {
      source += '[^/]';
    } else if ('\\^$+.()|{}[]'.includes(character)) {
      source += `\\${character}`;
    } else {
      source += character;
    }
  }
  return new RegExp(`^${source}$`);
}

export function matchesGlob(pattern: string, relativePath: string): boolean {
  const normalizedPattern = normalizePath(pattern).replace(/\/+$/, '');
  const normalizedPath = normalizePath(relativePath).replace(/\/+$/, '');
  if (normalizedPattern === '') return false;
  const base = normalizedPath.split('/').at(-1) ?? normalizedPath;
  const regex = globToRegExp(normalizedPattern);
  if (regex.test(normalizedPath)) return true;
  if (!normalizedPattern.includes('/')) return regex.test(base);
  return false;
}

export function isIgnored(relativePath: string, patterns: string[]): boolean {
  const normalized = normalizePath(relativePath).replace(/\/+$/, '');
  const segments = normalized.split('/');
  for (const pattern of patterns) {
    const normalizedPattern = normalizePath(pattern).replace(/\/+$/, '');
    if (normalizedPattern === '') continue;
    if (!normalizedPattern.includes('*') && !normalizedPattern.includes('?')) {
      if (!normalizedPattern.includes('/')) {
        if (segments.includes(normalizedPattern)) return true;
        continue;
      }
      if (normalized === normalizedPattern || normalized.startsWith(`${normalizedPattern}/`)) return true;
      continue;
    }
    if (matchesGlob(normalizedPattern, normalized)) return true;
  }
  return false;
}

interface RawConfig {
  ignorePaths?: unknown;
  ignoreRules?: unknown;
  allowPatterns?: unknown;
  entropyThreshold?: unknown;
  entropyMinLength?: unknown;
  maxFileSizeKb?: unknown;
}

function stringArray(value: unknown, field: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some(item => typeof item !== 'string')) {
    throw new ConfigError(`"${field}" must be an array of strings.`);
  }
  return value as string[];
}

function positiveNumber(value: unknown, field: string, fallback: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new ConfigError(`"${field}" must be a positive number.`);
  }
  return value;
}

export function parseConfig(text: string, source: string): ScannerConfig {
  let raw: RawConfig;
  try {
    raw = JSON.parse(text) as RawConfig;
  } catch {
    throw new ConfigError(`Could not parse ${source}. It must contain valid JSON.`);
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ConfigError(`${source} must contain a JSON object.`);
  }

  const ignorePaths = stringArray(raw.ignorePaths, 'ignorePaths');
  const ignoreRules = stringArray(raw.ignoreRules, 'ignoreRules');
  const allowPatterns = stringArray(raw.allowPatterns, 'allowPatterns');
  const maxFileSizeKb = positiveNumber(raw.maxFileSizeKb, 'maxFileSizeKb', DEFAULT_CONFIG.maxFileSize / 1024);

  for (const pattern of allowPatterns) {
    try {
      new RegExp(pattern);
    } catch {
      throw new ConfigError(`allowPatterns contains an invalid regular expression: ${pattern}`);
    }
  }

  return {
    ignorePaths: [...DEFAULT_IGNORE_PATHS, ...ignorePaths],
    ignoreRules,
    allowPatterns,
    entropyThreshold: positiveNumber(raw.entropyThreshold, 'entropyThreshold', DEFAULT_CONFIG.entropyThreshold),
    entropyMinLength: Math.round(positiveNumber(raw.entropyMinLength, 'entropyMinLength', DEFAULT_CONFIG.entropyMinLength)),
    maxFileSize: Math.round(maxFileSizeKb * 1024)
  };
}

export async function loadConfig(cwd: string, explicitPath?: string): Promise<ScannerConfig> {
  const target =
    explicitPath === undefined
      ? resolve(cwd, '.envsentinel.json')
      : isAbsolute(explicitPath)
        ? explicitPath
        : resolve(cwd, explicitPath);
  let text: string;
  try {
    text = await readFile(target, 'utf8');
  } catch (error) {
    if (explicitPath !== undefined) {
      throw new ConfigError(`Could not read config file "${explicitPath}".`);
    }
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return { ...DEFAULT_CONFIG, ignorePaths: [...DEFAULT_CONFIG.ignorePaths] };
    }
    throw new ConfigError(`Could not read ${target}.`);
  }
  return parseConfig(text, explicitPath ?? '.envsentinel.json');
}
