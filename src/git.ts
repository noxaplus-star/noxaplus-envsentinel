import { execFileSync } from 'node:child_process';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';

export class GitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GitError';
  }
}

function runGit(args: string[], cwd: string): string {
  try {
    return execFileSync('git', args, {
      cwd,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe']
    });
  } catch (error) {
    const stderr = (error as { stderr?: string }).stderr?.trim();
    throw new GitError(stderr && stderr.length > 0 ? stderr : 'Git command failed. Is this a git repository?');
  }
}

function runGitBuffer(args: string[], cwd: string): Buffer {
  try {
    return execFileSync('git', args, {
      cwd,
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe']
    });
  } catch (error) {
    const stderr = (error as { stderr?: Buffer }).stderr?.toString('utf8').trim();
    throw new GitError(stderr && stderr.length > 0 ? stderr : 'Git command failed. Is this a git repository?');
  }
}

export function isGitRepository(cwd: string): boolean {
  try {
    return runGit(['rev-parse', '--is-inside-work-tree'], cwd).trim() === 'true';
  } catch {
    return false;
  }
}

export function repositoryRoot(cwd: string): string {
  return resolve(runGit(['rev-parse', '--show-toplevel'], cwd).trim());
}

export function listStagedFiles(cwd: string): string[] {
  return runGit(['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'], cwd)
    .split('\0')
    .filter(entry => entry.length > 0);
}

export function readStagedFile(cwd: string, relativePath: string): Buffer {
  return runGitBuffer(['show', `:${relativePath}`], cwd);
}

export function listTrackedFiles(cwd: string): Set<string> {
  const output = runGit(['ls-files', '-z'], cwd);
  return new Set(output.split('\0').filter(entry => entry.length > 0));
}

export const HOOK_MARKER = 'Installed by NoxaPlus EnvSentinel';

export const HOOK_SCRIPT = `#!/bin/sh
# ${HOOK_MARKER}. Remove this file to stop scanning before commits.
ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$ROOT" ]; then
  echo "EnvSentinel: not inside a git work tree." >&2
  exit 0
fi
if [ -x "$ROOT/node_modules/.bin/envsentinel" ]; then
  exec "$ROOT/node_modules/.bin/envsentinel" scan --staged --fail-on high
fi
if command -v envsentinel >/dev/null 2>&1; then
  exec envsentinel scan --staged --fail-on high
fi
echo "EnvSentinel: command not found. Install it with npm install -g noxaplus-envsentinel, then commit again." >&2
exit 1
`;

export interface HookResult {
  path: string;
  replaced: boolean;
}

export async function installHook(cwd: string, force: boolean): Promise<HookResult> {
  if (!isGitRepository(cwd)) {
    throw new GitError('Not inside a git repository. Run this command from a project that uses git.');
  }
  const gitDirOutput = runGit(['rev-parse', '--git-dir'], cwd).trim();
  const gitDir = isAbsolute(gitDirOutput) ? gitDirOutput : resolve(cwd, gitDirOutput);
  const hooksDir = join(gitDir, 'hooks');
  const hookPath = join(hooksDir, 'pre-commit');

  let replaced = false;
  if (existsSync(hookPath)) {
    const existing = await readFile(hookPath, 'utf8');
    if (!existing.includes(HOOK_MARKER) && !force) {
      throw new GitError(`A pre-commit hook already exists at ${hookPath}. Re-run with --force to replace it.`);
    }
    replaced = true;
  }

  await mkdir(hooksDir, { recursive: true });
  await writeFile(hookPath, HOOK_SCRIPT, 'utf8');
  try {
    await chmod(hookPath, 0o755);
  } catch {
    // Windows does not use POSIX modes; Git for Windows still runs the hook.
  }
  return { path: hookPath, replaced };
}
