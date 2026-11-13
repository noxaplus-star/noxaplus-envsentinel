import { execFileSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, normalize, resolve } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  GitError,
  HOOK_MARKER,
  installHook,
  isGitRepository,
  listStagedFiles,
  readStagedFile,
  repositoryRoot
} from '../src/git.js';

let workspace: string;

function git(args: string[]): string {
  return execFileSync('git', args, { cwd: workspace, encoding: 'utf8' });
}

beforeEach(async () => {
  workspace = await mkdtemp(join(tmpdir(), 'envsentinel-git-'));
});

afterEach(async () => {
  await rm(workspace, { recursive: true, force: true });
});

describe('git integration', () => {
  it('detects a repository and its root', () => {
    expect(isGitRepository(workspace)).toBe(false);
    git(['init', '-q']);
    expect(isGitRepository(workspace)).toBe(true);
    expect(normalize(realpathSync.native(repositoryRoot(workspace))).toLowerCase()).toBe(
      normalize(realpathSync.native(resolve(workspace))).toLowerCase()
    );
  });

  it('reads staged content, not the working tree', async () => {
    git(['init', '-q']);
    git(['config', 'user.email', 'test@example.com']);
    git(['config', 'user.name', 'Test']);
    await writeFile(join(workspace, 'app.ts'), 'staged content\n', 'utf8');
    git(['add', 'app.ts']);
    await writeFile(join(workspace, 'app.ts'), 'working tree content\n', 'utf8');

    expect(listStagedFiles(workspace)).toEqual(['app.ts']);
    expect(readStagedFile(workspace, 'app.ts').toString('utf8')).toBe('staged content\n');
  });

  it('installs, refuses to overwrite, and replaces with --force', async () => {
    git(['init', '-q']);
    const first = await installHook(workspace, false);
    expect(first.replaced).toBe(false);
    const hook = await readFile(first.path, 'utf8');
    expect(hook).toContain(HOOK_MARKER);
    expect(hook).toContain('--staged --fail-on high');

    await writeFile(first.path, '#!/bin/sh\necho foreign hook\n', 'utf8');
    await expect(installHook(workspace, false)).rejects.toBeInstanceOf(GitError);
    const second = await installHook(workspace, true);
    expect(second.replaced).toBe(true);
    expect(await readFile(second.path, 'utf8')).toContain(HOOK_MARKER);
  });

  it('fails when outside a git repository', async () => {
    await expect(installHook(workspace, false)).rejects.toBeInstanceOf(GitError);
  });
});
