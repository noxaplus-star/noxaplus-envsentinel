export { DEFAULT_CONFIG, DEFAULT_IGNORE_PATHS, ConfigError, globToRegExp, isIgnored, loadConfig, matchesGlob, normalizePath, parseConfig } from './config.js';
export { shannonEntropy } from './entropy.js';
export { HOOK_SCRIPT, GitError, installHook, isGitRepository, listStagedFiles, listTrackedFiles, readStagedFile, repositoryRoot } from './git.js';
export { countBySeverity, renderJson, renderText } from './report.js';
export { FILE_RULES, RULES, ruleById } from './rules.js';
export { buildSarif } from './sarif.js';
export { highestSeverity, isPlaceholder, maskValue, scanContent, scanPaths, ScanError } from './scanner.js';
export type { FailLevel, Finding, OutputFormat, Rule, ScanOptions, ScanSummary, ScannerConfig, Severity } from './types.js';
export { SEVERITY_ORDER } from './types.js';
