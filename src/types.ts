export type Severity = 'low' | 'medium' | 'high' | 'critical';

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};

export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  pattern: RegExp;
  secretGroup?: number;
  hideMatch?: boolean;
}

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  file: string;
  line: number;
  column: number;
  match: string;
  message: string;
  entropy?: number;
}

export interface ScannerConfig {
  ignorePaths: string[];
  ignoreRules: string[];
  allowPatterns: string[];
  entropyThreshold: number;
  entropyMinLength: number;
  maxFileSize: number;
}

export interface ScanSummary {
  filesScanned: number;
  filesSkipped: number;
  findings: Finding[];
  durationMs: number;
  root: string;
  mode: 'tree' | 'staged';
}

export type OutputFormat = 'text' | 'json' | 'sarif';

export type FailLevel = Severity | 'none';

export interface ScanOptions {
  cwd: string;
  paths: string[];
  staged: boolean;
  config: ScannerConfig;
  excludePatterns?: string[];
  entropy?: boolean;
}

export interface CliOptions {
  command: 'scan' | 'install-hook' | 'rules' | 'help' | 'version';
  paths: string[];
  staged: boolean;
  format: OutputFormat;
  out?: string;
  failOn: FailLevel;
  configPath?: string;
  noColor: boolean;
  quiet: boolean;
  force: boolean;
  entropy: boolean;
  excludePatterns: string[];
}

export const DEFAULT_FAIL_ON: FailLevel = 'high';
