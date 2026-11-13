import type { Rule, Severity } from './types.js';

export interface FileRule {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  message: string;
  matches: (baseName: string) => boolean;
}

export const RULES: Rule[] = [
  {
    id: 'aws-access-key-id',
    name: 'AWS access key ID',
    severity: 'critical',
    description: 'An AWS access key ID can be used to identify an account and pair with a secret key.',
    pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b/g
  },
  {
    id: 'aws-secret-access-key',
    name: 'AWS secret access key',
    severity: 'critical',
    description: 'An AWS secret access key is assigned in plain text.',
    pattern: /(?:aws_?secret_?access_?key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    secretGroup: 1
  },
  {
    id: 'github-token',
    name: 'GitHub token',
    severity: 'critical',
    description: 'A GitHub personal access, OAuth, app, or fine-grained token is present.',
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g
  },
  {
    id: 'gitlab-token',
    name: 'GitLab token',
    severity: 'critical',
    description: 'A GitLab personal access token is present.',
    pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g
  },
  {
    id: 'google-api-key',
    name: 'Google API key',
    severity: 'high',
    description: 'A Google API key is present. Unrestricted keys can bill and expose enabled services.',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g
  },
  {
    id: 'stripe-live-key',
    name: 'Stripe live key',
    severity: 'critical',
    description: 'A Stripe live secret or restricted key is present.',
    pattern: /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/g
  },
  {
    id: 'stripe-test-key',
    name: 'Stripe test key',
    severity: 'low',
    description: 'A Stripe test key is present. It cannot move real money, but it still should not be committed.',
    pattern: /\b(?:sk|rk)_test_[0-9A-Za-z]{16,}\b/g
  },
  {
    id: 'slack-token',
    name: 'Slack token',
    severity: 'critical',
    description: 'A Slack bot, app, user, or refresh token is present.',
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g
  },
  {
    id: 'slack-webhook',
    name: 'Slack webhook URL',
    severity: 'high',
    description: 'A Slack incoming webhook can post messages into a workspace.',
    pattern: /\bhttps:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{16,}\b/g
  },
  {
    id: 'sendgrid-key',
    name: 'SendGrid API key',
    severity: 'critical',
    description: 'A SendGrid API key can send email as the account owner.',
    pattern: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{30,}\b/g
  },
  {
    id: 'npm-token',
    name: 'npm token',
    severity: 'high',
    description: 'An npm access token can publish packages and read private registries.',
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g
  },
  {
    id: 'anthropic-key',
    name: 'Anthropic API key',
    severity: 'high',
    description: 'An Anthropic API key is present and can spend account credits.',
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g
  },
  {
    id: 'openai-key',
    name: 'OpenAI API key',
    severity: 'high',
    description: 'An OpenAI API key is present and can spend account credits.',
    pattern: /\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/g
  },
  {
    id: 'huggingface-token',
    name: 'Hugging Face token',
    severity: 'high',
    description: 'A Hugging Face access token can read or write private models and datasets.',
    pattern: /\bhf_[A-Za-z0-9]{30,}\b/g
  },
  {
    id: 'digitalocean-token',
    name: 'DigitalOcean token',
    severity: 'critical',
    description: 'A DigitalOcean personal access token is present.',
    pattern: /\bdop_v1_[a-f0-9]{64}\b/g
  },
  {
    id: 'discord-bot-token',
    name: 'Discord bot token',
    severity: 'high',
    description: 'A Discord bot token can control the bot and read its servers.',
    pattern: /\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b/g
  },
  {
    id: 'private-key',
    name: 'Private key material',
    severity: 'critical',
    description: 'A PEM private key block is present in a text file.',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    hideMatch: true
  },
  {
    id: 'jwt',
    name: 'JSON Web Token',
    severity: 'medium',
    description: 'A JSON Web Token is embedded in the file. Treat it as a credential until it expires.',
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g
  },
  {
    id: 'database-url',
    name: 'Database URL with credentials',
    severity: 'high',
    description: 'A database connection string includes a username and password.',
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^\s:@/]+:[^\s@/]+@[^\s"'`]+/gi
  },
  {
    id: 'url-credentials',
    name: 'URL with embedded credentials',
    severity: 'high',
    description: 'A URL embeds a username and password in the authority section.',
    pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@[^\s"'`]+/gi
  },
  {
    id: 'generic-assignment',
    name: 'Credential-like assignment',
    severity: 'high',
    description: 'A value is assigned to a credential-like name, such as password, token, or api_key.',
    pattern: /(?:api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?key|auth[_-]?token|token|password|passwd|pwd|client[_-]?secret|private[_-]?key)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-./+=]{12,})["']?/gi,
    secretGroup: 1
  },
  {
    id: 'mailgun-key',
    name: 'Mailgun key',
    severity: 'medium',
    description: 'A Mailgun API key is present.',
    pattern: /\bkey-[0-9a-zA-Z]{32}\b/g
  }
];

export const FILE_RULES: FileRule[] = [
  {
    id: 'env-file',
    name: 'Committed environment file',
    severity: 'high',
    description: 'A .env file is a common place to keep real credentials and usually should not be committed.',
    message: 'Environment file is included in git. Add it to .gitignore and rotate any real values it contains.',
    matches: baseName => /^\.env(?:\.(?!example|sample|template|dist).+)?$/.test(baseName)
  },
  {
    id: 'private-key-file',
    name: 'Private key file',
    severity: 'critical',
    description: 'Private key files should never be committed to a repository.',
    message: 'A private key file is included in git. Remove it from the index and rotate the key.',
    matches: baseName => /^(?:id_(?:rsa|dsa|ecdsa|ed25519)|.+\.key)$/.test(baseName)
  },
  {
    id: 'credentials-file',
    name: 'Credentials file',
    severity: 'high',
    description: 'Credential stores and service account files often contain long-lived secrets.',
    message: 'A credentials file is included in git. Remove it from the index and rotate any values it contains.',
    matches: baseName => /^(?:credentials\.json|service-account[^/]*\.json|serviceAccount[^/]*\.json|\.netrc|\.pypirc)$/i.test(baseName)
  },
  {
    id: 'npmrc-file',
    name: 'npm configuration',
    severity: 'medium',
    description: 'An .npmrc file can contain an npm auth token.',
    message: 'An .npmrc file is included in git. Commit a token-free version or add it to .gitignore.',
    matches: baseName => baseName === '.npmrc'
  }
];

export function ruleById(id: string): Rule | undefined {
  return RULES.find(rule => rule.id === id);
}
