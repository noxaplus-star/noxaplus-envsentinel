import { describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG } from '../src/config.js';
import { isPlaceholder, maskValue, scanContent } from '../src/scanner.js';

const AWS_KEY = `AKIA${'IOSFODNN7EXAMPLQ'}`;
const GITHUB_TOKEN = `ghp_${'a1'.repeat(18)}`;
const GITLAB_TOKEN = `glpat-${'a'.repeat(20)}`;
const GOOGLE_KEY = `AIza${'A1'.repeat(17)}A`;
const STRIPE_LIVE = `sk_live_${'a'.repeat(24)}`;
const STRIPE_TEST = `sk_test_${'a'.repeat(24)}`;
const SLACK_TOKEN = `xoxb-${'1234567890'}-${'abcdef'}`;
const SENDGRID_KEY = `SG.${'a'.repeat(22)}.${'b'.repeat(43)}`;
const NPM_TOKEN = `npm_${'a1'.repeat(18)}`;
const ANTHROPIC_KEY = `sk-ant-api03-${'a1'.repeat(10)}`;
const OPENAI_KEY = `sk-proj-${'a1'.repeat(10)}`;
const HUGGINGFACE_TOKEN = `hf_${'a1'.repeat(15)}`;
const DIGITALOCEAN_TOKEN = `dop_v1_${'a1'.repeat(32)}`;
const DISCORD_TOKEN = `M${'a1'.repeat(11)}a.abcdef.${'x'.repeat(27)}`;
const JWT_TOKEN = `eyJ${'hbGciOiJIUzI1NiJ9'}.eyJ${'zdWIiOiIxMjM0NTY3ODkwIn0'}.${'abcdefghijklmnop'}`;
const PRIVATE_KEY_HEADER = `-----BEGIN ${'OPENSSH '}PRIVATE KEY-----`;
const DATABASE_URL = `postgres${'://'}app:${'s3cr3tpass'}@db.internal:5432/prod`;
const URL_CREDENTIALS = `ftp${'://'}user:${'pass'}@example.com/file`;
const SAMPLE_VALUE = 'hunter2' + 'hunter2';
const MAILGUN_KEY = `key-${'a1'.repeat(16)}`;
const AWS_SECRET = `A1${'A1'.repeat(20)}`.slice(0, 40);
const SLACK_WEBHOOK = `https://hooks.slack.com/services/T${'00000001'}/B${'00000001'}/${'abcdefghijklmnop'}`;

function scan(line: string): string[] {
  const findings = scanContent('sample.txt', line, DEFAULT_CONFIG, { entropy: false });
  return findings.map(finding => finding.ruleId);
}

describe('secret rules', () => {
  const cases: Array<[string, string]> = [
    ['aws-access-key-id', `const key = "${AWS_KEY}";`],
    ['github-token', `const token = "${GITHUB_TOKEN}";`],
    ['gitlab-token', `const token = "${GITLAB_TOKEN}";`],
    ['google-api-key', `const key = "${GOOGLE_KEY}";`],
    ['stripe-live-key', `const key = "${STRIPE_LIVE}";`],
    ['stripe-test-key', `const key = "${STRIPE_TEST}";`],
    ['slack-token', `const token = "${SLACK_TOKEN}";`],
    ['sendgrid-key', `const key = "${SENDGRID_KEY}";`],
    ['npm-token', `const token = "${NPM_TOKEN}";`],
    ['anthropic-key', `const key = "${ANTHROPIC_KEY}";`],
    ['openai-key', `const key = "${OPENAI_KEY}";`],
    ['huggingface-token', `const token = "${HUGGINGFACE_TOKEN}";`],
    ['digitalocean-token', `const token = "${DIGITALOCEAN_TOKEN}";`],
    ['discord-bot-token', `const token = "${DISCORD_TOKEN}";`],
    ['jwt', `const token = "${JWT_TOKEN}";`],
    ['private-key', PRIVATE_KEY_HEADER],
    ['database-url', `const url = "${DATABASE_URL}";`],
    ['url-credentials', `const url = "${URL_CREDENTIALS}";`],
    ['generic-assignment', `const password = "${SAMPLE_VALUE}";`],
    ['mailgun-key', `const key = "${MAILGUN_KEY}";`],
    ['aws-secret-access-key', `aws_secret_access_key = "${AWS_SECRET}"`],
    ['slack-webhook', `const hook = "${SLACK_WEBHOOK}";`]
  ];

  for (const [ruleId, line] of cases) {
    it(`detects ${ruleId}`, () => {
      expect(scan(line)).toContain(ruleId);
    });
  }

  it('does not flag environment references or obvious placeholders', () => {
    const lines = [
      'const apiKey = process.env.API_KEY;',
      'password = "changeme"',
      'const token = "your_token_here";',
      'const key = "${API_KEY}";',
      'client_secret: "<insert-secret>"',
      'const secret = "xxxxxxxxxxxxxxxx";'
    ];
    for (const line of lines) {
      expect(scan(line)).toEqual([]);
    }
  });

  it('does not duplicate a specific token as a generic assignment', () => {
    const findings = scanContent('sample.txt', `const token = "${GITHUB_TOKEN}";`, DEFAULT_CONFIG, { entropy: false });
    expect(findings.map(finding => finding.ruleId)).toEqual(['github-token']);
  });
});

describe('masking and placeholders', () => {
  it('masks the middle of a value', () => {
    const masked = maskValue(AWS_KEY);
    expect(masked).not.toContain('IOSFODNN7EXAMPL');
    expect(masked.startsWith('AKIA')).toBe(true);
    expect(masked.endsWith('PLQ')).toBe(true);
  });

  it('fully masks short values', () => {
    expect(maskValue('short')).toBe('*****');
  });

  it('recognizes common placeholder values', () => {
    for (const value of ['changeme', 'example', 'your_key_here', '${TOKEN}', 'process.env.KEY', 'xxxxxxxx']) {
      expect(isPlaceholder(value)).toBe(true);
    }
    expect(isPlaceholder(SAMPLE_VALUE)).toBe(false);
  });
});
