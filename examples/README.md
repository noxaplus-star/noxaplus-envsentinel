# Example configuration

`envsentinel.config.json` shows every supported field with its default value. Copy it to the root of your repository as `.envsentinel.json` and edit what you need.

```bash
cp examples/envsentinel.config.json .envsentinel.json
envsentinel scan
```

| Field | Default | Notes |
| --- | --- | --- |
| `ignorePaths` | built-in list | Extra globs. Added to the defaults, not a replacement. |
| `ignoreRules` | `[]` | Rule IDs from `envsentinel rules`. |
| `allowPatterns` | `[]` | JavaScript regular expressions, matched against the raw value. |
| `entropyThreshold` | `4.5` | Raise it to reduce noise from hashes and encoded data. |
| `entropyMinLength` | `32` | Shortest candidate the entropy rule considers. |
| `maxFileSizeKb` | `1024` | Files larger than this are skipped. |

The built-in ignore list already covers `.git`, dependencies, build output, lockfiles, minified assets, and common binary formats. Add only what is specific to your repository.

This directory intentionally contains no secrets. Tests and examples in this project construct fake values at runtime so the repository can scan itself cleanly.
