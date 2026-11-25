# arca-guhya

A zero-dependency secrets scanner for source trees: provider-specific rules, Shannon-entropy detection, allowlists, baselines and SARIF output.

*arca* (Latin, strongbox) + *guhya* (Sanskrit, hidden, secret) - it finds what should have stayed locked away.

> Only scan systems and code you own or are authorized to test.

## Features

- **16 provider rules**: AWS access key IDs and secret keys, GitHub classic and fine-grained tokens, GitLab, Slack tokens and webhooks, Stripe live/test keys, Google API keys, npm, SendGrid, Twilio, JWTs, private key blocks (RSA/EC/DSA/OpenSSH/PGP), passwords embedded in URLs.
- **Generic high-entropy detector**: quoted or assigned values of 20+ characters are scored with Shannon entropy, normalised for length and alphabet (hex vs base64). Bare hex strings are only reported next to words such as `secret`, `token` or `key`, so commit hashes do not drown the output. Lockfiles, minified files and source maps skip this detector.
- **Respects `.gitignore`**, including nested ignore files, negation (`!`), `**`, anchored and directory-only patterns. Always skips `.git`, `node_modules`, virtualenvs and caches; binary files (by extension or NUL bytes) and files over 1 MB are skipped.
- **Secrets are always masked** in every output format (`ghp_*****...Gi`); the raw value never leaves the process.
- **Allowlist file** (`.arca-allowlist` in the scan root is picked up automatically) and inline `arca:allow` comments.
- **Baseline file**: record today's accepted findings and only fail on new ones. Fingerprints are hashes of rule + path + secret, so they survive the secret moving to another line, and the baseline file itself never contains secrets.
- **Text, JSON and SARIF 2.1.0** output - SARIF uploads straight into GitHub code scanning.
- CI-friendly exit codes: `0` clean, `1` findings, `2` usage or I/O error.

## Install

```sh
pip install .
# or without installing
python -m arca_guhya --help
```

## Usage

```sh
arca-guhya                       # scan the current directory
arca-guhya path/to/repo --min-severity high
arca-guhya . --format sarif -o results.sarif
arca-guhya . --json
arca-guhya . --write-baseline .arca-baseline.json   # accept existing findings
arca-guhya . --baseline .arca-baseline.json         # fail only on new ones
arca-guhya --list-rules
```

Example run against a small demo repository (with `app.log` excluded by its `.gitignore`):

```text
$ arca-guhya demo-repo
CRITICAL  private-key            deploy/id_rsa:1:1
          Private key block
          -----BEGIN OPENSSH PRIVATE KEY-----
          fingerprint 610a94b1c631cc43
CRITICAL  stripe-live-key        src/billing.js:1:35
          Stripe live secret or restricted key
          const stripe = require('stripe')('sk_l**************************Bc');
          fingerprint d75b86c98de1fc35
HIGH      aws-access-key-id      src/settings.py:2:22
          AWS access key ID
          AWS_ACCESS_KEY_ID = "AKIA**************XZ"
          fingerprint 64b985a11b2570b2
HIGH      github-token           src/settings.py:3:17
          GitHub token (personal, OAuth, app or refresh)
          GITHUB_TOKEN = "ghp_***********************************Gi"
          fingerprint 3199d0755cd4fa75
MEDIUM    high-entropy-string    src/settings.py:4:19
          High-entropy string (possible secret) (entropy 4.95 bits/char)
          SESSION_SECRET = "Vq9t*************************Ac"
          fingerprint 82b3e9cf187b5e71

5 finding(s): 2 critical, 2 high, 1 medium  (scanned 4 file(s), skipped 1)
```

### Allowlist format

One entry per line in `.arca-allowlist` (or any file passed with `--allowlist`):

```text
# comments are fine
rule:stripe-test-key          # silence a rule everywhere
path:tests/fixtures/*         # glob on the relative path; bare lines are paths too
regex:^AKIAIOSFODNN7          # regex searched in the secret value
fingerprint:82b3e9cf187b5e71  # one specific finding
```

To silence a single line in code, add a comment containing `arca:allow`.

### GitHub Actions

```yaml
- run: pip install ./arca-guhya
- run: arca-guhya . --format sarif -o arca.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: arca.sarif
```

## How it works

1. The tree is walked top-down; `.gitignore` files are loaded as they are encountered and applied relative to their own directory, and ignored directories are pruned without being entered.
2. Each text line is matched against the provider rules first. Their matched spans are reserved so the entropy detector never double-reports the same characters.
3. Entropy candidates are values after a quote, `=` or `:`. A candidate is reported when it mixes letters and digits, has at least 3.5 bits/char and reaches 85% of the maximum entropy possible for its length and alphabet.
4. Findings are filtered by severity, baseline fingerprints and the allowlist, then rendered as text, JSON or SARIF with secrets masked.

## Running the tests

```sh
python -m unittest discover -s tests
```

Test fixtures assemble fake credentials at runtime; `.arca-allowlist` excludes `tests/` and the sample output above, so a self-scan of this repository is clean.

## License

MIT - see [LICENSE](LICENSE).
