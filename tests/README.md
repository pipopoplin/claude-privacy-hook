# Tests

Test suites for all four security hook layers plus the override system and persistent NLP service.

## Quick Start

```bash
# Run everything (604 tests)
python3 tests/run_all.py

# Skip slow service tests
python3 tests/run_all.py --fast
```

## Test Suites

| Suite | File | Cases | What it tests |
|-------|------|-------|---------------|
| **Regex Filter** | `test_regex_filter.py` | 518 | Pattern matching for Bash, Write/Edit, and Read rules |
| **NLP Filter** | `test_nlp_filter.py` | 39 | PII detection plugins + supplementary plugins |
| **Output Sanitizer** | `test_output_sanitizer.py` | 19 | Post-execution redaction of sensitive data in stdout/stderr |
| **Rate Limiter** | `test_rate_limiter.py` | 9 | Session-based violation threshold escalation |
| **Overrides** | `test_overrides.py` | 9 | Three-layer override resolver, CLI tool, audit logging |
| **NLP Service** | `test_nlp_service.py` | 10 | Persistent TCP service lifecycle, client auto-start, performance |

## Shared Infrastructure

`conftest.py` provides shared helpers used by all suites:

- **Path constants** — `PROJECT_ROOT`, `HOOKS_DIR`, all hook script and config paths
- **`run_hook()`** — run any PreToolUse hook and get back `"allow"`, `"warn"`, or `"block"`
- **`run_hook_raw()`** — run a hook and get the raw `subprocess.CompletedProcess`
- **`parse_decision()`** — parse hook output into `"allow"` / `"warn"` / `"block"`
- **`detected()`** — boolean: did the hook detect something?
- **`TestRunner`** — lightweight runner with `check()`, `run_fn()`, section headers, and summary

## Suite Details

### test_regex_filter.py

Tests the regex filter (`regex_filter.py`) against all three rule sets with extensive edge-value coverage:

**Bash rules** (`filter_rules.json`) — 332 cases:
- Allow: no-network commands, trusted endpoints (localhost, GitHub, PyPI, npm, GitLab, rubygems, crates.io, bitbucket, pkg.go.dev)
- Warn (ask): untrusted network endpoints (curl, wget, httpie, httpx, axios, urllib, aiohttp, fetch, rsync, telnet, socat, nmap, AI SDKs), employee IDs, IBANs, sensitive files, DB connections (postgres, mysql, mongodb, redis, JDBC, AMQP, ADO.NET, DSN, Data Source, cockroachdb, couchdb, mariadb), internal IPs (IPv4, IPv6 ULA/link-local, .local/.lan/.corp/.internal/.intranet/.private suffixes), customer/contract IDs
- Block (deny): API keys (Anthropic, OpenAI, AWS, GitHub PAT/OAuth, Slack, Stripe live/test/restricted, Google API/OAuth/client ID/client secret, SendGrid, Twilio SID/key, GitLab PAT/runner/OAuth, Discord, Telegram, npm, PyPI, Hugging Face, DigitalOcean, Heroku, Vault, JWT), private keys (RSA, EC, DSA, OPENSSH, generic), hardcoded passwords, prompt injection (ignore instructions, role reassignment, pretend, DAN mode, do anything now, sudo/admin mode, new instructions, no restrictions, jailbreak, XML tag injection, system prompt override, forget/bypass/override instructions), shell obfuscation (eval with string/variable/network tool, hex/octal escapes, /dev/tcp, /dev/udp, exec FD, source stdin/process substitution, IFS, consecutive hex), path traversal (3+ levels, sensitive file, /etc/, URL-encoded, double-encoded, mixed ..%2f, UTF-8 overlong, Windows backslash), DNS exfiltration (dig/nslookup/host with subst/backtick, pipe to DNS, dig +short, dig TXT, resolvectl), pipe-chain exfiltration (file read to network, reverse shell, mkfifo, compress-and-pipe, redirect to /dev/tcp+udp, encrypt-and-pipe, mail/sendmail, socat), base64 (CLI tool, pipe, Python encode/decode, JS atob/btoa, Node Buffer.from, long strings, echo-pipe patterns), passport/licence numbers (passport number/value/num/no, driver licence/license, DL, national ID), Unicode/homoglyph bypass (Cyrillic, zero-width)
- Edge values: boundary-length keys, minimum/maximum digit counts, false positives for below-minimum lengths, non-matching prefixes

**Write/Edit rules** (`filter_rules_write.json`) — 89 cases:
- Block: API keys (Anthropic, OpenAI, GitHub PAT/OAuth, Slack, Stripe live/restricted, Google API/OAuth/client secret, SendGrid, Twilio, GitLab, npm, PyPI, HuggingFace, DigitalOcean, JWT, Telegram), private keys (RSA, EC, DSA, OPENSSH, generic), passwords (password/passwd/secret, Vault token, Heroku key, boundary 4-char minimum), DB URIs (postgres, mysql, mongodb, redis, JDBC, ADO.NET, AMQP, Data Source), SSNs (raw, assignment, social_security_number), credit cards (Visa, Mastercard, Amex, Discover, assignment patterns), internal IPs (10.x, 172.16.x, 192.168.x)
- Allow: normal code, config, JSON, HTML, SQL, imports, safe edits, below-minimum passwords

**Read rules** (`filter_rules_read.json`) — 63 cases:
- Block: system auth (/etc/passwd, /etc/shadow, /etc/sudoers), SSH (id_rsa, id_ecdsa, id_dsa, config, authorized_keys, known_hosts, host keys), .env variants (.env, .env.production, .env.local, .env.staging, .env.development), cloud credentials (AWS, GCloud, Azure, Terraform), Kubernetes (kube config, PKI), history files (bash, zsh, python, mysql, psql), credential dotfiles (.netrc, .pgpass, .my.cnf), package manager auth (.npmrc, .pypirc), Docker, GPG, wallet.dat, Rails (master.key, credentials.yml.enc), Vault token
- Allow: normal source files, README, /etc/hostname, /etc/hosts, /etc/os-release, /etc/resolv.conf, config files, .gitignore, Dockerfile, .envrc, .env_template, public keys

### test_nlp_filter.py

Tests the NLP filter (`llm_filter.py`) plugin system:

- **Config edge cases** — disabled config, no plugins available
- **PII detection** (requires spaCy/Presidio/DistilBERT) — emails, phone numbers, SSNs, credit cards, safe commands
- **Prompt injection plugin** — instruction override, role reassignment, XML injection, safety override
- **Sensitive categories plugin** — medical data (patient IDs, MRNs, ICD-10), biometric data, protected categories (ethnicity, religion)
- **Entropy detector plugin** — high-entropy secrets, no false positives on normal text
- **Semantic intent plugin** — exfiltration intent, credential theft, no false positives on normal uploads

PII tests are skipped if no PII plugin is installed. Supplementary plugin tests always run (pure Python, no external deps).

### test_output_sanitizer.py

Tests the PostToolUse output sanitizer (`output_sanitizer.py`):

- **Redaction cases** — API keys (Anthropic, GitHub, Stripe, AWS, JWT), SSNs, credit cards (Visa, Mastercard), email addresses, private keys, DB connection strings, internal IPs, stderr redaction
- **Pass-through cases** — normal text, JSON, build logs, git output, empty output

### test_rate_limiter.py

Tests the rate limiter (`rate_limiter.py`):

- Under threshold → allow
- 5 violations → warn (ask)
- 10 violations → block (deny)
- Session isolation — other sessions' violations don't count
- Expired violations — old entries outside the 5-minute window
- Non-violation actions (allow, redact, override_allow) don't count
- Missing session ID → allow
- Disabled config → allow
- Missing audit log file → allow

### test_overrides.py

Tests the three-layer override system:

- Override resolver unit tests (match, non-overridable, expired, no match)
- Override allows previously-blocked (`ask`) command
- Override does NOT apply to non-overridable (`deny`) rules
- Expired overrides are ignored
- Wrong rule_name overrides are ignored
- Missing config_overrides.json = unchanged behavior
- Audit log records `override_allow` events
- CLI add/list/remove functional test
- Performance: 50 overrides complete under 500ms

### test_nlp_service.py

Tests the persistent NLP detection service (`llm_service.py` + `llm_client.py`):

- Service starts and writes lock file
- Service allows safe commands
- Service detects prompt injection
- Service detects PII
- Multiple requests reuse the same service process
- Performance: warm requests average under 100ms
- Client auto-starts service when not running
- Client detects through the service
- Graceful shutdown on SIGTERM
- Disabled config returns no output

## Adding Test Cases

Each suite uses a data-driven pattern — add cases to the appropriate list:

```python
# Regex filter (test_regex_filter.py)
BASH_CASES = [
    ("Description", "command string", "allow|warn|block"),
    ...
]

WRITE_CASES = [
    ("Description", "Write|Edit", "content", "allow|block"),
    ...
]

READ_CASES = [
    ("Description", "/path/to/file", "allow|block"),
    ...
]

# NLP filter (test_nlp_filter.py)
PII_CASES = [
    ("Description", "command", True|False),  # True = should detect
    ...
]
```

For standalone tests (overrides, rate limiter, service), add a new `test_*()` function that returns `bool` and register it in the `tests` list in `main()`.

## Dependencies

- All regex filter, output sanitizer, rate limiter, and override tests work with Python 3.10+ only (no extra deps)
- NLP filter PII tests require at least one: `spacy`, `presidio-analyzer`, or `transformers`
- Supplementary NLP plugin tests (prompt injection, categories, entropy, intent) have no extra deps
- NLP service tests require the service to be startable (same deps as NLP filter)
