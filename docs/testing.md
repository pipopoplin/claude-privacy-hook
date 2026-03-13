# Testing

## Running Tests

```bash
# Run all 1312 tests across 7 suites
python3 tests/run_all.py

# Skip slow NLP service tests
python3 tests/run_all.py --fast

# Run individual suites
python3 tests/test_regex_filter.py      # Regex filter (518 cases)
python3 tests/test_nlp_filter.py        # NLP filter (272 cases)
python3 tests/test_output_sanitizer.py  # Output sanitizer (179 cases)
python3 tests/test_rate_limiter.py      # Rate limiter (60 cases)
python3 tests/test_overrides.py         # Override system (81 cases)
python3 tests/test_nlp_service.py       # NLP persistent service (42 cases)
python3 tests/test_conftest.py          # Test infrastructure (160 cases)
```

## Test Suites

| Suite | File | Cases | What it tests |
|-------|------|-------|---------------|
| **Regex Filter** | `test_regex_filter.py` | 518 | Pattern matching for Bash, Write/Edit, and Read rules |
| **NLP Filter** | `test_nlp_filter.py` | 272 | PII detection, prompt injection, sensitive categories, entropy, semantic intent, config edge cases |
| **Output Sanitizer** | `test_output_sanitizer.py` | 179 | API keys (20 patterns), SSNs, credit cards, emails, private keys, DB connections, internal IPs, stderr, config/input edge cases, audit logging, Unicode |
| **Rate Limiter** | `test_rate_limiter.py` | 60 | Threshold boundaries, action filtering, session isolation, time window, config variants, malformed input, output format |
| **Overrides** | `test_overrides.py` | 81 | Resolver unit tests, NLP override merging, integration allows, non-overridable rules, edge cases, audit logging, CLI tool, performance |
| **NLP Service** | `test_nlp_service.py` | 42 | Persistent TCP service lifecycle, protocol edge cases, concurrency, client behavior, config variants, performance |
| **Conftest Infrastructure** | `test_conftest.py` | 160 | Path constants, parse_decision, detected, run_hook_raw, run_hook, TestRunner, integration round-trips, edge cases |

## Shared Infrastructure

`tests/conftest.py` provides shared helpers used by all suites:

- **Path constants** — `PROJECT_ROOT`, `HOOKS_DIR`, all hook script and config paths
- **`run_hook()`** — run any PreToolUse hook and get back `"allow"`, `"warn"`, or `"block"`
- **`run_hook_raw()`** — run a hook and get the raw `subprocess.CompletedProcess`
- **`parse_decision()`** — parse hook output into `"allow"` / `"warn"` / `"block"`
- **`detected()`** — boolean: did the hook detect something?
- **`TestRunner`** — lightweight runner with `check()`, `run_fn()`, section headers, and summary

## Testing Individual Hooks Directly

```bash
# Test regex filter (Bash rules)
echo '{"tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}' | \
  python3 .claude/hooks/regex_filter.py .claude/hooks/filter_rules.json

# Test regex filter (Write rules)
echo '{"tool_name":"Write","tool_input":{"content":"password=secret123"}}' | \
  python3 .claude/hooks/regex_filter.py .claude/hooks/filter_rules_write.json

# Test NLP filter
echo '{"tool_name":"Bash","tool_input":{"command":"send to john@example.com"}}' | \
  python3 .claude/hooks/llm_filter.py .claude/hooks/llm_filter_config.json

# Test output sanitizer
echo '{"tool_name":"Bash","tool_input":{"command":"cat secrets"},"tool_result":{"stdout":"key=sk-ant-abc123","stderr":""}}' | \
  python3 .claude/hooks/output_sanitizer.py .claude/hooks/output_sanitizer_rules.json
```

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

# Output sanitizer (test_output_sanitizer.py)
API_KEY_CASES = [
    ("Description", "stdout text", "stderr text", True|False, check_fn),
    ...
]
```

For standalone tests (overrides, rate limiter, service, conftest), add a new `test_*()` function and call it from `main()`.

## Dependencies

- All regex filter, output sanitizer, rate limiter, override, and conftest tests work with Python 3.10+ only (no extra deps)
- NLP filter PII tests require at least one: `spacy`, `presidio-analyzer`, or `transformers`
- Supplementary NLP plugin tests (prompt injection, categories, entropy, intent) have no extra deps
- NLP service tests require the service to be startable (same deps as NLP filter)
