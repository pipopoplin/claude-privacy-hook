# Testing

## Running Tests

```bash
# Run all tests
python3 test_hook.py && python3 test_llm_hook.py

# Regex filter tests only (126 cases, no dependencies)
python3 test_hook.py

# NLP filter tests only (39+ cases, supplementary plugins always work, PII needs a plugin)
python3 test_llm_hook.py
```

## Test Suites

### `test_hook.py` — Regex Filter (126 cases)

Tests the regex filter against all three rule configs:

- **Bash rules** (`filter_rules.json`) — credential detection, network blocking, attack patterns, exfiltration
- **Write/Edit rules** (`filter_rules_write.json`) — sensitive data in file content
- **Read rules** (`filter_rules_read.json`) — sensitive file path access

Each test case is a tuple of `(description, command, expected_result)` where `expected_result` is `"allow"`, `"deny"`, or `"ask"`.

### `test_llm_hook.py` — NLP Filter (39+ cases)

Tests the NLP filter including:

- PII detection (names, emails, SSNs, credit cards, phone numbers, IP addresses)
- Supplementary plugins (prompt injection, sensitive categories, entropy detection, semantic intent)
- Clean commands that should pass through

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
```

## Adding Test Cases

Add entries to the test case list in either test file. Follow the existing format:

```python
("Description of what this tests", "the command to test", "expected_result"),
```

Where `expected_result` is one of: `"allow"`, `"deny"`, or `"ask"`.
