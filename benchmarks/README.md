# Benchmarks

Performance benchmarks for every component of the Claude Privacy Hook system. Each benchmark measures both **subprocess** latency (real-world end-to-end, including Python interpreter startup) and **in-process** speed (pure function cost with warm caches).

## Quick Start

```bash
# Run all benchmarks (~2-3 minutes)
python3 benchmarks/run_all.py

# Run a single benchmark
python3 benchmarks/bench_regex_filter.py
python3 benchmarks/bench_output_sanitizer.py
python3 benchmarks/bench_rate_limiter.py
python3 benchmarks/bench_overrides.py
python3 benchmarks/bench_hook_utils.py
python3 benchmarks/bench_audit_logger.py
```

## Benchmark Suites

### 1. Regex Filter (`bench_regex_filter.py`)

Benchmarks `regex_filter.py` with all three rule sets (Bash, Write, Read).

**Subprocess scenarios** (50 iterations each):
| Scenario | What it tests |
|----------|--------------|
| Bash: safe command (allow) | Full rule scan, no match — worst-case allow path |
| Bash: API key (block) | Early match on `block_sensitive_data` (hard deny) |
| Bash: untrusted network (warn) | Match on `block_untrusted_network` (ask rule) |
| Write: safe content (allow) | Write rules, no match |
| Write: password (block) | Write rules, credential match |
| Read: safe path (allow) | Read rules, no match |
| Read: SSH key (block) | Read rules, sensitive file match |

**In-process scenarios** (5,000 iterations each):
Same scenarios plus a long safe command (repeated `git status && npm test`), benchmarking `evaluate_rules()` directly without subprocess overhead.

**Key metric**: Bash rules are the slowest (~0.07ms) because they have 18 rules and ~180 patterns. Read rules are the fastest (~0.006ms) with only 1 rule.

---

### 2. Output Sanitizer (`bench_output_sanitizer.py`)

Benchmarks `output_sanitizer.py` (PostToolUse hook) redaction performance.

**Subprocess scenarios** (50 iterations each):
| Scenario | What it tests |
|----------|--------------|
| Safe output (no redaction) | No patterns match — pass-through path |
| API keys (2 keys) | Anthropic + GitHub token redaction |
| PII (SSN + card + email) | Multiple PII pattern matches |
| DB conn + internal IP | Database URL and RFC 1918 address redaction |
| Private key block | Multi-line PEM key detection |
| Mixed (all rule types) | Every rule fires in a single output |
| Large safe (500 lines) | Throughput on large clean output |
| Large mixed (510 lines, 10 keys) | Throughput with scattered matches |

**In-process scenarios** (5,000 iterations each):
Same scenarios, benchmarking `redact_text()` with pre-compiled regex patterns.

**Key metric**: Typical redaction costs ~0.02ms. Large outputs (500 lines) degrade to ~3.5ms per call.

---

### 3. Rate Limiter (`bench_rate_limiter.py`)

Benchmarks `rate_limiter.py` with varying audit log sizes.

**Subprocess scenarios** (50 iterations each):
Tests with 0, 5, 10, 50, 100, 500, and 1,000 audit log entries. The rate limiter reads the JSONL audit log and counts recent violations in a rolling window.

**In-process scenarios** (200-5,000 iterations):
Benchmarks pure JSONL parsing and violation counting for the same log sizes.

**Key metric**: Rate limiter performance scales linearly with audit log size. At 1,000 entries, subprocess latency is ~25ms (mostly Python startup + file I/O).

---

### 4. Override Resolver (`bench_overrides.py`)

Benchmarks the two-layer override system.

**`check_override()` scenarios** (10,000 iterations each):
| Scenario | What it tests |
|----------|--------------|
| 0-100 overrides, no match | Linear scan cost with increasing override count |
| N overrides, match at #1 | Best-case early match |
| N overrides, match at #N | Worst-case late match |
| Non-overridable rule (early return) | Short-circuit when `overridable: false` |
| Empty overrides list | Baseline with no overrides configured |

**`load_overrides()` scenarios** (500 iterations):
File I/O cost of loading and parsing `config_overrides.json` from user and project paths.

**Key metric**: `check_override()` with 50 overrides and no match costs ~0.015ms (67K ops/s). Non-overridable early return is essentially free.

---

### 5. Hook Utils (`bench_hook_utils.py`)

Benchmarks shared utility functions from `hook_utils.py`.

**`normalize_unicode()` scenarios** (50,000 iterations each):
| Scenario | What it tests |
|----------|--------------|
| Plain ASCII (16 chars) | Fast path — no normalization needed |
| Cyrillic homoglyph (short) | Homoglyph translation table |
| Zero-width chars | Zero-width character stripping |
| Mixed homoglyphs (8 chars) | Multiple homoglyph replacements |
| Long ASCII (6KB) | Throughput on large clean input |
| Long Unicode (4KB) | Throughput on large input with homoglyphs |
| Empty string | Edge case baseline |

**`resolve_field()` scenarios** (50,000 iterations each):
| Scenario | What it tests |
|----------|--------------|
| Shallow: tool_input.command | 2-level dot-path resolution |
| Top-level: tool_name | 1-level direct access |
| Deep: a.b.c.d.e (5 levels) | 5-level nested resolution |
| Missing field (returns '') | Graceful fallback path |
| Empty field path | Edge case baseline |

**Key metric**: `normalize_unicode()` on plain ASCII runs at ~1.2M ops/s. `resolve_field()` runs at ~6.9M ops/s for shallow lookups.

---

### 6. Audit Logger (`bench_audit_logger.py`)

Benchmarks `audit_logger.py` JSONL write performance.

**Scenarios** (2,000-5,000 iterations):
| Scenario | What it tests |
|----------|--------------|
| Deny event (2 patterns) | Standard deny audit entry with pattern list |
| Override allow event | Audit entry with override metadata fields |
| Burst: 5,000 entries | Sustained write throughput |

**Key metric**: `log_event()` runs at ~128K ops/s with sustained burst writes producing predictable file sizes.

---

## Methodology

### Two-Level Benchmarking

Every component is measured at two levels to give a complete performance picture:

1. **Subprocess** — Measures real-world hook latency as Claude Code would experience it. Each iteration spawns `python3 hook_script.py config.json` with JSON on stdin, timing the full round-trip. This includes Python interpreter startup (~17ms), module imports, config loading, and processing.

2. **In-process** — Measures the pure computational cost by importing functions directly and calling them in a tight loop with warm caches. This isolates the algorithm from startup overhead and shows the true cost of adding more rules/patterns/overrides.

### Timing

- All timings use `time.perf_counter()` for high-resolution monotonic measurement
- Warmup iterations run before timing to eliminate cold-start artifacts (JIT, file caching, etc.)
- Subprocess benchmarks report **mean**, **p50** (median), **p95**, and optionally **p99**
- In-process benchmarks report **per-call time** (ms) and **ops/sec** (throughput)

### Iteration Counts

Iteration counts are tuned per scenario to balance accuracy against total runtime:

| Level | Typical iterations | Rationale |
|-------|------------------:|-----------|
| Subprocess (fast hooks) | 50 | Each takes ~20ms; 50 iterations = ~1s per scenario |
| In-process (fast funcs) | 5,000–50,000 | Sub-microsecond calls need high N for stable medians |

### Environment Factors

Results will vary based on:
- **CPU speed** — all benchmarks are CPU-bound (no network I/O)
- **Disk speed** — affects subprocess startup and audit logger writes
- **Python version** — 3.10+ recommended; regex performance improved in 3.11
- **System load** — run benchmarks on a quiet system for stable results

## Interpreting Results

### What "Good" Looks Like

The hook system is designed to add minimal latency to Claude Code tool execution:

| Metric | Target | Why |
|--------|--------|-----|
| Regex filter subprocess | <30ms | Dominated by Python startup; the actual rule evaluation takes <0.1ms |
| Output sanitizer subprocess | <30ms | Same Python startup; redaction itself is <0.05ms |
| Rate limiter subprocess | <30ms | JSONL parsing scales linearly; keep audit logs under 1,000 entries |
| Full Bash pipeline | <100ms | Sum of all PreToolUse hooks; imperceptible to users |

### When to Investigate

- **Subprocess latency >50ms** for a single hook — check system load or Python startup issues
- **In-process regex >1ms** — rule count or pattern complexity may have grown; consider rule ordering
- **Rate limiter >50ms** — audit log may be too large; consider log rotation

### Subprocess Overhead

The ~17ms baseline subprocess overhead is the cost of:
1. Python interpreter startup
2. Module imports (json, re, os, sys)
3. Config file loading and JSON parsing

This is fixed overhead per hook invocation and does not scale with rule count or input size.

## File Reference

| File | Component | Subprocess | In-process |
|------|-----------|:----------:|:----------:|
| `bench_regex_filter.py` | Regex filter (all 3 rule sets) | 7 scenarios | 8 scenarios |
| `bench_output_sanitizer.py` | Output sanitizer | 8 scenarios | 8 scenarios |
| `bench_rate_limiter.py` | Rate limiter | 7 scenarios | 6 scenarios |
| `bench_overrides.py` | Override resolver | — | 12 scenarios |
| `bench_hook_utils.py` | Shared utilities | — | 12 scenarios |
| `bench_audit_logger.py` | Audit logger | — | 3 scenarios |
| `run_all.py` | Runner (all suites) | — | — |

> NLP filter benchmarks are available in [claude-privacy-hook-pro](https://github.com/anthropics/claude-privacy-hook-pro).
