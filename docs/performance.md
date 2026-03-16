# Performance

Every hook is benchmarked at two levels: **subprocess** (real-world latency including Python startup) and **in-process** (pure function cost).

## Full pipeline — Bash command (heaviest path)

| Stage | Subprocess (p50) | In-process | Notes |
|-------|----------------:|----------:|-------|
| Regex filter | 24ms | 0.07ms | 6 rules, ~80 patterns |
| Rate limiter | 20ms | 0.06ms | ~50 audit log entries |
| Output sanitizer | 20ms | 0.02ms | 3 redaction rules |
| **Total** | **~64ms** | **~0.15ms** | Subprocess dominated by Python startup |

Write/Edit and Read paths only run the regex filter (~20ms subprocess, <0.01ms in-process).

## Component highlights

| Component | In-process speed | Notes |
|-----------|----------------:|-------|
| `normalize_unicode()` | 1.2M ops/s | Plain ASCII; 5K ops/s for 6KB text |
| `resolve_field()` | 6.9M ops/s | Dot-path field resolution |
| `evaluate_rules()` | 14K–155K ops/s | Varies by rule set (Bash slowest, Read fastest) |
| `redact_text()` | 52K ops/s | Typical output; 280/s for 500-line output |
| `check_override()` | 67K ops/s | 50 overrides, no match |
| `log_event()` | 128K ops/s | JSONL append |
| Supplementary plugins | 100K–4.6M ops/s | Pure Python, no external deps |

## Running benchmarks

```bash
python3 benchmarks/run_all.py                  # All benchmarks (~2 min)
python3 benchmarks/bench_regex_filter.py       # Regex filter (subprocess + in-process)
python3 benchmarks/bench_output_sanitizer.py   # Output sanitizer
python3 benchmarks/bench_rate_limiter.py       # Rate limiter + log parsing
python3 benchmarks/bench_overrides.py          # Override resolver
python3 benchmarks/bench_hook_utils.py         # Unicode normalization + field resolution
python3 benchmarks/bench_audit_logger.py       # Audit log write performance
```

> **Note:** Performance numbers may improve with the reduced free-tier rule set (6 Bash rules, 3 Write rules, 3 sanitizer rules). Pro tier benchmarks with the full 40-rule set are available in the [Pro documentation](https://github.com/anthropics/claude-privacy-hook-pro).

See the full [Benchmark README](../benchmarks/README.md) for methodology, all scenarios, and detailed results.
