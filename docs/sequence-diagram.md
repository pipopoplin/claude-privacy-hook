# Hook System — Diagrams

## Full Pipeline Sequence

```mermaid
sequenceDiagram
    participant User
    participant ClaudeCode as Claude Code
    participant Regex as regex_filter.py
    participant Rules as filter_rules*.json
    participant RateLim as rate_limiter.py
    participant Shell as Bash Shell
    participant Sanitizer as output_sanitizer.py
    participant Audit as audit_logger.py

    User->>ClaudeCode: Prompt (e.g. "run curl to fetch data")
    ClaudeCode->>ClaudeCode: Claude decides to use Bash tool

    Note over ClaudeCode: PreToolUse event fires (matcher: Bash)

    rect rgb(240, 248, 255)
        Note over Regex,Rules: Hook 1: Regex Filter (18 rules, <1ms)
        ClaudeCode->>Regex: JSON on stdin
        Regex->>Regex: Unicode normalize + homoglyph detect + zero-width strip
        Regex->>Rules: Load filter_rules.json

        loop For each rule (top to bottom, first match wins)
            Regex->>Regex: Match patterns against field value
            alt deny
                Regex->>Audit: log_event(deny)
                Regex-->>ClaudeCode: {"permissionDecision":"deny"}
                ClaudeCode-->>User: Command blocked
            else allow
                Regex-->>ClaudeCode: (empty stdout) exit 0
            else ask
                Regex->>Audit: log_event(ask)
                Regex-->>ClaudeCode: {"permissionDecision":"ask"}
                ClaudeCode-->>User: Approve?
            end
        end
    end

    rect rgb(248, 240, 255)
        Note over RateLim,Audit: Hook 2: Rate Limiter (<1ms)
        ClaudeCode->>RateLim: JSON on stdin
        RateLim->>Audit: Read audit.log for session violations
        RateLim->>RateLim: Count violations in rolling window

        alt Violations >= block threshold (10)
            RateLim->>Audit: log_event(escalate_block)
            RateLim-->>ClaudeCode: {"permissionDecision":"deny"}
            ClaudeCode-->>User: Session rate-limited
        else Violations >= warn threshold (5)
            RateLim-->>ClaudeCode: {"permissionDecision":"ask"}
            ClaudeCode-->>User: Multiple violations warning
        else Below thresholds
            RateLim-->>ClaudeCode: (empty stdout) exit 0
        end
    end

    ClaudeCode->>Shell: Execute command
    Shell-->>ClaudeCode: Command output (stdout + stderr)

    rect rgb(240, 255, 240)
        Note over Sanitizer,Audit: PostToolUse: Output Sanitizer (<1ms)
        ClaudeCode->>Sanitizer: tool_result JSON on stdin
        Sanitizer->>Sanitizer: Match 7 redaction rules against output

        alt Sensitive data found
            Sanitizer->>Sanitizer: Replace matches with [REDACTED]
            Sanitizer->>Audit: log_event(redact)
            Sanitizer-->>ClaudeCode: {"updatedToolResult": redacted output}
        else Clean output
            Sanitizer-->>ClaudeCode: (empty stdout) exit 0
        end
    end

    ClaudeCode-->>User: Result (redacted if needed)

    Note over ClaudeCode: Write/Edit tools use regex_filter.py + filter_rules_write.json
    Note over ClaudeCode: Read tool uses regex_filter.py + filter_rules_read.json
```

## Decision Flow

```mermaid
flowchart TD
    A[Tool use intercepted] --> B{Which tool?}

    B -->|Bash| C[Hook 1: regex_filter.py<br/>filter_rules.json — 18 rules]
    B -->|Write / Edit| W[regex_filter.py<br/>filter_rules_write.json]
    B -->|Read| R[regex_filter.py<br/>filter_rules_read.json]

    W --> W1{Sensitive data in content?<br/>API keys, passwords, SSNs,<br/>credit cards, DB strings, IPs}
    W1 -->|Match| W2[DENY - sensitive content blocked]
    W1 -->|No match| W3[ALLOW]

    R --> R1{Sensitive file path?<br/>.env, .ssh, .aws, .kube,<br/>/etc/shadow, shell history}
    R1 -->|Match| R2[DENY - sensitive file blocked]
    R1 -->|No match| R3[ALLOW]

    C --> D{Rules 1-6: Sensitive data?<br/>API keys, tokens, passwords,<br/>employee IDs, IBANs, passports,<br/>SSNs, credit cards}
    D -->|Match| E[DENY - sensitive data detected]
    D -->|No match| F{Rules 7-10: Attack patterns?<br/>base64, prompt injection,<br/>shell obfuscation, path traversal}
    F -->|Match| F1[DENY - attack pattern detected]
    F -->|No match| G{Rules 11-16: Exfiltration?<br/>sensitive files, DB strings,<br/>DNS exfil, pipe chains,<br/>internal IPs, customer IDs}
    G -->|Match| G1[DENY - exfiltration blocked]
    G -->|No match| H{Rule 17: Trusted endpoint?<br/>localhost, GitHub, PyPI,<br/>npm, crates.io, etc.}
    H -->|Match| I[ALLOW - trusted host]
    H -->|No match| J{Rule 18: Network call?<br/>curl, wget, ssh, requests,<br/>httpx, fetch, AI SDKs}
    J -->|Match| K[DENY - untrusted network]
    J -->|No match| L[ALLOW - no regex match]

    I --> N[Hook 2: rate_limiter.py]
    L --> N
    N --> N1{Session violations<br/>in rolling window?}
    N1 -->|>= 10 block threshold| N2[DENY - rate limited]
    N1 -->|>= 5 warn threshold| N3[ASK - violation warning]
    N1 -->|Below thresholds| N4[ALLOW]

    N3 --> O[Execute command]
    N4 --> O
    O --> P[PostToolUse: output_sanitizer.py]
    P --> P1{Sensitive data in output?<br/>API keys, SSNs, credit cards,<br/>emails, private keys, DB strings, IPs}
    P1 -->|Match| P2[Redact with REDACTED]
    P1 -->|No match| P3[Pass through unchanged]

    style E fill:#ff6b6b,color:#fff
    style F1 fill:#ff6b6b,color:#fff
    style G1 fill:#ff6b6b,color:#fff
    style K fill:#ff6b6b,color:#fff
    style N2 fill:#ff6b6b,color:#fff
    style W2 fill:#ff6b6b,color:#fff
    style R2 fill:#ff6b6b,color:#fff

    style I fill:#51cf66,color:#fff
    style L fill:#51cf66,color:#fff
    style N4 fill:#51cf66,color:#fff
    style W3 fill:#51cf66,color:#fff
    style R3 fill:#51cf66,color:#fff

    style N3 fill:#ffd43b,color:#333
    style P2 fill:#748ffc,color:#fff
```

> NLP plugin dispatch diagrams are available in [claude-privacy-hook-pro](https://github.com/anthropics/claude-privacy-hook-pro).
