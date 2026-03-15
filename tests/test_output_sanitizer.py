#!/usr/bin/env python3
"""Test the output sanitizer PostToolUse hook.

Verifies that sensitive data in command stdout/stderr is redacted and
that safe output passes through unchanged.  Covers all 7 rules in
output_sanitizer_rules.json with edge-value coverage for every pattern.
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import (
    OUTPUT_SANITIZER,
    SANITIZER_RULES,
    HOOKS_DIR,
    run_hook_raw,
    TestRunner,
)


# =====================================================================
# Helpers
# =====================================================================

def _run_sanitizer(stdout: str = "", stderr: str = "") -> dict:
    """Run the output sanitizer and return the parsed response.

    Returns {"redacted": bool, "stdout": str, "stderr": str}.
    """
    hook_input = {
        "session_id": "test-session",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "test"},
        "tool_result": {"stdout": stdout, "stderr": stderr},
    }
    result = run_hook_raw(OUTPUT_SANITIZER, SANITIZER_RULES, hook_input)

    if result.returncode == 0 and result.stdout.strip():
        try:
            output = json.loads(result.stdout)
            updated = output.get("hookSpecificOutput", {}).get("updatedToolResult", {})
            return {
                "redacted": True,
                "stdout": updated.get("stdout", stdout),
                "stderr": updated.get("stderr", stderr),
            }
        except json.JSONDecodeError:
            pass
    return {"redacted": False, "stdout": stdout, "stderr": stderr}


def _run_sanitizer_raw(hook_input: dict) -> "subprocess.CompletedProcess":
    """Run the sanitizer with a custom hook_input dict."""
    return run_hook_raw(OUTPUT_SANITIZER, SANITIZER_RULES, hook_input)


def _run_with_config(config: dict, stdout: str = "", stderr: str = "") -> dict:
    """Run the sanitizer with a custom config file."""
    fd, path = tempfile.mkstemp(suffix=".json", prefix="test_san_", dir=HOOKS_DIR)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(config, f)
        hook_input = {
            "session_id": "test-session",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "test"},
            "tool_result": {"stdout": stdout, "stderr": stderr},
        }
        result = run_hook_raw(OUTPUT_SANITIZER, path, hook_input)
        if result.returncode == 0 and result.stdout.strip():
            try:
                output = json.loads(result.stdout)
                updated = output.get("hookSpecificOutput", {}).get("updatedToolResult", {})
                return {
                    "redacted": True,
                    "stdout": updated.get("stdout", stdout),
                    "stderr": updated.get("stderr", stderr),
                }
            except json.JSONDecodeError:
                pass
        return {"redacted": False, "stdout": stdout, "stderr": stderr}
    finally:
        os.unlink(path)


# =====================================================================
# Test cases — Rule 1: redact_api_keys (20 patterns)
# =====================================================================

API_KEY_CASES = [
    # Anthropic
    ("Redact: Anthropic API key",
     "Key: sk-ant-abc123def456-xyz", "",
     True, lambda r: "sk-ant-" not in r["stdout"]),
    ("Redact: Anthropic key in middle of output",
     "Connecting... token=sk-ant-ABCDEF1234567890 done", "",
     True, lambda r: "sk-ant-" not in r["stdout"]),

    # OpenAI-style
    ("Redact: OpenAI key sk-proj-",
     "key=sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcd", "",
     True, lambda r: "sk-proj-" not in r["stdout"]),
    ("Redact: OpenAI key sk- (20 chars)",
     "key=sk-abcdefghijklmnopqrst", "",
     True, lambda r: "sk-abcdefghij" not in r["stdout"]),

    # GitHub
    ("Redact: GitHub PAT ghp_",
     "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "",
     True, lambda r: "ghp_" not in r["stdout"]),
    ("Redact: GitHub OAuth gho_",
     "token=gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "",
     True, lambda r: "gho_" not in r["stdout"]),

    # Slack
    ("Redact: Slack bot token xoxb-",
     "SLACK_TOKEN=xoxb-123456789-abcdefghijklm", "",
     True, lambda r: "xoxb-" not in r["stdout"]),
    ("Redact: Slack app token xoxa-",
     "token: xoxa-2-abc-def-ghi", "",
     True, lambda r: "xoxa-" not in r["stdout"]),
    ("Redact: Slack user token xoxp-",
     "SLACK=xoxp-111-222-333-abcdef", "",
     True, lambda r: "xoxp-" not in r["stdout"]),

    # Stripe
    ("Redact: Stripe live key",
     "STRIPE=sk_live_abc123def456ghi789jkl012", "",
     True, lambda r: "sk_live_" not in r["stdout"]),
    ("Redact: Stripe test key",
     "STRIPE=sk_test_abc123def456ghi789jkl012", "",
     True, lambda r: "sk_test_" not in r["stdout"]),
    ("Redact: Stripe restricted key rk_live_",
     "key=rk_live_abc123def456ghi789jkl012", "",
     True, lambda r: "rk_live_" not in r["stdout"]),
    ("Redact: Stripe restricted key rk_test_",
     "key=rk_test_abc123def456ghi789jkl012", "",
     True, lambda r: "rk_test_" not in r["stdout"]),

    # Google
    ("Redact: Google API key AIza...",
     "GOOGLE_KEY=AIzaSyB-abcdefghijklmnopqrstuvwxyz12345", "",
     True, lambda r: "AIza" not in r["stdout"]),
    ("Redact: Google OAuth ya29.",
     "access_token=ya29.a0AfH6SMBxyz123-abc_def", "",
     True, lambda r: "ya29." not in r["stdout"]),

    # SendGrid
    ("Redact: SendGrid API key",
     "SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst", "",
     True, lambda r: "SG." not in r["stdout"]),

    # Twilio
    ("Redact: Twilio API key SK...",
     "TWILIO_KEY=SK1234567890abcdef1234567890abcdef", "",
     True, lambda r: "SK1234" not in r["stdout"]),
    ("Redact: Twilio Account SID AC...",
     "TWILIO_SID=AC1234567890abcdef1234567890abcdef", "",
     True, lambda r: "AC1234" not in r["stdout"]),

    # JWT
    ("Redact: JWT token",
     "auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "",
     True, lambda r: "eyJhbG" not in r["stdout"]),
    ("Redact: JWT in Authorization header",
     "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIn0.signature_here", "",
     True, lambda r: "eyJhbG" not in r["stdout"]),

    # GitLab
    ("Redact: GitLab PAT glpat-",
     "GITLAB=glpat-abcdefghijklmnopqrstu", "",
     True, lambda r: "glpat-" not in r["stdout"]),

    # npm
    ("Redact: npm access token",
     "NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyz1234567890", "",
     True, lambda r: "npm_" not in r["stdout"]),

    # PyPI
    ("Redact: PyPI API token",
     "PYPI_TOKEN=pypi-AgEIcHlwaS5vcmcCJDMxNjQ1NTBmLTk2YjAtNGRiMS1hMmUwLTkzMjA4YzFiMAACJXs", "",
     True, lambda r: "pypi-" not in r["stdout"]),

    # Hugging Face
    ("Redact: Hugging Face token hf_",
     "HF_TOKEN=hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh", "",
     True, lambda r: "hf_" not in r["stdout"]),

    # DigitalOcean
    ("Redact: DigitalOcean PAT",
     "DO_TOKEN=DOPATv1_abcdefghijklmnopqrstuvwxyz1234567890abcdef", "",
     True, lambda r: "DOPAT" not in r["stdout"]),

    # AWS
    ("Redact: AWS access key assignment",
     "aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "",
     True, lambda r: "AKIA" not in r["stdout"]),
    ("Redact: AWS secret key assignment",
     "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'", "",
     True, lambda r: "aws_secret_access_key" not in r["stdout"]),
    ("Redact: AWS access key ID standalone",
     "key: AKIAIOSFODNN7EXAMPLE", "",
     True, lambda r: "AKIA" not in r["stdout"]),

    # Edge: boundary-length tokens
    ("Redact: OpenAI key exactly 20 chars after sk-",
     "sk-12345678901234567890", "",
     True, lambda r: "sk-1234567890" not in r["stdout"]),
    ("FP: sk- with only 19 chars (below minimum)",
     "sk-1234567890123456789", "",
     False, None),

    # Edge: multiple keys in one line
    ("Redact: two keys in one line",
     "key1=sk-ant-abc123 key2=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "",
     True, lambda r: "sk-ant-" not in r["stdout"] and "ghp_" not in r["stdout"]),
]


# =====================================================================
# Test cases — Rule 2: redact_ssn
# =====================================================================

SSN_CASES = [
    ("Redact: SSN standard format",
     "SSN: 123-45-6789", "",
     True, lambda r: "123-45-6789" not in r["stdout"]),
    ("Redact: SSN assignment with =",
     "SSN=123-45-6789", "",
     True, lambda r: "123-45-6789" not in r["stdout"]),
    ("Redact: SSN assignment with colon",
     "SSN: 123456789", "",
     True, lambda r: "123456789" not in r["stdout"]),
    ("Redact: SSN with spaces",
     "SSN: 123 45 6789", "",
     True, lambda r: "123 45 6789" not in r["stdout"]),
    ("Redact: SSN dashed in middle of text",
     "The value 999-88-7777 was found", "",
     True, lambda r: "999-88-7777" not in r["stdout"]),
    ("Redact: SSN quoted in assignment",
     "SSN='987-65-4321'", "",
     True, lambda r: "987-65-4321" not in r["stdout"]),

    # Edge: boundary digits
    ("Redact: SSN with all zeros except boundary",
     "Found: 000-00-0001", "",
     True, lambda r: "000-00-0001" not in r["stdout"]),
    ("Redact: SSN with all nines",
     "Found: 999-99-9999", "",
     True, lambda r: "999-99-9999" not in r["stdout"]),

    # False positives
    ("FP SSN: date format MM-DD-YYYY (12 digits total, not 9)",
     "Date: 2024-01-15 is scheduled", "",
     False, None),
    ("FP SSN: phone-like NNN-NN-NNNN with context",
     "version 1.2.3 in release notes", "",
     False, None),
]


# =====================================================================
# Test cases — Rule 3: redact_credit_cards
# =====================================================================

CREDIT_CARD_CASES = [
    # Visa
    ("Redact: Visa card with spaces",
     "card: 4111 1111 1111 1111", "",
     True, lambda r: "4111" not in r["stdout"]),
    ("Redact: Visa card with dashes",
     "card: 4111-1111-1111-1111", "",
     True, lambda r: "4111" not in r["stdout"]),
    ("Redact: Visa card no separators",
     "card: 4111111111111111", "",
     True, lambda r: "4111111111111111" not in r["stdout"]),
    ("Redact: Visa starting with 4000",
     "card: 4000 1234 5678 9010", "",
     True, lambda r: "4000" not in r["stdout"]),

    # Mastercard
    ("Redact: Mastercard 5100",
     "card: 5100 0000 0000 0000", "",
     True, lambda r: "5100" not in r["stdout"]),
    ("Redact: Mastercard 5500 with spaces",
     "card: 5500 0000 0000 0004", "",
     True, lambda r: "5500" not in r["stdout"]),
    ("Redact: Mastercard 5200 no separators",
     "card: 5200123456789012", "",
     True, lambda r: "5200123456789012" not in r["stdout"]),
    ("Redact: Mastercard 5300 with dashes",
     "cc: 5300-0000-0000-0000", "",
     True, lambda r: "5300" not in r["stdout"]),
    ("Redact: Mastercard 5400",
     "cc: 5400 1234 5678 9012", "",
     True, lambda r: "5400" not in r["stdout"]),

    # Amex
    ("Redact: Amex 34xx (spaces)",
     "amex: 3400 123456 12345", "",
     True, lambda r: "3400" not in r["stdout"]),
    ("Redact: Amex 37xx (spaces)",
     "amex: 3700 123456 12345", "",
     True, lambda r: "3700" not in r["stdout"]),
    ("Redact: Amex no separators",
     "amex: 340012345612345", "",
     True, lambda r: "340012345612345" not in r["stdout"]),
    ("Redact: Amex with dashes",
     "amex: 3700-123456-12345", "",
     True, lambda r: "3700" not in r["stdout"]),

    # Discover
    ("Redact: Discover 6011",
     "card: 6011 1234 5678 9012", "",
     True, lambda r: "6011" not in r["stdout"]),
    ("Redact: Discover 65xx",
     "card: 6500 1234 5678 9012", "",
     True, lambda r: "6500" not in r["stdout"]),
    ("Redact: Discover no separators",
     "card: 6011123456789012", "",
     True, lambda r: "6011123456789012" not in r["stdout"]),

    # Edge: boundary patterns
    ("Redact: Visa boundary — starts with 4, 16 digits",
     "num: 4999999999999999", "",
     True, lambda r: "4999999999999999" not in r["stdout"]),

    # False positives
    ("FP CC: 16-digit number not starting with valid prefix",
     "id: 1234567890123456", "",
     False, None),
    ("FP CC: 15-digit number (too short for Visa/MC)",
     "num: 411111111111111", "",
     False, None),
]


# =====================================================================
# Test cases — Rule 4: redact_email_addresses
# =====================================================================

EMAIL_CASES = [
    ("Redact: standard email",
     "contact: user@example.com", "",
     True, lambda r: "user@example.com" not in r["stdout"]),
    ("Redact: email with subdomain",
     "mail: admin@mail.company.co.uk", "",
     True, lambda r: "admin@mail.company.co.uk" not in r["stdout"]),
    ("Redact: email with dots in local part",
     "first.last@domain.org", "",
     True, lambda r: "first.last@domain.org" not in r["stdout"]),
    ("Redact: email with plus addressing",
     "user+tag@example.com", "",
     True, lambda r: "user+tag@example.com" not in r["stdout"]),
    ("Redact: email with percent in local",
     "user%tag@example.com", "",
     True, lambda r: "user%tag@" not in r["stdout"]),
    ("Redact: email with hyphens in domain",
     "info@my-company.example.com", "",
     True, lambda r: "info@my-company" not in r["stdout"]),
    ("Redact: email with underscore",
     "test_user@test.io", "",
     True, lambda r: "test_user@test.io" not in r["stdout"]),
    ("Redact: email with numbers",
     "user123@example456.com", "",
     True, lambda r: "user123@example456.com" not in r["stdout"]),
    ("Redact: email with short TLD",
     "x@y.co", "",
     True, lambda r: "x@y.co" not in r["stdout"]),

    # Multiple emails
    ("Redact: two emails in one line",
     "from: a@b.com to: c@d.org", "",
     True, lambda r: "a@b.com" not in r["stdout"] and "c@d.org" not in r["stdout"]),

    # False positives
    ("FP email: @ in shell variable",
     'echo "${array[@]}"', "",
     False, None),
    ("FP email: at-sign in git ref",
     "HEAD@{1}", "",
     False, None),
]


# =====================================================================
# Test cases — Rule 5: redact_private_keys
# =====================================================================

PRIVATE_KEY_CASES = [
    ("Redact: RSA private key header",
     "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQI...", "",
     True, lambda r: "BEGIN RSA PRIVATE KEY" not in r["stdout"]),
    ("Redact: EC private key header",
     "-----BEGIN EC PRIVATE KEY-----\nMHQCAQ...", "",
     True, lambda r: "BEGIN EC PRIVATE KEY" not in r["stdout"]),
    ("Redact: DSA private key header",
     "-----BEGIN DSA PRIVATE KEY-----\nMIIBuw...", "",
     True, lambda r: "BEGIN DSA PRIVATE KEY" not in r["stdout"]),
    ("Redact: OPENSSH private key header",
     "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnN...", "",
     True, lambda r: "BEGIN OPENSSH PRIVATE KEY" not in r["stdout"]),
    ("Redact: generic private key header",
     "-----BEGIN PRIVATE KEY-----\nMIIEvQI...", "",
     True, lambda r: "BEGIN PRIVATE KEY" not in r["stdout"]),
    ("Redact: private key footer",
     "...data...\n-----END RSA PRIVATE KEY-----", "",
     True, lambda r: "END RSA PRIVATE KEY" not in r["stdout"]),
    ("Redact: EC key footer",
     "data\n-----END EC PRIVATE KEY-----", "",
     True, lambda r: "END EC PRIVATE KEY" not in r["stdout"]),
    ("Redact: generic key footer",
     "blob\n-----END PRIVATE KEY-----", "",
     True, lambda r: "END PRIVATE KEY" not in r["stdout"]),
    ("Redact: full key block (header + footer)",
     "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----", "",
     True, lambda r: "BEGIN RSA PRIVATE KEY" not in r["stdout"] and "END RSA PRIVATE KEY" not in r["stdout"]),

    # False positives
    ("FP key: public key header",
     "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...", "",
     False, None),
    ("FP key: certificate header",
     "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWg...", "",
     False, None),
]


# =====================================================================
# Test cases — Rule 6: redact_database_connection_strings
# =====================================================================

DB_CONN_CASES = [
    # URI format with credentials
    ("Redact: postgres URI",
     "postgres://admin:secret@db.example.com:5432/mydb", "",
     True, lambda r: "admin:secret" not in r["stdout"]),
    ("Redact: postgresql URI",
     "postgresql://user:pass@host:5432/db", "",
     True, lambda r: "user:pass" not in r["stdout"]),
    ("Redact: mysql URI",
     "mysql://root:password@mysql.internal:3306/app", "",
     True, lambda r: "root:password" not in r["stdout"]),
    ("Redact: mariadb URI",
     "mariadb://admin:pwd@mariadb.local:3306/db", "",
     True, lambda r: "admin:pwd" not in r["stdout"]),
    ("Redact: mongodb URI",
     "mongodb://user:pass@mongo.cluster.local:27017/app", "",
     True, lambda r: "user:pass" not in r["stdout"]),
    ("Redact: mongodb+srv URI",
     "mongodb+srv://admin:secret@cluster0.abc.mongodb.net/test", "",
     True, lambda r: "admin:secret" not in r["stdout"]),
    ("Redact: redis URI",
     "redis://default:mypass@redis.internal:6379/0", "",
     True, lambda r: "default:mypass" not in r["stdout"]),
    ("Redact: amqp URI",
     "amqp://guest:guest@rabbit.local:5672/vhost", "",
     True, lambda r: "guest:guest" not in r["stdout"]),
    ("Redact: rabbitmq URI",
     "rabbitmq://user:pass@rmq.internal:5672/", "",
     True, lambda r: "user:pass" not in r["stdout"]),
    ("Redact: cockroachdb URI",
     "cockroachdb://root:secret@crdb.local:26257/defaultdb", "",
     True, lambda r: "root:secret" not in r["stdout"]),
    ("Redact: couchdb URI",
     "couchdb://admin:admin@couch.local:5984/mydb", "",
     True, lambda r: "admin:admin" not in r["stdout"]),
    ("Redact: mssql URI",
     "mssql://sa:StrongPass@mssql.internal:1433/master", "",
     True, lambda r: "sa:StrongPass" not in r["stdout"]),

    # Environment variable assignments
    ("Redact: DATABASE_URL assignment",
     "DATABASE_URL=postgres://u:p@host/db", "",
     True, lambda r: "u:p@host" not in r["stdout"]),
    ("Redact: MONGO_URI assignment",
     "MONGO_URI=mongodb://u:p@host:27017/db", "",
     True, lambda r: "u:p@host" not in r["stdout"]),
    ("Redact: MONGODB_URI assignment",
     "MONGODB_URI='mongodb://u:p@host/db'", "",
     True, lambda r: "u:p@host" not in r["stdout"]),
    ("Redact: REDIS_URL assignment",
     "REDIS_URL=redis://default:pw@host:6379", "",
     True, lambda r: "default:pw@" not in r["stdout"]),
    ("Redact: AMQP_URL assignment",
     "AMQP_URL=amqp://guest:guest@host:5672/", "",
     True, lambda r: "guest:guest@" not in r["stdout"]),

    # ADO.NET / ODBC
    ("Redact: ADO.NET connection string",
     "Server=myServer;Database=myDB;User Id=sa;Password=secret;", "",
     True, lambda r: "Password" not in r["stdout"]),
    ("Redact: ODBC with Uid and Pwd",
     "Server=host;Uid=admin;Pwd=pass123;", "",
     True, lambda r: "Pwd" not in r["stdout"]),

    # JDBC
    ("Redact: JDBC MySQL",
     "jdbc:mysql://host:3306/db?user=root&password=secret", "",
     True, lambda r: "jdbc:mysql" not in r["stdout"]),
    ("Redact: JDBC PostgreSQL",
     "jdbc:postgresql://db.internal:5432/app", "",
     True, lambda r: "jdbc:postgresql" not in r["stdout"]),
    ("Redact: JDBC SQL Server",
     "jdbc:sqlserver://host:1433;databaseName=myDB", "",
     True, lambda r: "jdbc:sqlserver" not in r["stdout"]),
    ("Redact: JDBC Oracle",
     "jdbc:oracle://host:1521/service", "",
     True, lambda r: "jdbc:oracle" not in r["stdout"]),

    # Data Source
    ("Redact: Data Source with Password",
     "Data Source=server;Initial Catalog=db;Password=secret", "",
     True, lambda r: "Password" not in r["stdout"]),

    # False positives
    ("FP DB: plain URL without credentials",
     "https://example.com/api/data", "",
     False, None),
    ("FP DB: database name without URI scheme",
     "mydb on port 5432", "",
     False, None),
]


# =====================================================================
# Test cases — Rule 7: redact_internal_ip_addresses
# =====================================================================

INTERNAL_IP_CASES = [
    # RFC1918 Class A: 10.x.x.x
    ("Redact: 10.0.0.1",
     "Server: 10.0.0.1", "",
     True, lambda r: "10.0.0.1" not in r["stdout"]),
    ("Redact: 10.0.1.55:8080",
     "Server: 10.0.1.55:8080", "",
     True, lambda r: "10.0.1.55" not in r["stdout"]),
    ("Redact: 10.255.255.255 (max)",
     "host: 10.255.255.255", "",
     True, lambda r: "10.255.255.255" not in r["stdout"]),
    ("Redact: 10.100.200.50",
     "gateway: 10.100.200.50", "",
     True, lambda r: "10.100.200.50" not in r["stdout"]),

    # RFC1918 Class B: 172.16-31.x.x
    ("Redact: 172.16.0.1 (lower boundary)",
     "addr: 172.16.0.1", "",
     True, lambda r: "172.16.0.1" not in r["stdout"]),
    ("Redact: 172.31.255.255 (upper boundary)",
     "addr: 172.31.255.255", "",
     True, lambda r: "172.31.255.255" not in r["stdout"]),
    ("Redact: 172.20.10.5 (middle)",
     "host: 172.20.10.5", "",
     True, lambda r: "172.20.10.5" not in r["stdout"]),

    # RFC1918 Class C: 192.168.x.x
    ("Redact: 192.168.0.1",
     "router: 192.168.0.1", "",
     True, lambda r: "192.168.0.1" not in r["stdout"]),
    ("Redact: 192.168.1.100",
     "host: 192.168.1.100", "",
     True, lambda r: "192.168.1.100" not in r["stdout"]),
    ("Redact: 192.168.255.255 (max)",
     "gw: 192.168.255.255", "",
     True, lambda r: "192.168.255.255" not in r["stdout"]),

    # Link-local: 169.254.x.x
    ("Redact: 169.254.0.1",
     "link-local: 169.254.0.1", "",
     True, lambda r: "169.254.0.1" not in r["stdout"]),
    ("Redact: 169.254.169.254 (AWS metadata)",
     "meta: 169.254.169.254", "",
     True, lambda r: "169.254.169.254" not in r["stdout"]),

    # IPv6 ULA (fdxx:)
    ("Redact: IPv6 ULA fd00::",
     "addr: fd00:1234:5678:abcd::1", "",
     True, lambda r: "fd00:" not in r["stdout"]),
    ("Redact: IPv6 ULA fdab::",
     "host: fdab::1", "",
     True, lambda r: "fdab::" not in r["stdout"]),

    # IPv6 link-local (fe80::)
    ("Redact: IPv6 link-local fe80::",
     "link: fe80::1", "",
     True, lambda r: "fe80::" not in r["stdout"]),
    ("Redact: IPv6 link-local fe80::abcd",
     "iface: fe80::abcd:ef01:2345", "",
     True, lambda r: "fe80::" not in r["stdout"]),

    # Edge: multiple IPs
    ("Redact: two internal IPs in one line",
     "from 10.0.0.1 to 192.168.1.1", "",
     True, lambda r: "10.0.0.1" not in r["stdout"] and "192.168.1.1" not in r["stdout"]),

    # False positives
    ("FP IP: public IP 8.8.8.8",
     "dns: 8.8.8.8", "",
     False, None),
    ("FP IP: public IP 1.1.1.1",
     "resolver: 1.1.1.1", "",
     False, None),
    ("FP IP: 172.32.0.1 (above RFC1918 range)",
     "host: 172.32.0.1", "",
     False, None),
    ("FP IP: 172.15.0.1 (below RFC1918 range)",
     "host: 172.15.0.1", "",
     False, None),
    ("FP IP: 11.0.0.1 (not 10.x)",
     "host: 11.0.0.1", "",
     False, None),
    ("FP IP: localhost 127.0.0.1",
     "server: 127.0.0.1", "",
     False, None),
]


# =====================================================================
# Test cases — Stderr redaction
# =====================================================================

STDERR_CASES = [
    ("Redact: API key in stderr",
     "", "Error: invalid key sk-ant-abc123def456",
     True, lambda r: "sk-ant-" not in r["stderr"]),
    ("Redact: SSN in stderr",
     "", "Warning: found SSN: 111-22-3333",
     True, lambda r: "111-22-3333" not in r["stderr"]),
    ("Redact: email in stderr",
     "", "Failed to send to admin@corp.com",
     True, lambda r: "admin@corp.com" not in r["stderr"]),
    ("Redact: internal IP in stderr",
     "", "Connection refused: 10.0.0.5:3000",
     True, lambda r: "10.0.0.5" not in r["stderr"]),
    ("Redact: DB URI in stderr",
     "", "Error connecting: postgres://u:p@db.local:5432/app",
     True, lambda r: "u:p@" not in r["stderr"]),
    ("Redact: private key in stderr",
     "", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...",
     True, lambda r: "BEGIN RSA PRIVATE KEY" not in r["stderr"]),

    # Both stdout and stderr
    ("Redact: sensitive data in both stdout and stderr",
     "key=sk-ant-abc123", "err: 192.168.1.1",
     True, lambda r: "sk-ant-" not in r["stdout"] and "192.168.1.1" not in r["stderr"]),
]


# =====================================================================
# Test cases — Pass-through (safe output)
# =====================================================================

PASS_THROUGH_CASES = [
    ("Pass: normal output",
     "Hello, world!", "", False, None),
    ("Pass: JSON output",
     '{"status": "ok", "count": 42}', "", False, None),
    ("Pass: build log",
     "Compiling src/main.rs...\nFinished release [optimized]", "", False, None),
    ("Pass: git log",
     "abc1234 Fix typo in README\ndef5678 Add feature X", "", False, None),
    ("Pass: empty output",
     "", "", False, None),
    ("Pass: npm install output",
     "added 150 packages in 3s", "", False, None),
    ("Pass: test results",
     "Tests: 42 passed, 0 failed\nTime: 1.234s", "", False, None),
    ("Pass: file listing",
     "src/\n  main.py\n  utils.py\ntests/\n  test_main.py", "", False, None),
    ("Pass: public IP address",
     "Server running at 203.0.113.50:8080", "", False, None),
    ("Pass: version numbers that look numeric",
     "v1.2.3.4.5.6", "", False, None),
    ("Pass: hex color codes",
     "color: #ff0000, background: #1a2b3c", "", False, None),
    ("Pass: MAC address (not an IP)",
     "device: 00:1A:2B:3C:4D:5E", "", False, None),
    ("Pass: URL without credentials",
     "Fetching https://api.github.com/repos/foo/bar", "", False, None),
    ("Pass: SQL query without secrets",
     "SELECT id, name FROM users WHERE active = true", "", False, None),
    ("Pass: Docker image digest",
     "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", "", False, None),
    ("Pass: only stderr, safe text",
     "", "warning: unused variable 'x'", False, None),
    ("Pass: large safe output",
     "line\n" * 500, "", False, None),
]


# =====================================================================
# Test cases — Redaction quality
# =====================================================================

def test_redaction_replaces_with_marker(t: TestRunner):
    """Verify redacted text contains [REDACTED] placeholder."""
    result = _run_sanitizer(stdout="key=sk-ant-abc123def456-xyz")
    ok = result["redacted"] and "[REDACTED]" in result["stdout"]
    t.check("Redacted text contains [REDACTED] marker", ok, True)



def test_multiple_rules_redact_all(t: TestRunner):
    """Verify multiple rule hits in one output all get redacted."""
    text = "key=sk-ant-abc123 ssn=123-45-6789 card=4111111111111111 email=x@y.com ip=10.0.0.1"
    result = _run_sanitizer(stdout=text)
    ok = (result["redacted"]
          and "sk-ant-" not in result["stdout"]
          and "123-45-6789" not in result["stdout"]
          and "4111111111111111" not in result["stdout"]
          and "x@y.com" not in result["stdout"]
          and "10.0.0.1" not in result["stdout"])
    t.check("Multiple rules all redact in single output", ok, True)


# =====================================================================
# Test cases — Config edge cases
# =====================================================================

def test_config_disabled_rule(t: TestRunner):
    """Disabled rule should not redact."""
    config = {
        "rules": [{
            "name": "disabled_rule",
            "enabled": False,
            "action": "redact",
            "match": "any",
            "patterns": [{"pattern": "sk-ant-[a-zA-Z0-9\\-]+", "label": "test"}],
        }]
    }
    result = _run_with_config(config, stdout="key=sk-ant-abc123def456")
    t.check("Disabled rule does NOT redact", result["redacted"], False)


def test_config_action_allow(t: TestRunner):
    """Rule with action=allow should not redact even on match."""
    config = {
        "rules": [{
            "name": "allow_rule",
            "action": "allow",
            "match": "any",
            "patterns": [{"pattern": "sk-ant-[a-zA-Z0-9\\-]+", "label": "test"}],
        }]
    }
    result = _run_with_config(config, stdout="key=sk-ant-abc123def456")
    t.check("Action=allow does NOT redact", result["redacted"], False)


def test_config_match_all(t: TestRunner):
    """Rule with match=all only triggers when ALL patterns match."""
    config = {
        "rules": [{
            "name": "all_match_rule",
            "action": "redact",
            "match": "all",
            "patterns": [
                {"pattern": "secret_a", "label": "A"},
                {"pattern": "secret_b", "label": "B"},
            ],
        }]
    }
    # Only one pattern present — should NOT trigger
    result = _run_with_config(config, stdout="has secret_a but not the other")
    t.check("match=all: one of two patterns → no redaction", result["redacted"], False)

    # Both patterns present — should trigger
    result = _run_with_config(config, stdout="has secret_a and secret_b both")
    t.check("match=all: both patterns present → redacts", result["redacted"], True)


def test_config_empty_rules(t: TestRunner):
    """Empty rules array → no redaction."""
    config = {"rules": []}
    result = _run_with_config(config, stdout="sk-ant-abc123def456")
    t.check("Empty rules → no redaction", result["redacted"], False)


def test_config_invalid_regex_skipped(t: TestRunner):
    """Invalid regex pattern is skipped; valid patterns still work."""
    config = {
        "rules": [{
            "name": "mixed_rule",
            "action": "redact",
            "match": "any",
            "patterns": [
                {"pattern": "[invalid(", "label": "broken"},
                {"pattern": "SECRET_VAL", "label": "valid"},
            ],
        }]
    }
    result = _run_with_config(config, stdout="found SECRET_VAL here")
    t.check("Invalid regex skipped, valid pattern still redacts", result["redacted"], True)


def test_config_string_patterns(t: TestRunner):
    """Patterns can be plain strings (not just dicts)."""
    config = {
        "rules": [{
            "name": "string_pat_rule",
            "action": "redact",
            "match": "any",
            "patterns": ["PLAINTEXT_SECRET"],
        }]
    }
    result = _run_with_config(config, stdout="found PLAINTEXT_SECRET here")
    t.check("String pattern (not dict) redacts", result["redacted"], True)


def test_config_missing_rules_key(t: TestRunner):
    """Config without 'rules' key exits gracefully (exit 0, no redaction)."""
    config = {"version": 1}
    result = _run_with_config(config, stdout="sk-ant-abc123def456")
    t.check("Missing 'rules' key → no redaction (graceful)", result["redacted"], False)


def test_config_no_patterns(t: TestRunner):
    """Rule with no patterns key is skipped."""
    config = {
        "rules": [{
            "name": "no_patterns",
            "action": "redact",
            "match": "any",
        }]
    }
    result = _run_with_config(config, stdout="sk-ant-abc123def456")
    t.check("Rule without patterns → no redaction", result["redacted"], False)


# =====================================================================
# Test cases — Input edge cases
# =====================================================================

def test_input_missing_tool_result(t: TestRunner):
    """Missing tool_result in hook input → no crash."""
    hook_input = {
        "session_id": "test",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "test"},
    }
    result = _run_sanitizer_raw(hook_input)
    t.check("Missing tool_result → exit 0", result.returncode, 0)


def test_input_non_dict_tool_result(t: TestRunner):
    """tool_result that is not a dict → no crash."""
    hook_input = {
        "session_id": "test",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "test"},
        "tool_result": "just a string",
    }
    result = _run_sanitizer_raw(hook_input)
    t.check("Non-dict tool_result → exit 0", result.returncode, 0)


def test_input_empty_stdout_and_stderr(t: TestRunner):
    """Empty stdout and stderr → no redaction."""
    result = _run_sanitizer(stdout="", stderr="")
    t.check("Empty stdout+stderr → no redaction", result["redacted"], False)


def test_input_malformed_json_stdin(t: TestRunner):
    """Malformed JSON on stdin → exit 0 (no crash)."""
    import subprocess
    result = subprocess.run(
        [sys.executable, OUTPUT_SANITIZER, SANITIZER_RULES],
        input="not json",
        capture_output=True, text=True,
    )
    t.check("Malformed JSON stdin → exit 0", result.returncode, 0)


def test_input_no_config_arg(t: TestRunner):
    """No config file argument → exit 0."""
    import subprocess
    result = subprocess.run(
        [sys.executable, OUTPUT_SANITIZER],
        input="{}",
        capture_output=True, text=True,
    )
    t.check("No config argument → exit 0", result.returncode, 0)


def test_input_nonexistent_config(t: TestRunner):
    """Nonexistent config file → exit 0."""
    import subprocess
    result = subprocess.run(
        [sys.executable, OUTPUT_SANITIZER, "/tmp/nonexistent_config_xyz.json"],
        input="{}",
        capture_output=True, text=True,
    )
    t.check("Nonexistent config → exit 0", result.returncode, 0)


# =====================================================================
# Test cases — Audit logging
# =====================================================================

def test_audit_log_on_redaction(t: TestRunner):
    """Verify audit log entry is written on redaction."""
    import tempfile, subprocess, glob, time
    audit_dir = tempfile.mkdtemp()
    audit_log = os.path.join(audit_dir, "audit.log")
    env = {**os.environ, "HOOK_AUDIT_LOG": audit_log}

    hook_input = {
        "session_id": "audit-test",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cat secrets"},
        "tool_result": {"stdout": "key=sk-ant-abc123def456", "stderr": ""},
    }
    subprocess.run(
        [sys.executable, OUTPUT_SANITIZER, SANITIZER_RULES],
        input=json.dumps(hook_input),
        capture_output=True, text=True,
        env=env,
    )

    logged = False
    if os.path.isfile(audit_log):
        with open(audit_log) as f:
            for line in f:
                entry = json.loads(line)
                if entry.get("filter") == "output_sanitizer" and entry.get("action") == "redact":
                    logged = True
                    break
    t.check("Audit log records redaction event", logged, True)

    # Clean up
    import shutil
    shutil.rmtree(audit_dir, ignore_errors=True)


def test_no_audit_log_on_pass_through(t: TestRunner):
    """No audit log entry for safe output."""
    import tempfile, subprocess, shutil
    audit_dir = tempfile.mkdtemp()
    audit_log = os.path.join(audit_dir, "audit.log")
    env = {**os.environ, "HOOK_AUDIT_LOG": audit_log}

    hook_input = {
        "session_id": "audit-test",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hello"},
        "tool_result": {"stdout": "hello", "stderr": ""},
    }
    subprocess.run(
        [sys.executable, OUTPUT_SANITIZER, SANITIZER_RULES],
        input=json.dumps(hook_input),
        capture_output=True, text=True,
        env=env,
    )

    logged = os.path.isfile(audit_log) and os.path.getsize(audit_log) > 0
    t.check("No audit log for safe output", logged, False)
    shutil.rmtree(audit_dir, ignore_errors=True)


# =====================================================================
# Test cases — Unicode / case insensitivity
# =====================================================================

# =====================================================================
# Test cases — Anonymization modes (pseudonymize, hash, redact)
# =====================================================================

def test_anonymization_pseudonymize_mode(t: TestRunner):
    """Pseudonymize mode replaces with [PII-{8-char-hash}]."""
    config = {
        "rules": [{
            "name": "pseudo_rule",
            "action": "redact",
            "match": "any",
            "anonymization_mode": "pseudonymize",
            "patterns": [{"pattern": r"\d{3}-\d{2}-\d{4}", "label": "SSN"}],
        }]
    }
    result = _run_with_config(config, stdout="SSN: 123-45-6789")
    ok = (result["redacted"]
          and "123-45-6789" not in result["stdout"]
          and "[PII-" in result["stdout"]
          and result["stdout"].count("[PII-") == 1)
    t.check("Pseudonymize: SSN replaced with [PII-{hash}]", ok, True)


def test_anonymization_hash_mode(t: TestRunner):
    """Hash mode replaces with sha256:{full-hash}."""
    config = {
        "rules": [{
            "name": "hash_rule",
            "action": "redact",
            "match": "any",
            "anonymization_mode": "hash",
            "patterns": [{"pattern": r"\d{3}-\d{2}-\d{4}", "label": "SSN"}],
        }]
    }
    result = _run_with_config(config, stdout="SSN: 123-45-6789")
    ok = (result["redacted"]
          and "123-45-6789" not in result["stdout"]
          and "sha256:" in result["stdout"])
    t.check("Hash: SSN replaced with sha256:{hash}", ok, True)


def test_anonymization_redact_mode_default(t: TestRunner):
    """Default (redact) mode uses [REDACTED]."""
    config = {
        "rules": [{
            "name": "redact_rule",
            "action": "redact",
            "match": "any",
            "patterns": [{"pattern": r"\d{3}-\d{2}-\d{4}", "label": "SSN"}],
        }]
    }
    result = _run_with_config(config, stdout="SSN: 123-45-6789")
    ok = (result["redacted"]
          and "123-45-6789" not in result["stdout"]
          and "[REDACTED]" in result["stdout"])
    t.check("Redact (default): SSN replaced with [REDACTED]", ok, True)


def test_anonymization_pseudonymize_deterministic(t: TestRunner):
    """Same input always produces same pseudonym token."""
    import hashlib
    config = {
        "rules": [{
            "name": "pseudo_determ",
            "action": "redact",
            "match": "any",
            "anonymization_mode": "pseudonymize",
            "patterns": [{"pattern": r"\d{3}-\d{2}-\d{4}", "label": "SSN"}],
        }]
    }
    result1 = _run_with_config(config, stdout="SSN: 123-45-6789")
    result2 = _run_with_config(config, stdout="SSN: 123-45-6789")
    # Both should produce the same token
    expected_token = hashlib.sha256("123-45-6789".encode()).hexdigest()[:8]
    expected = f"[PII-{expected_token}]"
    ok = (expected in result1["stdout"] and expected in result2["stdout"])
    t.check("Pseudonymize: deterministic — same input same token", ok, True)


def test_anonymization_hash_full_sha256(t: TestRunner):
    """Hash mode produces full 64-char SHA-256."""
    import hashlib
    config = {
        "rules": [{
            "name": "hash_full",
            "action": "redact",
            "match": "any",
            "anonymization_mode": "hash",
            "patterns": [{"pattern": r"\d{3}-\d{2}-\d{4}", "label": "SSN"}],
        }]
    }
    result = _run_with_config(config, stdout="SSN: 123-45-6789")
    expected_hash = hashlib.sha256("123-45-6789".encode()).hexdigest()
    ok = result["redacted"] and f"sha256:{expected_hash}" in result["stdout"]
    t.check("Hash: produces full 64-char SHA-256", ok, True)


def test_anonymization_unknown_mode_defaults_redact(t: TestRunner):
    """Unknown anonymization_mode falls back to [REDACTED]."""
    config = {
        "rules": [{
            "name": "unknown_mode",
            "action": "redact",
            "match": "any",
            "anonymization_mode": "unknown_value",
            "patterns": [{"pattern": r"\d{3}-\d{2}-\d{4}", "label": "SSN"}],
        }]
    }
    result = _run_with_config(config, stdout="SSN: 123-45-6789")
    ok = result["redacted"] and "[REDACTED]" in result["stdout"]
    t.check("Unknown anonymization_mode defaults to [REDACTED]", ok, True)


def test_anonymization_per_rule_config(t: TestRunner):
    """Different rules can have different anonymization modes."""
    config = {
        "rules": [
            {
                "name": "rule_pseudo",
                "action": "redact",
                "match": "any",
                "anonymization_mode": "pseudonymize",
                "patterns": [{"pattern": r"\d{3}-\d{2}-\d{4}", "label": "SSN"}],
            },
            {
                "name": "rule_hash",
                "action": "redact",
                "match": "any",
                "anonymization_mode": "hash",
                "patterns": [{"pattern": r"sk-ant-[a-zA-Z0-9\-]+", "label": "API key"}],
            },
        ]
    }
    result = _run_with_config(config, stdout="SSN: 123-45-6789 key=sk-ant-abc123def")
    ok = (result["redacted"]
          and "[PII-" in result["stdout"]
          and "sha256:" in result["stdout"]
          and "123-45-6789" not in result["stdout"]
          and "sk-ant-" not in result["stdout"])
    t.check("Per-rule: pseudonymize SSN + hash API key", ok, True)


def test_case_insensitive_redaction(t: TestRunner):
    """Patterns are case-insensitive (re.IGNORECASE)."""
    # AWS key pattern is uppercase, test mixed case
    result = _run_sanitizer(stdout="AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE")
    ok1 = result["redacted"] and "AKIA" not in result["stdout"]

    result = _run_sanitizer(stdout="aws_access_key_id = AKIAIOSFODNN7EXAMPLE")
    ok2 = result["redacted"] and "AKIA" not in result["stdout"]

    t.check("Case-insensitive: uppercase key assignment redacted", ok1, True)
    t.check("Case-insensitive: lowercase key assignment redacted", ok2, True)


def test_unicode_normalization(t: TestRunner):
    """Unicode normalization handles homoglyphs."""
    # Cyrillic 'а' (U+0430) in place of Latin 'a' in sk-ant-
    cyrillic_a = "\u0430"
    text = f"key=sk-{cyrillic_a}nt-abc123def456"
    result = _run_sanitizer(stdout=text)
    # After NFKC normalization, this should match sk-ant-
    t.check("Unicode-normalized homoglyph redacted", result["redacted"], True)


# =====================================================================
# Main
# =====================================================================

def _run_cases(t: TestRunner, section_name: str, cases: list):
    """Run a list of (desc, stdout, stderr, should_redact, check_fn) cases."""
    t.section(section_name)
    for case in cases:
        desc, stdout, stderr, should_redact, check_fn = case
        result = _run_sanitizer(stdout, stderr)
        if should_redact:
            ok = result["redacted"] and (check_fn is None or check_fn(result))
            print(f"  [{'PASS' if ok else 'FAIL'}] {desc}")
            if not ok:
                print(f"         redacted={result['redacted']}, stdout={result['stdout'][:120]}, stderr={result['stderr'][:80]}")
        else:
            ok = not result["redacted"]
            print(f"  [{'PASS' if ok else 'FAIL'}] {desc}")
            if not ok:
                print(f"         Unexpectedly redacted: stdout={result['stdout'][:120]}")
        if ok:
            t.passed += 1
        else:
            t.failed += 1


def main():
    t = TestRunner("Testing Output Sanitizer Hook")
    t.header()

    # Data-driven per-rule tests
    _run_cases(t, "API key redaction (Rule 1)", API_KEY_CASES)
    _run_cases(t, "SSN redaction (Rule 2)", SSN_CASES)
    _run_cases(t, "Credit card redaction (Rule 3)", CREDIT_CARD_CASES)
    _run_cases(t, "Email redaction (Rule 4)", EMAIL_CASES)
    _run_cases(t, "Private key redaction (Rule 5)", PRIVATE_KEY_CASES)
    _run_cases(t, "Database connection string redaction (Rule 6)", DB_CONN_CASES)
    _run_cases(t, "Internal IP redaction (Rule 7)", INTERNAL_IP_CASES)
    _run_cases(t, "Stderr redaction", STDERR_CASES)
    _run_cases(t, "Pass-through (safe output)", PASS_THROUGH_CASES)

    # Functional tests
    t.section("Redaction quality")
    test_redaction_replaces_with_marker(t)
    # Fix the surrounding-text test inline (avoid NameError for 'r')
    result = _run_sanitizer(stdout="before sk-ant-abc123def456 after")
    ok = (result["redacted"]
          and "before" in result["stdout"]
          and "after" in result["stdout"]
          and "sk-ant-" not in result["stdout"])
    t.check("Surrounding text preserved after redaction", ok, True)
    test_multiple_rules_redact_all(t)

    t.section("Config edge cases")
    test_config_disabled_rule(t)
    test_config_action_allow(t)
    test_config_match_all(t)
    test_config_empty_rules(t)
    test_config_invalid_regex_skipped(t)
    test_config_string_patterns(t)
    test_config_missing_rules_key(t)
    test_config_no_patterns(t)

    t.section("Input edge cases")
    test_input_missing_tool_result(t)
    test_input_non_dict_tool_result(t)
    test_input_empty_stdout_and_stderr(t)
    test_input_malformed_json_stdin(t)
    test_input_no_config_arg(t)
    test_input_nonexistent_config(t)

    t.section("Audit logging")
    test_audit_log_on_redaction(t)
    test_no_audit_log_on_pass_through(t)

    t.section("Unicode / case insensitivity")
    test_case_insensitive_redaction(t)
    test_unicode_normalization(t)

    t.section("Anonymization modes")
    test_anonymization_pseudonymize_mode(t)
    test_anonymization_hash_mode(t)
    test_anonymization_redact_mode_default(t)
    test_anonymization_pseudonymize_deterministic(t)
    test_anonymization_hash_full_sha256(t)
    test_anonymization_unknown_mode_defaults_redact(t)
    test_anonymization_per_rule_config(t)

    sys.exit(t.summary())


if __name__ == "__main__":
    main()
