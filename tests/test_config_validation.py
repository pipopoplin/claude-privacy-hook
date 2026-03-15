#!/usr/bin/env python3
"""Test that JSON config files have required metadata fields.

Validates that all rules in filter_rules.json, filter_rules_write.json,
filter_rules_read.json, and output_sanitizer_rules.json have:
  - data_classification field (restricted/confidential/internal/public)
  - scf metadata object with domain, controls, risk_level
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import (
    HOOKS_DIR, BASH_RULES, WRITE_RULES, READ_RULES, SANITIZER_RULES,
    TestRunner,
)

VALID_CLASSIFICATIONS = {"restricted", "confidential", "internal", "public"}
VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}


# =====================================================================
# Helpers
# =====================================================================

def _load_rules(path: str) -> list[dict]:
    """Load rules from a JSON config file."""
    with open(path) as f:
        data = json.load(f)
    return data.get("rules", [])


# =====================================================================
# Tests: data_classification
# =====================================================================

def test_bash_rules_have_data_classification(t: TestRunner):
    """All Bash rules have data_classification field."""
    rules = _load_rules(BASH_RULES)
    for rule in rules:
        name = rule.get("name", "?")
        cls = rule.get("data_classification")
        t.check(f"Bash: {name} has data_classification",
                cls in VALID_CLASSIFICATIONS, True)


def test_write_rules_have_data_classification(t: TestRunner):
    """All Write rules have data_classification field."""
    rules = _load_rules(WRITE_RULES)
    for rule in rules:
        name = rule.get("name", "?")
        cls = rule.get("data_classification")
        t.check(f"Write: {name} has data_classification",
                cls in VALID_CLASSIFICATIONS, True)


def test_read_rules_have_data_classification(t: TestRunner):
    """All Read rules have data_classification field."""
    rules = _load_rules(READ_RULES)
    for rule in rules:
        name = rule.get("name", "?")
        cls = rule.get("data_classification")
        t.check(f"Read: {name} has data_classification",
                cls in VALID_CLASSIFICATIONS, True)


def test_sanitizer_rules_have_data_classification(t: TestRunner):
    """All sanitizer rules have data_classification field."""
    rules = _load_rules(SANITIZER_RULES)
    for rule in rules:
        name = rule.get("name", "?")
        cls = rule.get("data_classification")
        t.check(f"Sanitizer: {name} has data_classification",
                cls in VALID_CLASSIFICATIONS, True)


# =====================================================================
# Tests: SCF metadata
# =====================================================================

def test_bash_rules_have_scf_metadata(t: TestRunner):
    """All Bash rules have scf.domain and scf.risk_level."""
    rules = _load_rules(BASH_RULES)
    for rule in rules:
        name = rule.get("name", "?")
        scf = rule.get("scf", {})
        t.check(f"Bash: {name} has scf.domain",
                bool(scf.get("domain")), True)
        t.check(f"Bash: {name} has scf.risk_level",
                scf.get("risk_level") in VALID_RISK_LEVELS, True)


def test_write_rules_have_scf_metadata(t: TestRunner):
    """All Write rules have scf metadata."""
    rules = _load_rules(WRITE_RULES)
    for rule in rules:
        name = rule.get("name", "?")
        scf = rule.get("scf", {})
        t.check(f"Write: {name} has scf.domain",
                bool(scf.get("domain")), True)


def test_read_rules_have_scf_metadata(t: TestRunner):
    """All Read rules have scf metadata."""
    rules = _load_rules(READ_RULES)
    for rule in rules:
        name = rule.get("name", "?")
        scf = rule.get("scf", {})
        t.check(f"Read: {name} has scf.domain",
                bool(scf.get("domain")), True)


def test_sanitizer_rules_have_scf_metadata(t: TestRunner):
    """All sanitizer rules have scf metadata."""
    rules = _load_rules(SANITIZER_RULES)
    for rule in rules:
        name = rule.get("name", "?")
        scf = rule.get("scf", {})
        t.check(f"Sanitizer: {name} has scf.domain",
                bool(scf.get("domain")), True)


# =====================================================================
# Tests: SCF controls list
# =====================================================================

def test_bash_rules_have_scf_controls(t: TestRunner):
    """All Bash rules have non-empty scf.controls list."""
    rules = _load_rules(BASH_RULES)
    for rule in rules:
        name = rule.get("name", "?")
        scf = rule.get("scf", {})
        controls = scf.get("controls", [])
        t.check(f"Bash: {name} has scf.controls",
                isinstance(controls, list) and len(controls) > 0, True)


# =====================================================================
# Tests: Rule count validation
# =====================================================================

def test_bash_rule_count(t: TestRunner):
    """Bash rules count matches expected (18 rules)."""
    rules = _load_rules(BASH_RULES)
    t.check("Bash: 18 rules", len(rules), 18)


def test_write_rule_count(t: TestRunner):
    """Write rules count matches expected (8 rules)."""
    rules = _load_rules(WRITE_RULES)
    t.check("Write: 8 rules", len(rules), 8)


def test_read_rule_count(t: TestRunner):
    """Read rules count matches expected (1 rule)."""
    rules = _load_rules(READ_RULES)
    t.check("Read: 1 rule", len(rules), 1)


def test_sanitizer_rule_count(t: TestRunner):
    """Sanitizer rules count matches expected (7 rules)."""
    rules = _load_rules(SANITIZER_RULES)
    t.check("Sanitizer: 7 rules", len(rules), 7)


# =====================================================================
# Tests: Deny-before-allow ordering
# =====================================================================

def test_bash_deny_before_allow(t: TestRunner):
    """In Bash rules, all deny rules come before the allow rule.

    The expected ordering is: deny rules → ask rules → allow → final ask catch-all.
    The key invariant is that deny rules are never after the allow rule.
    """
    rules = _load_rules(BASH_RULES)
    seen_allow = False
    deny_after_allow = False
    for rule in rules:
        action = rule.get("action", "deny")
        if action == "allow":
            seen_allow = True
        elif seen_allow and action == "deny":
            deny_after_allow = True
            break
    t.check("Bash: no deny rules after allow", deny_after_allow, False)


# =====================================================================
# Main
# =====================================================================

def main():
    t = TestRunner("Testing Config Validation")
    t.header()

    t.section("data_classification on all rules")
    test_bash_rules_have_data_classification(t)
    test_write_rules_have_data_classification(t)
    test_read_rules_have_data_classification(t)
    test_sanitizer_rules_have_data_classification(t)

    t.section("SCF metadata on all rules")
    test_bash_rules_have_scf_metadata(t)
    test_write_rules_have_scf_metadata(t)
    test_read_rules_have_scf_metadata(t)
    test_sanitizer_rules_have_scf_metadata(t)

    t.section("SCF controls lists")
    test_bash_rules_have_scf_controls(t)

    t.section("Rule counts")
    test_bash_rule_count(t)
    test_write_rule_count(t)
    test_read_rule_count(t)
    test_sanitizer_rule_count(t)

    t.section("Rule ordering")
    test_bash_deny_before_allow(t)

    sys.exit(t.summary())


if __name__ == "__main__":
    main()
