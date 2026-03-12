# Managed Security Policy Deployment

This directory contains templates for IT teams deploying organization-wide security policies that cannot be overridden by project or user configurations.

## Overview

The managed layer is the highest-priority security layer. Rules deployed here:
- Always use `"action": "deny"` (hard block)
- Have `"overridable": false` (cannot be bypassed by overrides)
- Run before project and user hooks

## Files

| File | Description |
|------|-------------|
| `managed_rules.json` | 8 hard-deny rules for Bash commands (credentials, injection, exfiltration) |
| `managed_settings.json` | Claude Code settings template for hook registration |

## Installation

### Linux

```bash
# 1. Create the managed hooks directory
sudo mkdir -p /etc/claude-code/hooks

# 2. Copy the hook engine and rules
sudo cp .claude/hooks/regex_filter.py /etc/claude-code/hooks/
sudo cp .claude/hooks/hook_utils.py /etc/claude-code/hooks/
sudo cp managed/managed_rules.json /etc/claude-code/hooks/

# 3. Copy managed settings
sudo cp managed/managed_settings.json /etc/claude-code/managed-settings.json

# 4. Set permissions (read-only for users)
sudo chmod 644 /etc/claude-code/hooks/*.py /etc/claude-code/hooks/*.json
sudo chmod 644 /etc/claude-code/managed-settings.json
```

### macOS

```bash
# Same steps, but using /Library/Application Support/claude-code/
sudo mkdir -p "/Library/Application Support/claude-code/hooks"
sudo cp .claude/hooks/regex_filter.py "/Library/Application Support/claude-code/hooks/"
sudo cp .claude/hooks/hook_utils.py "/Library/Application Support/claude-code/hooks/"
sudo cp managed/managed_rules.json "/Library/Application Support/claude-code/hooks/"
```

## How It Works

1. Claude Code loads `managed-settings.json` from the system-wide config directory
2. Managed hooks run first, before any project or user hooks
3. If a managed rule triggers, the command is blocked with no option to override
4. Project and user hooks run after managed hooks pass

## Interaction with Override System

- Managed rules have `"overridable": false` — the override system skips them entirely
- Project-level `config_overrides.json` has no effect on managed rules
- User-level `~/.claude/hooks/config_overrides.json` has no effect on managed rules
- Only IT administrators can modify managed rules

## Customization

### Adding Rules

Add rules to `managed_rules.json` following the standard rule format. Always set:
```json
{
  "action": "deny",
  "overridable": false
}
```

### Write Rules

Create `managed_rules_write.json` (same format as `filter_rules_write.json`) for managed Write/Edit restrictions, and update `managed_settings.json` to reference it.

## Security Considerations

- Deploy hook scripts as read-only to prevent tampering
- Consider using file integrity monitoring on `/etc/claude-code/`
- Audit logs from managed rules use `[MANAGED]` prefix in messages for easy filtering
