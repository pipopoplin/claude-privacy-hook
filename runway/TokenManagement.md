# Token Management

## Overview

Pro features are gated by a signed token issued on login. A background heartbeat keeps the token alive. If the token expires without renewal, pro features fall back to free tier.

## Properties

| Property | Value |
|----------|-------|
| Token validity | 3 hours |
| Heartbeat interval | 10 min |
| Max offline grace | 3 hours |
| Max sharing exposure | 3 hours |
| Time to detect device switch | ≤10 min |
| Trial period | 14 days (full Pro, no payment) |
| Trial token expiry | 14 days from signup (hard expiry, no renewal after) |

## Login

1. User runs `claude-privacy-hook login`
2. Authenticates with license server (email + password, or SSO)
3. Server creates a session tied to user account + machine fingerprint
4. Server returns a signed token
5. Token stored locally:
   - User scope: `~/.claude/hooks/license_token`
   - Computer scope: `/etc/claude-code/license_token`

If the user already had an active session on another machine, that session is marked stale.

## Token Contents

| Field | Description |
|-------|-------------|
| `user_id` | Account identifier |
| `email` | User email |
| `tier` | `trial` or `pro` |
| `org` | Organization name |
| `machine_id` | Fingerprint of the current machine |
| `session_id` | Server-side session reference |
| `issued_at` | Token creation timestamp |
| `expires_at` | 3 hours from `issued_at` |
| `trial_ends_at` | Only for trial tokens: 14 days from signup |
| `signature` | Server-signed (RSA/Ed25519), verifiable offline |

## Trial

14-day free trial with full Pro features, no payment required.

1. User runs `claude-privacy-hook login --trial`
2. Creates account (email only, no credit card)
3. Server issues token with `tier: trial` and `trial_ends_at: signup + 14 days`
4. Token renews normally via heartbeat (3h validity, 10min heartbeat)
5. After 14 days: heartbeat renewal returns `trial_expired` → token not renewed → falls back to free tier

| Event | Behavior |
|-------|----------|
| Day 1–14 | Full Pro features, normal heartbeat renewal |
| Day 14 | Heartbeat returns `trial_expired`, token not renewed |
| Day 14 + 3h | Last token expires → free tier |
| User subscribes | Server upgrades tier to `pro`, normal renewal resumes |
| User does nothing | Free tier permanently, all detection still works |

The trial cannot be restarted — one trial per email address.

## Heartbeat

The persistent NLP service (`llm_service.py`) runs the heartbeat loop.

Every 10 minutes:
1. Send `POST /auth/heartbeat` with current token
2. **Success** → server returns renewed token (new `expires_at` = now + 3h), write to token file and status file
3. **Fail** (timeout, network error, server down, session stale) → do nothing, wait for next cycle

No retries. One attempt per cycle. The 3-hour token validity covers transient failures.

## License Status File

Written by the heartbeat. Read by all pro hooks at runtime.

Location: `/tmp/claude-hook-license-{uid}.json`

```json
{
  "status": "valid",
  "tier": "team",
  "user": "dev@company.com",
  "machine_id": "a1b2c3",
  "last_validated": "2026-03-12T14:00:00Z",
  "next_check": "2026-03-12T14:10:00Z",
  "failures": 0
}
```

| Status | Meaning | Pro features? |
|--------|---------|:-------------:|
| `valid` | Token present and not expired | Yes |
| `degraded` | Token expired, heartbeat can't renew | No — free tier |
| `expired` | Token past `expires_at` | No — free tier |
| `revoked` | Server explicitly revoked session | No — free tier |

## Hook Runtime Check

Every pro hook reads the status file before running paid features. No network call, no crypto — single file read (<0.1ms):

```python
def is_pro_active():
    status = read_json("/tmp/claude-hook-license-{uid}.json")
    return status.get("status") == "valid"
```

If `is_pro_active()` returns `False`, the hook skips pro logic and lets the command pass (free tier behavior).

## Timeline: Normal Operation

```
0:00   Login → token valid until 3:00, status: valid
0:10   Heartbeat → success → token renewed until 3:10
0:20   Heartbeat → success → token renewed until 3:20
0:30   Heartbeat → success → token renewed until 3:30
...    (continues indefinitely while server is reachable)
```

## Timeline: Server Outage

```
1:20   Heartbeat → success → token renewed until 4:20
1:30   Server goes down
1:40   Heartbeat → fail → do nothing
1:50   Heartbeat → fail → do nothing
2:00   Heartbeat → fail → do nothing
...    (token from 1:20 still valid)
4:20   Token expires → status: degraded → free tier
4:30   Server back → heartbeat succeeds → token renewed → pro restored
```

Max pro features without server: 3 hours from last successful heartbeat.

## Timeline: Device Switch

```
Machine A:
0:00   User logs in → token(machine_a) valid until 3:00

Machine B:
0:25   User logs in → token(machine_b) valid until 3:25
       Server marks machine_a session as stale

Machine A:
0:30   Heartbeat → server says session stale → token NOT renewed
0:30   Status still valid (token not expired yet)
...
3:00   Token expires → status: degraded → free tier
       Colleague on Machine A loses pro features
```

Max sharing exposure: 3 hours (remaining token validity at time of device switch).

## Timeline: Colleague Sharing

```
User A logs in on Machine 1 → token valid 3h
User A switches to Machine 2 → logs in → Machine 1 session stale
Colleague B on Machine 1 → pro features work until token expires (≤3h)
Token expires → Colleague B cannot renew (session stale) → free tier
Colleague B must login with own account or stay on free tier
```

## NLP Service Integration

The heartbeat runs inside `llm_service.py` (already a background process):

```
llm_service.py
├── NLP plugin detection (existing)
├── Config hot-reload (existing)
└── License heartbeat (new)
    ├── Every 10 min: POST /auth/heartbeat
    ├── On success: write renewed token + update status file
    └── On fail: increment failure count in status file
```

If `llm_service.py` is not running (e.g., free tier only, or service crashed):
- Next pro hook call starts the service (existing auto-start behavior)
- Service starts heartbeat loop on startup
- If no valid token exists, status file says `expired` → free tier

## License Server Endpoints

| Endpoint | Purpose | Called by |
|----------|---------|----------|
| `POST /auth/login` | Authenticate, create session, return token | `claude-privacy-hook login` CLI |
| `POST /auth/heartbeat` | Validate session, return renewed token | `llm_service.py` every 10 min |
| `POST /auth/logout` | Destroy session, invalidate token | `claude-privacy-hook logout` CLI |
| `GET /auth/status` | Check session status | `claude-privacy-hook status` CLI |

## Multi-Seat (Team/Enterprise)

| Tier | Seats | Behavior |
|------|-------|----------|
| Team | N seats purchased | Up to N users can have active sessions simultaneously |
| Enterprise | Unlimited or pool | Org-wide, managed by admin |

When seat N+1 tries to log in: reject with "All seats in use, contact admin."

## CLI Commands

```bash
claude-privacy-hook login
  Email: dev@company.com
  Password: ********
  ✓ Logged in. Team license active. Token valid for 3h (auto-renews).

claude-privacy-hook status
  User:     dev@company.com
  Tier:     Team
  Org:      Acme Corp
  Machine:  dev-laptop (active)
  Token:    valid (expires in 2h47m)
  Seats:    3 of 10 used

claude-privacy-hook logout
  ✓ Session ended. Pro features disabled.
```

## Graceful Degradation

Pro hooks never hard-fail. Behavior when pro is unavailable:

| Situation | Behavior |
|-----------|----------|
| No token file | Free tier only |
| Token expired, heartbeat failing | Free tier, log warning |
| Session revoked (device switch) | Free tier, show "session ended — login again" |
| Invalid/tampered token | Free tier, log warning |
| NLP service not running | Auto-start on next hook call |
| Status file missing/corrupt | Treat as expired → free tier |

The user is never blocked from working. They lose pro detection (NLP, overrides, managed layer) until the token is restored.
