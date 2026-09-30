# Bug Bounty Harness — Focused Web Testing

Targeted harness for finding real P1-P3 web vulnerabilities on authorized targets.

## Architecture

Two-pass approach: **black-box first** (no auth), then **grey-box** (authenticated).

```
                    ┌──────────────────────┐
                    │     TARGET CONFIG     │
                    │  base_url, scope,     │
                    │  wordlists, creds     │
                    └──────────┬───────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
     ═════ PASS 1: BLACK-BOX ═════    ═════ PASS 2: GREY-BOX ═════
              │                                 │
     ┌────────▼────────┐               ┌───────▼────────┐
     │  ENDPOINT        │               │  AUTH MANAGER   │
     │  DISCOVERY       │               │  Login, tokens, │
     │                  │               │  session mgmt   │
     │  • Crawl sitemap │               └───────┬────────┘
     │  • Brute paths   │                       │
     │  • Check no-auth │               ┌───────▼────────┐
     │    access         │               │  IDOR SCANNER   │
     └────────┬────────┘               │                 │
              │                         │  • Swap IDs     │
     ┌────────▼────────┐               │  • UUID predict │
     │  INFO DISCLOSURE │               │  • Param tamper │
     │                  │               └───────┬────────┘
     │  • Error pages   │                       │
     │  • Headers leak  │               ┌───────▼────────┐
     │  • Debug endpts  │               │  AUTHZ TESTER   │
     │  • Source maps   │               │                 │
     │  • .env / .git   │               │  • Horiz priv   │
     └────────┬────────┘               │  • Vert priv    │
              │                         │  • Role bypass  │
              │                         └───────┬────────┘
              └────────────┬────────────────────┘
                           │
                  ┌────────▼────────┐
                  │    REPORTER      │
                  │  Findings + PoC  │
                  │  CVSS scoring    │
                  │  Platform format │
                  └─────────────────┘
```

## Usage

```bash
# Pass 1: Find what's exposed without auth
python -m harness.run --target https://api.example.com --phase blackbox

# Pass 2: Test IDOR + authz with credentials
python -m harness.run --target https://api.example.com --phase greybox \
  --user-token "eyJhbG..." --victim-token "eyJhbG..."

# Full run
python -m harness.run --target https://api.example.com --phase all \
  --user-token "..." --victim-token "..."
```

## What it finds

| Phase     | Bug Class                  | CWE     | Typical Severity |
|-----------|----------------------------|---------|------------------|
| Black-box | Unauth endpoint access     | CWE-306 | High-Critical    |
| Black-box | Information disclosure      | CWE-200 | Low-Medium       |
| Black-box | Debug/admin panel exposure  | CWE-489 | Medium-High      |
| Black-box | Sensitive file exposure     | CWE-538 | Medium-High      |
| Grey-box  | IDOR                        | CWE-639 | High-Critical    |
| Grey-box  | Horizontal privilege esc    | CWE-284 | High             |
| Grey-box  | Vertical privilege esc      | CWE-269 | Critical         |
| Grey-box  | Missing function-level authz| CWE-285 | High             |
