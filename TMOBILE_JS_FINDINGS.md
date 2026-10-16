# T-Mobile JS Analysis — Exploitable Findings Only

> **Date:** 2026-10-16 | **Source:** 2,171 in-scope JS files from 168 live hosts
> **Primary source:** `digits.t-mobile.com/static/js/main.js` (8.3MB React bundle)

---

## 1. Internal/Staging DIGITS API Endpoints in Production JS

**Severity:** Critical (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N — 9.1)
**Class:** CWE-200 — Exposure of Sensitive Information
**Target:** `digits.t-mobile.com/static/js/main.js`

### Summary
Production DIGITS bundle hardcodes 3 internal/staging API base URLs and 1 production CPaaS endpoint. Staging environments typically run with weaker auth, debug mode, or no WAF.

### Endpoints
| URL | Env |
|-----|-----|
| `https://api-dev.lab.t-mobile.com/v1/digitsApi` | Internal lab |
| `https://api-devstg.t-mobile.com/v1/digitsApi` | Dev staging |
| `https://api-teststg.t-mobile.com/v1/digitsApi` | Test staging |
| `https://cpaas-geo.t-mobile.com/v1/digitsApi` | Production CPaaS |

### What to test
- Direct unauthenticated requests to staging endpoints
- Compare auth enforcement staging vs production
- Verbose error messages / stack traces on staging
- MSISDN manipulation on staging without rate limits

---

## 2. DIGITS DAAS API — IDOR on Line/Device Management

**Severity:** Critical (CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N — 8.1)
**Class:** CWE-639 — Authorization Bypass Through User-Controlled Key
**Target:** `cpaas-geo.t-mobile.com/v1/digitsApi`

### Summary
JS exposes DAAS API paths that accept raw MSISDN as a parameter. If the backend trusts the MSISDN from the request without verifying ownership, swapping it yields access to another user's line data, E911 info, or device instances.

### API Paths
| Path | Attack |
|------|--------|
| `/daas/lines/deviceInstances` | IDOR — swap `{msisdn: "VICTIM_NUMBER"}` to list their devices |
| `/daas/call/e911/information` | IDOR — `{msisdn: "VICTIM", clientId: "..."}` leaks E911 address |
| `/digitslink/api/unlink` | Unlink victim's device from their line |
| `/digitslink/v1/userlinkinfo` | Enumerate linked accounts for any MSISDN |
| `/digitsOrchestratorService/daas` | Orchestrator — register your device on victim's line |

### JS Evidence
```
BaseUrl}/daas/lines/deviceInstances`, a={msisdn:e}
BaseUrl}/daas/call/e911/information`, a={msisdn:e, clientId:this.iamClientId}
```
The `msisdn` param is passed directly from client-side state.

---

## 3. Firebase RTDB — Potential Unauthenticated Data Access

**Severity:** High (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — 7.5)
**Class:** CWE-306 — Missing Authentication for Critical Function
**Target:** `phone-2-1247.firebaseio.com`

### Summary
DIGITS uses Firebase project `phone-2-1247`. The Realtime Database URL is exposed. If security rules allow unauthenticated reads, call logs, messages, and phone numbers are exposed.

### What to test
```
curl https://phone-2-1247.firebaseio.com/.json
curl https://phone-2-1247.firebaseio.com/users.json
curl https://phone-2-1247.firebaseio.com/messages.json
```
Also test Firebase Storage: `phone-2-1247.appspot.com`

---

## 4. MSISDN Registration Flow — Carrier Auth Bypass Vector

**Severity:** Critical (Special Target — Carrier Auth Bypass)
**Class:** CWE-287 — Improper Authentication
**Target:** DIGITS DAAS Registration APIs

### Summary
The JS exposes the complete MSISDN-to-device registration flow. Key parameters (`msisdn`, `serviceFingerprint`, `isRegistered`, `mobilityEnabled`) are visible. If the registration endpoint trusts client-supplied MSISDN without carrier-level verification, registering another user's number to your device is possible.

### Key Functions/Params
| Name | Purpose |
|------|---------|
| `DaasRegAPIs` | Device registration API calls |
| `registeredMsisdnList` | Array of registered phone numbers |
| `serviceFingerprint` | Per-line auth fingerprint |
| `DaasTokenRenewalRequest` | Token refresh (test for replay) |
| `getRegisteredMsisdns()` | Retrieves all registered lines |
| `/digitsOrchestratorService` | Line orchestration |

### Attack flow
1. Authenticate with your own T-Mobile account
2. Intercept DAAS registration request
3. Replace your MSISDN with victim's MSISDN
4. If server doesn't verify MSISDN ownership at carrier level → your device receives victim's calls/texts

---

## 5. Device Unlinking Without Ownership Verification

**Severity:** High (CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H — 8.1)
**Class:** CWE-862 — Missing Authorization
**Target:** `/digitslink/api/unlink`

### Summary
The unlink endpoint may allow removing another user's device from their DIGITS line if only the MSISDN or device ID is needed (no ownership check).

### What to test
- Call `/digitslink/api/unlink` with victim's MSISDN/device ID
- Check if auth token is validated against line ownership
- Combine with `/digitslink/v1/userlinkinfo` to enumerate targets

---

## 6. OAuth Open Redirect / Token Theft

**Severity:** High (CVSS 3.1: AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N — 7.4)
**Class:** CWE-601 — URL Redirection to Untrusted Site
**Target:** DIGITS Google/Microsoft OAuth flows

### Summary
DIGITS integrates Google OAuth (`contacts.readonly`, `userinfo.email`) and Microsoft OAuth. If the redirect_uri is not strictly validated, you can steal OAuth tokens.

### Endpoints
- `accounts.google.com/o/oauth2/v2/auth` → redirect_uri manipulation
- `login.microsoftonline.com/common/oauth2/v2.0/authorize` → redirect_uri manipulation

### What to test
- Change `redirect_uri` to attacker-controlled domain
- Use `/../` path traversal in redirect_uri
- Open redirect chains via T-Mobile subdomains as stepping stones

---

## PRIORITY ATTACK PLAN

| # | Target | Bug Class | Payout Tier |
|---|--------|-----------|-------------|
| 1 | DAAS IDOR (`/daas/lines/deviceInstances` + MSISDN swap) | P1 — Account Takeover | Core DIGITS |
| 2 | MSISDN registration bypass (register victim's line to your device) | P1 — Carrier Auth Bypass | **Special Target** |
| 3 | Device unlink without auth (`/digitslink/api/unlink`) | P1 — Account Manipulation | Core DIGITS |
| 4 | Firebase RTDB unauthenticated read | P1/P2 — Data Exposure | Wildcard |
| 5 | Staging API access (no auth / debug mode) | P2 — Internal Access | Wildcard |
| 6 | OAuth redirect_uri bypass → token theft | P2 — Account Takeover | Core DIGITS |

---

## FILES

- JS URL list: `recon/js/inscope_js_urls.txt` (2,171 URLs)
- Key findings JSON: `recon/js/key_findings.json`
- Full findings JSON: `recon/js/js_findings.json`
- Analysis script: `recon/js/analyze_js.py`
