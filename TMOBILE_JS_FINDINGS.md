# T-Mobile JS Analysis — Exploitable Findings Only

> **Date:** 2026-10-16 | **Source:** 2,171 in-scope JS files from 168 live hosts
> **Primary source:** `digits.t-mobile.com/static/js/main.js` (8.3MB React bundle)

---

## ~~1. Internal/Staging DIGITS API Endpoints~~ — DEAD (Validated 2026-10-16)

**Status:** All 3 staging endpoints timeout (internal-only, not internet-reachable). Production CPaaS returns 403 via Akamai WAF. Not exploitable from external.

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

## ~~3. Firebase RTDB~~ — DEAD (Validated 2026-10-16)

**Status:** Database deactivated (HTTP 423). Firestore returns 404. Storage bucket 404. Project decommissioned.

---

## 3. MSISDN Registration Flow — Carrier Auth Bypass Vector

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

## 4 (was 5). Device Unlinking Without Ownership Verification

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

## 4. OAuth Token Theft — Microsoft redirect_uri (Needs Browser Validation)

**Severity:** High (CVSS 3.1: AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N — 7.4)
**Class:** CWE-601 — URL Redirection to Untrusted Site
**Target:** DIGITS Microsoft OAuth flow
**Status:** Suspected — needs browser-based validation

### Summary
DIGITS Microsoft OAuth (client_id `1fad2d37-c0ad-4eb6-9ead-9b4f8429f3fb`) renders a full login page when an arbitrary `redirect_uri` (e.g. `https://evil.com/callback`) is supplied. Azure AD shows no error at the authorization endpoint. If redirect_uri is also not validated at the consent/redirect step, the auth code is sent to the attacker's domain.

### Validated Results
| Provider | Client ID | redirect_uri=evil.com | Verdict |
|----------|-----------|----------------------|---------|
| **Google** | `791229224196-mag7...` | `redirect_uri_mismatch` error (HTTP 302) | **PROTECTED** — strict validation |
| **Microsoft** | `1fad2d37-c0ad-4eb6...` | Login page renders (HTTP 200) with evil.com embedded | **NEEDS BROWSER TEST** |

### OAuth Config from JS
- Google legit redirect: `{dassRootUrl}/digitslink/glink`
- Microsoft legit redirect: `{daasRootUrl}/digitslink/mlink`
- Google scopes: `contacts.readonly`, `userinfo.email`
- Microsoft scopes: `Contacts.Read`, `Calendars.Read`, `offline_access`, `User.Read`, `openid`, `email`

### What to test next (browser required)
1. Open in browser: `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=1fad2d37-c0ad-4eb6-9ead-9b4f8429f3fb&redirect_uri=https://ATTACKER.com/callback&response_type=code&scope=Contacts.Read%20Calendars.Read%20offline_access%20User.Read%20openid%20email`
2. Sign in with any Microsoft account
3. If redirected to `ATTACKER.com/callback?code=AUTH_CODE` → **P2 confirmed** (OAuth token theft)
4. If `AADSTS50011` error → redirect_uri is validated server-side (not exploitable)

### Impact if confirmed
Attacker steals Microsoft OAuth code → exchanges for access token → reads victim's Contacts, Calendars, and email via Microsoft Graph API. Combined with DIGITS account linking, could enumerate linked devices.

---

## PRIORITY ATTACK PLAN (Updated after validation)

| # | Target | Bug Class | Status |
|---|--------|-----------|--------|
| 1 | DAAS IDOR (`/daas/lines/deviceInstances` + MSISDN swap) | P1 — Account Takeover | **Needs SIM** |
| 2 | MSISDN registration bypass (register victim's line) | P1 — Carrier Auth Bypass (Special Target) | **Needs SIM** |
| 3 | Device unlink without auth (`/digitslink/api/unlink`) | P1 — Account Manipulation | **Needs SIM** |
| 4 | Microsoft OAuth redirect_uri bypass → token theft | P2 — Account Takeover | **Needs browser test** |
| ~~5~~ | ~~Staging API access~~ | ~~P2~~ | **DEAD** — internal only |
| ~~6~~ | ~~Firebase RTDB~~ | ~~P1/P2~~ | **DEAD** — deactivated |

---

## FILES

- JS URL list: `recon/js/inscope_js_urls.txt` (2,171 URLs)
- Key findings JSON: `recon/js/key_findings.json`
- Full findings JSON: `recon/js/js_findings.json`
- Analysis script: `recon/js/analyze_js.py`
