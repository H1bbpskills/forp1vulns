# T-Mobile JavaScript Analysis — Findings Report

> **Scan Date:** 2026-10-16
> **Hosts Crawled:** 168 responsive hosts across all in-scope domains
> **JS URLs Discovered:** 2,171 in-scope JavaScript files
> **JS Files Analyzed:** 55 unique priority files (32MB total content)
> **Source:** `digits.t-mobile.com`, `account.t-mobile.com`, `account.my.t-mobile.com`, `*.promos.t-mobile.com`, `*.sprint.com`, IoT portal, prepaid auth, and more

---

## CRITICAL FINDINGS

### 1. Hardcoded API Keys in Production JavaScript

**Severity:** High
**CWE:** CWE-798 — Use of Hard-coded Credentials

| Key | Value | Source |
|-----|-------|--------|
| **Google Firebase API Key** | `AIzaSyBP1Q...REDACTED` | `digits.t-mobile.com/static/js/main.js` |
| **Google Maps Static API Key** | `AIzaSyCTuX...REDACTED` | `digits.t-mobile.com/static/js/main.js` |
| **Analytics API Key 1** | `d09e6c...REDACTED` | `account.my.t-mobile.com/.../clientlib-analytics-main.js` |
| **Analytics API Key 2** | `4f982b...REDACTED` | `account.my.t-mobile.com/.../clientlib-analytics-main.js` |

**Impact:** Firebase API key allows enumeration of Firebase project `phone-2-1247`. Google Maps key could be abused for quota exhaustion. Analytics keys may allow data injection.

---

### 2. Full Firebase Configuration Exposed

**Severity:** High
**CWE:** CWE-200 — Exposure of Sensitive Information

Found in `digits.t-mobile.com/static/js/main.js`:

```
apiKey: "AIzaSyBP1Q...REDACTED"
authDomain: "phone-2-1247.firebaseapp.com"
projectId: "phone-2-1247"
storageBucket: "phone-2-1247.appspot.com"
messagingSenderId: "REDACTED"
appId: "1:REDACTED:web:REDACTED"
measurementId: "G-REDACTED"
```

**Impact:** Complete Firebase project configuration. Test for:
- Firebase Auth user enumeration
- Firestore/RTDB read access without auth
- Storage bucket public read
- FCM push notification abuse via `messagingSenderId`

---

### 3. Internal/Staging DIGITS API Endpoints Leaked

**Severity:** High
**CWE:** CWE-200 — Exposure of Sensitive Information

Found hardcoded in **production** `digits.t-mobile.com/static/js/main.js`:

| Endpoint | Environment |
|----------|-------------|
| `https://api-dev.lab.t-mobile.com/v1/digitsApi` | **DEV (internal lab)** |
| `https://api-devstg.t-mobile.com/v1/digitsApi` | **DEV STAGING** |
| `https://api-teststg.t-mobile.com/v1/digitsApi` | **TEST STAGING** |
| `https://cpaas-geo.t-mobile.com/v1/digitsApi` | **PRODUCTION (CPaaS geo)** |
| `http://localhost:8080` | **LOCAL DEV** |

**Impact:** Internal/staging API endpoints may have weaker security controls. Test for:
- Unauthenticated access to staging DIGITS APIs
- Different authorization policies vs production
- Debug endpoints or verbose error messages
- Direct MSISDN/line manipulation without proper auth

---

## HIGH FINDINGS

### 4. DIGITS DAAS (Device-as-a-Service) API Endpoints

**Severity:** High — Core DIGITS Infrastructure
**Source:** `digits.t-mobile.com/static/js/main.js`

**API Endpoints discovered:**
| Path | Purpose |
|------|---------|
| `/v1/digitsApi` | Main DIGITS API |
| `/digitsOrchestratorService` | DIGITS Orchestrator |
| `/digitsOrchestratorService/daas` | DAAS via Orchestrator |
| `/daas/lines/deviceInstances` | **Line/Device instance management** |
| `/daas/call/e911/information` | **E911 caller information** |
| `/digitslink/api/unlink` | **Device unlinking API** |
| `/digitslink/glink` | Google account linking |
| `/digitslink/mlink` | Microsoft account linking |
| `/digitslink/v1/userlinkinfo` | **User link information** |
| `/v1/daasvmsvc` | DAAS Voicemail Service |
| `/v1/myStore` | Store/profile data |
| `/v1/signout` | Sign out |
| `/v1/userlinkinfo` | User link info |
| `/v2/auth` | Auth v2 |
| `/v2/ottlogs` | OTT logging |
| `/chat/sessions` | Chat sessions |
| `/chat/v1/` | Chat API v1 |
| `/oauth2/v1/signout` | OAuth signout |

**Impact:** These endpoints expose the DIGITS line management, device registration, and linking APIs. Key targets for:
- IDOR on `/daas/lines/deviceInstances` (accessing other users' lines)
- Unauthorized device unlinking via `/digitslink/api/unlink`
- E911 information disclosure via `/daas/call/e911/information`
- Line hijacking through `/digitsOrchestratorService`

---

### 5. MSISDN/Line Registration Logic Exposed

**Severity:** High — Carrier Auth Bypass Potential
**Source:** `digits.t-mobile.com/static/js/main.js`

The DIGITS main.js exposes the complete MSISDN registration and line management flow:

**Key patterns found:**
- `registeredMsisdnList` — Full list of registered MSISDNs
- `getRegisteredMsisdns()` — Function to retrieve registered lines
- `msisdn` parameter used in DAAS API calls: `{msisdn: e}` 
- `daas/lines/deviceInstances` accepts MSISDN parameter
- `daas/call/e911/information` accepts `{msisdn: e, clientId: this.iamClientId}`
- `DaasRegAPIs` — Device registration APIs
- `DaasTokenRenewalRequest` — Token renewal flow
- `serviceFingerprint` — Per-line service fingerprint
- `mobilityEnabled` — Mobility flag per MSISDN
- `locTcInfo` — Location/T&C info per line
- `defaultAccount` — Default account flag
- `isRegistered` — Registration status
- `lineName` — User-assigned line name

**Impact:** Understanding the MSISDN registration flow enables:
- Testing IDOR by swapping MSISDN values in API calls
- Attempting to register another user's MSISDN to your device
- Enumerating valid MSISDNs via error-based differences
- Bypassing carrier auth by manipulating `serviceFingerprint`

---

### 6. OAuth/SSO Integration Endpoints

**Severity:** Medium-High
**Source:** `digits.t-mobile.com/static/js/main.js`

| Provider | Endpoint | Scope |
|----------|----------|-------|
| **Google OAuth** | `accounts.google.com/o/oauth2/v2/auth` | `contacts.readonly`, `userinfo.email` |
| **Microsoft OAuth** | `login.microsoftonline.com/common/oauth2/v2.0/authorize` | — |
| **Firebase Auth** | `securetoken.google.com/` | Token exchange |
| **Google Contacts** | `googleapis.com/auth/contacts.readonly` | Contact import |

**Impact:** OAuth flows may be vulnerable to:
- Open redirect via callback URL manipulation
- CSRF in OAuth state parameter
- Token leakage via referrer headers
- Scope escalation (contacts.readonly → broader access)

---

### 7. Firebase Realtime Database Endpoint

**Severity:** Medium-High
**Source:** `digits.t-mobile.com/static/js/main.js`

```
https://phone-2-1247.firebaseio.com
```

**Impact:** Test for:
- `/.json` — Unauthenticated database read
- Insecure Firebase security rules
- User data exposure (phone numbers, messages, call logs)

---

## MEDIUM FINDINGS

### 8. DIGITS Application Routes

**Source:** `digits.t-mobile.com/static/js/main.js`

Complete DIGITS web app route map:
```
/calls                      — Call history
/calls/dialpad              — Dialpad
/channels                   — Message channels
/channels/newConversation   — New conversation
/contacts                   — Contact list
/dialpad                    — Dialpad
/voicemail                  — Voicemail
/voicemails                 — Voicemail list
/settings                   — Settings
/settings/calling           — Calling settings
/settings/voicemail         — Voicemail settings
/settings/notifications     — Notification settings
/settings/block-numbers     — Block numbers
/settings/edit-blocked-numbers — Edit blocked numbers
/blockedcall                — Blocked calls
/blockedcalls               — Blocked calls list
/blockedchannel             — Blocked channels
/adhoc/                     — Ad-hoc calling
/conference/                — Conference calling
```

---

### 9. Developer Email Leaked

**Severity:** Low
**Source:** `digits.t-mobile.com/static/js/main.js`

```
jhruby.web@gmail.com
```

This appears to be a developer email left in the DIGITS production bundle — potential for social engineering or developer account compromise.

---

### 10. Facebook App ID Exposed

**Severity:** Low
**Source:** `carrierfreedom.promos.t-mobile.com/app/common/directives/facebookAuthentication.js`

```
Facebook App ID: 14252900414
```

The promos site uses Facebook OAuth with `public_profile,email` scope and `age_range,email,first_name,last_name` fields.

---

### 11. Amplitude Analytics Keys

**Severity:** Informational
**Source:** `authorization.js` (shared across T-Mobile AEM sites)

References to Amplitude analytics SDK:
- `cdn.amplitude.com/libs/analytics-browser-2.45.8-min.js.gz`
- `cdn.amplitude.com/libs/plugin-session-replay-browser-1.32.1-min.js.gz`
- `cdn.amplitude.com/script/`

Session replay enabled — may capture sensitive user interactions.

---

## INFRASTRUCTURE OBSERVATIONS

### T-Mobile Tech Stack (from JS analysis)

| Component | Technology |
|-----------|-----------|
| **DIGITS Frontend** | React SPA |
| **Account Portal** | Angular (AEM - Adobe Experience Manager) |
| **Auth** | Custom JWT + Firebase Auth + OAuth2 |
| **Push Notifications** | Firebase Cloud Messaging (FCM) |
| **Analytics** | Amplitude + Adobe DTM + MoEngage |
| **Maps** | Google Maps Static API |
| **Chat/Messaging** | CPaaS (Communications Platform as a Service) |
| **CDN/WAF** | Akamai Bot Manager |
| **CMS** | Adobe Experience Manager (AEM/digx) |

### Multiple EUI Instances (Canary Deployments)
Different `main-*.js` hashes across EUI instances suggest canary/staged deployments:
- `eui1.account.t-mobile.com/main-RDF3YDMN.js`
- `eui2.account.t-mobile.com/main-UEU3QZZO.js`
- `eui3.account.t-mobile.com/main-YZUQN7JZ.js`
- `eui6.account.t-mobile.com/main-V3RUAISE.js`
- `eui7.account.t-mobile.com/main-WGZ7NXV4.js`
- `eui10.account.t-mobile.com/main-W6A34CFS.js`

**These different builds may have different bugs — test each independently.**

---

## PRIORITY TESTING TARGETS (Based on JS Analysis)

### Tier 1 — Carrier Auth Bypass (Special Target, Highest Payout)
1. **`/daas/lines/deviceInstances`** — IDOR to access other users' line/device info
2. **`/digitslink/api/unlink`** — Unauthorized device unlinking
3. **`/daas/call/e911/information`** with MSISDN parameter manipulation
4. **`/digitsOrchestratorService/daas`** — Line orchestration bypass
5. **`/v1/userlinkinfo`** — User link information IDOR

### Tier 2 — Firebase/Auth Bypass
6. **Firebase RTDB** `phone-2-1247.firebaseio.com/.json` — Unauthenticated read
7. **Firebase Auth** — User enumeration via API key
8. **OAuth redirect** — Open redirect in Google/Microsoft OAuth flows
9. **Token replay** — `/v2/auth` and DAAS token renewal

### Tier 3 — Internal API Access
10. **`api-dev.lab.t-mobile.com/v1/digitsApi`** — Internal lab API
11. **`api-devstg.t-mobile.com/v1/digitsApi`** — Dev staging
12. **`api-teststg.t-mobile.com/v1/digitsApi`** — Test staging
13. **`cpaas-geo.t-mobile.com/v1/digitsApi`** — Production CPaaS

---

## FILES

- Full JS URL list: `recon/js/inscope_js_urls.txt` (2,171 URLs)
- DIGITS main.js analysis: `recon/js/digits_main.js` (8.3MB)
- JS findings JSON: `recon/js/js_findings.json`
- Analysis script: `recon/js/analyze_js.py`
