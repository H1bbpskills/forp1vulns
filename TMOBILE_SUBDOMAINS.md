# T-Mobile In-Scope Subdomain Enumeration Results

> Enumerated via subfinder (passive sources: crt.sh, SecurityTrails, Shodan, VirusTotal, etc.)
> Date: 2026-10-16
> **Always verify against the live Bugcrowd brief — scope changes frequently.**

---

## Summary

| Domain | Subdomains Found |
|--------|-----------------|
| **t-mobile.com** | 14,946 |
| **sprint.com** | 2,504 |
| **uscc.com** | 842 |
| **uscellular.com** | 922 |
| **uscc.net** | 81 (after filtering *.mobile.uscc.net) |
| **metrobyt-mobile.com** | 546 |
| **assurancewireless.com** | 321 |
| **TOTAL (in-scope, deduplicated)** | **20,162** |

---

## HIGH-PRIORITY: DIGITS Infrastructure

These subdomains are directly related to DIGITS — your primary target for carrier auth bypass:

### DIGITS Production
- `digits.t-mobile.com` — DIGITS web app (PRIMARY ASSET)
- `cdigits.t-mobile.com` — DIGITS client
- `cdigits.sipgeo.t-mobile.com` — DIGITS SIP geo
- `cdigits1.uccprod.t-mobile.com` — DIGITS UCC production
- `cdigits1.uccprodgeo.t-mobile.com` — DIGITS UCC production geo
- `cdigits17.uccprod.t-mobile.com` — DIGITS UCC prod instance
- `digits.msg.t-mobile.com` — DIGITS messaging
- `digits.iamstg.msg.t-mobile.com` — DIGITS IAM staging
- `digitsdownloader.ucc.t-mobile.com` — DIGITS downloader
- `digitsdownloader.uccprodgeo.t-mobile.com` — DIGITS downloader geo
- `mydigits.t-mobile.com` — My DIGITS portal
- `es.mydigits.my.t-mobile.com` — My DIGITS (Spanish)
- `es.mydigits.t-mobile.com` — My DIGITS (Spanish)
- `webdigits.t-mobile.com` — Web DIGITS

### DIGITS Staging/Dev/Test (Bug Hunting Gold)
- `digits-beta.msg.t-mobile.com` — DIGITS beta
- `digits-beta.t-mobile.com` — DIGITS beta
- `digits-dev.msg.t-mobile.com` — DIGITS dev
- `digits-dev.stg.t-mobile.com` — DIGITS dev staging
- `digits-devnext.msg.t-mobile.com` — DIGITS dev next
- `digits-devnext.stg.t-mobile.com` — DIGITS dev next staging
- `digits-k8s-int.msg.t-mobile.com` — DIGITS K8s internal
- `digits-preprod.msg.t-mobile.com` — DIGITS pre-production
- `digits-preprod.stg.t-mobile.com` — DIGITS pre-production staging
- `digits-test.msg.t-mobile.com` — DIGITS test
- `digits-test.stg.t-mobile.com` — DIGITS test staging
- `digits-testnext.msg.t-mobile.com` — DIGITS test next
- `digits-testnext.stg.t-mobile.com` — DIGITS test next staging
- `edigits1.stg.t-mobile.com` through `edigits60.stg.t-mobile.com` — 60+ eDIGITS staging instances
- `edigitsweb1.stg.t-mobile.com` through `edigitsweb20.stg.t-mobile.com` — eDIGITS web staging

---

## HIGH-PRIORITY: eSIM Infrastructure

Critical for carrier auth bypass testing:

- `esim-ext.msg.t-mobile.com` — eSIM external
- `esim-mgmt.t-mobile.com` — eSIM management (PRODUCTION)
- `esim-mgmt-ext.msg.t-mobile.com` — eSIM management external
- `esim-mgmt.msg.t-mobile.com` — eSIM management messaging
- `esim-mgmt-int.msg.t-mobile.com` — eSIM management internal
- `esim-mgmt-int-pol.msg.t-mobile.com` — eSIM management internal POL
- `esim-mgmt-int-ttn.msg.t-mobile.com` — eSIM management internal TTN
- `esim-int.msg.t-mobile.com` — eSIM internal
- `esim-int-pol.msg.t-mobile.com` — eSIM internal POL
- `esim-int-pol.t-mobile.com` — eSIM internal POL
- `esim-int-ttn.msg.t-mobile.com` — eSIM internal TTN
- `esim-int-ttn.t-mobile.com` — eSIM internal TTN
- `esim-k8s-int.msg.t-mobile.com` — eSIM K8s internal
- `esim-stg1-ext.msg.t-mobile.com` — eSIM staging external
- `esim-stg1-int-pol.msg.t-mobile.com` — eSIM staging internal POL
- `esim-stg1-int-pol.t-mobile.com` — eSIM staging internal POL
- `esim-stg1-int-ttn.msg.t-mobile.com` — eSIM staging internal TTN
- `admin.poc.esim.t-mobile.com` — eSIM admin PoC
- `api.poc.esim.t-mobile.com` — eSIM API PoC

---

## HIGH-PRIORITY: Auth/SSO/Identity

- `authentication.t-mobile.com` — Main authentication
- `consumer.auth.t-mobile.com` — Consumer auth (PRODUCTION)
- `stg.consumer.auth.t-mobile.com` — Consumer auth staging
- `identity-api.bluescape.stg.t-mobile.com` — Identity API
- `identityproofing.t-mobile.com` — Identity proofing
- `signin.sso.idp.t-mobile.com` — SSO IDP (PRODUCTION)
- `signin-stg.sso.idp.t-mobile.com` — SSO IDP staging
- `magenta-mfa.t-mobile.com` — MFA (PRODUCTION)
- `stg.magenta-mfa.t-mobile.com` — MFA staging
- `opensso.t-mobile.com` — OpenSSO
- `eapauth.t-mobile.com` — EAP auth (PRODUCTION)
- `eapauth.stg.t-mobile.com` — EAP auth staging
- `webauth.t-mobile.com` — Web auth (PRODUCTION)
- `device-auth.api.isp.kube.t-mobile.com` — Device auth API
- `oauth.iot.t-mobile.com` — IoT OAuth (PRODUCTION)
- `verify.t-mobile.com` — Verification (PRODUCTION)
- `mfa.corporate.t-mobile.com` — Corporate MFA
- `tokenizer.t-mobile.com` — Tokenizer (PRODUCTION)

---

## HIGH-PRIORITY: API Endpoints

- `account.api.t-mobile.com` — Account API
- `api-dev.devedge.t-mobile.com` — DevEdge API dev
- `api-gateway.doxipilot.t-mobile.com` — API gateway
- `analytics-api.t-mobile.com` — Analytics API
- `androidapi.t-mobile.com` — Android API
- `androidapi.geo.t-mobile.com` — Android API geo
- `api-be.social.t-mobile.com` — Social API backend
- `aoaiapi.ai.t-mobile.com` — AI/OpenAI API

---

## HIGH-PRIORITY: Admin/Internal Panels

- `admin.t-mobile.com` — Main admin
- `admin.adn.t-mobile.com` — ADN admin
- `admin.businesscenter.t-mobile.com` — Business center admin
- `admin.network.t-mobile.com` — Network admin
- `admin.staging.network.t-mobile.com` — Network admin staging
- `admin.ucc.t-mobile.com` — UCC admin
- `adminportal.t-mobile.com` — Admin portal
- `adminportal.tfb.t-mobile.com` — TFB admin portal
- `alm.internal.t-mobile.com` — ALM internal
- `adsearch.internal.t-mobile.com` — Internal ad search
- `airflow.ceq.internal.t-mobile.com` — Airflow (data pipelines)

---

## HIGH-PRIORITY: Staging/Dev Environments

- `staging-login.vistarmedia.com` — Vistar staging login
- `docker-staging.adstruc.com` — Docker staging
- `staging-trafficking.vistarmedia.com` — Vistar staging
- `jenkins-github.gcp.blis.com` — Jenkins CI
- `internal.platform.blis.com` — Internal platform
- `platform.development.blis.com` — Dev platform
- `platform.development2.blis.com` — Dev platform 2

---

## Carrier/Network Infrastructure

- `carrier-freedom-api.duck.prd.promos.t-mobile.com` — Carrier API (PRODUCTION)
- `admin.network.t-mobile.com` — Network admin
- `4gltecellspotsetup.t-mobile.com` — CellSpot setup

---

## Full subdomain lists saved at:
- `subfinder_t-mobile.com.txt` (14,946 subdomains)
- `subfinder_sprint.com.txt` (2,504 subdomains)
- `subfinder_metrobyt-mobile.com.txt` (546 subdomains)
- `subfinder_assurancewireless.com.txt` (321 subdomains)
- `subfinder_uscc.com.txt` (842 subdomains)
- `subfinder_uscc.net.txt` (filtered in-scope)
- `subfinder_uscellular.com.txt` (922 subdomains)
