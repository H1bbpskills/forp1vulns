# T-Mobile Bug Bounty — Complete In-Scope Assets

> Source: [Bugcrowd T-Mobile Program](https://bugcrowd.com/engagements/t-mobile) via [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data)
> **Always verify against the live Bugcrowd brief before testing — scope changes frequently.**

---

## CORE / PRIMARY ASSETS (High Payout Tier)

| # | Target | URL | Type |
|---|--------|-----|------|
| 1 | **t-mobile.com** | https://t-mobile.com | Website |
| 2 | **account.t-mobile.com** | https://account.t-mobile.com | Website |
| 3 | **digits.t-mobile.com** (DIGITS - Web/Desktop/Mobile) | https://digits.t-mobile.com | Website |
| 4 | **tfb.t-mobile.com** (T-Mobile for Business) | https://tfb.t-mobile.com | Website |
| 5 | **account.business.t-mobile.com** | https://account.business.t-mobile.com | Website |
| 6 | **\*.api.t-mobile.com** | https://api.t-mobile.com | API |
| 7 | **sprint.com** | https://sprint.com | Website |
| 8 | **metrobyt-mobile.com** | https://metrobyt-mobile.com | Website |

## WILDCARD DOMAINS

| # | Wildcard | Notes |
|---|----------|-------|
| 1 | **\*.t-mobile.com** | All T-Mobile subdomains (except listed Core assets have separate tier) |
| 2 | **\*.sprint.com** | All Sprint subdomains |
| 3 | **\*.metrobyt-mobile.com** | All Metro by T-Mobile subdomains |
| 4 | **\*.assurancewireless.com** | Assurance Wireless (T-Mobile Lifeline) |
| 5 | **\*.uscc.net** | US Cellular |
| 6 | **\*.uscc.com** | US Cellular |
| 7 | **\*.uscellular.com** | US Cellular |

## MOBILE APPS

| # | App | Platform | Link |
|---|-----|----------|------|
| 1 | **T-Life** | Android | https://play.google.com/store/apps/details?id=com.tmobile.tuesdays |
| 2 | **T-Life** | iOS | https://apps.apple.com/us/app/t-life/id1111876388 |

## SPECIAL TARGETS

| # | Target | Type | Notes |
|---|--------|------|-------|
| 1 | **Cellular Network Auth Bypass via Web App/T-Life** | Network | Phone: 404-200-7239. Routes to Special Target for carrier-layer bypass |
| 2 | **T&P Flag Servers** | Network | **TEMPORARILY OUT OF SCOPE** (10.72.218.66, 10.62.252.214) |
| 3 | **Self-Register Account on T-Mobile Microsoft Entra ID** | Other | Azure AD/Entra self-registration |
| 4 | **Subdomain Takeover** | Other | Any dangling T-Mobile subdomain |

## SUPPLEMENTAL ASSETS — Vistar Media (T-Mobile Advertising)

| # | Target | URL |
|---|--------|-----|
| 1 | api.vistarmedia.com | https://api.vistarmedia.com |
| 2 | api.vistarmedia.eu | https://api.vistarmedia.eu |
| 3 | production-dynam-creative.vistarmedia.com | https://production-dynam-creative.vistarmedia.com |
| 4 | storybook.vistarmedia.com | https://storybook.vistarmedia.com |
| 5 | creatives.vistarmedia.com | https://creatives.vistarmedia.com |
| 6 | production-delivery-metrics-svc.vistarmedia.com | https://production-delivery-metrics-svc.vistarmedia.com |
| 7 | maps.vistarmedia.com | https://maps.vistarmedia.com |
| 8 | transcodes-cdn.vistarmedia.com | https://transcodes-cdn.vistarmedia.com |
| 9 | assets-cdn.vistarmedia.com | https://assets-cdn.vistarmedia.com |
| 10 | staging-trafficking.vistarmedia.com | https://staging-trafficking.vistarmedia.com |
| 11 | job-svc-b.vistarmedia.com | https://job-svc-b.vistarmedia.com |
| 12 | docsite.vistarmedia.com | https://docsite.vistarmedia.com |
| 13 | audience-builder.vistarmedia.com | https://audience-builder.vistarmedia.com |
| 14 | staging-login.vistarmedia.com | https://staging-login.vistarmedia.com |

## SUPPLEMENTAL ASSETS — Cortex Powered

| # | Target | URL |
|---|--------|-----|
| 1 | packages.cortexpowered.com | https://packages.cortexpowered.com |
| 2 | sflower.cortexpowered.com | https://sflower.cortexpowered.com |
| 3 | sfleet.cortexpowered.com | https://sfleet.cortexpowered.com |

## SUPPLEMENTAL ASSETS — AdStruc

| # | Target | URL |
|---|--------|-----|
| 1 | docker-staging.adstruc.com | https://docker-staging.adstruc.com |
| 2 | clients.adstruc.com | https://clients.adstruc.com |
| 3 | demo.adstruc.com | https://demo.adstruc.com |

## SUPPLEMENTAL ASSETS — Blis / BlisMedia (T-Mobile Advertising)

| # | Target | URL |
|---|--------|-----|
| 1 | blis.com | https://blis.com |
| 2 | platform.blis.com | https://platform.blis.com |
| 3 | platform.blismedia.com | https://platform.blismedia.com |
| 4 | platform.development.blis.com | https://platform.development.blis.com |
| 5 | platform.development2.blis.com | https://platform.development2.blis.com |
| 6 | platform.rc.blis.com | https://platform.rc.blis.com |
| 7 | internal.platform.blis.com | https://internal.platform.blis.com |
| 8 | assets.platform.blis.com | https://assets.platform.blis.com |
| 9 | assets.platform.development.blis.com | https://assets.platform.development.blis.com |
| 10 | assets.platform.rc.blis.com | https://assets.platform.rc.blis.com |
| 11 | imply.blis.com | https://imply.blis.com |
| 12 | imply.platform.blis.com | https://imply.platform.blis.com |
| 13 | imply.platform.development.blis.com | https://imply.platform.development.blis.com |
| 14 | imply.platform.rc.blis.com | https://imply.platform.rc.blis.com |
| 15 | imply.internal.platform.blis.com | https://imply.internal.platform.blis.com |
| 16 | imply.test.blis.com | https://imply.test.blis.com |
| 17 | imply-pivot.blis.com | https://imply-pivot.blis.com |
| 18 | imply-pivot.test.blis.com | https://imply-pivot.test.blis.com |
| 19 | audiencelogos.blis.com | https://audiencelogos.blis.com |
| 20 | creative.infinity.blismedia.com | https://creative.infinity.blismedia.com |
| 21 | jenkins-github.gcp.blis.com | https://jenkins-github.gcp.blis.com |
| 22 | privacy.blismedia.com | https://privacy.blismedia.com |
| 23 | signature.blis.com | https://signature.blis.com |
| 24 | sitepixel.blis.com | https://sitepixel.blis.com |
| 25 | sitepixel.dev.blis.com | https://sitepixel.dev.blis.com |

## SUPPLEMENTAL ASSETS — WM Audience / Other

| # | Target | URL |
|---|--------|-----|
| 1 | wmaudience.com | https://wmaudience.com |
| 2 | development.wmaudience.com | https://development.wmaudience.com |
| 3 | rc.wmaudience.com | https://rc.wmaudience.com |
| 4 | imply.wmaudience.com | https://imply.wmaudience.com |
| 5 | wiki.atom-lens.com | https://wiki.atom-lens.com |
| 6 | assets.development.amazon-tacticalplanner.com | https://assets.development.amazon-tacticalplanner.com |
| 7 | dashboard-101.moengage.com | https://dashboard-101.moengage.com |
| 8 | assurancewireless.com | https://www.assurancewireless.com |
| 9 | devedge.t-mobile.com | https://devedge.t-mobile.com |
| 10 | tess.service-now.com | https://tess.service-now.com |

---

## OUT OF SCOPE

| Target | Notes |
|--------|-------|
| /self-service-* | Path exclusion on all domains |
| *.sprint.net | Sprint network infra |
| *.mobile.uscc.net | US Cellular mobile |
| *.mobile.uscc.com | US Cellular mobile |
| *.moengage.com | MoEngage (except dashboard-101) |
| appointments.uscellular.com | US Cellular appointments |
| T&P Flag Servers (10.72.218.66, 10.62.252.214) | Temporarily out of scope |
| Deutsche Telekom domains/systems | Separate program |
| Anything not explicitly listed | Default exclusion |

---

## TOTAL: 76 in-scope targets

- 69 websites
- 1 API (*.api.t-mobile.com)
- 2 mobile apps (T-Life iOS + Android)
- 2 network targets
- 2 other targets
