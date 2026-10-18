# Self-Hosted Paid Bug Bounty Programs — researched 2026-10-18

Company-run programs only: you report through the vendor's **own** portal, security.txt or
security@ address, and they pay you directly. No HackerOne / Bugcrowd / Intigriti / YesWeHack /
Immunefi middleman.

**Why these are worth it:** far less duplicate pressure than mature platform programs, no platform
signal/rep gatekeeping, and often direct bank transfer in local currency.

**The trade-off, stated plainly:** there is no platform escrow or mediation. If a self-hosted program
decides not to pay, you have no arbiter. Vet payment history before sinking weeks into a small
company's program — a community-maintained list of self-hosted programs known for non-payment exists
at `github.com/pdelteil/scammy-bbp`. The large vendors below all have documented payout records.

---

## 1. CHF — paid in Swiss francs

### Swisscom — the only verified CHF-denominated self-hosted program found
- **Rewards:** CHF 100 – CHF 10,000, at Swisscom's discretion (technical impact, business
  criticality, exploitation likelihood, report quality).
- **Payment:** **Swiss francs, bank transfer only.** Payee must hold the account in their own or
  their company's name. Due within 30 days of payment confirmation, and **generally paid only after
  remediation** — budget for that delay.
- **Submission:** portal at `bugbounty.swisscom.ch` only; reports via other channels are disregarded.
- **Registration requires:** name, postal address, **valid ID/passport with machine-readable zone**,
  and bank details. Non-trivial onboarding — start it before you start hunting.
- **Scope:** Swisscom-owned assets plus affiliates >50% owned. **Fastweb SpA is explicitly out of
  scope**; so are customer systems and customer systems outsourced to Swisscom. Authoritative scope
  lives in the `scope/` folder of `github.com/swisscom/bugbounty`.
- **Rules worth noting:** tag your traffic with a User-Agent suffix `-bugbounty-<username>`; you must
  disclose any AI use in preparing the report.
- Historically reported ~CHF 350,000/year in bounties paid.

### SCIP (Swiss)
Runs under RFC 9116 security.txt, but rewards are **mostly non-cash** (VulDB subscription, hall of
fame, a book). Cash reserved for "highly critical" issues, with no published amounts. Low priority.

**Note:** other Swiss orgs (Swiss Post, Infomaniak, OneDoc) are **not** self-hosted — they run on
YesWeHack and pay EUR.

---

## 2. EUR — paid in euros

### Deutsche Telekom — self-hosted, published tiers
`telekom.com/en/about-us/data-privacy-and-security/hacking-and-testing/bug-bounty`
- **Critical / P1: €10,000** · **High / P2: €4,000** · **Medium / P3: €2,000**
- Scope: telekom.de web portals and related domains.
- **Caveat:** the figures page indexed at ~453 days old — confirm current tiers before committing.
- **T-Mobile US is a separate Bugcrowd program and explicitly excludes Deutsche Telekom assets** —
  don't cross-report.

### Zalando
VDP on Intigriti, **no bounties**. Excluded.

Honest gap: beyond Deutsche Telekom I found **no** large EU company running a self-hosted program
with published EUR amounts. Most European paid programs have consolidated onto Intigriti/YesWeHack.
The EUR money is on those platforms (see `HUNTING_TARGETS_2026-10.md`), not in self-hosted programs.

---

## 3. GBP — paid in pounds

**Nothing found.** No UK company was confirmed running its own GBP-denominated paid program outside a
platform. The two closest are both platform-hosted:
- **Monzo** — £50–£12,500, but on **Intigriti**, not self-hosted.
- **Flutter UK&I** (Betfair / Paddy Power / Sky Betting) — on **HackerOne**, priced in USD.

UK government (NCSC) runs an unpaid VDP. If you want GBP specifically, Monzo on Intigriti is the
realistic answer and self-hosting isn't available to you there.

---

## 4. Dinars (KWD / BHD / JOD)

Still essentially nonexistent, and self-hosting doesn't change that.

- **Gulf Bank (Kuwait)** — launched its **own** VDP + bug bounty mid-2025. Rewards are severity-based
  and set by an internal team; **no dinar figure has ever been published**. Its earlier YesWeHack
  listing capped at **USD 1,200**. Self-hosted, but trivial money.
- **NBK and Kuwait Finance House** — HackerOne pages exist but are community-curated summaries, not
  confirmed paid programs.
- **Bahrain, Jordan** — nothing found, bank or telecom.
- **UAE** — `bugbounty.ae` (Cyber Security Council) is invite-only per the disclose.io registry.

Treat this bucket as zero expected income.

---

## 5. USD — where self-hosted actually pays

### 5a. Apple Security Bounty — `security.apple.com/bounty/`
Entirely self-hosted, verified table (read 2026-10-18):

| Category | Max |
|---|---|
| Network attack, **no** user interaction → kernel | **$2,000,000** |
| Network attack, no interaction → user space | $350,000 |
| Network attack, with interaction → kernel | $1,000,000 |
| Wireless proximity attack on Apple-designed radios → application processor | $1,000,000 |
| Browser attack → kernel | $1,000,000 |
| Browser: **WebContent sandbox escape** | $300,000 |
| Browser: WebContent code execution | $10,000 |
| App sandbox escape → kernel | $500,000 |
| App sandbox escape → sensitive user data | $100,000 |
| Unauthorized physical device access → sensitive user data | $500,000 |
| Unauthorized iCloud account data access on Apple servers | $1,000,000 |
| Private Cloud Compute: unsigned code exec w/ arbitrary entitlements | $1,000,000 |
| PCC: remote attack exposing user request data | $250,000 |
| PCC: privileged-network-position (data access / unattested code exec) | $150,000 / $100,000 |
| Services: RCE | $100,000 |
| macOS: full Gatekeeper quarantine bypass, standard interaction | $100,000 |
| Services: unrestricted FS/DB access · logic flaw bypassing security controls | $50,000 each |
| Services: code execution client/server | $40,000 |
| Services: PII exposure | $30,000 |
| macOS: Gatekeeper bypass, limited interaction · TCC flag + sandbox escape | $10,000 each |
| macOS-only sandbox escape · TCC flag (unsandboxed) · subdomain takeover | $5,000 each |

**Bonuses:** beta software **+50%**, Lockdown Mode bypass **+100%**, both **+150%**, plus
discretionary awards for exceptional research — this is how the "over $5M" headline is reached.
Program has paid **$35M to 800+ researchers since 2020**.

### 5b. Google Bug Hunters — `bughunters.google.com`
Self-hosted across all its VRPs.
- **Android / Pixel (raised May 2026):** **$1,500,000** for a zero-click full-chain Pixel compromise
  targeting the **Titan M2** security chip **with persistence**; **$750,000** for the same chain
  without persistence. Highest self-hosted hardware-security payout available.
- **Chrome VRP (retabled 2026-10-13):** memory-corruption base back to **$2,000**; **up to $20,000**
  for a controlled write demonstrated from web contents in the browser/GPU/network process;
  **$4,000** reads/crashes; renderer writes and UAFs **up to $8,000**; **V8 sandbox flat $5,000**,
  V8 logic **$4,000**; high-impact **non**-memory-safety sandbox escape up to **$20,000**;
  medium-severity non-memory-safety flat $2,000; **$2,000 novel-fuzzer bonus reinstated**.
  Reports queued after 2026-04-30 are paid at these new rates.
- **Google / Alphabet VRP:** up to **$151,515**.
- **Cloud VRP:** top award **$101,010** (launch-post figure, ~2 years old — verify).
- **AI VRP (launched Oct 2026):** **$20,000** base top tier, **up to $30,000** with report multipliers.

### 5c. Microsoft MSRC — `microsoft.com/msrc`
Self-hosted, per-program rate cards:

| Program | Range |
|---|---|
| Windows Insider Preview (Canary channel) | $500 – **$100,000** |
| Azure | $1,250 – $60,000 |
| .NET | $1,250 – $40,000 |
| Copilot / AI | $250 – $30,000 |
| M365 | $1,250 – $19,500 |

The $100,000 Windows top tier is for remote, no-interaction, unauthenticated **non-sandboxed** code
execution. MSRC awarded **>$20M to 562 researchers** in its year to Aug 2026. There is **no separate
Hyper-V bounty page** — Hyper-V falls under Windows/Azure scope (but see Pwn2Own below, which prices
a Hyper-V guest-to-host escape at $250,000).

### 5d. Meta — `bugbounty.meta.com`
- **Min $500, max $300,000.** All payouts USD.
- **$300K:** Mobile RCE, **WhatsApp Private Processing**, Muse VM escape
- **$130K:** account takeover · **$30K:** Quest persistent full secure-boot bypass
- **$20K:** 2FA bypass · **$10K:** contact-point deanonymization · **$5K:** page admin disclosure
- **Hacker Plus** tier and bonuses add **up to 30%**.

### 5e. Samsung Mobile Security Rewards — `security.samsungmobile.com`
- **$200 – $1,000,000.** $1M requires **0-click, persistent RCE**; local arbitrary execution $300,000.
- Paid $827,925 to 113 researchers in 2023 — i.e. real payouts cluster far below the cap.
- **Caveat:** most recent terms I could confirm are from late 2024. Verify on the program page.

### 5f. Mozilla — `mozilla.org/security/client-bug-bounty/`
Self-hosted, Firefox/client side (USD, cash):
- **Up to $20,000** — sandbox escape, or bypassing WebExtension install prompts (local attacks excluded)
- **$10,000** — UXSS (JS execution in arbitrary cross-origin context)
- **$3,000** — sec-high in supported configs, **GPU process memory corruption**, parent→content infoleak
- Exceptional-moderate paid at committee discretion; lower-rated bugs occasionally paid
- **Exploit mitigation bypass without privileged access: +50% of the category payout** (a UXSS that
  also bypasses HTML sanitization = $10,000 + 50%)

### 5g. Crypto / hardware — strongest fit for native + cryptography work
- **Trezor** (`trezor.io`, self-hosted): **$500 – $100,000**. Scope covers **hardware, firmware,
  Suite, backend infrastructure and trezor.io** — the broadest self-hosted hardware-wallet scope.
  Context: Ledger's Donjon team published a lab chip attack on the Trezor Safe 7 in June 2026, so
  this surface is actively contested and the vendor is responsive.
- **Ethereum Foundation** (self-hosted): raised max to **$1,000,000** (Mar 2026) from $250,000.
  **$1M applies only to critical** — affects >50% of validators, enables ETH theft from wallets, or
  unlimited minting. **Everything else, low through high, caps at $50,000.** A $50,000 max award was
  paid in Feb 2026 for an ERC-4337 account-abstraction flaw. The **Glamsterdam** upgrade scope is
  open for reports with reward multipliers as Sepolia testing nears — new code, fewer eyes.
- **Solana Firedancer** — validator client **written in C**; tiers reported $100,000–$500,000 for
  criticals. Verify where it's hosted (likely Immunefi, not self-hosted) before counting it here.
- **Zcash** — `bounty.z.cash` plus a community-run `bountyzcash.org` (first bounty paid Apr 2026).
  Amounts unverified.
- **Monero** — no bounty program found.

### 5h. ZDI — exploit acquisition, not a bounty program
`zerodayinitiative.com` — vendor-agnostic buyer, self-hosted, buys **year-round**, not just at
Pwn2Own. You submit an unpatched bug, their analysts validate it in-lab and **make you a monetary
offer**. There is **no published rate card** — pricing is per case, which cuts both ways.
Recent price signals:
- **Pwn2Own Berlin 2026:** $1,298,250 total across 47 unique zero-days. Top single award **$200,000**
  (three chained bugs → RCE as SYSTEM on Microsoft Exchange). **Hyper-V guest-to-host escalation:
  $250,000.** VMware ESXi: $150,000.
- **Pwn2Own Ireland 2026:** day 1 alone, 32 zero-days for $388,500, including **$40,000 for an
  OpenAI Codex exploit** and **$40,000 for LiteLLM**.
- Its targeted incentive rounds have gone **up to $1.5M** for critical server-side flaws.

For a native-code researcher who doesn't want to wait on a vendor's triage queue, ZDI is the fastest
path from "I have a memory-corruption bug" to "I have an offer."

---

## 6. How to find more self-hosted programs yourself

1. **`/.well-known/security.txt`** (RFC 9116) on any target — it names the contact and often links a
   policy page stating whether rewards are paid. Sweep a list of companies in your target sector.
2. **`/security`, `/security-policy`, `/responsible-disclosure`, `/vdp`** paths on company sites.
3. **FireBounty** (`firebounty.com`) aggregates independent/self-hosted programs that the big
   platform directories don't list.
4. **disclose.io registry** — classifies programs and marks which are private vs. public.
5. Filter hard on one question: **does the policy state a reward amount, or only "may be eligible"?**
   Vague wording in a self-hosted program with no payment history is where time goes to die.

---

## 7. What this means for the $20,000 / 2-month target

Self-hosted programs change the shape of the problem: fewer duplicates, but harder targets and
slower payment. The honest read for each route:

| Route | Single-bug value | Realistic in 8 weeks? |
|---|---|---|
| **Mozilla sandbox escape** | $20,000 (+50% w/ mitigation bypass) | **One bug clears the target.** Hard, but Firefox is the most tractable major browser and GPU-process memory corruption pays $3,000 as a consolation floor. |
| **Chrome privileged-process controlled write** | $20,000 | One bug clears it. Needs a working fuzzing pipeline; the reinstated $2,000 fuzzer bonus pays for the pipeline itself. |
| **Trezor** | up to $100,000 | Best skill match in the list — hardware + firmware + crypto. Actively contested surface. |
| **Ethereum Foundation** | $50,000 non-critical cap | A single high clears 2.5× the target. Glamsterdam is new code with multipliers. |
| **ZDI** | per-case offers; $40k–$250k observed | Fastest payout path for native bugs; 2–4 solid submissions plausibly clear it. No queue-waiting on a vendor. |
| **Swisscom** | CHF 10,000 cap | Would need ~2 maxed criticals, and it pays **after remediation** — likely lands outside your window. |
| **Deutsche Telekom** | €10,000 cap | ~2 criticals. Web scope, high competition. |
| **Apple / Google Android / Samsung / Meta** | $300K–$2M ceilings | Highest ceilings in existence, lowest probability per hour. Not a 2-month plan. |

**Recommendation given your background** (native C++ and threshold-crypto review — the Fireblocks MPC
library work in this repo): go **Trezor + Ethereum Foundation Glamsterdam + ZDI**, with Mozilla client
as the fourth if you want a defined $20k ceiling to aim at. All four reward exactly the skill you've
already demonstrated, and ZDI removes the vendor-triage delay that will otherwise push payment past
your 8-week window.

**Payment-latency warning, which matters more here than on platforms:** Swisscom pays after
remediation; Apple, Google and Samsung triage slowly on hardware-class bugs; and self-hosted programs
have no platform SLA. Anything submitted in week 7–8 almost certainly pays **after** your window
closes. Front-load submissions into weeks 1–5.
