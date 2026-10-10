# Android and Google Devices Security Reward Program Rules

**Source:** [Google Bug Hunters — Android and Google Devices Security Reward Program Rules](https://bughunters.google.com/about/rules/android-friends/android-and-google-devices-security-reward-program-rules)
**Last Reviewed:** 2026-10-10
**Program Type:** Vulnerability Reward Program (VRP)

---

## Program Overview

The Android and Google Devices Security Reward Program rewards security researchers who report vulnerabilities affecting Android OS and Google-manufactured devices. The program is structured around demonstrable user impact, with rewards scaled by risk severity, exploit complexity, and report quality.

---

## Scope

### In-Scope Devices

| Category | Devices |
|----------|---------|
| **Pixel Phones** | All currently-supported Pixel smartphones |
| **Pixel Tablets** | Pixel Tablet and successors |
| **Pixel Watches** | Pixel Watch series |
| **Nest Devices** | Cameras, speakers, displays, thermostats, routers |
| **Fitbit Devices** | Trackers and smartwatches |

### In-Scope Software

- **AOSP** (Android Open Source Project) code
- **Android TV**
- **WearOS**
- **Android Automotive OS (AAOS)**
- **GooglebookOS**
- **Trusted Execution Environment (TEE)**
- **Secure Elements** (e.g., Titan M2)
- **Bootloaders**
- **Device firmware**
- **OEM proprietary code and drivers** on eligible devices

### Out of Scope

- Devices within **90 days** of the end of their guaranteed security update window
- **Backend services, server-side infrastructure**, and Google cloud APIs (report these to the [Google and Alphabet VRP](https://bughunters.google.com/about/rules/google-friends/google-and-alphabet-vulnerability-reward-program-vrp-rules))
- **Generic upstream Linux kernel bugs** unless a working PoC demonstrates direct impact on Android or Pixel-maintained kernel modules
- Vulnerabilities in **third-party apps** not developed by Google (report to the app developer)
- Devices from other OEMs (Samsung, OnePlus, etc.) unless the vulnerability is in AOSP code affecting Pixel
- **Google-built Android apps** (covered separately by the [Google Mobile VRP](https://bughunters.google.com/about/rules/android-friends/6618732618186752/google-mobile-vulnerability-reward-program-rules))

---

## Reward Structure

### Exploit Chain Rewards (Top-Tier)

These are maximum ceilings for full exploit chains demonstrated against supported Pixel devices. Amounts were raised in the May 2026 revision.

| Category | Maximum Reward | Previous Maximum |
|----------|---------------|-----------------|
| **Titan M2 exploit with persistence** | $1,500,000 | $1,000,000 |
| **Titan M2 exploit without persistence** | $750,000 | $500,000 |
| **Secure element data exfiltration** | $375,000 | $250,000 |
| **Software-based lockscreen bypass** | $150,000 | — |

To qualify for top-tier payouts, exploit chains must be:
- **Novel** — not a variant of a previously reported chain
- **Highly reliable** — consistent reproduction across supported devices
- **Achieve specific outcomes** — such as zero-click remote code execution or data exfiltration from isolated security elements

Additional bonuses may apply for chains demonstrated against developer preview builds of Android.

### Standalone Bug Rewards

Google uses a **dynamic reward model** for individual vulnerabilities (no fixed price sheet):

- **Base reward for memory-safety issues:** $500
- **Multipliers applied for:** reachability, exploitability, user impact, and report quality
- **Exceptional standalone submissions:** up to $25,000

The final payout is calculated as a multiplier of an adjustable baseline, assessed on:
1. Specific risk impact to users
2. Actionability of the report
3. Quality of the submission (PoC, root cause analysis, patch suggestion)

### Discontinued Bonuses (as of 2026)

The following bonus categories from 2025 have been phased out:
- Renderer remote code execution bonuses
- Arbitrary read/write bonuses

Google cited an overwhelming influx of AI-generated reports as a factor in discontinuing these.

---

## Submission Requirements

### Required Elements

1. **Clear demonstration of user risk** — the report must show how a real user could be harmed
2. **Functional Proof of Concept (PoC)** — a working exploit or reproduction script
3. **Reproduction on latest build** — vulnerabilities must reproduce on the latest publicly available build of the affected device
4. **Detailed write-up** including:
   - Affected component and version
   - Step-by-step reproduction instructions
   - Root cause analysis
   - Impact assessment

### Reward Multipliers

Reports earn higher rewards for:
- **Patch suggestions** — concrete, actionable fix code earns significant incentives
- **Root cause analysis** — deep explanation of the underlying flaw
- **Exploit reliability** — consistent reproduction without race conditions or timing dependencies
- **Broader impact assessment** — analysis of how many devices/users are affected

### Severity Ratings

Submissions are rated by severity using CVSS-compatible criteria:

| Severity | Description |
|----------|-------------|
| **Critical** | Remote code execution without user interaction, full device compromise, Titan M2/secure element bypass |
| **High** | Privilege escalation to kernel/TEE, persistent data exfiltration, lockscreen bypass |
| **Moderate** | Local privilege escalation with user interaction, information disclosure of sensitive data |
| **Low** | Minor information leaks, denial of service with limited impact |

**Note:** As of March 2023, Google no longer assigns CVEs to moderate-severity issues. CVEs continue to be assigned to critical and high-severity vulnerabilities.

---

## Qualifying Conditions

- Reports must be submitted through [Google Bug Hunters](https://bughunters.google.com)
- The vulnerability must not have been previously reported or publicly disclosed
- The researcher must not be a current Google employee or contractor
- Testing must be performed on devices you own or have authorization to test
- No privacy violations, data destruction, or service disruption during testing
- Coordinated disclosure — do not publicize before Google issues a fix

---

## Key Differences from Related Programs

| Program | Scope | Where to Report |
|---------|-------|-----------------|
| **Android & Google Devices VRP** | AOSP, Pixel/Nest/Fitbit firmware, TEE, bootloaders | [Bug Hunters](https://bughunters.google.com) |
| **Google Mobile VRP** | Google-built Android apps (Gmail, Maps, etc.) | [Bug Hunters](https://bughunters.google.com) |
| **Google & Alphabet VRP** | Google web services, cloud, backend infrastructure | [Bug Hunters](https://bughunters.google.com) |
| **Chrome VRP** | Chrome browser, ChromeOS | [Bug Hunters](https://bughunters.google.com) |

---

## Program Statistics

- **2024:** Over $3.3 million paid to researchers across Android and Google Mobile VRP combined
- **2025:** $17.1 million paid to 747 researchers across all Google VRPs
- **2026:** Total aggregate rewards expected to increase despite per-bug adjustments

---

## Sources

- [Android and Google Devices Security Reward Program Rules — Google Bug Hunters](https://bughunters.google.com/about/rules/android-friends/android-and-google-devices-security-reward-program-rules)
- [Google to pay up to $1.5 million for zero-click Pixel Titan M exploits — Help Net Security](https://www.helpnetsecurity.com/2026/05/05/google-vulnerability-reward-program-android-chrome-pixel/)
- [Google Revamps Bug Bounty Programs — Security Affairs](https://securityaffairs.com/191600/security/google-revamps-bug-bounty-programs-android-rewards-rise-chrome-payouts-drop-in-the-age-of-ai.html)
- [Google Adjusts Bug Bounties — SecurityWeek](https://www.securityweek.com/google-adjusts-bug-bounties-chrome-payouts-drop-as-android-rewards-rise-amid-ai-surge/)
- [Google Updates Android Bug Bounty Program — Forbes](https://www.forbes.com/sites/daveywinder/2026/05/05/google-to-pay-15-million-for-pixel-phone-security-exploit/)
- [Google VRP: Android Rewards Hit $1.5M — ISACChain](https://www.isacchain.com/blog/google-vrp-overhaul-android-rewards-reach-1-5m-while-chrome-payouts-drop/)
- [Google now offers up to $1.5 million for some Android exploits — BleepingComputer](https://www.bleepingcomputer.com/news/security/google-now-offers-up-to-15-million-for-some-android-exploits/)
