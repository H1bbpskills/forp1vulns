# Bug Bounty Harness — Architecture & Usage

A modular framework for systematic vulnerability research on authorized targets.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    HARNESS CONTROLLER                    │
│              (harness/controller.py)                     │
│  Orchestrates recon → analysis → exploitation → report   │
└───────────┬──────────┬──────────┬──────────┬────────────┘
            │          │          │          │
    ┌───────▼──┐ ┌─────▼────┐ ┌──▼───────┐ ┌▼──────────┐
    │  RECON   │ │ ANALYSIS │ │ EXPLOIT  │ │ REPORTING │
    │  MODULE  │ │  MODULE  │ │  MODULE  │ │  MODULE   │
    └───────┬──┘ └─────┬────┘ └──┬───────┘ └┬──────────┘
            │          │          │          │
    ┌───────▼──┐ ┌─────▼────┐ ┌──▼───────┐ ┌▼──────────┐
    │ - Scope  │ │ - SAST   │ │ - PoC    │ │ - CVSS    │
    │   parse  │ │ - Deps   │ │   runner │ │   scoring │
    │ - Asset  │ │ - Fuzzer │ │ - Payload│ │ - Template│
    │   enum   │ │ - Manual │ │   gen    │ │   render  │
    │ - Tech   │ │   review │ │ - Impact │ │ - Platform│
    │   detect │ │ - Config │ │   verify │ │   submit  │
    └──────────┘ └──────────┘ └──────────┘ └───────────┘
```

## Directory Layout

```
harness/
├── README.md              # This file
├── controller.py          # Main orchestrator
├── config.py              # Target & scope configuration
├── recon/
│   ├── __init__.py
│   ├── scope_parser.py    # Parse program scope into targets
│   ├── asset_enum.py      # Enumerate endpoints, repos, APIs
│   └── tech_detect.py     # Fingerprint stack/frameworks
├── analysis/
│   ├── __init__.py
│   ├── static_review.py   # Pattern-based source code review
│   ├── dependency_audit.py # Known CVE / supply chain checks
│   ├── config_review.py   # Misconfig detection
│   └── fuzzer.py          # Protocol/input fuzzing harness
├── exploit/
│   ├── __init__.py
│   ├── poc_runner.py       # Execute & validate PoC scripts
│   ├── payload_gen.py      # Context-aware payload generation
│   └── impact_verify.py   # Confirm real-world impact
├── reporting/
│   ├── __init__.py
│   ├── cvss_scorer.py      # CVSS 3.1 vector calculator
│   ├── template_render.py  # Markdown report generator
│   └── platform_submit.py  # HackerOne/Bugcrowd formatters
├── templates/
│   ├── finding.md          # Per-finding template
│   └── full_report.md      # Full assessment template
└── tests/
    ├── test_recon.py
    ├── test_analysis.py
    └── test_reporting.py
```

## Workflow

1. **Configure** — Define target scope in `config.py`
2. **Recon** — Enumerate attack surface within authorized scope
3. **Analyze** — Run static analysis, dependency checks, manual review
4. **Exploit** — Build PoC, verify impact, document reproduction
5. **Report** — Score severity, render report, format for platform

## Usage

```bash
python harness/controller.py --target <scope> --phase all
python harness/controller.py --target <scope> --phase recon
python harness/controller.py --target <scope> --phase analyze
python harness/controller.py --target <scope> --phase report
```

## Principles

- **Authorization first** — Never test without explicit scope authorization
- **Minimal impact** — PoCs demonstrate, not damage
- **Reproducibility** — Every finding must have exact repro steps
- **Evidence chain** — Screenshots, logs, request/response pairs
- **Honest severity** — CVSS reflects real impact, never inflated
