# Security Assessment Report — {{ target_name }}

**Assessment Date:** {{ date }}
**Target:** {{ target_url }}
**Scope:** {{ scope }}
**Platform:** {{ platform }}
**Methodology:** {{ methodology }}

---

## Executive Summary

{{ executive_summary }}

## Findings Summary

| # | Severity | CWE | Title | File |
|---|----------|-----|-------|------|
{% for finding in findings %}
| {{ loop.index }} | {{ finding.severity }} | {{ finding.cwe }} | {{ finding.title }} | {{ finding.file }} |
{% endfor %}

---

{% for finding in findings %}
{{ finding.rendered }}
{% endfor %}

---

## Methodology

{{ methodology_detail }}

## Appendix A — False Positives

{{ false_positives }}
