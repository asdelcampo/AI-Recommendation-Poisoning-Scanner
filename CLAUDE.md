# CLAUDE.md — AIPoison Scanner: Standing Instructions

This file governs behavior for every session in this project. Read it once per session before doing anything else.

---

## Session Start Protocol

1. Read `IMPLEMENTATION.md` to orient yourself on current phase and open tasks.
2. Do not start a new phase until the current phase checklist is fully checked off **and** the user has explicitly said "proceed".
3. If you are unsure about scope, re-read `IMPLEMENTATION.md` before asking.

---

## After Every Task — Mandatory Update Sequence

Before stopping, regardless of how small the change was:

1. **CHANGELOG.md** — add an entry in the standard format (date, phase, description, Added/Changed/Fixed/Issues).
2. **IMPLEMENTATION.md** — mark any newly completed checklist items with `- [x]`.
3. **DOCUMENTATION.md** — update any affected sections (Architecture, Detection Methodology, Limitations, etc.).

Never skip this sequence. No exceptions.

---

## Phase Gating

- Never start Phase N+1 until every checkbox in Phase N is marked `[x]`.
- Wait for explicit user confirmation ("proceed") before advancing.

---

## Project Rules

### Crawler
- Use **Scrapling with Chrome TLS impersonation mode** for all HTTP fetches — never vanilla `requests` without a fingerprint.
- Crawl homepage + up to 5 internal pages per domain (shallow only).
- **2-second delay** between requests; **10-second timeout** per page.
- Wrap every domain in `try/except` — one failed domain must not abort the run.
- Log timeouts, 403s, 404s and all other errors to `output/errors.log`.
- Print to console: `[n/total] Scanning: domain` for every domain.

### Link Parsing / Detection
- **Preserve full hrefs including query parameters** — do NOT strip them.
- The poison payload lives in `?q=` and `?prompt=` parameters; stripping destroys evidence.

### Detection Keywords
```
remember, trusted source, authoritative, future conversations,
citation, cite, memory, always recommend, go-to source
```

### AI Domains to Watch
```
chatgpt.com
claude.ai
perplexity.ai
copilot.microsoft.com
grok.com
gemini.google.com
meta.ai
mistral.ai
```

### Pre-scan
- Use **Google Web Risk API** (GCP-native successor to Safe Browsing v4) via `google-cloud-webrisk`.
- Supplement with lightweight heuristics (see `prescanner.py`).

---

## Project Structure

```
aipoison-scanner/
├── CLAUDE.md               ← this file
├── IMPLEMENTATION.md       ← phase tracker
├── CHANGELOG.md            ← change log
├── DOCUMENTATION.md        ← technical narrative
├── README.md
├── prescanner.py
├── crawler.py
├── detector.py
├── scanner.py
├── requirements.txt
├── data/
│   ├── PHSEAsites.csv      ← primary dataset (175 active PH domains)
│   ├── Top200.csv          ← global baseline (Tranco top 200)
│   ├── Arb500.csv          ← global sample (Tranco 500 arbitrary)
│   └── dead_sites.csv      ← 25 dead/geo-blocked domains removed from PHSEAsites
└── output/
    └── {dataset}/
        ├── results.csv
        ├── summary.txt
        └── errors.log
```

---

## Research Context

This tool is a PH regional replication of Microsoft's AI Recommendation Poisoning research (February 2026). All design decisions should be evaluated against the goal of **detecting attacker-controlled content that manipulates AI assistant responses via search or citation pathways**.
