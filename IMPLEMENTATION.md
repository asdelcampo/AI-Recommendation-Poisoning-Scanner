# IMPLEMENTATION.md — AIPoison Scanner: Phased Task Tracker

> **Rule:** Never mark a task `[x]` unless the code is written, tested, and working.
> **Rule:** Never start a new phase until all checkboxes in the current phase are checked AND the user has said "proceed".

---

## Phase 0 — Project Setup

- [x] Create project folder structure
- [x] Create requirements.txt with all dependencies
- [x] Create sites.csv template with columns: domain, industry, country
- [x] Verify all imports work

---

## Phase 1 — Pre-Scan Layer (URL Safety Check)

- [x] Implement Google Safe Browsing API lookup in prescanner.py
- [x] Implement lightweight heuristic checks in prescanner.py:
      IP-based URLs, excessive subdomains, homoglyph characters,
      known bad TLDs, URL length anomalies
- [x] Pre-scan accepts a domain, returns: safe / phishing_risk / malware / unknown
- [x] Unit test pre-scan on 5 sample URLs (2 clean, 2 known bad, 1 edge case)

---

## Phase 2 — Crawler (Scrapling)

- [x] Install and verify Scrapling works
- [x] Implement crawler.py using Scrapling with Chrome TLS fingerprint mode
- [x] Crawl homepage + up to 5 internal pages per domain (shallow, not deep)
- [x] Preserve full hrefs including query parameters (do NOT strip them)
- [x] 2-second delay between requests, 10-second timeout per page
- [x] Graceful error handling — one failed domain does not stop the run
- [x] Log all errors (timeouts, 403s, 404s) to output/errors.log
- [x] Print console progress: [n/total] Scanning: domain

---

## Phase 3 — Detection Engine

- [x] Implement detector.py with three detection functions
- [x] detect_ai_poisoning(): scan hrefs for AI domain + poison keyword in ?q= or ?prompt=
- [x] detect_citemet(): scan page source for CiteMET npm package references
- [x] detect_hidden_text(): scan for invisible elements containing AI instruction language
- [x] Detection returns structured dict: signal_type, target_platform, decoded_prompt,
      keywords_matched, confidence (low/medium/high)
- [x] Unit test detector on 3 synthetic poisoned HTML samples
      (extended to 6 tests: +fragment payload, +false-positive guard, +escalation; 6/6 pass)

---

## Phase 4 — Pipeline and Output

- [x] Implement scanner.py as main orchestrator:
      load sites.csv → pre-scan → crawl → detect → write results
- [x] Output results.csv with columns: domain, industry, country, page_url,
      link_found, target_ai_platform, decoded_prompt, keywords_matched,
      signal_type, confidence, prescan_verdict, notes
- [x] Output summary.txt: total scanned, flagged count, breakdown by industry,
      by country, by target AI platform, by signal type
- [x] End-to-end test: run full pipeline on 3 test domains
      (gcash.com, maya.ph, maribank.ph — 6 pages fetched per domain via Chrome TLS,
       0 findings as expected on clean fintech sites, no errors)

---

## Post-Run Fixes (applied after first full scan)

- [x] FIX 1: prescanner.py — switched from Web Risk API to Safe Browsing v4 REST
      (free tier, no billing; errors logged to errors.log with [prescanner] tag)
- [x] FIX 2: crawler.py — per-curl-error-code retry logic (_fetch helper);
      crawl() now returns dict {pages, domain_status, retry_attempted}
- [x] FIX 3: detector.py — removed "always recommend" from POISON_KEYWORDS;
      raised hidden text min length 15→40; 6/6 unit tests pass
- [x] FIX 4: scanner.py — socket.getaddrinfo() DNS pre-check before every crawl;
      dead domains logged and listed in summary.txt
- [x] FIX 5: results.csv — added domain_status and retry_attempted columns;
      summary.txt gains Crawl coverage section and DEAD domains list
- [x] End-to-end test on 5 domains — all pass (false positive gone, dns_dead
      skipped, tls retry fires, ssl verify=False retry fires)
- [x] Safe Browsing API v4 enabled and confirmed working (all 177 crawlable
      domains returned verdict="safe" in second full run)
- [x] Folder restructure: data/ created, all CSVs moved, sites.csv renamed
      to PHSEAsites.csv, dead_sites.csv moved, Top200.csv and Arb500.csv added
- [x] scanner.py --dataset flag: routes input/output per dataset name
- [x] Full output isolation: output/{dataset}/ subfolders; crawler.py and
      prescanner.py gained set_output_dir() so all errors go to per-dataset log
- [x] Dead site recovery: 8 corrected domains verified live and added back
      to PHSEAsites.csv (183 active domains); dead_sites.csv trimmed to 16

---

## Phase 4.5 — Hardening

- [x] D: prescanner.py startup banner; suppress per-domain "key not set" log spam
- [x] D: introduce verdict="unchecked" distinct from "unknown"; update scanner summary
- [x] C: _save_evidence() in scanner.py — HTML + JSON sidecar on confidence="high"
- [x] C: evidence/ directory created per dataset
- [x] B: imperative-verb + AI-token proximity sets in detector.py
- [x] B: 50-token proximity check inside detect_hidden_text()
- [x] B: 2 new unit tests (proximity-no-match → 0 findings; proximity-match → high)
- [x] B: full 8/8 detector unit tests pass
- [x] A: AsyncFetcher integration in crawler.py (chrome131 parity confirmed)
- [x] A: asyncio.Semaphore(10) over domains in scanner.run()
- [x] A: errors.log writer wrapped in asyncio.Lock
- [x] A: smoke test parity — 20-domain async run confirmed clean (20/20 crawled, 0 errors)

---

## Phase 5 — Documentation Finalization

- [x] Write final DOCUMENTATION.md narrative (methodology, findings framework,
      how to reproduce)
- [x] Write README.md with setup instructions and usage examples
- [x] Clean up all code comments
- [x] Final review of all checklist items

---

## Phase 6 — JS-Rendered Detection Baseline (Playwright Validation)

- [x] Add playwright to requirements.txt (already present from Phase 2)
- [x] Run `playwright install chromium` — Chromium 147 downloaded
- [x] Create playwright_fetcher.py: async fetch_with_playwright(url) returning
      {url, status, html, hrefs} matching crawler.py page dict schema
- [x] Run detector against confirmed positive (llmrefs.com/blog/citemet-ai-share-buttons):
      96 total findings; 2 ai_poisoning on chatgpt.com (confidence=high), 94 citemet —
      decoder fires correctly on JS-rendered content
- [x] Add test_real_world_positive() to detector.py test suite:
      async integration test; PASS confirmed (≥1 ai_poisoning on chatgpt.com, high confidence)
- [x] Document result in DOCUMENTATION.md: Findings section (Phase 6 confirmed positive),
      Limitations section (JS gap confirmed and qualified), How to Reproduce updated

---

## Phase 7 — Full Playwright Crawl + Re-scan

- [x] playwright_fetcher.py: add fetch_page_with_browser(browser, url) — reuses an
      existing browser instance to avoid ~2s cold-start per page
- [x] playwright_fetcher.py: add open_browser() async context manager for domain-scoped
      browser lifecycle; refactor fetch_with_playwright() to use both internally
- [x] playwright_fetcher.py: raise _TIMEOUT_MS from 10s to 30s
- [x] crawler.py: replace crawl_async() Scrapling implementation with Playwright;
      one browser per domain via open_browser() + fetch_page_with_browser();
      add _playwright_domain_status() helper
- [x] scanner.py: print fetcher banner at scan start
- [x] 10-domain smoke test: python scanner.py --dataset PHSEAsites --limit 10
      — Playwright confirmed active, 0 errors, 0 findings (expected on clean sites)
- [x] Full re-scan — PHSEAsites (183 domains): 181 crawled, 22m 23s, 0 findings
- [x] Full re-scan — Top200 (200 domains): 149 crawled, 23m 52s, 0 findings
- [x] Full re-scan — Arb500 (500 domains): 452 crawled, 48m 10s, 0 findings
- [x] DOCUMENTATION.md updated: Architecture, Findings, Limitations, How to Reproduce
- [x] CHANGELOG.md updated: Phase 7 entry added

---

## Phase 8 — Evaluation Suite

- [x] eval.py: 8-URL ground truth benchmark (4 positive, 4 negative), hardcoded by design
- [x] eval.py: all fetches via playwright_fetcher.py (fetch_with_playwright) — no static HTML
- [x] eval.py: all three detectors run per URL (detect_ai_poisoning, detect_citemet, detect_hidden_text)
- [x] eval.py: TP/FN/TN/FP scoring with Precision / Recall / F1 output
- [x] eval.py: per-signal-type breakdown (ai_poisoning / citemet / hidden_text)
- [x] eval.py: SKIP outcome for timed-out or errored URLs (not counted as FN/FP)
- [x] eval.py: results table + summary printed to stdout
- [x] eval.py: output/eval/eval_results.json and output/eval/eval_summary.txt written
- [x] eval.py: high-confidence findings persisted to output/eval/evidence/ (HTML + JSON)
- [x] DOCUMENTATION.md: Architecture diagram updated; Evaluation section added
- [x] CHANGELOG.md: Phase 8 entry added
