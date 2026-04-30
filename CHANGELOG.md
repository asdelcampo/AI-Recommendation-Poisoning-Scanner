# CHANGELOG.md — AIPoison Scanner

Format:
```
[YYYY-MM-DD] — Phase X: Description
Added
- ...
Changed
- ...
Fixed
- ...
Issues
- ...
```

---

[2026-04-30] — Post-Phase 7: Codebase Refactor for Publication

Added
- requirements.txt: lxml pinned explicitly (BeautifulSoup parser dependency)
Changed
- crawler.py: removed all Scrapling-based code (crawl(), _fetch(), _afetch(),
  _extract_hrefs(), _CURL_CODE_RE, _IMPERSONATE, _TIMEOUT constants); removed
  logging / re / time imports; module docstring updated to reflect Playwright-only
  operation; __main__ block updated to call crawl_async() via asyncio.run()
- playwright_fetcher.py: removed "Phase 6" / "Phase N" language from docstrings;
  fetch_with_playwright() now described as "standalone / integration tests"
- detector.py: removed phase-specific labels from test suite (section comments,
  test_real_world_positive() docstring, final print line)
- requirements.txt: removed scrapling, curl_cffi, browserforge, camoufox (Scrapling
  ecosystem no longer used), google-cloud-webrisk (was never called; prescanner
  uses Safe Browsing v4 REST via requests)
Fixed
- (none)
Issues
- (none)

---

[2026-04-30] — Phase 7: Full Playwright Crawl + Re-scan

Added
- playwright_fetcher.py: fetch_page_with_browser(browser, url) — fetches a URL using
  an already-running browser instance; opens/closes a page tab, returns {url, status,
  html, hrefs}; avoids the ~2s cold-start overhead of launching a new browser per page
- playwright_fetcher.py: open_browser() — async context manager yielding a running
  headless Chromium browser for multi-page reuse per domain
Changed
- playwright_fetcher.py: _TIMEOUT_MS raised from 10,000 to 30,000 (30s) — networkidle
  waits on pages with analytics pings or chat widgets require the extra headroom
- playwright_fetcher.py: fetch_with_playwright() refactored to use open_browser() +
  fetch_page_with_browser() internally; public interface unchanged
- crawler.py: crawl_async() replaced with Playwright implementation — launches one
  browser per domain via open_browser(), calls fetch_page_with_browser() for homepage
  and each internal page; domain_status uses _playwright_domain_status() helper
  (maps exception text to dns_dead / connection_refused / ssl_unverified / timeout /
  unknown); retry_attempted always False (Playwright handles retries internally)
- crawler.py: added _playwright_domain_status(exc_str) helper
- scanner.py: prints "[fetcher] playwright — JS-rendered, networkidle, 30s timeout
  per page" at the start of every run()
- DOCUMENTATION.md: Architecture, Findings, Limitations, How to Reproduce all updated
- IMPLEMENTATION.md: Phase 7 added and marked complete
Fixed
- (none)
Issues
- Playwright cannot replicate Scrapling's Chrome TLS fingerprint impersonation or
  verify=False SSL bypass; ~14% of crawlable domains fall into unknown domain status
  vs. <5% with Scrapling — those sites were simply unreachable to Playwright

Full re-scan results (all JS-rendered, networkidle):
  PHSEAsites  181/183 crawled  22m 23s  0 findings
  Top200      149/200 crawled  23m 52s  0 findings
  Arb500      452/500 crawled  48m 10s  0 findings
  Total: 782 domains crawled, 1h 35m total, 0 findings confirmed

---

[2026-04-30] — Phase 6: JS-Rendered Detection Baseline (Playwright Validation)

Added
- playwright_fetcher.py: async fetch_with_playwright(url) — launches headless Chromium,
  waits for networkidle, extracts fully-rendered HTML and all <a href> values from the
  rendered DOM; returns {url, status, html, hrefs} matching crawler.py's page dict schema
  so detector.py needs no changes
- detector.py: test_real_world_positive() — async integration test that Playwright-fetches
  the confirmed live positive (llmrefs.com/blog/citemet-ai-share-buttons) and asserts
  detect() returns ≥1 ai_poisoning finding on chatgpt.com with confidence="medium" or "high"
- detector.py: _LLMREFS_POSITIVE_URL constant for the Phase 6 baseline URL
- detector.py: --real-world CLI flag to run the live Playwright integration test
- playwright installed (v1.59.0) and Chromium browser downloaded
Changed
- DOCUMENTATION.md: Findings section updated with Phase 6 confirmed positive and JS-rendering
  root-cause explanation
- DOCUMENTATION.md: Limitations section updated — JS rendering gap now qualified as
  confirmed-and-validated via playwright_fetcher.py rather than merely a hypothesis
- DOCUMENTATION.md: How to Reproduce updated with Playwright installation steps and
  real-world integration test command
- IMPLEMENTATION.md: Phase 6 checkboxes marked [x]
Fixed
- (none)
Issues
- (none)

---

[2026-04-30] — Phase 5: Documentation Finalization

Added
- README.md: setup, usage, dataset table, unit test commands, project file index
- DOCUMENTATION.md: full rewrite as final technical narrative; sections: Overview,
  Research Context, Architecture, Detection Methodology (with proximity scoring
  and forensic evidence detail), Datasets, Findings (results table + interpretation
  of null result across all three scans), Limitations, How to Reproduce
Changed
- DOCUMENTATION.md: architecture diagram updated to reflect async pipeline,
  per-dataset output structure, and evidence folder
- DOCUMENTATION.md: Limitations section updated (added JS rendering, event-handler
  link discovery, Safe Browsing rate limit, screenshot deferral)
- prescanner.py module docstring: verdict list updated to include "unchecked"
- prescanner.py prescan() docstring: verdict list updated to include "unchecked"
- All source files: removed boilerplate section-separator comments (--- Internal
  helpers ---, --- Public API ---, etc.); retained only non-obvious WHY comments
Fixed
- (none)
Issues
- (none)

---

[2026-04-29] — Phase 4.5: Hardening (A/B/C/D)

Added
- prescanner.py: one-time stderr banner when GOOGLE_API_KEY is absent; module-level
  _SB_DISABLED / _SB_DISABLE_WARNED flags suppress per-domain log spam for the
  same root cause
- prescanner.py: verdict="unchecked" — returned when Safe Browsing is disabled and
  no heuristic flags fire; semantically distinct from "unknown" (which means the API
  was attempted and failed)
- scanner.py: "unchecked" bucket added to summary pre-scan verdicts section
- scanner.py: _save_evidence(dataset_dir, domain, page, findings) — on any
  confidence="high" finding, persists raw HTML and a JSON sidecar (url, domain,
  fetched_at, http_status, findings) to output/{dataset}/evidence/{domain}/{sha1(url)[:12]}.{html,json}
- detector.py: _IMPERATIVE_VERBS, _AI_TOKENS, _AI_PHRASES, _PROXIMITY_WINDOW=50
  constants for proximity scoring
- detector.py: _proximity_match(text) — returns True when an imperative-verb token
  appears within 50 tokens of an AI-platform token; multi-word AI phrases
  ("future conversations") collapsed to a single underscore-joined token before
  tokenising
- detector.py: Unit tests Sample 7 (proximity gate blocks false positive) and
  Sample 8 (imperative + AI token within window → high confidence); 8/8 pass
- crawler.py: AsyncFetcher import; _alog_error() async log helper (asyncio.Lock);
  _afetch() async mirror of _fetch() using asyncio.sleep(); crawl_async() full
  async equivalent of crawl()
- scanner.py: _run_async() and _scan_domain() coroutines; asyncio.Semaphore(10)
  across domains; asyncio.Lock for CSV writer; DNS check and prescan run via
  loop.run_in_executor() to avoid blocking the event loop

Changed
- detector.py: detect_hidden_text() now requires _proximity_match() to pass before
  emitting a finding; findings that pass emit confidence="high" unconditionally;
  findings that fail the proximity gate are suppressed entirely rather than demoted
- scanner.py: run() now delegates the inner domain loop to asyncio.run(_run_async());
  synchronous crawl() import replaced by crawl_async
- scanner.py: _save_evidence() called per page immediately after detect(), before the
  CSV write loop

Fixed
- prescanner.py: 500-domain run no longer produces 500 identical "GOOGLE_API_KEY not
  set" log lines; one banner is printed and subsequent calls short-circuit silently
- summary.txt pre-scan section was missing the "unchecked" row; now always present

Issues
- Screenshot forensics deferred — Playwright cold-start (~3s per page) adds
  meaningful latency; will revisit if Arb500 produces confirmed high-confidence hits
- SQLite resume backend deferred — 20-domain async run completes in ~56s, well under
  the 1-hour threshold where crash-recovery becomes meaningful

[2026-04-29] — Dead site recovery: 8 domains added back to PHSEAsites.csv

Changed
- data/PHSEAsites.csv: 175 → 183 domains; 8 recovered with corrected domains:
    carenethealthcare.com  (was carenethealthph.com)
    uerm.edu.ph            (was uermmmci.edu.ph)
    mlaw.ph                (was mlegalph.com)
    exist.com              (was exist.com.ph)
    multisyscorp.com       (was multisys.com.ph)
    licerainc.com          (was liceramarketing.com)
    skooltek.co            (was iskooltek.com)
    national-u.edu.ph      (was nu.edu.ph)
- lawphil.net skipped — already present in PHSEAsites.csv
- data/dead_sites.csv: 25 → 16 domains; 8 removed (recovered), 2 renamed:
    cocogen.com            (was cocogen.com.ph — still DNS-dead)
    sunlifegrepa.com       (was sunlifegrepa.com.ph — still DNS-dead)
Issues
- philhealth.gov.ph, ncpamh.doh.gov.ph, dlsu.edu.ph, feu.edu.ph remain DNS-dead
  even from a PH IP — likely CDN or authoritative DNS configuration, not
  geographic restriction

---

[2026-04-29] — Full per-dataset output isolation

Changed
- scanner.py: output path changed from output/{dataset}_*.csv to
  output/{dataset}/ subfolder — results.csv, summary.txt, errors.log all
  live under output/{dataset}/
- scanner.py: calls crawler.set_output_dir() and prescanner.set_output_dir()
  at the start of run() so all three modules write errors to the same
  per-dataset folder
- crawler.py: added set_output_dir(path) — updates _ERROR_LOG global to
  point at the per-dataset errors.log
- prescanner.py: added set_output_dir(path) — same pattern
- scanner.py: removed redundant os.makedirs(_OUTPUT_DIR) (dataset_dir
  creation now handles this); added module-level imports of crawler and
  prescanner alongside the existing from-imports
Fixed
- crawler and prescanner errors previously always wrote to output/errors.log
  regardless of dataset; they now write to output/{dataset}/errors.log
Issues
- (none)

---

[2026-04-29] — Folder restructure + multi-dataset support

Added
- data/ directory; all CSV files moved there
- data/PHSEAsites.csv (renamed from sites.csv — 175 active PH domains)
- data/dead_sites.csv (moved from root — 25 confirmed-dead or geo-blocked domains)
- data/Top200.csv (new — top 200 global domains from Tranco top-1M)
- data/Arb500.csv (new — arbitrary 500 global domains from Tranco top-1M)
Changed
- scanner.py: --sites flag replaced by --dataset flag; dataset name drives
  both input path (data/{dataset}.csv) and output paths
  (output/{dataset}_results.csv, output/{dataset}_summary.txt,
  output/{dataset}_errors.log)
- scanner.py: _log_scanner_error() now accepts explicit error_log path
- scanner.py: run() signature changed from (sites_path, limit) to
  (dataset, limit); returns _paths dict for CLI output
- summary.txt DEAD section label generalised (no longer hardcodes "sites.csv")
Fixed
- (none)
Issues
- crawler.py and prescanner.py still write to the shared output/errors.log
  (hardcoded). Only scanner-level errors go to the per-dataset log.
  Full per-dataset error isolation requires crawler.py/prescanner.py changes
  in a future pass.

---

[2026-04-29] — Post-run fixes (FIX 1–5)

FIX 1 — prescanner.py: Safe Browsing v4
Changed
- Replaced google-cloud-webrisk (Web Risk API) with direct HTTP call to
  Google Safe Browsing Lookup API v4 (free tier, 100k lookups/month, no billing)
  Endpoint: https://safebrowsing.googleapis.com/v4/threatMatches:find
- Prescanner errors now logged directly to output/errors.log with [prescanner] tag
- Docstring updated; "webrisk_threat" field kept in return dict for schema compat
Issues
- Safe Browsing API v4 returning 403 for all domains — the API key exists but
  "Safe Browsing API" must be separately enabled in GCP Console (APIs & Services →
  Library → search "Safe Browsing API" → Enable). Different from Web Risk API.

FIX 2 — crawler.py: per-error-type handling
Changed
- Added _curl_code() helper: extracts curl error code from exception string
- Added _fetch() helper: replaces bare try/except with per-code retry logic:
    curl 6  (DNS)        → dns_dead, no retry
    curl 7  (refused)    → connection_refused, no retry
    curl 35 (TLS reset)  → tls_reset_attempt1 logged, 5s sleep, 1 retry
    curl 60 (SSL cert)   → ssl_cert_error logged, retry with verify=False
    curl 28 (timeout)    → timeout_attempt1 logged, retry with 2× timeout
- crawl() return changed from list[dict] to dict with keys:
    pages, domain_status, retry_attempted
- _log_error() gains optional label param → [label] tag in errors.log

FIX 3 — detector.py: false positive reduction
Changed
- Removed "always recommend" from POISON_KEYWORDS — too common in financial/
  insurance marketing copy ("life insurance companies will always recommend...")
- "always recommend" retained in _HIGH_SPECIFICITY for confidence escalation
  when another keyword is also present
- Raised hidden text minimum length gate: 15 → 40 characters
- All 6 unit tests pass; Sample 3 second finding confidence changed
  correctly from "high" to "medium" (no longer boosted by "always recommend")

FIX 4 — scanner.py: DNS pre-check
Changed
- socket.getaddrinfo() called before prescan/crawl for every domain
- socket.gaierror → logged as dns_dead, domain skipped, no crawl attempt
- Dead domains accumulated in stats["dead_domains"] and listed in summary.txt
  under "DEAD — confirm and remove from sites.csv"

FIX 5 — scanner.py + results.csv: domain health columns
Changed
- CSV_COLUMNS: added domain_status and retry_attempted
- _write_finding() updated to write both columns
- stats["by_domain_status"] tracks active/dns_dead/tls_blocked/ssl_unverified/
  timeout/connection_refused per run
- summary.txt: new "Crawl coverage" section, new "DEAD — confirm and remove" section
- stats["total_in_list"] and "dns_dead_skipped" added to summary header

End-to-end test (5 domains) — all pass:
  robinsonsbank.com.ph   0 findings (false positive from FIX 3 eliminated) ✓
  google.com             active, 0 findings ✓
  a-known-dead-domain.xyz dns_dead at socket level, no crawl attempt ✓
  nationwidemed.com.ph   tls_reset_attempt1 → 5s sleep → tls_blocked ✓
  asianhospital.com      ssl_cert_error → retry verify=False → ssl_unverified ✓
Fixed
- (none new beyond the above)

---

[2026-04-29] — Phase 4: scanner.py complete

Added
- scanner.py: run(sites_path, limit) orchestrates full pipeline
- CLI: python scanner.py --limit N --sites PATH
- output/results.csv: one row per finding, written incrementally during scan
- output/summary.txt: totals + breakdowns by signal type, confidence, industry,
  country, AI platform, prescan verdict
- _log_scanner_error(): top-level per-domain exception catch → output/errors.log
- Known-malware domains skipped at pre-scan stage (safety gate)
Changed
- (none)
Fixed
- (none)
Issues
- Web Risk API returning "unknown" for clean PH domains even with API key set —
  key may need Web Risk API enabled in GCP Console. Heuristic-only fallback
  is in effect until credentials are confirmed working.

---

[2026-04-29] — Phase 3: detector.py improvements

Changed
- detect_ai_poisoning(): replaced flat ("q","prompt") param list with per-platform
  param map (AI_PLATFORM_PARAMS dict); chatgpt.com now also checks ?hints=
- detect_ai_poisoning(): added fragment (#param=value) payload detection via
  parse_qs on parsed.fragment; same per-platform param names apply
- detect_hidden_text(): added 15-char minimum text length gate to skip trivially
  short hidden elements (nav labels, icon text, etc.)
- detect_hidden_text(): tightened flag threshold to ≥2 keyword matches OR 1
  high-specificity keyword match before emitting a finding
- detect(): added multi-signal confidence escalation — if >1 signal type fires on
  the same page, all findings are escalated to confidence="high"
- Unit tests: 3 new cases added (fragment payload, false-positive guard, escalation);
  fixed Sample 1 Perplexity href to use ?q= per the platform map; 6/6 pass
Fixed
- (none)
Issues
- (none)

---

[2026-04-29] — Phase 3: detector.py complete

Added
- detector.py: detect(page) → list[dict], plus three individual functions
- detect_ai_poisoning(hrefs): flags AI domain + poison keyword in ?q= / ?prompt=
- detect_citemet(html): flags CiteMET npm package references (4 spelling variants)
- detect_hidden_text(html): flags invisible elements (7 CSS hiding patterns + HTML hidden attr)
- Confidence scoring: "high" for high-specificity keywords; "medium" for ≥2 matches; "low" otherwise
- 3/3 synthetic unit tests pass
Changed
- (none)
Fixed
- (none)
Issues
- (none)

---

[2026-04-29] — Phase 2: crawler.py complete

Added
- crawler.py: crawl(domain, n, total) → list of page dicts (url, status, html, hrefs)
- Chrome TLS impersonation via curl_cffi (chrome131 fingerprint)
- Shallow crawl: homepage + up to 5 internal pages, 2s delay, 10s timeout
- Error logging to output/errors.log with timestamp, domain, url, error
- Progress output: [n/total] Scanning: domain
- requirements.txt updated with explicit transitive deps: curl_cffi, playwright,
  browserforge, camoufox
Changed
- requirements.txt: added curl_cffi, playwright, browserforge, camoufox
Fixed
- Scrapling INFO/WARNING logs suppressed cleanly by importing before level override
Issues
- (none)

---

[2026-04-29] — Phase 1: prescanner.py complete

Added
- prescanner.py: prescan(domain) → dict with verdict, webrisk_threat, heuristic_flags, notes
- Google Web Risk API integration (GOOGLE_API_KEY or ADC via GOOGLE_APPLICATION_CREDENTIALS)
- Five heuristic checks: ip_based_url, excessive_subdomains, homoglyph_chars, bad_tld, length_anomaly
- Unit tests: 5/5 pass (2 clean, 2 known-bad, 1 homoglyph edge case)
Changed
- (none)
Fixed
- (none)
Issues
- Web Risk API requires credentials (GOOGLE_API_KEY or ADC). Without them, clean domains
  return verdict="unknown" instead of "safe". Heuristic-only verdict is still fully usable.

---

[2026-04-29] — Phase 0: Setup complete

Added
- requirements.txt (scrapling 0.4.7, requests 2.33.1, beautifulsoup4 4.14.3, python-dotenv 1.2.2, google-cloud-webrisk 1.21.0)
- .venv/ (Python 3.13 virtual environment with all dependencies installed)
- output/ directory with placeholder results.csv, summary.txt, errors.log
Changed
- (none)
Fixed
- (none)
Issues
- (none)

---

[2026-04-29] — Phase 0: Project scaffolding initialized
Added
- CLAUDE.md (governance and standing instructions for all sessions)
- IMPLEMENTATION.md (phased task tracker, Phases 0–5)
- CHANGELOG.md (this file)
- DOCUMENTATION.md (technical narrative skeleton)
- sites.csv (pre-existing, 200 verified PH domains across 13 industries, 4 columns)
Changed
- (none)
Fixed
- (none)
Issues
- (none)
