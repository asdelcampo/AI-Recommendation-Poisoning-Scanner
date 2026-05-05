# AIPoison Scanner

A web crawler and detection pipeline for identifying **AI Recommendation Poisoning** patterns on Philippine websites. Built as a regional replication of Microsoft's February 2026 research on adversarial manipulation of AI assistant responses via crawled web content.

## Background

In February 2026, Microsoft security researchers published a study identifying a widespread technique where websites embed hidden instructions into "Summarize with AI" share buttons and invisible DOM elements to manipulate AI assistant memory. When a user clicks one of these buttons, a pre-crafted prompt silently instructs the AI to treat the site as a trusted or authoritative source — a preference that can persist across future conversations.

Microsoft found **over 50 unique prompts from 31 companies across 14 industries** using this technique, deployed through freely available tools like CiteMET and AI Share URL Creator. The affected sectors include finance, healthcare, and legal — areas where biased AI recommendations carry real-world consequences.

This project applies the same detection framework to **183 Philippine websites** across 13 industries to measure regional prevalence.

> Reference: [AI Recommendation Poisoning — Microsoft Security Blog, February 10, 2026](https://www.microsoft.com/en-us/security/blog/2026/02/10/ai-recommendation-poisoning/)

## What it detects

Three signal types, each returning a structured finding with signal type, target platform, decoded payload, matched keywords, and confidence level:

| Signal | Technique |
|---|---|
| **AI Poisoning Links** | Outbound hrefs to AI platforms (`chatgpt.com`, `claude.ai`, etc.) carrying poison keywords in `?q=` / `?prompt=` parameters or URL fragments |
| **CiteMET** | References to the CiteMET npm package — structured metadata designed to influence AI citation ranking |
| **Hidden Text** | CSS-invisible DOM elements containing imperative AI instructions (proximity-gated to suppress false positives) |

## Requirements

- Python 3.11+
- A Google API key with **Safe Browsing API v4** enabled ([GCP Console → APIs & Services → Safe Browsing API](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com))
- Internet access

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

echo "GOOGLE_API_KEY=<your-key>" > .env
```

> If `GOOGLE_API_KEY` is absent, a warning is printed once and the scanner runs in heuristics-only mode. Domains that pass heuristics will show `verdict="unchecked"` rather than `"safe"`.

## Usage

```bash
# Primary PH dataset (183 domains)
python scanner.py --dataset PHSEAsites

# Global top-200 baseline
python scanner.py --dataset Top200

# Global arbitrary-500 sample
python scanner.py --dataset Arb500

# Limit to first N domains (useful for testing)
python scanner.py --dataset PHSEAsites --limit 10
```

Output is written to `output/{dataset}/`:

```
output/PHSEAsites/
├── results.csv      # one row per finding (empty if none)
├── summary.txt      # totals and breakdowns
├── errors.log       # per-domain errors with curl codes
└── evidence/        # HTML + JSON snapshots for high-confidence hits
```

## Datasets

| File | Description | Domains |
|---|---|---|
| `data/PHSEAsites.csv` | PH regional — 13 industries | 183 |
| `data/Top200.csv` | Tranco global top 200 | 200 |
| `data/Arb500.csv` | Tranco arbitrary 500 | 500 |

Add a custom dataset by creating `data/MyDataset.csv` with columns `domain,industry,country` and running `python scanner.py --dataset MyDataset`.

## Unit tests

```bash
python3 detector.py    # 8/8 detection engine tests
python3 prescanner.py  # 5/5 pre-scan tests
python3 crawler.py     # crawler smoke test (fetches example.com)
```

## Evaluation

`eval.py` is a fixed benchmark suite that measures detector accuracy against 8 labeled ground truth URLs (4 positive, 4 negative). All fetches use Playwright.

```bash
python3 eval.py
```

**Results (May 2026):**

| Metric | Score |
|---|---|
| Precision | **1.00** |
| Recall | **0.75** |
| F1 | **0.86** |

| | Count |
|---|---|
| True Positives | 3 |
| False Negatives | 1 |
| True Negatives | 4 |
| False Positives | 0 |

**Signal breakdown across positives:**

| Signal | Findings |
|---|---|
| `ai_poisoning_link` | 6 across 3 URLs |
| `citemet` | 191 across 3 URLs |
| `hidden_text` | 0 |

The one false negative (`managednerds.com`) was an article that appeared in search results with a raw CiteMET button, but the live page no longer renders the `?prompt=remember` payload at fetch time — the content changed between discovery and evaluation. Zero false positives across all tested AI-adjacent clean pages.

## Findings

Scanned across all three datasets (April 2026): **0 findings** out of 784 crawled domains.

## Project files

```
scanner.py         — pipeline orchestrator (asyncio, semaphore=10)
crawler.py         — async Playwright fetcher (headless Chromium, JS-rendered)
detector.py        — three-signal detection engine with proximity scoring
prescanner.py      — Google Safe Browsing + heuristic pre-filter
eval.py            — ground truth benchmark (Precision 1.00, Recall 0.75, F1 0.86)
playwright_fetcher.py — JS-rendered page fetcher (used by crawler and eval)
data/              — input CSV datasets
output/            — per-dataset results, summaries, logs, evidence
CHANGELOG.md       — version history
```
