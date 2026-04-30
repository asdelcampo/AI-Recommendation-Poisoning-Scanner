# AIPoison Scanner

A web crawler and detection pipeline for identifying **AI Recommendation Poisoning** patterns on Philippine and Southeast Asian websites. Built as a regional replication of Microsoft's February 2026 research on adversarial manipulation of AI assistant responses via crawled web content.

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
# Primary PH/SEA dataset (183 domains)
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
| `data/PHSEAsites.csv` | PH/SEA regional — 13 industries | 183 |
| `data/Top200.csv` | Tranco global top 200 | 200 |
| `data/Arb500.csv` | Tranco arbitrary 500 | 500 |

Add a custom dataset by creating `data/MyDataset.csv` with columns `domain,industry,country` and running `python scanner.py --dataset MyDataset`.

## Unit tests

```bash
python detector.py    # 8/8 detection engine tests
python prescanner.py  # 5/5 pre-scan tests
python crawler.py     # crawler smoke test (fetches example.com)
```

## Findings

Scanned across all three datasets (April 2026): **0 findings** out of 784 crawled domains. See `DOCUMENTATION.md` for full methodology and result interpretation.

## Project files

```
scanner.py        — pipeline orchestrator (asyncio, semaphore=10)
crawler.py        — async Scrapling fetcher with chrome131 TLS impersonation
detector.py       — three-signal detection engine with proximity scoring
prescanner.py     — Google Safe Browsing + heuristic pre-filter
data/             — input CSV datasets
output/           — per-dataset results, summaries, logs, evidence
DOCUMENTATION.md  — full technical narrative and methodology
CHANGELOG.md      — version history
IMPLEMENTATION.md — phase-by-phase task tracker
```
