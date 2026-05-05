"""
eval.py — Ground truth evaluation suite for the AIPoison Scanner detector pipeline.

Measures precision, recall, and F1 against a fixed set of labeled URLs.
All fetches use playwright_fetcher.py (JS-rendered). Ground truth is hardcoded
by design — this is a fixed benchmark, not a configurable scan.

Usage:
    python eval.py
"""

import asyncio
import json
import os
import time
import traceback
from datetime import datetime, timezone

from detector import detect, detect_ai_poisoning, detect_citemet, detect_hidden_text
from playwright_fetcher import fetch_with_playwright

# ---------------------------------------------------------------------------
# Ground truth dataset
# ---------------------------------------------------------------------------

GROUND_TRUTH = [
    # --- TRUE POSITIVES (expect at least 1 finding per URL) ---------------
    {
        "url": "https://llmrefs.com/blog/citemet-ai-share-buttons",
        "expected": "positive",
        "label": "ai_poisoning_link + citemet",
        "note": "confirmed in Phase 6, 96 findings with Playwright",
    },
    {
        "url": "https://cite-met.com/blog/post/what-is-citemet",
        "expected": "positive",
        "label": "citemet",
        "note": "cite-met.com is the CiteMET platform itself, expected to self-deploy buttons",
    },
    {
        "url": "https://metehan.ai/blog/citemet-ai-share-buttons-growth-hack-for-llms",
        "expected": "positive",
        "label": "ai_poisoning_link + citemet",
        "note": "original CiteMET article by the method's inventor",
    },
    {
        "url": "https://managednerds.com/seo/how-to-add-summarize-with-chatgpt-to-your-blog",
        "expected": "positive",
        "label": "ai_poisoning_link",
        "note": "article showed raw ChatGPT button HTML with ?prompt=remember in search results",
    },
    # --- TRUE NEGATIVES (expect zero findings) ----------------------------
    {
        "url": "https://www.g2.com/articles/perplexity-vs-chatgpt",
        "expected": "negative",
        "label": "clean",
        "note": "AI comparison article, links to AI platforms legitimately, no memory manipulation",
    },
    {
        "url": "https://clickup.com/blog/perplexity-ai-vs-chatgpt",
        "expected": "negative",
        "label": "clean",
        "note": "same category, no CiteMET deployment expected",
    },
    {
        "url": "https://example.com",
        "expected": "negative",
        "label": "clean",
        "note": "baseline control, no AI links at all",
    },
    # --- FALSE POSITIVE STRESS TEST (expect zero despite AI-adjacent content) ---
    {
        "url": "https://llmrefs.com",
        "expected": "negative",
        "label": "clean",
        "note": "homepage may have generic AI links but should not have poison payloads on root domain",
    },
]

# ---------------------------------------------------------------------------
# Output paths
# ---------------------------------------------------------------------------

_EVAL_DIR = os.path.join("output", "eval")
_RESULTS_JSON = os.path.join(_EVAL_DIR, "eval_results.json")
_SUMMARY_TXT = os.path.join(_EVAL_DIR, "eval_summary.txt")
_EVIDENCE_DIR = os.path.join(_EVAL_DIR, "evidence")


# ---------------------------------------------------------------------------
# Eval runner
# ---------------------------------------------------------------------------

async def _eval_url(entry: dict) -> dict:
    """Fetch one URL, run all detectors, return a result record."""
    url = entry["url"]
    t0 = time.monotonic()
    error = None
    page = None

    try:
        page = await fetch_with_playwright(url)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    elapsed = time.monotonic() - t0

    if error is not None:
        return {
            "url": url,
            "expected": entry["expected"],
            "label": entry["label"],
            "note": entry["note"],
            "outcome": "SKIP",
            "findings": [],
            "findings_count": 0,
            "elapsed_s": round(elapsed, 2),
            "error": error,
            "signal_breakdown": {},
        }

    findings = detect(page)

    # Per-signal breakdown counts
    breakdown: dict[str, int] = {}
    for f in findings:
        st = f["signal_type"]
        breakdown[st] = breakdown.get(st, 0) + 1

    # Scoring
    n = len(findings)
    if entry["expected"] == "positive":
        outcome = "TP" if n > 0 else "FN"
    else:
        outcome = "TN" if n == 0 else "FP"

    # Save evidence for any high-confidence finding
    if page and any(f["confidence"] == "high" for f in findings):
        _save_evidence(url, page, findings)

    return {
        "url": url,
        "expected": entry["expected"],
        "label": entry["label"],
        "note": entry["note"],
        "outcome": outcome,
        "findings": findings,
        "findings_count": n,
        "elapsed_s": round(elapsed, 2),
        "error": None,
        "signal_breakdown": breakdown,
    }


def _save_evidence(url: str, page: dict, findings: list[dict]) -> None:
    import hashlib

    domain = url.split("/")[2] if "//" in url else url
    safe_domain = domain.replace(":", "_")
    ev_dir = os.path.join(_EVIDENCE_DIR, safe_domain)
    os.makedirs(ev_dir, exist_ok=True)

    slug = hashlib.sha1(url.encode()).hexdigest()[:12]
    html_path = os.path.join(ev_dir, f"{slug}.html")
    json_path = os.path.join(ev_dir, f"{slug}.json")

    with open(html_path, "w", encoding="utf-8", errors="replace") as fh:
        fh.write(page.get("html", ""))

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump({
            "url": url,
            "domain": domain,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "http_status": page.get("status", 0),
            "findings": findings,
        }, fh, indent=2)


async def _run_eval() -> list[dict]:
    results = []
    total = len(GROUND_TRUTH)
    for i, entry in enumerate(GROUND_TRUTH, 1):
        print(f"[{i}/{total}] Fetching: {entry['url']}")
        result = await _eval_url(entry)
        outcome_label = result["outcome"]
        if outcome_label == "SKIP":
            print(f"       SKIP — {result['error']}")
        else:
            print(f"       {outcome_label} — {result['findings_count']} finding(s) in {result['elapsed_s']}s")
        results.append(result)
    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _print_results_table(results: list[dict]) -> None:
    header = f"{'URL':<60}  {'Expected':<8}  {'Findings':>8}  {'Result'}"
    sep = "-" * len(header)
    print(header)
    print(sep)
    for r in results:
        short_url = r["url"].replace("https://", "").replace("http://", "")
        if len(short_url) > 58:
            short_url = short_url[:55] + "..."
        print(f"{short_url:<60}  {r['expected']:<8}  {r['findings_count']:>8}  {r['outcome']}")


def _compute_and_print_summary(results: list[dict]) -> str:
    tp = sum(1 for r in results if r["outcome"] == "TP")
    fn = sum(1 for r in results if r["outcome"] == "FN")
    tn = sum(1 for r in results if r["outcome"] == "TN")
    fp = sum(1 for r in results if r["outcome"] == "FP")
    skipped = sum(1 for r in results if r["outcome"] == "SKIP")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    # Per-signal breakdown across all results
    signal_totals: dict[str, int] = {}
    signal_url_counts: dict[str, int] = {}
    for r in results:
        for sig, cnt in r["signal_breakdown"].items():
            signal_totals[sig] = signal_totals.get(sig, 0) + cnt
            signal_url_counts[sig] = signal_url_counts.get(sig, 0) + 1

    elapsed_all = [r["elapsed_s"] for r in results if r["outcome"] != "SKIP"]
    slowest_time = max(elapsed_all) if elapsed_all else 0.0
    slowest_url = next(
        (r["url"] for r in results if r["elapsed_s"] == slowest_time and r["outcome"] != "SKIP"),
        "N/A",
    )
    total_runtime = sum(r["elapsed_s"] for r in results)

    lines = [
        "",
        "=== EVAL SUMMARY ===",
        f"Total URLs evaluated: {len(results)}  (skipped: {skipped})",
        f"TP: {tp} | FN: {fn} | TN: {tn} | FP: {fp}",
        f"Precision: {precision:.2f}",
        f"Recall:    {recall:.2f}",
        f"F1 Score:  {f1:.2f}",
        "",
        "Signal breakdown:",
    ]

    for sig in ("ai_poisoning", "citemet", "hidden_text"):
        total_sig = signal_totals.get(sig, 0)
        url_cnt = signal_url_counts.get(sig, 0)
        lines.append(f"  {sig:<22}: {total_sig:>4} findings across {url_cnt} URL(s)")

    lines += [
        "",
        f"Slowest fetch: {slowest_time:.1f}s ({slowest_url})",
        f"Total eval runtime: {total_runtime:.1f}s",
    ]

    # FP / FN notes
    fp_results = [r for r in results if r["outcome"] == "FP"]
    fn_results = [r for r in results if r["outcome"] == "FN"]
    if fp_results:
        lines.append("")
        lines.append("FALSE POSITIVES — investigate:")
        for r in fp_results:
            lines.append(f"  {r['url']}")
            lines.append(f"    label: {r['label']}  note: {r['note']}")
            for sig, cnt in r["signal_breakdown"].items():
                lines.append(f"    {sig}: {cnt} finding(s)")
    if fn_results:
        lines.append("")
        lines.append("FALSE NEGATIVES — missed positives:")
        for r in fn_results:
            lines.append(f"  {r['url']}")
            lines.append(f"    label: {r['label']}  note: {r['note']}")

    summary_text = "\n".join(lines)
    print(summary_text)
    return summary_text


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _save_outputs(results: list[dict], summary_text: str) -> None:
    os.makedirs(_EVAL_DIR, exist_ok=True)

    # Strip non-serialisable finding objects (all fields are already primitives)
    with open(_RESULTS_JSON, "w", encoding="utf-8") as fh:
        json.dump({
            "run_at": datetime.now(timezone.utc).isoformat(),
            "results": results,
        }, fh, indent=2)

    with open(_SUMMARY_TXT, "w", encoding="utf-8") as fh:
        fh.write(summary_text.strip() + "\n")

    print(f"\nResults saved to {_RESULTS_JSON}")
    print(f"Summary saved to  {_SUMMARY_TXT}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    wall_start = time.monotonic()

    print(f"=== AIPoison Scanner — Eval Suite ===")
    print(f"URLs: {len(GROUND_TRUTH)}  "
          f"({sum(1 for e in GROUND_TRUTH if e['expected'] == 'positive')} positive, "
          f"{sum(1 for e in GROUND_TRUTH if e['expected'] == 'negative')} negative)")
    print(f"Fetcher: Playwright (JS-rendered, networkidle, 30s timeout)")
    print()

    results = await _run_eval()

    print()
    _print_results_table(results)
    summary_text = _compute_and_print_summary(results)
    _save_outputs(results, summary_text)

    wall_elapsed = time.monotonic() - wall_start
    print(f"\nDone in {wall_elapsed:.1f}s")


if __name__ == "__main__":
    asyncio.run(main())
