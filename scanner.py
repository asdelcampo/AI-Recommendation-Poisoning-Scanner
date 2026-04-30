"""
scanner.py — Main Orchestrator

Pipeline per domain:
    load data/{dataset}.csv → DNS pre-check → pre-scan → crawl → detect → write results

Outputs (fully isolated per dataset under output/{dataset}/):
    results.csv  — one row per finding
    summary.txt  — aggregate statistics
    errors.log   — all errors (scanner, crawler, prescanner)

Usage:
    .venv/bin/python3 scanner.py                         # PHSEAsites, all domains
    .venv/bin/python3 scanner.py --dataset Top200        # Top200 dataset
    .venv/bin/python3 scanner.py --dataset Arb500        # Arb500 dataset
    .venv/bin/python3 scanner.py --dataset PHSEAsites --limit 10
"""

import argparse
import asyncio
import csv
import hashlib
import json
import os
import socket
from collections import defaultdict
from datetime import datetime

import crawler as _crawler_mod
import prescanner as _prescanner_mod
from prescanner import prescan
from crawler import crawl_async
from detector import detect

_DIR = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_DIR, "data")
_OUTPUT_DIR = os.path.join(_DIR, "output")
_DEFAULT_DATASET = "PHSEAsites"

CSV_COLUMNS = [
    "domain", "industry", "country", "page_url",
    "link_found", "target_ai_platform", "decoded_prompt", "keywords_matched",
    "signal_type", "confidence", "prescan_verdict", "notes",
    "domain_status", "retry_attempted",
]


def _load_sites(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _write_finding(
    writer: csv.DictWriter,
    site: dict,
    page_url: str,
    finding: dict,
    prescan_result: dict,
    domain_status: str,
    retry_attempted: bool,
) -> None:
    writer.writerow({
        "domain":             site["domain"],
        "industry":           site.get("industry", ""),
        "country":            site.get("country", ""),
        "page_url":           page_url,
        "link_found":         finding.get("link_found") or "",
        "target_ai_platform": finding.get("target_platform") or "",
        "decoded_prompt":     finding.get("decoded_prompt") or "",
        "keywords_matched":   "; ".join(finding.get("keywords_matched") or []),
        "signal_type":        finding.get("signal_type", ""),
        "confidence":         finding.get("confidence", ""),
        "prescan_verdict":    prescan_result.get("verdict", ""),
        "notes":              prescan_result.get("notes", ""),
        "domain_status":      domain_status,
        "retry_attempted":    str(retry_attempted).lower(),
    })


def _write_summary(path: str, stats: dict, run_start: datetime, run_end: datetime) -> None:
    duration = run_end - run_start
    minutes, seconds = divmod(int(duration.total_seconds()), 60)

    def _pad(label: str, value) -> str:
        return f"  {label:<32}{value}"

    dead_domains = stats.get("dead_domains", [])

    lines = [
        "=== AIPoison Scanner — Scan Summary ===",
        "",
        _pad("Run start:",     run_start.strftime("%Y-%m-%d %H:%M:%S")),
        _pad("Run end:",       run_end.strftime("%Y-%m-%d %H:%M:%S")),
        _pad("Duration:",      f"{minutes}m {seconds}s"),
        _pad("Sites file:",    stats["sites_file"]),
        "",
        _pad("Domains in list:",     stats["total_in_list"]),
        _pad("DNS dead (skipped):",  stats["dns_dead_skipped"]),
        _pad("Malware (skipped):",   stats["skipped_malware"]),
        _pad("Domains crawled:",     stats["scanned"]),
        _pad("Domains flagged:",     stats["flagged_domains"]),
        _pad("Total findings:",      stats["findings"]),
        "",
        "--- Pre-scan verdicts ---",
        _pad("safe:",          stats["prescan"]["safe"]),
        _pad("phishing_risk:", stats["prescan"]["phishing_risk"]),
        _pad("malware:",       stats["prescan"]["malware"]),
        _pad("unknown:",       stats["prescan"]["unknown"]),
        _pad("unchecked:",     stats["prescan"]["unchecked"]),
        "",
        "--- Crawl coverage ---",
        *[_pad(f"{k}:", v)
          for k, v in sorted(stats["by_domain_status"].items(), key=lambda x: -x[1])],
        "",
        "--- Findings by signal type ---",
        *[_pad(f"{k}:", v)
          for k, v in sorted(stats["by_signal"].items(), key=lambda x: -x[1])],
        "",
        "--- Findings by confidence ---",
        *[_pad(f"{k}:", v)
          for k, v in sorted(stats["by_confidence"].items(), key=lambda x: -x[1])],
        "",
        "--- Findings by industry ---",
        *[_pad(f"{k}:", v)
          for k, v in sorted(stats["by_industry"].items(), key=lambda x: -x[1])],
        "",
        "--- Findings by country ---",
        *[_pad(f"{k}:", v)
          for k, v in sorted(stats["by_country"].items(), key=lambda x: -x[1])],
        "",
        "--- Findings by target AI platform ---",
        *[_pad(f"{k}:", v)
          for k, v in sorted(stats["by_platform"].items(), key=lambda x: -x[1])],
        "",
    ]

    if dead_domains:
        lines += [
            "--- DEAD — confirm and remove from dataset ---",
            *[f"  {d}" for d in sorted(dead_domains)],
            "",
        ]

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def run(dataset: str = _DEFAULT_DATASET, limit: int = 0) -> dict:
    """
    Execute the full scan pipeline for the given dataset.

    Domains are processed concurrently (asyncio.Semaphore, limit=10).
    The 2-second inter-page delay within each domain is preserved.

    Args:
        dataset: name of the CSV in data/ (without .csv extension)
        limit:   if > 0, only process the first N domains

    Returns:
        stats dict (also written to output/{dataset}/summary.txt)
    """
    sites_path   = os.path.join(_DATA_DIR, f"{dataset}.csv")
    dataset_dir  = os.path.join(_OUTPUT_DIR, dataset)
    results_csv  = os.path.join(dataset_dir, "results.csv")
    summary_txt  = os.path.join(dataset_dir, "summary.txt")
    error_log    = os.path.join(dataset_dir, "errors.log")

    os.makedirs(dataset_dir, exist_ok=True)
    _crawler_mod.set_output_dir(dataset_dir)
    _prescanner_mod.set_output_dir(dataset_dir)

    print("[fetcher] playwright — JS-rendered, networkidle, 30s timeout per page")

    sites = _load_sites(sites_path)
    if limit:
        sites = sites[:limit]

    total = len(sites)
    run_start = datetime.now()

    stats: dict = {
        "sites_file":        f"{dataset}.csv",
        "total_in_list":     total,
        "scanned":           0,
        "flagged_domains":   0,
        "skipped_malware":   0,
        "dns_dead_skipped":  0,
        "findings":          0,
        "dead_domains":      [],
        "prescan":           defaultdict(int),
        "by_domain_status":  defaultdict(int),
        "by_industry":       defaultdict(int),
        "by_country":        defaultdict(int),
        "by_platform":       defaultdict(int),
        "by_signal":         defaultdict(int),
        "by_confidence":     defaultdict(int),
    }

    asyncio.run(_run_async(
        sites, total, dataset_dir, results_csv, error_log, stats,
    ))

    run_end = datetime.now()

    for key in ("prescan", "by_domain_status", "by_industry", "by_country",
                "by_platform", "by_signal", "by_confidence"):
        stats[key] = dict(stats[key])

    for bucket in ("safe", "phishing_risk", "malware", "unknown", "unchecked"):
        stats["prescan"].setdefault(bucket, 0)

    _write_summary(summary_txt, stats, run_start, run_end)
    stats["_paths"] = {"results": results_csv, "summary": summary_txt, "errors": error_log}
    return stats


async def _run_async(
    sites: list[dict],
    total: int,
    dataset_dir: str,
    results_csv: str,
    error_log: str,
    stats: dict,
) -> None:
    """Inner async loop; called by run() via asyncio.run()."""
    sem = asyncio.Semaphore(10)
    csv_lock = asyncio.Lock()

    with open(results_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        tasks = [
            _scan_domain(site, i, total, sem, writer, csv_lock, dataset_dir, error_log, stats)
            for i, site in enumerate(sites, 1)
        ]
        await asyncio.gather(*tasks)


async def _scan_domain(
    site: dict,
    i: int,
    total: int,
    sem: asyncio.Semaphore,
    writer: csv.DictWriter,
    csv_lock: asyncio.Lock,
    dataset_dir: str,
    error_log: str,
    stats: dict,
) -> None:
    """Process a single domain: DNS → prescan → crawl → detect → write."""
    async with sem:
        domain   = site["domain"].strip()
        industry = site.get("industry", "").strip()
        country  = site.get("country", "").strip()

        try:
            loop = asyncio.get_running_loop()
            try:
                await loop.run_in_executor(None, socket.getaddrinfo, domain, None)
            except socket.gaierror:
                print(f"[{i}/{total}] DNS_DEAD: {domain}")
                _log_scanner_error(domain, "", "dns_dead: socket.gaierror", error_log)
                async with csv_lock:
                    stats["dns_dead_skipped"] += 1
                    stats["dead_domains"].append(domain)
                    stats["by_domain_status"]["dns_dead"] += 1
                return

            prescan_result = await loop.run_in_executor(None, prescan, domain)
            verdict = prescan_result["verdict"]
            async with csv_lock:
                stats["prescan"][verdict] += 1

            if verdict == "malware":
                print(f"[{i}/{total}] SKIPPED (malware): {domain}")
                async with csv_lock:
                    stats["skipped_malware"] += 1
                return

            async with csv_lock:
                stats["scanned"] += 1

            crawl_result    = await crawl_async(domain, n=i, total=total)
            pages           = crawl_result["pages"]
            domain_status   = crawl_result["domain_status"]
            retry_attempted = crawl_result["retry_attempted"]

            async with csv_lock:
                stats["by_domain_status"][domain_status] += 1
                if domain_status in ("dns_dead", "connection_refused"):
                    stats["dead_domains"].append(domain)

            domain_findings = 0
            for page in pages:
                try:
                    findings = detect(page)
                except Exception as exc:
                    _log_scanner_error(domain, page.get("url", ""), exc, error_log)
                    continue

                _save_evidence(dataset_dir, domain, page, findings)

                async with csv_lock:
                    for finding in findings:
                        _write_finding(
                            writer, site, page["url"], finding,
                            prescan_result, domain_status, retry_attempted,
                        )
                        domain_findings += 1
                        stats["findings"] += 1
                        stats["by_industry"][industry] += 1
                        stats["by_country"][country] += 1
                        stats["by_platform"][finding.get("target_platform") or "none"] += 1
                        stats["by_signal"][finding.get("signal_type", "unknown")] += 1
                        stats["by_confidence"][finding.get("confidence", "unknown")] += 1

            if domain_findings > 0:
                async with csv_lock:
                    stats["flagged_domains"] += 1

        except Exception as exc:
            _log_scanner_error(domain, "", exc, error_log)


def _save_evidence(dataset_dir: str, domain: str, page: dict, findings: list[dict]) -> None:
    """
    Persist raw HTML + JSON sidecar for any page that produced a high-confidence finding.
    Saved to output/{dataset}/evidence/{domain}/{sha1(url)[:12]}.{html,json}.
    No-op if no findings are high confidence.
    """
    high = [f for f in findings if f.get("confidence") == "high"]
    if not high:
        return

    url = page.get("url", "")
    slug = hashlib.sha1(url.encode()).hexdigest()[:12]
    evidence_dir = os.path.join(dataset_dir, "evidence", domain)
    os.makedirs(evidence_dir, exist_ok=True)

    html_path = os.path.join(evidence_dir, f"{slug}.html")
    with open(html_path, "w", encoding="utf-8", errors="replace") as f:
        f.write(page.get("html", ""))

    meta = {
        "url": url,
        "domain": domain,
        "fetched_at": datetime.now().isoformat(),
        "http_status": page.get("status"),
        "findings": high,
    }
    json_path = os.path.join(evidence_dir, f"{slug}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


def _log_scanner_error(domain: str, url: str, exc, error_log: str) -> None:
    os.makedirs(os.path.dirname(error_log), exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(error_log, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] [scanner] domain={domain!r} url={url!r} error={exc!r}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AIPoison Scanner")
    parser.add_argument("--dataset", default=_DEFAULT_DATASET,
                        help="Dataset name in data/ (without .csv). Default: PHSEAsites")
    parser.add_argument("--limit", type=int, default=0,
                        help="Only scan the first N domains (0 = all)")
    args = parser.parse_args()

    stats = run(dataset=args.dataset, limit=args.limit)

    paths = stats["_paths"]
    print()
    print(f"Scan complete. {stats['scanned']} domains crawled, "
          f"{stats['flagged_domains']} flagged, {stats['findings']} total findings.")
    print(f"DNS dead (skipped): {stats['dns_dead_skipped']}")
    print(f"Results → {paths['results']}")
    print(f"Summary → {paths['summary']}")
