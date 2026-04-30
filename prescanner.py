"""
prescanner.py — Pre-Scan Layer

Checks a domain against the Google Safe Browsing Lookup API v4 (free tier,
100k lookups/month, no billing required) and five lightweight heuristics.

Requires:
  GOOGLE_API_KEY=<key>  in .env
  (Enable "Safe Browsing API" — NOT Web Risk — in your GCP project)

Verdicts: safe | phishing_risk | malware | unknown | unchecked
"""

import ipaddress
import os
import sys
from datetime import datetime
from urllib.parse import urlparse

import requests as _http
from dotenv import load_dotenv

load_dotenv()

_SB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_ERROR_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output", "errors.log")

# Set once on first prescan() call; suppresses per-domain log spam when key is absent.
_SB_DISABLED: bool = False
_SB_DISABLE_WARNED: bool = False


def set_output_dir(path: str) -> None:
    """Point error logging at a per-dataset output directory."""
    global _ERROR_LOG
    _ERROR_LOG = os.path.join(path, "errors.log")

# TLDs frequently abused for free phishing / malware hosting
_BAD_TLDS = frozenset({
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw",
    ".click", ".work", ".party", ".date", ".win", ".stream",
    ".gdn", ".men", ".download", ".review", ".racing", ".accountant",
})

_MAX_DOMAIN_LEN = 60
_MAX_SUBDOMAIN_LABELS = 4


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _log_error(uri: str, error: str) -> None:
    os.makedirs(os.path.dirname(_ERROR_LOG), exist_ok=True)
    with open(_ERROR_LOG, "a", encoding="utf-8") as fh:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        fh.write(f"[{ts}] [prescanner] uri={uri!r} error={error!r}\n")


def _to_uri(domain: str) -> str:
    if domain.startswith(("http://", "https://")):
        return domain
    return "https://" + domain


def _hostname(domain: str) -> str:
    parsed = urlparse(_to_uri(domain))
    return (parsed.hostname or domain).lower()


def _check_safebrowsing(uri: str) -> dict:
    """
    Query Google Safe Browsing Lookup API v4 for uri.
    Free tier: 100k lookups/month. No billing required.
    Returns {"found": bool, "threat_type": str|None, "error": str|None}.
    """
    global _SB_DISABLED, _SB_DISABLE_WARNED
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        if not _SB_DISABLE_WARNED:
            print(
                "[prescanner] WARNING: GOOGLE_API_KEY not set — "
                "Safe Browsing disabled, heuristics only.",
                file=sys.stderr,
            )
            _SB_DISABLED = True
            _SB_DISABLE_WARNED = True
        return {"found": False, "threat_type": None, "error": None}

    try:
        payload = {
            "client": {"clientId": "aipoison-scanner", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": uri}],
            },
        }
        resp = _http.post(
            f"{_SB_ENDPOINT}?key={api_key}",
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("matches"):
            threat_type = data["matches"][0].get("threatType", "SOCIAL_ENGINEERING")
            return {"found": True, "threat_type": threat_type, "error": None}

        return {"found": False, "threat_type": None, "error": None}

    except Exception as exc:
        error_str = str(exc)[:200]
        _log_error(uri, error_str)
        return {"found": False, "threat_type": None, "error": error_str}


def _check_heuristics(domain: str) -> list[str]:
    """
    Run five lightweight heuristic checks.
    Returns a list of triggered flag strings.
    """
    flags = []
    host = _hostname(domain)

    # 1. IP-based URL
    try:
        ipaddress.ip_address(host)
        flags.append("ip_based_url")
    except ValueError:
        pass

    # 2. Excessive subdomains
    labels = host.split(".")
    if len(labels) > _MAX_SUBDOMAIN_LABELS + 1:
        flags.append("excessive_subdomains")

    # 3. Homoglyph / non-ASCII characters
    #    Checks for raw non-ASCII labels AND punycode-encoded labels (xn--),
    #    which attackers use to register visually identical lookalike domains.
    for label in labels:
        if label.startswith("xn--"):
            flags.append("homoglyph_chars")
            break
        try:
            label.encode("ascii")
        except UnicodeEncodeError:
            flags.append("homoglyph_chars")
            break

    # 4. Known bad TLD
    tld = "." + labels[-1] if labels else ""
    if tld in _BAD_TLDS:
        flags.append("bad_tld")

    # 5. URL length anomaly
    if len(host) > _MAX_DOMAIN_LEN:
        flags.append("length_anomaly")

    return flags


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def prescan(domain: str) -> dict:
    """
    Pre-scan a domain.

    Returns:
        {
            "verdict":         "safe" | "phishing_risk" | "malware" | "unknown" | "unchecked",
            "webrisk_threat":  str | None,   (field kept for schema compat)
            "heuristic_flags": list[str],
            "notes":           str,
        }
    """
    uri = _to_uri(domain)
    sb = _check_safebrowsing(uri)
    flags = _check_heuristics(domain)

    if sb["found"]:
        threat = sb["threat_type"] or ""
        verdict = "malware" if threat == "MALWARE" else "phishing_risk"
    elif "ip_based_url" in flags or "homoglyph_chars" in flags:
        verdict = "phishing_risk"
    elif flags:
        verdict = "unknown"
    elif sb["error"]:
        verdict = "unknown"
    elif _SB_DISABLED:
        # "unchecked" means API was never configured — distinct from "unknown" (API tried, transient failure).
        verdict = "unchecked"
    else:
        verdict = "safe"

    notes_parts = []
    if sb["error"]:
        notes_parts.append(f"safebrowsing_error: {sb['error']}")
    if flags:
        notes_parts.append("heuristics: " + ", ".join(flags))

    return {
        "verdict": verdict,
        "webrisk_threat": sb["threat_type"],   # kept for schema compat
        "heuristic_flags": flags,
        "notes": "; ".join(notes_parts),
    }


# ---------------------------------------------------------------------------
# Unit tests  (.venv/bin/python3 prescanner.py)
# ---------------------------------------------------------------------------

def _run_unit_tests() -> None:
    tests = [
        {
            "domain": "google.com",
            "desc": "Clean — well-known domain",
            "must_have_flags": [],
            "verdict_not_in": ["malware"],
        },
        {
            "domain": "gcash.com",
            "desc": "Clean — verified PH fintech",
            "must_have_flags": [],
            "verdict_not_in": ["malware"],
        },
        {
            "domain": "free-gifts.tk",
            "desc": "Known-bad TLD (.tk)",
            "must_have_flags": ["bad_tld"],
            "verdict_not_in": ["safe"],
        },
        {
            "domain": "192.168.1.1",
            "desc": "IP-based URL",
            "must_have_flags": ["ip_based_url"],
            "verdict_not_in": ["safe"],
        },
        {
            # "paypal" spelled with Cyrillic а (U+0430)
            "domain": "pаypаl.com",
            "desc": "Edge case — Cyrillic homoglyph (pаypаl.com)",
            "must_have_flags": ["homoglyph_chars"],
            "verdict_not_in": ["safe"],
        },
    ]

    passed = failed = 0
    for t in tests:
        result = prescan(t["domain"])
        flags = result["heuristic_flags"]
        verdict = result["verdict"]

        flag_ok = all(f in flags for f in t["must_have_flags"])
        verdict_ok = verdict not in t["verdict_not_in"]
        ok = flag_ok and verdict_ok

        status = "PASS" if ok else "FAIL"
        passed += ok
        failed += not ok

        print(f"  [{status}] {t['desc']}")
        print(f"         verdict={verdict!r}  flags={flags}")
        if result["notes"]:
            print(f"         notes={result['notes']!r}")
        if not ok:
            if not flag_ok:
                print(f"         EXPECTED flags: {t['must_have_flags']}")
            if not verdict_ok:
                print(f"         VERDICT must not be one of: {t['verdict_not_in']}")
        print()

    print(f"  {passed}/{passed + failed} tests passed.")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    print("=== prescanner.py unit tests ===\n")
    _run_unit_tests()
