"""
playwright_fetcher.py — JS-rendered page fetcher

Three public interfaces:

  fetch_with_playwright(url)            — one browser per call (standalone / integration tests)
  fetch_page_with_browser(browser, url) — reuse an existing browser (crawl efficiency)
  open_browser()                        — async context manager yielding a browser

All return the same page dict schema as crawler.py:

    {
        "url":    str,        # final URL after any redirects
        "status": int,        # HTTP status code (0 on navigation failure)
        "html":   str,        # fully-rendered HTML from page.content()
        "hrefs":  list[str],  # all absolute hrefs extracted from rendered DOM
    }
"""

import asyncio
from contextlib import asynccontextmanager
from urllib.parse import urljoin

from playwright.async_api import async_playwright

# 30s to handle SPA frameworks that trigger many async network requests.
# networkidle waits until no network activity for 500ms — pages with analytics
# pings or chat widgets can stay "active" well past initial render.
_TIMEOUT_MS = 30_000


async def fetch_page_with_browser(browser, url: str) -> dict:
    """
    Fetch url using an already-running browser instance.

    Opens a new page tab, navigates, extracts content, closes the tab.
    Reusing the browser avoids repeated cold-start overhead (~2s per launch)
    when crawling multiple pages within the same domain.
    """
    page = await browser.new_page()
    status = 0
    final_url = url
    html = ""
    hrefs: list[str] = []

    try:
        try:
            response = await page.goto(url, wait_until="networkidle", timeout=_TIMEOUT_MS)
            if response is not None:
                status = response.status
        except Exception:
            # networkidle timed out — try domcontentloaded so partially-rendered
            # pages still contribute their injected links
            try:
                response = await page.goto(url, wait_until="domcontentloaded", timeout=_TIMEOUT_MS)
                if response is not None:
                    status = response.status
            except Exception:
                pass

        final_url = page.url
        html = await page.content()
        hrefs = await _extract_hrefs(page, final_url)
    finally:
        await page.close()

    return {"url": final_url, "status": status, "html": html, "hrefs": hrefs}


@asynccontextmanager
async def open_browser():
    """
    Async context manager that yields a running headless Chromium browser.

    Use with fetch_page_with_browser() to amortise the browser launch cost
    across multiple page fetches within the same domain:

        async with open_browser() as browser:
            page1 = await fetch_page_with_browser(browser, url1)
            page2 = await fetch_page_with_browser(browser, url2)
    """
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            yield browser
        finally:
            await browser.close()


async def fetch_with_playwright(url: str) -> dict:
    """
    Fetch url with a dedicated browser instance (one launch per call).

    Intended for integration tests and standalone use.
    For multi-page crawls use open_browser() + fetch_page_with_browser().
    """
    async with open_browser() as browser:
        return await fetch_page_with_browser(browser, url)


async def _extract_hrefs(page, base_url: str) -> list[str]:
    """
    Extract all <a href> values from the rendered DOM, resolve to absolute URLs,
    and preserve query parameters. Mirrors crawler._extract_hrefs().
    """
    raw_hrefs: list[str] = await page.eval_on_selector_all(
        "a[href]",
        "els => els.map(el => el.getAttribute('href') || '')",
    )

    results = []
    for raw in raw_hrefs:
        raw = raw.strip()
        if not raw or raw.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        try:
            resolved = urljoin(base_url, raw)
        except Exception:
            continue
        if resolved.startswith(("http://", "https://")):
            results.append(resolved)
    return results


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "https://llmrefs.com/blog/citemet-ai-share-buttons"

    async def _main():
        print(f"Fetching: {target}")
        page = await fetch_with_playwright(target)
        print(f"  final_url : {page['url']}")
        print(f"  status    : {page['status']}")
        print(f"  html_len  : {len(page['html'])}")
        print(f"  hrefs     : {len(page['hrefs'])}")
        print()

        ai_hrefs = [h for h in page["hrefs"] if any(d in h for d in [
            "chatgpt.com", "claude.ai", "perplexity.ai",
            "copilot.microsoft.com", "grok.com", "gemini.google.com",
            "meta.ai", "mistral.ai",
        ])]
        if ai_hrefs:
            print(f"  AI-platform hrefs found ({len(ai_hrefs)}):")
            for h in ai_hrefs:
                print(f"    {h}")
        else:
            print("  No AI-platform hrefs found in rendered DOM.")

        from detector import detect
        findings = detect(page)
        print(f"\n  Detector findings: {len(findings)}")
        for f in findings:
            print(f"    signal={f['signal_type']}  platform={f['target_platform']!r}"
                  f"  confidence={f['confidence']!r}")
            print(f"    keywords={f['keywords_matched']}")
            if f["decoded_prompt"]:
                print(f"    prompt={f['decoded_prompt'][:120]!r}")
            print()

    asyncio.run(_main())
