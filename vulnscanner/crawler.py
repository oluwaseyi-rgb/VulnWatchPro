"""Minimal same-origin BFS crawler used to discover pages up to --depth."""
from __future__ import annotations

import urllib.parse


def extract_links(base_url: str, page_url: str, html: str) -> list:
    if not html:
        return []
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        hrefs = [a["href"] for a in soup.find_all("a", href=True)]
    except ImportError:
        import re
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', html)

    base_netloc = urllib.parse.urlparse(base_url).netloc
    links = set()
    for href in hrefs:
        full = urllib.parse.urljoin(page_url, href)
        parsed = urllib.parse.urlparse(full)
        if parsed.netloc == base_netloc and parsed.scheme in ("http", "https"):
            links.add(full.split("#")[0])
    return list(links)
