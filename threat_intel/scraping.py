from typing import Dict, List, Any
import time
import yaml
import feedparser
from bs4 import BeautifulSoup

from .utils import build_session, safe_get, clamp
from .parsing import html_to_text


def load_sources_config(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or []
    for s in data:
        s.setdefault("enabled", True)
        s.setdefault("max_items", 25)
        s["max_items"] = clamp(int(s["max_items"]), 1, 100)
    return data


def fetch_rss(url: str, max_items: int = 25) -> List[Dict[str, Any]]:
    d = feedparser.parse(url)
    items = []
    for entry in d.entries[:max_items]:
        title = entry.get("title", "")
        link = entry.get("link", "")
        published = entry.get("published", "") or entry.get("updated", "") or ""
        summary = entry.get("summary", "") or entry.get("description", "") or ""
        items.append(
            {
                "title": title,
                "url": link,
                "published_at": published,
                "raw_html": summary,
                "text": html_to_text(summary),
            }
        )
    return items


def fetch_html(url: str, max_items: int, selectors: Dict[str, str]) -> List[Dict[str, Any]]:
    session = build_session()
    resp = safe_get(session, url)
    if not resp:
        return []

    soup = BeautifulSoup(resp.text, "lxml")
    list_sel = selectors.get("list_selector") or "article"
    nodes = soup.select(list_sel)[:max_items]

    results = []
    for n in nodes:
        title = None
        link = None
        published = None

        if "title_selector" in selectors:
            t_node = n.select_one(selectors["title_selector"])
            if t_node:
                title = t_node.get_text(strip=True) or None
        if "href_selector" in selectors:
            h_node = n.select_one(selectors["href_selector"])
            if h_node and h_node.has_attr("href"):
                link = h_node["href"]
        if "date_selector" in selectors:
            d_node = n.select_one(selectors["date_selector"])
            if d_node:
                published = d_node.get_text(" ", strip=True)

        if not title:
            title = n.get_text(" ", strip=True)[:140]
        if not link:
            a = n.find("a")
            if a and a.has_attr("href"):
                link = a["href"]

        body_text = ""
        if link and selectors.get("body_selector"):
            try:
                art = safe_get(session, link)
                if art:
                    s2 = BeautifulSoup(art.text, "lxml")
                    b = s2.select_one(selectors["body_selector"])
                    if b:
                        body_text = b.get_text(" ", strip=True)
            except Exception:
                pass

        results.append(
            {
                "title": title or "",
                "url": link or "",
                "published_at": published or "",
                "raw_html": "",
                "text": body_text,
            }
        )
        time.sleep(0.1)  # polite
    return results


def list_source_items(source_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    stype = source_cfg.get("type", "rss").lower()
    url = source_cfg["url"]
    max_items = int(source_cfg.get("max_items", 25))
    if stype == "rss":
        return fetch_rss(url, max_items=max_items)
    elif stype == "html":
        selectors = source_cfg.get("selectors", {}) or {}
        return fetch_html(url, max_items=max_items, selectors=selectors)
    else:
        raise ValueError(f"Unknown source type: {stype}")
