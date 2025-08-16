import re
from typing import Dict, List
from bs4 import BeautifulSoup

from .utils import collapse_ws

RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_IPV6 = re.compile(r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b", re.IGNORECASE)
RE_URL = re.compile(r"\bhttps?://[^\s<>()\"']+\b", re.IGNORECASE)
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b", re.IGNORECASE)
RE_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}\b", re.IGNORECASE)
RE_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
RE_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)


def html_to_text(html: str) -> str:
    if not html:
        return ""
    try:
        soup = BeautifulSoup(html, "lxml")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(" ")
        return collapse_ws(text)
    except Exception:
        return collapse_ws(html)


def extract_iocs(text: str) -> Dict[str, List[str]]:
    text = text or ""
    out = {
        "ipv4": sorted(set(RE_IPV4.findall(text))),
        "ipv6": sorted(set(RE_IPV6.findall(text))),
        "url": sorted(set(RE_URL.findall(text))),
        "domain": sorted(set(RE_DOMAIN.findall(text))),
        "email": sorted(set(RE_EMAIL.findall(text))),
        "md5": sorted(set(RE_MD5.findall(text))),
        "sha1": sorted(set(RE_SHA1.findall(text))),
        "sha256": sorted(set(RE_SHA256.findall(text))),
    }
    return out
