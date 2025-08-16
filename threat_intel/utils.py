import os
import re
import hashlib
from typing import Optional, Dict, Any, List
from datetime import datetime
from dateutil import parser as dtparser
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup


def ensure_dir(path: str):
    if not path:
        return
    os.makedirs(path, exist_ok=True)


def collapse_ws(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()


def hash_key(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8", errors="ignore")).hexdigest()


def normalize_date(val: Optional[str]) -> str:
    if not val:
        return ""
    try:
        dt = dtparser.parse(val)
        if not dt.tzinfo:
            return dt.replace(tzinfo=None).isoformat()
        return dt.isoformat()
    except Exception:
        return ""


def build_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "ThreatIntelBot/1.0 (+https://example.com; Streamlit demo)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )
    retries = Retry(
        total=2,
        backoff_factor=0.4,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=["GET", "HEAD"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def safe_get(session: requests.Session, url: str, timeout: float = 12.0) -> Optional[requests.Response]:
    try:
        resp = session.get(url, timeout=timeout)
        if resp.status_code >= 400:
            return None
        return resp
    except Exception:
        return None


def clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))


def strip_html(html: str) -> str:
    try:
        soup = BeautifulSoup(html or "", "lxml")
        for t in soup(["script", "style", "noscript"]):
            t.decompose()
        return collapse_ws(soup.get_text(" "))
    except Exception:
        return collapse_ws(html or "")


def generate_markdown_report(df) -> str:
    lines = [
        "# Threat Intelligence Report",
        "",
        f"_Generated: {datetime.utcnow().isoformat()}Z_",
        "",
        f"Total items: **{len(df)}**",
        "",
        "---",
    ]
    for _, row in df.iterrows():
        lines += [
            f"## {row.get('title') or '(no title)'}",
            f"- Source: `{row.get('source','')}`",
            f"- URL: {row.get('url','')}",
            f"- Published: {row.get('published_at','')}",
            f"- Severity: **{row.get('severity','')}**",
            "",
            "**Summary**",
            "",
            (row.get("summary") or "")[:2000],
            "",
            "---",
        ]
    return "\n".join(lines)


def parse_eml(raw_bytes: bytes) -> Dict[str, Any]:
    import email
    from email import policy
    from email.parser import BytesParser

    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    result: Dict[str, Any] = {
        "from": str(msg.get("From", "")),
        "to": str(msg.get("To", "")),
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "received": [str(h) for h in msg.get_all("Received", [])] if msg.get_all("Received") else [],
        "attachments": [],
        "body_text": "",
        "body_html": "",
    }

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", "")).lower()
            if "attachment" in disp:
                filename = part.get_filename()
                if filename:
                    result["attachments"].append(filename)
                continue
            if ctype == "text/plain":
                try:
                    result["body_text"] += part.get_content()
                except Exception:
                    pass
            elif ctype == "text/html":
                try:
                    result["body_html"] += part.get_content()
                except Exception:
                    pass
    else:
        ctype = msg.get_content_type()
        if ctype == "text/plain":
            result["body_text"] = msg.get_content()
        elif ctype == "text/html":
            result["body_html"] = msg.get_content()

    return result


_VT_CACHE: Dict[str, Any] = {}

def vt_lookup_cached(indicator: str):
    indicator = (indicator or "").strip()
    if not indicator:
        return None
    if indicator in _VT_CACHE:
        return _VT_CACHE[indicator]
    key = os.environ.get("VIRUSTOTAL_API_KEY") or _get_secret("VIRUSTOTAL_API_KEY")
    if not key:
        return {"error": "No API key configured"}
    try:
        import base64
        sess = build_session()
        if indicator.startswith("http://") or indicator.startswith("https://"):
            id_b64 = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{id_b64}"
        else:
            url = f"https://www.virustotal.com/api/v3/files/{indicator}"
        resp = sess.get(url, headers={"x-apikey": key}, timeout=12)
        if resp.status_code >= 400:
            data = {"error": f"VT HTTP {resp.status_code}"}
        else:
            data = resp.json()
        _VT_CACHE[indicator] = data
        return data
    except Exception as e:
        return {"error": str(e)}


def _get_secret(name: str) -> Optional[str]:
    try:
        import streamlit as st
        return st.secrets.get(name)
    except Exception:
        return None
