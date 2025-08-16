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


# -------------------------------
# Phone utilities (lightweight)
# -------------------------------

def analyze_phone_number(raw: str, default_region: str = "US") -> Dict[str, Any]:
    """
    Normalize and inspect a phone number using the `phonenumbers` library.
    Returns a dict with E.164, validity, region, carrier, type, and location.

    This imports `phonenumbers` lazily so the app still runs if the package
    isn't installed (you'll just get a friendly message).
    """
    info: Dict[str, Any] = {"input": (raw or "").strip(), "error": None}
    if not raw or not raw.strip():
        info["error"] = "No number provided"
        return info

    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, number_type, PhoneNumberType
    except Exception:
        info["error"] = "phonenumbers not installed"
        return info

    try:
        num = phonenumbers.parse(raw, default_region or "US")
    except Exception as e:
        info["error"] = f"Parse error: {e}"
        return info

    info["possible"] = phonenumbers.is_possible_number(num)
    info["valid"] = phonenumbers.is_valid_number(num)
    info["e164"] = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    info["national"] = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL)
    info["region"] = phonenumbers.region_code_for_number(num) or default_region

    # Map type to human label
    t = number_type(num)
    type_map = {
        getattr(PhoneNumberType, "FIXED_LINE", 0): "fixed_line",
        getattr(PhoneNumberType, "MOBILE", 1): "mobile",
        getattr(PhoneNumberType, "FIXED_LINE_OR_MOBILE", 2): "fixed_line_or_mobile",
        getattr(PhoneNumberType, "TOLL_FREE", 3): "toll_free",
        getattr(PhoneNumberType, "PREMIUM_RATE", 4): "premium_rate",
        getattr(PhoneNumberType, "SHARED_COST", 5): "shared_cost",
        getattr(PhoneNumberType, "VOIP", 6): "voip",
        getattr(PhoneNumberType, "PERSONAL_NUMBER", 7): "personal_number",
        getattr(PhoneNumberType, "PAGER", 8): "pager",
        getattr(PhoneNumberType, "UAN", 9): "uan",
        getattr(PhoneNumberType, "VOICEMAIL", 10): "voicemail",
        getattr(PhoneNumberType, "UNKNOWN", 99): "unknown",
    }
    info["type"] = type_map.get(t, "unknown")

    # Offline metadata (best effort)
    try:
        info["carrier"] = carrier.name_for_number(num, "en") or ""
    except Exception:
        info["carrier"] = ""
    try:
        info["location"] = geocoder.description_for_number(num, "en") or ""
    except Exception:
        info["location"] = ""

    return info


def phone_risk_score(info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Heuristic 1–5 risk score with transparent signals.
    Focuses on validity and suspicious patterns (no geo-bias).
    """
    if not info or info.get("error"):
        return {"score": 5, "signals": ["No data / parse failure"]}

    e164 = info.get("e164", "") or info.get("input", "")
    base = 1
    signals: List[str] = []

    if not info.get("possible"):
        base = 5; signals.append("Number not possible")
    elif not info.get("valid"):
        base = max(base, 4); signals.append("Number format invalid for region")

    # Type-based hints (informational; small bumps)
    t = (info.get("type") or "").lower()
    if t in {"premium_rate", "shared_cost", "personal_number"}:
        base = min(5, base + 2); signals.append(f"Type={t} can be higher risk")
    elif t in {"voip", "uan", "pager"}:
        base = min(5, base + 1); signals.append(f"Type={t} sometimes abused")

    # Pattern hints (repeated/sequential digits)
    digits = "".join(ch for ch in e164 if ch.isdigit())
    if len(digits) >= 7:
        if any(digits.count(d) >= 6 for d in set(digits)):  # 6+ of the same digit
            base = min(5, base + 1); signals.append("Repetitive digits pattern")
        seq = "0123456789"
        if digits in seq or digits in seq[::-1]:
            base = min(5, base + 1); signals.append("Sequential digits pattern")

    # Clamp 1..5
    base = clamp(base, 1, 5)
    if base == 1 and not signals:
        signals.append("No obvious risk signals")

    return {"score": base, "signals": signals}


# Optional enrichment: NumVerify (https://numverify.com/)
_PHONE_CACHE: Dict[str, Any] = {}

def numverify_lookup_cached(e164: str) -> Optional[Dict[str, Any]]:
    """
    Very light external enrichment if NUMVERIFY_API_KEY is present in secrets.
    Returns the raw JSON from NumVerify or None on error/missing key.
    """
    key = _get_secret("NUMVERIFY_API_KEY")
    if not key or not e164:
        return None
    if e164 in _PHONE_CACHE:
        return _PHONE_CACHE[e164]
    try:
        sess = build_session()
        # NumVerify expects digits only or international without '+'
        q = e164.replace("+", "")
        url = f"http://apilayer.net/api/validate?access_key={key}&number={q}&format=1"
        r = sess.get(url, timeout=10)
        data = r.json() if r.status_code < 400 else {"error": f"http {r.status_code}"}
        _PHONE_CACHE[e164] = data
        return data
    except Exception:
        return None


# -------------------------------
# VirusTotal helpers (optional)
# -------------------------------

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
