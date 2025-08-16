from typing import List, Dict, Any, Optional
import re
import os

try:
    import streamlit as st
except Exception:
    st = None

try:
    from transformers import pipeline
except Exception:
    pipeline = None

CANDIDATE_LABELS = ["Malware", "Ransomware", "Phishing", "Vulnerability", "Data Breach", "Other"]


def _cache_resource(fn):
    if st is None:
        return fn
    return st.cache_resource(show_spinner=False)(fn)


@_cache_resource
def load_summarizer():
    if os.environ.get("DISABLE_HF", "").lower() in ("1", "true", "yes"):
        return None
    if pipeline is None:
        return None
    try:
        return pipeline(
            task="summarization",
            model="sshleifer/distilbart-cnn-12-6",
            device=-1,
        )
    except Exception:
        return None


@_cache_resource
def load_zeroshot():
    if os.environ.get("DISABLE_HF", "").lower() in ("1", "true", "yes"):
        return None
    if pipeline is None:
        return None
    try:
        return pipeline(
            task="zero-shot-classification",
            model="typeform/distilbert-base-uncased-mnli",
            device=-1,
        )
    except Exception:
        return None


def _simple_sent_split(text: str) -> list:
    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    return [p.strip() for p in parts if p.strip()]


def summarize_text(text: str, summarizer=None, max_len=120, min_len=40) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    if len(text.split()) < 50:
        return " ".join(text.split()[:80])

    if summarizer is not None:
        try:
            sm = summarizer(text[:4000], max_length=max_len, min_length=min_len, do_sample=False)
            if sm and isinstance(sm, list) and "summary_text" in sm[0]:
                return sm[0]["summary_text"].strip()
        except Exception:
            pass

    sents = _simple_sent_split(text)
    return " ".join(sents[:4])


def classify_labels(text: str, zeroshot=None) -> List[str]:
    text = (text or "").strip()
    if not text:
        return ["Other"]

    if zeroshot is not None:
        try:
            res = zeroshot(text, candidate_labels=CANDIDATE_LABELS, multi_label=True)
            labels = []
            for lbl, score in zip(res["labels"], res["scores"]):
                if score >= 0.40:
                    labels.append(lbl)
            if labels:
                return labels
        except Exception:
            pass

    t = text.lower()
    labels = set()
    if any(k in t for k in ["ransomware", "encrypts", "locker"]):
        labels.add("Ransomware")
    if any(k in t for k in ["phishing", "phish", "credential harvest", "spoof"]):
        labels.add("Phishing")
    if any(k in t for k in ["cve-", "vulnerability", "patch", "cwe-"]):
        labels.add("Vulnerability")
    if any(k in t for k in ["data breach", "exfiltration", "leak", "compromised records"]):
        labels.add("Data Breach")
    if any(k in t for k in ["malware", "trojan", "worm", "botnet"]):
        labels.add("Malware")
    if not labels:
        labels.add("Other")
    return sorted(labels)


def score_severity(text: str, labels: List[str], iocs: Dict[str, List[str]]) -> int:
    t = (text or "").lower()
    score = 1
    if re.search(r"\bcve-\d{4}-\d+\b", t):
        score += 1
    if any(k in t for k in ["rce", "remote code execution", "zero-day", "0day"]):
        score += 1
    if any(lbl in ("Ransomware", "Malware") for lbl in labels):
        score += 1
    ioc_count = sum(len(v) for v in iocs.values()) if iocs else 0
    if ioc_count >= 5:
        score += 1
    if any(k in t for k in ["data breach", "exfiltration", "stolen data"]):
        score += 1
    return max(1, min(score, 5))
