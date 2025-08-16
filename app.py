import os
import io
from datetime import datetime, timedelta
from typing import List, Dict, Any

import pandas as pd
import streamlit as st
import altair as alt

from threat_intel import utils
from threat_intel.scraping import load_sources_config, list_source_items
from threat_intel.parsing import html_to_text, extract_iocs
from threat_intel.nlp import (
    load_summarizer,
    load_zeroshot,
    summarize_text,
    classify_labels,
    score_severity,
)
from threat_intel.storage import (
    get_connection,
    migrate,
    upsert_item,
    insert_iocs,
    insert_labels,
    query_items,
    get_iocs_for_item_ids,
)
from threat_intel.viz import (
    chart_daily_counts,
    chart_category_distribution,
    chart_top_indicators,
    render_ioc_network_html,
)

APP_NAME = "AI Cyber Threat & Phishing Intelligence"

st.set_page_config(
    page_title=APP_NAME,
    layout="wide",
    page_icon="🛡️",
)

# --- Header / Branding ---
left, right = st.columns([1, 5], gap="large")
with left:
    try:
        st.image("assets/logo.png", width=96)
    except Exception:
        st.markdown("### 🛡️")
with right:
    st.markdown(f"# {APP_NAME}")
    st.caption("Scrape → Extract IoCs → Summarize → Classify → Store → Visualize (CPU-friendly)")

# --- Load config & resources (cached) ---
@st.cache_data(show_spinner=False)
def cached_sources():
    return load_sources_config("scrapers/sources.yaml")

@st.cache_resource(show_spinner=False)
def cached_db_conn():
    conn = get_connection("data/threats.db")
    migrate(conn)
    return conn

@st.cache_resource(show_spinner=False)
def cached_summarizer():
    return load_summarizer()

@st.cache_resource(show_spinner=False)
def cached_zeroshot():
    return load_zeroshot()

sources_cfg = cached_sources()
conn = cached_db_conn()
summarizer = cached_summarizer()  # may be None
zeroshot = cached_zeroshot()      # may be None

# --- Sidebar Filters / Tools ---
with st.sidebar:
    st.subheader("Filters")
    all_sources = [s["name"] for s in sources_cfg if s.get("enabled", True)]
    source_sel = st.multiselect("Sources", options=all_sources, default=all_sources)

    default_days = 14
    time_window_days = st.slider("Time window (days)", min_value=1, max_value=90, value=default_days)
    date_to = datetime.utcnow()
    date_from = date_to - timedelta(days=time_window_days)

    categories = ["Malware", "Ransomware", "Phishing", "Vulnerability", "Data Breach", "Other"]
    category_sel = st.multiselect("Categories", options=categories, default=[])

    severity_min = st.slider("Severity ≥", min_value=1, max_value=5, value=1)

    text_q = st.text_input("Search text", "")

    st.divider()
    st.subheader("VirusTotal (optional)")
    vt_key_present = bool(st.secrets.get("VIRUSTOTAL_API_KEY", ""))
    vt_indicator = st.text_input("URL or Hash")
    if vt_key_present and st.button("Lookup on VirusTotal"):
        with st.spinner("Querying VirusTotal..."):
            res = utils.vt_lookup_cached(vt_indicator.strip())
            st.json(res if res else {"info": "No result / error"})
    elif not vt_key_present:
        st.info("Provide `VIRUSTOTAL_API_KEY` in `.streamlit/secrets.toml` to enable lookups.", icon="🔐")

    st.divider()
    st.caption("Models load lazily and fall back to rules if unavailable.")

tabs = st.tabs(["📊 Dashboard", "🔎 Scrape Now", "✉️ Phishing Analyzer (EML)", "🗂️ Data Explorer"])

def apply_pipeline_and_persist(items: List[Dict[str, Any]], source_name: str) -> int:
    """Process raw items -> summarize, classify, IoCs, severity, persist."""
    inserted = 0
    for it in items:
        try:
            title = it.get("title") or "(no title)"
            url = it.get("url") or ""
            published_at = utils.normalize_date(it.get("published_at"))
            raw_text = it.get("text") or it.get("raw_html") or ""
            text = html_to_text(raw_text)

            # Summarize (fallback safe)
            summary = summarize_text(text, summarizer=summarizer, max_len=120, min_len=40)

            # IoCs
            iocs = extract_iocs(" ".join([title, text]))

            # Classify
            labels = classify_labels(" ".join([title, text]), zeroshot=zeroshot)

            # Severity heuristic
            severity = score_severity(" ".join([title, text]), labels, iocs)

            item_obj = {
                "title": title,
                "url": url,
                "source": source_name,
                "published_at": published_at,
                "text": text,
                "summary": summary,
                "severity": severity,
            }
            item_id = upsert_item(conn, item_obj)
            insert_iocs(conn, item_id, iocs)
            insert_labels(conn, item_id, labels)
            inserted += 1
        except Exception as e:
            st.warning(f"Error persisting an item from {source_name}: {e}")
    return inserted

# --- Tab: Dashboard ---
with tabs[0]:
    st.subheader("Overview")

    df = query_items(
        conn,
        sources=source_sel,
        date_from=date_from,
        date_to=date_to,
        categories=category_sel,
        severity_min=severity_min,
        text_query=text_q,
        limit=2000,
    )

    c1, c2, c3, c4 = st.columns(4)
    total_items = len(df)
    unique_iocs = 0
    top_source = "-"
    if total_items > 0:
        ids = df["id"].tolist()
        ioc_df = get_iocs_for_item_ids(conn, ids)
        unique_iocs = ioc_df["value"].nunique() if not ioc_df.empty else 0
        src_counts = df["source"].value_counts()
        if not src_counts.empty:
            top_source = src_counts.idxmax()

    c1.metric("Items", f"{total_items:,}")
    c2.metric("Unique IoCs", f"{unique_iocs:,}")
    c3.metric("Earliest", df["published_at"].min()[:10] if total_items else "—")
    c4.metric("Top Source", top_source)

    st.divider()
    if total_items == 0:
        st.info("No data yet. Try **Scrape Now** or upload EML in **Phishing Analyzer**.", icon="ℹ️")
    else:
        colA, colB = st.columns([2, 1])
        with colA:
            st.altair_chart(chart_daily_counts(df), use_container_width=True)
        with colB:
            st.altair_chart(chart_category_distribution(df), use_container_width=True)

        st.markdown("### Top Indicators")
        st.altair_chart(chart_top_indicators(ioc_df), use_container_width=True)

        st.markdown("### IoC Network")
        if not ioc_df.empty:
            html = render_ioc_network_html(df, ioc_df)
            st.components.v1.html(html, height=520, scrolling=True)
        else:
            st.caption("No IoCs in current selection.")

# --- Tab: Scrape Now ---
with tabs[1]:
    st.subheader("Fetch Latest from Sources")
    enabled = [s for s in sources_cfg if s.get("enabled", True)]
    options = [s["name"] for s in enabled]
    src_pick = st.multiselect("Choose sources", options=options, default=options)

    if st.button("Fetch Latest", type="primary"):
        progress = st.progress(0)
        total = max(len(src_pick), 1)
        done = 0
        total_inserted = 0
        for src_name in src_pick:
            source_cfg = next(s for s in sources_cfg if s["name"] == src_name)
            with st.spinner(f"Fetching {src_name}..."):
                try:
                    raw_items = list_source_items(source_cfg)
                    inserted = apply_pipeline_and_persist(raw_items, src_name)
                    total_inserted += inserted
                    st.success(f"{src_name}: {inserted} items processed.")
                except Exception as e:
                    st.error(f"{src_name}: {e}")
            done += 1
            progress.progress(int(done / total * 100))
        st.toast(f"Done. Inserted/updated {total_inserted} items.", icon="✅")
        # If you cached any data-fetch calls, clear them here.
        # st.cache_data.clear()

# --- Tab: Phishing Analyzer (EML) ---
with tabs[2]:
    st.subheader("Analyze EML")
    uploads = st.file_uploader("Upload .eml file(s)", type=["eml"], accept_multiple_files=True)
    if uploads:
        count = 0
        for up in uploads:
            try:
                data = up.read()
                parsed = utils.parse_eml(data)
                title = f"[EML] {parsed.get('subject','(no subject)')}"
                url = f"eml://{parsed.get('message_id','unknown')}"
                text = utils.strip_html(parsed.get("body_html") or "") or (parsed.get("body_text") or "")
                text = (text or "").strip()

                # Summarize / IoC / Classify
                summary = summarize_text(text, summarizer=summarizer, max_len=120, min_len=40)
                iocs = extract_iocs(" ".join([title, text]))
                labels = classify_labels(" ".join([title, text]), zeroshot=zeroshot)
                severity = score_severity(" ".join([title, text]), labels, iocs)

                item_obj = {
                    "title": title,
                    "url": url,
                    "source": "phishing:upload",
                    "published_at": utils.normalize_date(parsed.get("date")),
                    "text": f"From: {parsed.get('from')} | To: {parsed.get('to')} | Subject: {parsed.get('subject')}\n\n{text}",
                    "summary": summary,
                    "severity": severity,
                }
                item_id = upsert_item(conn, item_obj)
                insert_iocs(conn, item_id, iocs)
                insert_labels(conn, item_id, labels)
                count += 1

                with st.expander(f"Result: {title}"):
                    st.json(
                        {
                            "headers": {
                                "From": parsed.get("from"),
                                "To": parsed.get("to"),
                                "Subject": parsed.get("subject"),
                                "Date": parsed.get("date"),
                                "Message-ID": parsed.get("message_id"),
                                "Received": parsed.get("received")[:3],
                                "Attachments": parsed.get("attachments"),
                            },
                            "summary": summary,
                            "labels": labels,
                            "severity": severity,
                            "iocs": iocs,
                        }
                    )
            except Exception as e:
                st.error(f"Failed to process EML: {e}")
        st.success(f"Saved {count} EML item(s) to database.")

# --- Tab: Data Explorer ---
with tabs[3]:
    st.subheader("Explore & Export")

    df = query_items(
        conn,
        sources=source_sel,
        date_from=date_from,
        date_to=date_to,
        categories=category_sel,
        severity_min=severity_min,
        text_query=text_q,
        limit=5000,
    )

    st.dataframe(df, use_container_width=True, hide_index=True)

    c1, c2, c3 = st.columns(3)
    with c1:
        if not df.empty:
            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button("Export CSV", csv, file_name="threat_items.csv", mime="text/csv")
    with c2:
        if not df.empty:
            js = df.to_json(orient="records", indent=2).encode("utf-8")
            st.download_button("Export JSON", js, file_name="threat_items.json", mime="application/json")
    with c3:
        if not df.empty:
            md = utils.generate_markdown_report(df)
            st.download_button(
                "Download Markdown Report", md.encode("utf-8"), file_name="threat_report.md", mime="text/markdown"
            )

st.caption("© 2025 • For demo, education, and research. Respect source ToS.")
