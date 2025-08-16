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

# --- Session state (for auto-updated UI hints) ---
if "last_ingest" not in st.session_state:
    st.session_state["last_ingest"] = "—"
if "time_window_days" not in st.session_state:
    st.session_state["time_window_days"] = 14
if "sev_min" not in st.session_state:
    st.session_state["sev_min"] = 1

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

# Mode badge (lets users know if models are active or in fallback)
mode_cols = st.columns([1, 1.8, 3.2])
with mode_cols[0]:
    models_enabled = os.environ.get("DISABLE_HF", "").lower() not in ("1", "true", "yes")
    # Note: summarizer/zeroshot may still be None even if DISABLE_HF=0 due to install limits
    st.info("Mode: **Rules-only**" if not models_enabled else "Mode: **Models enabled**", icon="⚙️")
with mode_cols[1]:
    # Quick link to a built-in help panel
    st.link_button("Quick Guide ↓", "#quick-guide")
with mode_cols[2]:
    # Optional: one-click manual refresh (handy after changing filters)
    if st.button("🔄 Refresh data"):
        st.cache_data.clear()
        st.rerun()

# --- Quick Guide (collapsible help) ---
st.markdown("<div id='quick-guide'></div>", unsafe_allow_html=True)
with st.expander("🧭 How to use this app (quick guide)", expanded=False):
    st.markdown("""
1. **Pick sources** in the sidebar (Filters).
2. Go to **🔎 Scrape Now** and click **Fetch Latest**. The app will auto-refresh.
3. See totals & charts in **📊 Dashboard**. Use filters to refine.
4. Browse all rows in **🗂️ Data Explorer** and **Export** CSV/JSON or **Download Markdown**.
5. Analyze `.eml` files in **✉️ Phishing Analyzer (EML)** to extract headers, URLs/IoCs, summary, labels & severity.
6. (New) **📱 Phone Checker**: validate/normalize a phone number, view carrier/region/type, get a risk score, and optionally save to DB.
    """)

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

    st.caption("Time window")
    # Quick presets for time range
    p7, p30, p90 = st.columns(3)
    if p7.button("7d"):
        st.session_state["time_window_days"] = 7
        st.rerun()
    if p30.button("30d"):
        st.session_state["time_window_days"] = 30
        st.rerun()
    if p90.button("90d"):
        st.session_state["time_window_days"] = 90
        st.rerun()

    time_window_days = st.slider(
        "Days", min_value=1, max_value=90, value=st.session_state["time_window_days"], key="time_window_days"
    )
    date_to = datetime.utcnow()
    date_from = date_to - timedelta(days=time_window_days)

    categories = ["Malware", "Ransomware", "Phishing", "Vulnerability", "Data Breach", "Other"]
    category_sel = st.multiselect("Categories", options=categories, default=[])

    st.caption("Severity threshold")
    s3, s4, s5 = st.columns(3)
    if s3.button("≥3"):
        st.session_state["sev_min"] = 3
        st.rerun()
    if s4.button("≥4"):
        st.session_state["sev_min"] = 4
        st.rerun()
    if s5.button("≥5"):
        st.session_state["sev_min"] = 5
        st.rerun()
    severity_min = st.slider("Severity ≥", min_value=1, max_value=5, value=st.session_state["sev_min"], key="sev_min")

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
    with st.expander("Utilities", expanded=False):
        st.caption("Clear cached data if charts look stale.")
        if st.button("🧹 Clear cached data"):
            st.cache_data.clear()
            st.success("Cache cleared. Refreshing…")
            st.rerun()

    st.caption("Models load lazily and fall back to rules if unavailable.")

# NOTE: We now have five tabs including Phone Checker
tabs = st.tabs(["📊 Dashboard", "🔎 Scrape Now", "✉️ Phishing Analyzer (EML)", "📱 Phone Checker", "🗂️ Data Explorer"])

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
    st.caption(f"Last ingest: {st.session_state.get('last_ingest','—')}")

    # Friendly summary of current filters
    st.caption(
        f"Filters: {len(source_sel)} source(s) • {date_from.strftime('%Y-%m-%d')} → {date_to.strftime('%Y-%m-%d')} • "
        f"Severity ≥ {severity_min}" + (f" • Search: “{text_q}”" if text_q else "")
        + (f" • Categories: {', '.join(category_sel)}" if category_sel else "")
    )

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
    ioc_df = pd.DataFrame(columns=["item_id", "type", "value"])
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

        # Notify user
        st.toast(f"Done. Inserted/updated {total_inserted} items.", icon="✅")

        # Update UI hint and force fresh data on next render
        st.session_state["last_ingest"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
        st.cache_data.clear()  # clear cached data (safe; leaves models/DB conn cached)
        st.rerun()             # <— refresh the whole app so Dashboard shows new rows immediately

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

# --- Tab: Phone Checker ---
with tabs[3]:
    st.subheader("Phone Number Reputation")

    c1, c2 = st.columns([2, 1])
    with c1:
        raw_number = st.text_input("Enter a phone number", placeholder="+1 415 555 0100 or 415-555-0100")
    with c2:
        default_region = st.selectbox(
            "Default region",
            ["US","GB","CA","AU","IN","SG","DE","FR","BR","ZA","JP"],
            index=0
        )

    run = st.button("Check number", type="primary")
    save_to_db = st.checkbox("Also save result to database", value=False, help="Stores a summary as an item (source = phone:lookup)")

    analyze_func = getattr(utils, "analyze_phone_number", None)
    risk_func = getattr(utils, "phone_risk_score", None)
    enrich_func = getattr(utils, "numverify_lookup_cached", None)

    if run:
        if not callable(analyze_func) or not callable(risk_func):
            st.warning(
                "Phone checker helpers not found. Add `phonenumbers==8.13.43` to requirements and paste the "
                "`analyze_phone_number` and `phone_risk_score` helpers into `threat_intel/utils.py`.",
                icon="🧩",
            )
        else:
            info = analyze_func(raw_number, default_region=default_region)
            if info.get("error") == "phonenumbers not installed":
                st.warning("Install `phonenumbers==8.13.43` and redeploy.", icon="📦")
            elif info.get("error"):
                st.error(info["error"])
            else:
                risk = risk_func(info)
                colA, colB = st.columns([1,1])
                with colA:
                    st.metric("Risk score", risk["score"], help="Heuristic 1 (low) → 5 (high)")
                    st.json({"signals": risk["signals"]})
                with colB:
                    st.json(
                        {
                            "normalized": {
                                "e164": info.get("e164"),
                                "national": info.get("national"),
                                "region": info.get("region"),
                            },
                            "valid": info.get("valid"),
                            "type": info.get("type"),
                            "carrier": info.get("carrier"),
                            "location": info.get("location"),
                        }
                    )

                # Optional external enrichment (NumVerify), if key present and helper exists
                if st.secrets.get("NUMVERIFY_API_KEY") and callable(enrich_func):
                    with st.spinner("Enriching via NumVerify…"):
                        nv = enrich_func(info.get("e164", ""))
                        if nv:
                            st.markdown("**NumVerify**")
                            st.json(nv)

                # Optional: Save a simple record into DB as an "item"
                if save_to_db and info.get("e164"):
                    try:
                        title = f"Phone reputation: {info['e164']} (score {risk['score']})"
                        text = (
                            f"Region: {info.get('region','')} | Carrier: {info.get('carrier','')} | "
                            f"Type: {info.get('type','')} | Valid: {info.get('valid')}\n"
                            f"Signals: {', '.join(risk['signals'])}"
                        )
                        item_obj = {
                            "title": title,
                            "url": f"tel:{info['e164']}",
                            "source": "phone:lookup",
                            "published_at": datetime.utcnow().isoformat(),
                            "text": text,
                            "summary": text[:300],
                            "severity": int(risk["score"]),
                        }
                        item_id = upsert_item(conn, item_obj)
                        # Light labeling based on risk
                        lbls = ["Phishing"] if risk["score"] >= 4 else ["Other"]
                        insert_labels(conn, item_id, lbls)
                        st.success("Saved to database.")
                    except Exception as e:
                        st.warning(f"Could not save to DB: {e}")

    st.caption("Note: This offline check is heuristic. Use multiple signals before blocking a caller.")

# --- Tab: Data Explorer ---
with tabs[4]:
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

    c1, c2, c3, c4 = st.columns(4)
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
    with c4:
        # Optional: download the SQLite DB (handy for debugging/demo)
        db_path = "data/threats.db"
        if os.path.exists(db_path):
            with open(db_path, "rb") as f:
                st.download_button("Download DB", f, file_name="threats.db", mime="application/octet-stream")

st.caption("© 2025 • Made by Faiz Ahmed! For demo, education, and research. Respect source ToS.")
