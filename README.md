# 🛡️ AI-Powered Cyber Threat & Phishing Intelligence Platform

A CPU-friendly **Streamlit** dashboard that **scrapes** cyber-security sources (RSS/HTML), **extracts IoCs** (Indicators of Compromise), **summarizes & classifies** content, **de-duplicates & stores** to SQLite, and **visualizes** trends and an **IoC graph**. It also **parses `.eml` phishing emails** for rapid triage.

> Built to run on **Streamlit Community Cloud** with sensible limits and graceful fallbacks.

---

## ✨ Features

- **Scraping**
  - Configurable sources (`scrapers/sources.yaml`)
  - `requests` with timeouts/retries + polite pacing
  - `feedparser` for RSS, `BeautifulSoup` for HTML

- **NLP**
  - Summarization via `sshleifer/distilbart-cnn-12-6` (CPU)
  - Optional zero-shot via `typeform/distilbert-base-uncased-mnli`
  - Rule-based fallbacks when models unavailable
  - IoC regex: IPv4/IPv6, URLs, domains, emails, MD5/SHA1/SHA256
  - Simple **severity** heuristic (1–5)

- **Phishing `.eml` Analyzer**
  - Extract headers (From/To/Subject/Received), body, attachments (names)
  - Summarize, IoCs, labels, severity
  - Persist to DB as `source=phishing:upload`

- **Persistence**
  - SQLite DB `data/threats.db`
  - Tables: `items`, `ioc`, `labels` (unique by URL hash)
  - Lightweight migration on first run

- **Visualization**
  - Daily counts, category distribution, top indicators (Altair)
  - Interactive IoC graph (PyVis) embedded in-app
  - CSV/JSON export + Markdown report download

- **Secrets (optional)**
  - `VIRUSTOTAL_API_KEY` enables lookup tool in the sidebar
  - All features handle missing secrets gracefully

---

## 🗂 Repository Layout

```
.
├── app.py
├── threat_intel/
│   ├── __init__.py
│   ├── scraping.py
│   ├── parsing.py
│   ├── nlp.py
│   ├── storage.py
│   ├── viz.py
│   └── utils.py
├── scrapers/
│   └── sources.yaml
├── data/
│   └── .gitkeep
├── assets/
│   ├── logo.png            # placeholder (optional)
│   └── favicon.png         # placeholder (optional)
├── tests/
│   ├── test_ioc_regex.py
│   └── test_dedup.py
├── .streamlit/
│   └── secrets.toml.example
├── requirements.txt
├── packages.txt
├── .gitignore
└── README.md
```

---

## 🧰 Quick Start (Local)

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Optional: provide secrets
mkdir -p .streamlit
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# edit .streamlit/secrets.toml and add VIRUSTOTAL_API_KEY if you have one

streamlit run app.py
```

> **Note:** First load of Hugging Face models may take time. If you’re on a small instance or rate-limited, the app **automatically falls back** to simple rule-based summaries/classification.  
> To disable model downloads entirely: `export DISABLE_HF=1`.

---

## 🚀 Deploy to Streamlit Community Cloud

1. Push this repo to **GitHub**.
2. In Streamlit, **New app** → point to your repo/branch.
3. Add secrets (optional) via **Settings → Secrets**:
   ```toml
   VIRUSTOTAL_API_KEY = "..."
   HUGGINGFACE_HUB_TOKEN = "..."  # optional
   ```
4. Deploy. The app is single-process, CPU-friendly, and uses caching to stay within limits.

---

## ⚙️ Configuration

- **Sources**: edit `scrapers/sources.yaml`
  - RSS sources are easiest (less brittle).
  - HTML sources require CSS selectors; disable if unstable.
- **Per-source limits**: `max_items` (default 25)
- **Models**:
  - Summarizer: `sshleifer/distilbart-cnn-12-6`
  - Zero-shot: `typeform/distilbert-base-uncased-mnli`
  - Fallbacks kick in automatically if models cannot load.

---

## 🧪 Tests

```bash
pytest -q
```

- `test_ioc_regex.py`: sanity checks for IoC extraction
- `test_dedup.py`: ensures same URL upserts once

---

## 🖼️ Screenshots (placeholders)

- Dashboard metrics + charts
- IoC network graph
- EML analyzer results

> Replace `assets/logo.png` / `assets/favicon.png` with your own images. The app handles missing/invalid images gracefully.

---

## 🔐 Security Notes

- **Respect ToS** for each source. Limit requests and enable only feeds you’re allowed to scrape.
- This project is for **education, research, and demo**. Do not rely on it for critical incident response without review.
- VirusTotal API responses (if enabled) may be subject to license/ToS—store and share responsibly.

---

## 🧭 Roadmap

- ✅ Initial release (RSS/HTML scraping, IoC extraction, NLP fallbacks, SQLite persistence, visualization)
- ⏩ Add enrichment (WHOIS/DNS/CVE APIs) with minimal overhead
- ⏩ Add dedup across normalized titles
- ⏩ Add YARA/signature attachments parsing
- ⏩ Add user-auth & role-based sharing for enterprise deployments

---

## 📄 License

MIT. Contributions welcome!
