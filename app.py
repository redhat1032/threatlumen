import re
import os
import time
import json
import hashlib
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import List, Dict, Any

import requests
import pandas as pd
import feedparser
import streamlit as st


# ─────────────────────────────────────────────
#   ThreatLumen Product Identity
# ─────────────────────────────────────────────
SYSTEM_NAME = "ThreatLumen"
SYSTEM_VERSION = "1.0"
SYSTEM_TAGLINE = (
    "Illuminated Threat Intelligence • Unified • Enriched • Triage-Ready"
)


# ─────────────────────────────────────────────
#   Page Config / Branding
# ─────────────────────────────────────────────
st.set_page_config(
    page_title=f"{SYSTEM_NAME} | Illuminated Threat Intelligence",
    page_icon="🔦",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ─────────────────────────────────────────────
#   Feeds + Tagging Config
# ─────────────────────────────────────────────
RSS_FEEDS: Dict[str, str] = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "Bleeping Computer": "https://www.bleepingcomputer.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss/all.xml",
    "Threatpost": "https://threatpost.com/feed/",
    "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "Schneier on Security": "https://www.schneier.com/feed/atom/",
}

TAG_KEYWORDS = {
    "Ransomware": ["ransomware", "lockbit", "encrypt", "extortion"],
    "Supply Chain": ["supply chain", "dependency", "npm", "pypi", "solarwinds"],
    "Cloud / IAM": ["aws", "azure", "gcp", "iam", "identity", "entra", "okta"],
    "Patching Required": ["patch", "update", "zero-day", "0-day", "cisa kev"],
    "Malware": ["malware", "trojan", "botnet", "infostealer"],
    "Vulnerabilities": ["cve-", "vulnerability", "remote code", "privilege escalation"],
}

CVE_RE = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)


# ─────────────────────────────────────────────
#   UI Theme / Cyber-Neon Styling
# ─────────────────────────────────────────────
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Roboto+Mono:wght@400;600&display=swap');

.stApp {
    background-color: #050505;
    background-image: radial-gradient(#111 1px, transparent 1px);
    background-size: 22px 22px;
    color: #e0e0e0;
    font-family: 'Roboto Mono', monospace;
}

h1, h2, h3, h4 {
    font-family: 'Orbitron', sans-serif;
    color: #00ffcc;
    text-shadow: 0 0 10px rgba(0,255,204,.7);
}

a {
    color:#00ffcc;
    text-decoration:none;
}
a:hover {
    color:#ff00ff;
    text-shadow:0 0 8px rgba(255,0,255,.8);
}

.news-card {
    border-radius: 12px;
    padding: 14px 16px;
    margin-bottom: 12px;
    background: linear-gradient(135deg, rgba(0,0,0,.95), rgba(10,10,25,.95));
    border: 1px solid rgba(0,255,204,.25);
    box-shadow: 0 0 18px rgba(0,255,204,.12);
}

.news-meta {
    font-size:0.78rem;
    text-transform:uppercase;
    letter-spacing:0.08em;
    color:#888;
    display:flex;
    justify-content:space-between;
}

.news-title {
    font-size:1.05rem;
    font-weight:700;
    margin:6px 0 4px 0;
    color:#fff;
}

.news-summary {
    font-size:0.86rem;
    color:#c0c0c0;
}

.pill {
    display:inline-block;
    padding:2px 8px;
    margin-right:4px;
    margin-top:4px;
    border-radius:999px;
    border:1px solid rgba(0,255,204,.4);
    font-size:.7rem;
    text-transform:uppercase;
    letter-spacing:.06em;
    color:#00ffcc;
}

.pill-severity-CRITICAL { border-color:#ff0066; color:#ff4d88;}
.pill-severity-HIGH { border-color:#ff3300; color:#ff704d;}
.pill-severity-MEDIUM { border-color:#ffaa00; color:#ffcc66;}
.pill-severity-LOW { border-color:#33cc33; color:#66ff99;}

.footer-text {
    color:#555;
    font-size:.72rem;
}
</style>
""",
    unsafe_allow_html=True,
)


# ─────────────────────────────────────────────
#   Utility Functions
# ─────────────────────────────────────────────
def parse_date(entry: Any) -> datetime:
    """Parse RSS entry date to a naive UTC datetime."""
    for key in ("published", "updated", "created"):
        v = entry.get(key)
        if v:
            try:
                d = parsedate_to_datetime(v)
                # Normalize to UTC and drop tzinfo for consistency
                return d.astimezone(timezone.utc).replace(tzinfo=None)
            except Exception:
                continue
    return datetime(1970, 1, 1)


def label_article(title: str, summary: str) -> List[str]:
    text = f"{title} {summary}".lower()
    labels = [
        tag for tag, kws in TAG_KEYWORDS.items() if any(k in text for k in kws)
    ]
    return labels or ["General"]


def extract_cves(text: str) -> List[str]:
    return sorted(set(match.upper() for match in CVE_RE.findall(text)))


@st.cache_data(ttl=3600)
def enrich_cve(cve_id: str) -> Dict[str, Any]:
    """Fetch CVSS score/severity from NVD v2 API. Cached to avoid rate limits."""
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            timeout=8,
        )
        if not r.ok:
            return {"id": cve_id}
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return {"id": cve_id}

        metrics = vulns[0]["cve"].get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                cvss = metrics[key][0].get("cvssData", {})
                return {
                    "id": cve_id,
                    "score": cvss.get("baseScore"),
                    "severity": cvss.get("baseSeverity"),
                }
    except Exception:
        pass
    return {"id": cve_id}


@st.cache_data(ttl=600)
def fetch_feeds() -> List[Dict[str, Any]]:
    """Fetch, normalize, and deduplicate items from all feeds."""
    items: List[Dict[str, Any]] = []
    seen = set()

    for source, url in RSS_FEEDS.items():
        parsed = feedparser.parse(url)
        for e in getattr(parsed, "entries", []) or []:
            title = e.get("title", "").strip()
            link = e.get("link", "").strip()
            if not (title and link):
                continue

            uid_src = f"{source}|{title}|{link}"
            uid = hashlib.md5(uid_src.encode("utf-8")).hexdigest()
            if uid in seen:
                continue
            seen.add(uid)

            summary = e.get("summary", e.get("description", "")).strip()
            d = parse_date(e)

            item = {
                "id": uid,
                "source": source,
                "title": title,
                "link": link,
                "summary": summary,
                "published": d,
                "published_str": d.strftime("%Y-%m-%d %H:%M"),
                "labels": label_article(title, summary),
            }
            items.append(item)

    items.sort(key=lambda i: i["published"], reverse=True)
    return items


def add_cve_enrichment(items: List[Dict[str, Any]], limit: int = 40) -> None:
    """Attach CVE enrichment for the first N items (in-place)."""
    for idx, i in enumerate(items[:limit]):
        cves = extract_cves(f"{i['title']} {i['summary']}")
        i["cves"] = [enrich_cve(c) for c in cves] if cves else []


def items_to_dataframe(items: List[Dict[str, Any]]) -> pd.DataFrame:
    """Convert items into a DataFrame for CSV export."""
    rows = []
    for i in items:
        rows.append(
            {
                "published": i.get("published_str", ""),
                "source": i.get("source", ""),
                "title": i.get("title", ""),
                "link": i.get("link", ""),
                "labels": ", ".join(i.get("labels", [])),
                "cves": ", ".join(
                    c["id"] for c in i.get("cves", []) if c.get("id")
                ),
            }
        )
    return pd.DataFrame(rows)


def items_to_markdown(items: List[Dict[str, Any]]) -> str:
    """Convert items into a Markdown report."""
    lines = [f"# {SYSTEM_NAME} Export\n"]
    for i in items:
        lines.append(f"## {i['title']}")
        lines.append(f"- **Published:** {i['published_str']}")
        lines.append(f"- **Source:** {i['source']}")
        if i.get("labels"):
            lines.append(f"- **Tags:** {', '.join(i['labels'])}")
        if i.get("cves"):
            cve_bits = []
            for c in i["cves"]:
                sev = (c.get("severity") or "").upper()
                score = c.get("score")
                if sev or score:
                    cve_bits.append(
                        f"{c['id']} ({(sev or '').strip()} {(score or '')})".strip()
                    )
                else:
                    cve_bits.append(c["id"])
            lines.append(f"- **CVEs:** {', '.join(cve_bits)}")
        lines.append("")
        lines.append(i["summary"])
        lines.append("")
        lines.append(f"[Read more]({i['link']})")
        lines.append("\n---\n")
    return "\n".join(lines)


# ─────────────────────────────────────────────
#   Session State
# ─────────────────────────────────────────────
if "saved_articles" not in st.session_state:
    st.session_state.saved_articles = {}


# ─────────────────────────────────────────────
#   Header
# ─────────────────────────────────────────────
st.markdown("# ThreatLumen")
st.caption(SYSTEM_TAGLINE)


# ─────────────────────────────────────────────
#   Sidebar Controls
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("### Controls")

    sources = st.multiselect(
        "Sources",
        list(RSS_FEEDS.keys()),
        default=list(RSS_FEEDS.keys()),
    )

    time_window = st.selectbox(
        "Time window",
        ["Last 24 hours", "Last 3 days", "Last 7 days", "All"],
        index=2,
    )

    theme_options = ["General"] + list(TAG_KEYWORDS.keys())
    themes = st.multiselect(
        "Themes",
        options=theme_options,
        default=[],
    )

    query = st.text_input(
        "Search",
        placeholder="CVE-2025-1234, LockBit, Okta, Kubernetes…",
    )

    show_saved = st.checkbox("Show saved only", value=False)

    enrich = st.checkbox("Enable CVE enrichment", value=True)


# ─────────────────────────────────────────────
#   Data Pipeline
# ─────────────────────────────────────────────
items = [i for i in fetch_feeds() if i["source"] in sources]

# Time filter
if time_window != "All":
    base = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff_map = {
        "Last 24 hours": base - timedelta(days=1),
        "Last 3 days": base - timedelta(days=3),
        "Last 7 days": base - timedelta(days=7),
    }
    cutoff = cutoff_map[time_window]
    items = [i for i in items if i["published"] >= cutoff]

# Theme filter
if themes:
    selected = set(themes)
    items = [i for i in items if selected.intersection(i["labels"])]

# Search filter
if query:
    q = query.lower()
    items = [
        i
        for i in items
        if q in i["title"].lower()
        or q in i["summary"].lower()
        or q in i["source"].lower()
    ]

# Saved filter
if show_saved:
    saved_ids = set(st.session_state.saved_articles.keys())
    items = [i for i in items if i["id"] in saved_ids]

# CVE enrichment
if enrich and items:
    add_cve_enrichment(items)
else:
    for i in items:
        i["cves"] = []


# ─────────────────────────────────────────────
#   Export Controls
# ─────────────────────────────────────────────
if items:
    df = items_to_dataframe(items)
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    md_text = items_to_markdown(items)

    col_csv, col_md = st.columns(2)
    with col_csv:
        st.download_button(
            "⬇️ Export CSV",
            csv_bytes,
            file_name="threatlumen_intel.csv",
            mime="text/csv",
        )
    with col_md:
        st.download_button(
            "⬇️ Export Markdown",
            md_text,
            file_name="threatlumen_intel.md",
            mime="text/markdown",
        )

st.markdown("---")


# ─────────────────────────────────────────────
#   Render Items
# ─────────────────────────────────────────────
if not items:
    st.info("No intelligence matched the filters.")
else:
    for i in items:
        st.markdown(
            f"""
<div class="news-card">
  <div class="news-meta">
    <span>{i['source']}</span>
    <span>{i['published_str']}</span>
  </div>
  <div class="news-title">
    <a href="{i['link']}" target="_blank" rel="noopener noreferrer">{i['title']}</a>
  </div>
  <div class="news-summary">{i['summary']}</div>
</div>
""",
            unsafe_allow_html=True,
        )

        # Labels / themes
        if i.get("labels"):
            st.markdown(
                " ".join(f"<span class='pill'>{t}</span>" for t in i["labels"]),
                unsafe_allow_html=True,
            )

        # CVE pills
        if i.get("cves"):
            ctags = []
            for c in i["cves"]:
                sev = (c.get("severity") or "").upper()
                sev_class = f" pill-severity-{sev}" if sev else ""
                parts = [c["id"]]
                if c.get("score") is not None:
                    parts.append(str(c["score"]))
                if sev:
                    parts.append(sev)
                label = " • ".join(parts)
                ctags.append(f"<span class='pill{sev_class}'>{label}</span>")
            st.markdown("".join(ctags), unsafe_allow_html=True)

        # Save / Unsave
        col_btn, _ = st.columns([1, 4])
        with col_btn:
            if i["id"] in st.session_state.saved_articles:
                if st.button("★ Saved", key=f"unsave_{i['id']}"):
                    st.session_state.saved_articles.pop(i["id"], None)
                    st.experimental_rerun()
            else:
                if st.button("☆ Save", key=f"save_{i['id']}"):
                    st.session_state.saved_articles[i["id"]] = i
                    st.experimental_rerun()

        st.markdown("<br/>", unsafe_allow_html=True)


# ─────────────────────────────────────────────
#   Footer
# ─────────────────────────────────────────────
st.markdown("---")
st.markdown(
    f"<center class='footer-text'>{SYSTEM_NAME} {SYSTEM_VERSION} • Illuminated Intel</center>",
    unsafe_allow_html=True,
)
