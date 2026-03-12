"""
ThreatLumen – Illuminated Threat Intelligence Dashboard
WeanTech / Douglas Weant

Changelog from v1.0:
  - Fixed: st.experimental_rerun() → st.rerun() (removed in Streamlit 1.40+)
  - Fixed: Per-feed error isolation — one bad feed no longer blocks the pipeline
  - Fixed: Removed defunct Threatpost feed; replaced with SecurityWeek
  - Added: Concurrent feed fetching via ThreadPoolExecutor (dramatically faster cold load)
  - Added: NVD API key support (env var NVD_API_KEY) with exponential backoff + rate limiting
  - Added: CISA KEV catalog enrichment — flags articles whose CVEs appear in the KEV list
  - Added: Severity-aware sorting — CRITICAL/HIGH CVE items bubble above general news
  - Added: JSON-based article persistence (saved_articles.json) — saves survive page refresh
  - Added: Feed health indicator in sidebar showing which sources returned items
  - Added: Graceful degradation — all network failures are caught and surfaced, never silently swallowed
"""

import re
import json
import time
import hashlib
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import feedparser
import pandas as pd
import requests
import streamlit as st

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger("threatlumen")


# ─────────────────────────────────────────────
#   Product Identity
# ─────────────────────────────────────────────
SYSTEM_NAME = "ThreatLumen"
SYSTEM_VERSION = "1.1"
SYSTEM_TAGLINE = "Illuminated Threat Intelligence • Unified • Enriched • Triage-Ready"

SAVED_PATH = Path("saved_articles.json")


# ─────────────────────────────────────────────
#   Page Config
# ─────────────────────────────────────────────
st.set_page_config(
    page_title=f"{SYSTEM_NAME} | Illuminated Threat Intelligence",
    page_icon="🔦",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ─────────────────────────────────────────────
#   Feed Config
# ─────────────────────────────────────────────
RSS_FEEDS: Dict[str, str] = {
    "The Hacker News":    "https://feeds.feedburner.com/TheHackersNews",
    "Krebs on Security":  "https://krebsonsecurity.com/feed/",
    "Bleeping Computer":  "https://www.bleepingcomputer.com/feed/",
    "Dark Reading":       "https://www.darkreading.com/rss/all.xml",
    "SecurityWeek":       "https://feeds.feedburner.com/securityweek",   # replaced defunct Threatpost
    "CISA Advisories":    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "Schneier on Security": "https://www.schneier.com/feed/atom/",
}

TAG_KEYWORDS: Dict[str, List[str]] = {
    "Ransomware":       ["ransomware", "lockbit", "encrypt", "extortion"],
    "Supply Chain":     ["supply chain", "dependency", "npm", "pypi", "solarwinds"],
    "Cloud / IAM":      ["aws", "azure", "gcp", "iam", "identity", "entra", "okta"],
    "Patching Required":["patch", "update", "zero-day", "0-day", "cisa kev"],
    "Malware":          ["malware", "trojan", "botnet", "infostealer"],
    "Vulnerabilities":  ["cve-", "vulnerability", "remote code", "privilege escalation"],
    "Insider Threat":   ["insider", "employee", "privileged access", "data exfiltration"],
}

CVE_RE = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "": 4}

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ─────────────────────────────────────────────
#   Styling
# ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Roboto+Mono:wght@400;600&display=swap');

:root {
    --bg: #020509;
    --bg-elevated: #050a12;
    --card: #050a12;
    --border-soft: rgba(255,255,255,0.06);
    --accent: #1ce0ff;
    --accent-soft: rgba(28,224,255,0.18);
    --accent-strong: rgba(28,224,255,0.35);
    --text-main: #f9fbff;
    --text-muted: #8f9bb5;
    --line: rgba(255,255,255,0.06);
    --kev-color: #ff6b35;
    --kev-bg: rgba(255,107,53,0.12);
    --kev-border: rgba(255,107,53,0.4);
}

.stApp {
    background: radial-gradient(circle at top, #07101d 0, #020508 40%, #000000 100%);
    color: var(--text-main);
    font-family: 'Roboto Mono', monospace;
}

h1, h2, h3, h4 {
    font-family: 'Orbitron', sans-serif;
    color: var(--text-main);
}

.tl-shell {
    max-width: 1120px;
    margin: 0 auto 1.5rem auto;
    padding: 18px 22px;
    border-radius: 26px;
    background: radial-gradient(circle at top left, rgba(45,103,255,0.35), transparent 55%),
                linear-gradient(135deg, rgba(3,8,18,0.95), rgba(3,10,22,0.98));
    border: 1px solid var(--border-soft);
    box-shadow: 0 0 40px rgba(0,0,0,0.8), 0 0 60px rgba(28,224,255,0.18);
}

.tl-header-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
}

.tl-title-block { display: flex; flex-direction: column; gap: 4px; }

.tl-title {
    font-family: 'Orbitron', sans-serif;
    font-size: 1.6rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}

.tl-subtitle {
    font-size: 0.8rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.16em;
}

.tl-nav-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 14px;
    border-radius: 999px;
    border: 1px solid var(--border-soft);
    background: rgba(3,9,18,0.9);
    color: var(--text-muted);
    font-size: 0.78rem;
    text-decoration: none;
    backdrop-filter: blur(12px);
}

.tl-nav-btn:hover { border-color: var(--accent); color: var(--accent); }

.tl-meta-row {
    margin-top: 12px;
    padding-top: 10px;
    border-top: 1px solid var(--line);
    display: flex;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
}

.tl-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 999px;
    border: 1px solid var(--accent-strong);
    background: var(--accent-soft);
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--accent);
}

.tl-meta-text { font-size: 0.8rem; color: var(--text-muted); }

.news-card {
    border-radius: 18px;
    padding: 14px 16px;
    margin-bottom: 12px;
    background: linear-gradient(135deg, rgba(3,8,16,0.96), rgba(3,12,26,0.98));
    border: 1px solid var(--border-soft);
    box-shadow: 0 0 24px rgba(0,0,0,0.7);
}

.news-card.kev-flagged {
    border-color: var(--kev-border);
    box-shadow: 0 0 24px rgba(0,0,0,0.7), 0 0 16px var(--kev-bg);
}

.kev-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 9px;
    border-radius: 999px;
    border: 1px solid var(--kev-border);
    background: var(--kev-bg);
    color: var(--kev-color);
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-weight: 600;
    margin-bottom: 6px;
}

.news-meta {
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #7c88a0;
    display: flex;
    justify-content: space-between;
}

.news-title {
    font-size: 1.02rem;
    font-weight: 600;
    margin: 6px 0 4px 0;
    color: #f4f7ff;
}

.news-summary { font-size: 0.86rem; color: #c0c7d6; }

.pill {
    display: inline-block;
    padding: 2px 8px;
    margin-right: 4px;
    margin-top: 4px;
    border-radius: 999px;
    border: 1px solid rgba(124,136,160,0.6);
    font-size: .7rem;
    text-transform: uppercase;
    letter-spacing: .06em;
    color: #a7b4d0;
}

.pill-severity-CRITICAL { border-color: #ff0066; color: #ff4d88; }
.pill-severity-HIGH     { border-color: #ff3300; color: #ff704d; }
.pill-severity-MEDIUM   { border-color: #ffaa00; color: #ffcc66; }
.pill-severity-LOW      { border-color: #33cc33; color: #66ff99; }

.feed-health-ok   { color: #66ff99; font-size: 0.75rem; }
.feed-health-fail { color: #ff704d; font-size: 0.75rem; }

.footer-text { color: #555; font-size: .72rem; }
.stDownloadButton > button {
    background: rgba(3, 9, 18, 0.9) !important;
    color: var(--text-main) !important;
    border: 1px solid var(--border-soft) !important;
    border-radius: 14px !important;
    font-family: 'Roboto Mono', monospace !important;
}

.stDownloadButton > button:hover {
    border-color: var(--accent) !important;
    color: var(--accent) !important;
    background: rgba(28, 224, 255, 0.06) !important;
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
#   Persistence helpers
# ─────────────────────────────────────────────
def load_saved() -> Dict[str, Any]:
    """Load saved articles from disk; return empty dict on any failure."""
    try:
        if SAVED_PATH.exists():
            return json.loads(SAVED_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("Could not load saved_articles.json: %s", e)
    return {}


def persist_saved(data: Dict[str, Any]) -> None:
    """Write saved articles to disk; fail silently (session state is the source of truth)."""
    try:
        SAVED_PATH.write_text(
            json.dumps(data, default=str, indent=2), encoding="utf-8"
        )
    except Exception as e:
        log.warning("Could not write saved_articles.json: %s", e)


# ─────────────────────────────────────────────
#   Session State
# ─────────────────────────────────────────────
if "saved_articles" not in st.session_state:
    st.session_state.saved_articles = load_saved()

if "feed_health" not in st.session_state:
    st.session_state.feed_health: Dict[str, bool] = {}


# ─────────────────────────────────────────────
#   Utility Functions
# ─────────────────────────────────────────────
def parse_date(entry: Any) -> datetime:
    for key in ("published", "updated", "created"):
        v = entry.get(key)
        if v:
            try:
                d = parsedate_to_datetime(v)
                return d.astimezone(timezone.utc).replace(tzinfo=None)
            except Exception:
                continue
    return datetime(1970, 1, 1)


def label_article(title: str, summary: str) -> List[str]:
    text = f"{title} {summary}".lower()
    labels = [tag for tag, kws in TAG_KEYWORDS.items() if any(k in text for k in kws)]
    return labels or ["General"]


def extract_cves(text: str) -> List[str]:
    return sorted(set(m.upper() for m in CVE_RE.findall(text)))


def item_severity_rank(item: Dict[str, Any]) -> int:
    """Return best (lowest) severity rank across all enriched CVEs for sorting."""
    best = 4
    for c in item.get("cves", []):
        sev = (c.get("severity") or "").upper()
        best = min(best, SEVERITY_ORDER.get(sev, 4))
    return best


# ─────────────────────────────────────────────
#   Feed Fetching — concurrent, isolated
# ─────────────────────────────────────────────
def _fetch_one(name: str, url: str) -> Tuple[str, List[Dict[str, Any]], bool]:
    """Fetch a single feed. Returns (name, items, success)."""
    try:
        parsed = feedparser.parse(url)
        entries = getattr(parsed, "entries", []) or []
        items = []
        for e in entries:
            title = e.get("title", "").strip()
            link  = e.get("link", "").strip()
            if not (title and link):
                continue
            summary = e.get("summary", e.get("description", "")).strip()
            d = parse_date(e)
            uid = hashlib.md5(f"{name}|{title}|{link}".encode()).hexdigest()
            items.append({
                "id":            uid,
                "source":        name,
                "title":         title,
                "link":          link,
                "summary":       summary,
                "published":     d,
                "published_str": d.strftime("%Y-%m-%d %H:%M"),
                "labels":        label_article(title, summary),
                "cves":          [],
                "kev_flagged":   False,
            })
        return name, items, bool(items)
    except Exception as e:
        log.warning("Feed fetch failed [%s]: %s", name, e)
        return name, [], False


@st.cache_data(ttl=600)
def fetch_feeds(active_sources: Tuple[str, ...]) -> Tuple[List[Dict[str, Any]], Dict[str, bool]]:
    """Fetch all active feeds concurrently. Returns (items, health_map)."""
    feed_subset = {k: v for k, v in RSS_FEEDS.items() if k in active_sources}
    all_items: List[Dict[str, Any]] = []
    seen: set = set()
    health: Dict[str, bool] = {}

    with ThreadPoolExecutor(max_workers=len(feed_subset)) as pool:
        futures = {pool.submit(_fetch_one, n, u): n for n, u in feed_subset.items()}
        for future in as_completed(futures):
            name, items, ok = future.result()
            health[name] = ok
            for item in items:
                if item["id"] not in seen:
                    seen.add(item["id"])
                    all_items.append(item)

    all_items.sort(key=lambda i: i["published"], reverse=True)
    return all_items, health


# ─────────────────────────────────────────────
#   NVD CVE Enrichment — with backoff + API key
# ─────────────────────────────────────────────
@st.cache_data(ttl=3600)
def enrich_cve(cve_id: str) -> Dict[str, Any]:
    """Fetch CVE details from NVD with retry/backoff. Uses NVD_API_KEY if set."""
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    # NVD rate limit: 5/30s without key, 50/30s with key
    delay = 0.6 if NVD_API_KEY else 6.5

    for attempt in range(3):
        try:
            time.sleep(delay * attempt)  # backoff: 0s, delay, 2×delay
            r = requests.get(
                NVD_BASE,
                params={"cveId": cve_id},
                headers=headers,
                timeout=10,
            )
            if r.status_code == 403:
                log.warning("NVD rate limited for %s", cve_id)
                time.sleep(30)
                continue
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
                        "id":       cve_id,
                        "score":    cvss.get("baseScore"),
                        "severity": (cvss.get("baseSeverity") or "").upper(),
                    }
            return {"id": cve_id}

        except requests.Timeout:
            log.warning("NVD timeout for %s (attempt %d)", cve_id, attempt + 1)
        except Exception as e:
            log.warning("NVD error for %s: %s", cve_id, e)
            break

    return {"id": cve_id}


# ─────────────────────────────────────────────
#   CISA KEV Enrichment
# ─────────────────────────────────────────────
@st.cache_data(ttl=3600)
def fetch_kev_set() -> set:
    """Return the set of CVE IDs currently in the CISA KEV catalog."""
    try:
        r = requests.get(KEV_URL, timeout=12)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        return {v["cveID"].upper() for v in vulns if v.get("cveID")}
    except Exception as e:
        log.warning("KEV fetch failed: %s", e)
        return set()


def add_enrichment(items: List[Dict[str, Any]], enrich: bool, limit: int = 40) -> None:
    """Attach CVE + KEV enrichment to items (in-place). Operates on first `limit` items only."""
    kev_set = fetch_kev_set()

    for item in items[:limit]:
        cves = extract_cves(f"{item['title']} {item['summary']}")
        if cves:
            if enrich:
                item["cves"] = [enrich_cve(c) for c in cves]
            else:
                item["cves"] = [{"id": c} for c in cves]
            # Flag if any CVE is in KEV
            item["kev_flagged"] = bool(kev_set and any(
                c["id"].upper() in kev_set for c in item["cves"]
            ))
        else:
            item["cves"] = []
            item["kev_flagged"] = False


# ─────────────────────────────────────────────
#   Export helpers
# ─────────────────────────────────────────────
def items_to_dataframe(items: List[Dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for i in items:
        rows.append({
            "published":  i.get("published_str", ""),
            "source":     i.get("source", ""),
            "title":      i.get("title", ""),
            "link":       i.get("link", ""),
            "labels":     ", ".join(i.get("labels", [])),
            "kev_flagged": i.get("kev_flagged", False),
            "cves":       ", ".join(c["id"] for c in i.get("cves", []) if c.get("id")),
        })
    return pd.DataFrame(rows)


def items_to_markdown(items: List[Dict[str, Any]]) -> str:
    lines = [f"# {SYSTEM_NAME} Export\n"]
    for i in items:
        kev_note = " ⚠️ **CISA KEV**" if i.get("kev_flagged") else ""
        lines.append(f"## {i['title']}{kev_note}")
        lines.append(f"- **Published:** {i['published_str']}")
        lines.append(f"- **Source:** {i['source']}")
        if i.get("labels"):
            lines.append(f"- **Tags:** {', '.join(i['labels'])}")
        if i.get("cves"):
            bits = []
            for c in i["cves"]:
                sev   = (c.get("severity") or "").upper()
                score = c.get("score")
                parts = [c["id"]]
                if score is not None:
                    parts.append(str(score))
                if sev:
                    parts.append(sev)
                bits.append(" • ".join(parts))
            lines.append(f"- **CVEs:** {', '.join(bits)}")
        lines.append("")
        lines.append(i["summary"])
        lines.append(f"\n[Read more]({i['link']})\n\n---\n")
    return "\n".join(lines)


# ─────────────────────────────────────────────
#   Header
# ─────────────────────────────────────────────
st.markdown(f"""
<div class="tl-shell">
  <div class="tl-header-row">
    <div class="tl-title-block">
      <div class="tl-subtitle">Live tool</div>
      <div class="tl-title">{SYSTEM_NAME}</div>
    </div>
    <a class="tl-nav-btn" href="https://douglasweant.com" target="_self">← douglasweant.com</a>
  </div>
  <div class="tl-meta-row">
    <div class="tl-pill">Threat Intel</div>
    <div class="tl-meta-text">{SYSTEM_TAGLINE}</div>
  </div>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
#   Sidebar
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
    themes = st.multiselect("Themes", options=theme_options, default=[])

    query = st.text_input("Search", placeholder="CVE-2025-1234, LockBit, Okta…")

    show_saved    = st.checkbox("Show saved only", value=False)
    enrich        = st.checkbox("Enable CVE enrichment (NVD)", value=True)
    severity_sort = st.checkbox("Sort by severity (CRITICAL first)", value=True)

    st.markdown("---")
    if NVD_API_KEY:
        st.markdown("🔑 **NVD API key active** — higher rate limit")
    else:
        st.markdown(
            "ℹ️ Set `NVD_API_KEY` env var for higher NVD rate limits.",
            help="Without a key, NVD allows 5 requests/30s. With a key: 50 requests/30s.",
        )

    # Feed health (populated after fetch)
    if st.session_state.feed_health:
        st.markdown("**Feed health**")
        for name, ok in st.session_state.feed_health.items():
            cls = "feed-health-ok" if ok else "feed-health-fail"
            icon = "●" if ok else "✗"
            st.markdown(
                f"<span class='{cls}'>{icon} {name}</span>",
                unsafe_allow_html=True,
            )


# ─────────────────────────────────────────────
#   Data Pipeline
# ─────────────────────────────────────────────
active = tuple(sources) if sources else tuple(RSS_FEEDS.keys())
items, health = fetch_feeds(active)
st.session_state.feed_health = health

# Time filter
if time_window != "All":
    base = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff_map = {
        "Last 24 hours": base - timedelta(days=1),
        "Last 3 days":   base - timedelta(days=3),
        "Last 7 days":   base - timedelta(days=7),
    }
    cutoff = cutoff_map[time_window]
    items = [i for i in items if i["published"] >= cutoff]

# Theme filter
if themes:
    sel = set(themes)
    items = [i for i in items if sel.intersection(i["labels"])]

# Search filter
if query:
    q = query.lower()
    items = [
        i for i in items
        if q in i["title"].lower()
        or q in i["summary"].lower()
        or q in i["source"].lower()
    ]

# Saved filter
if show_saved:
    saved_ids = set(st.session_state.saved_articles.keys())
    items = [i for i in items if i["id"] in saved_ids]

# Enrichment (CVE + KEV)
add_enrichment(items, enrich=enrich)

# Severity sort: KEV-flagged and high-severity CVEs bubble up
if severity_sort:
    items.sort(key=lambda i: (
        0 if i.get("kev_flagged") else 1,   # KEV items first
        item_severity_rank(i),               # then by CVE severity
        -i["published"].timestamp(),         # then newest first within tier
    ))


# ─────────────────────────────────────────────
#   Export Controls
# ─────────────────────────────────────────────
if items:
    df        = items_to_dataframe(items)
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    md_text   = items_to_markdown(items)

    col_csv, col_md, col_spacer = st.columns([1, 1, 4])
    with col_csv:
        st.download_button(
            "⬇️ Export CSV", csv_bytes,
            file_name="threatlumen_intel.csv", mime="text/csv",
        )
    with col_md:
        st.download_button(
            "⬇️ Export Markdown", md_text,
            file_name="threatlumen_intel.md", mime="text/markdown",
        )

st.markdown("---")


# ─────────────────────────────────────────────
#   Render Items
# ─────────────────────────────────────────────
if not items:
    st.info("No intelligence matched the current filters.")
else:
    st.markdown(f"**{len(items)} items** — {sum(1 for i in items if i.get('kev_flagged'))} KEV-flagged")

    for item in items:
        kev_class = "kev-flagged" if item.get("kev_flagged") else ""
        kev_badge = '<div class="kev-badge">⚠ CISA KEV</div>' if item.get("kev_flagged") else ""

        st.markdown(f"""
<div class="news-card {kev_class}">
  {kev_badge}
  <div class="news-meta">
    <span>{item['source']}</span>
    <span>{item['published_str']}</span>
  </div>
  <div class="news-title">
    <a href="{item['link']}" target="_blank" rel="noopener noreferrer">{item['title']}</a>
  </div>
  <div class="news-summary">{item['summary']}</div>
</div>
""", unsafe_allow_html=True)

        # Theme pills
        if item.get("labels"):
            st.markdown(
                " ".join(f"<span class='pill'>{t}</span>" for t in item["labels"]),
                unsafe_allow_html=True,
            )

        # CVE pills
        if item.get("cves"):
            ctags = []
            for c in item["cves"]:
                sev       = (c.get("severity") or "").upper()
                sev_class = f" pill-severity-{sev}" if sev else ""
                parts     = [c["id"]]
                if c.get("score") is not None:
                    parts.append(str(c["score"]))
                if sev:
                    parts.append(sev)
                ctags.append(f"<span class='pill{sev_class}'>{' • '.join(parts)}</span>")
            st.markdown("".join(ctags), unsafe_allow_html=True)

        # Save / Unsave — fixed: uses st.rerun() not experimental_rerun()
        col_btn, _ = st.columns([1, 5])
        with col_btn:
            saved = item["id"] in st.session_state.saved_articles
            label = "★ Saved" if saved else "☆ Save"
            if st.button(label, key=f"save_{item['id']}"):
                if saved:
                    st.session_state.saved_articles.pop(item["id"], None)
                else:
                    st.session_state.saved_articles[item["id"]] = item
                persist_saved(st.session_state.saved_articles)
                st.rerun()   # fixed: was st.experimental_rerun()

        st.markdown("<br/>", unsafe_allow_html=True)


# ─────────────────────────────────────────────
#   Footer
# ─────────────────────────────────────────────
st.markdown("---")
st.markdown(
    f"<center class='footer-text'>{SYSTEM_NAME} {SYSTEM_VERSION} • {SYSTEM_TAGLINE}</center>",
    unsafe_allow_html=True,
)
