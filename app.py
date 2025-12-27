import streamlit as st
import feedparser
from datetime import datetime
import time

# --- Page Configuration ---
st.set_page_config(
    page_title="CyberPulse | Real-Time Threat Intel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- Custom CSS (Cyberpunk Aesthetic) ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Roboto+Mono:wght@400;600&display=swap');

    /* Global Styles */
    .stApp {
        background-color: #050505;
        background-image: radial-gradient(#111 1px, transparent 1px);
        background-size: 20px 20px;
        color: #e0e0e0;
        font-family: 'Roboto Mono', monospace;
    }
    
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Orbitron', sans-serif;
        color: #00ffcc; /* Neon Cyan */
        text-shadow: 0 0 10px rgba(0, 255, 204, 0.7);
    }
    
    a {
        color: #00ffcc;
        text-decoration: none;
        transition: all 0.3s ease;
    }
    a:hover {
        color: #ff00ff; /* Neon Pink */
        text-shadow: 0 0 8px rgba(255, 0, 255, 0.8);
    }

    /* Card Styling */
    .news-card {
        background: rgba(20, 20, 20, 0.8);
        border: 1px solid #333;
        border-left: 4px solid #00ffcc;
        padding: 20px;
        margin-bottom: 20px;
        border-radius: 5px;
        transition: transform 0.2s ease, box-shadow 0.2s ease;
        backdrop-filter: blur(5px);
    }
    
    .news-card:hover {
        transform: translateX(5px);
        box-shadow: -5px 5px 15px rgba(0, 255, 204, 0.2);
        border-left-color: #ff00ff;
    }

    .news-source {
        font-size: 0.8em;
        color: #888;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 5px;
    }
    
    .news-date {
        font-size: 0.8em;
        color: #666;
        float: right;
    }

    .news-title {
        font-size: 1.4em;
        font-weight: 700;
        margin: 10px 0;
        color: #fff;
    }
    
    .news-summary {
        font-size: 0.95em;
        color: #ccc;
        line-height: 1.5;
        margin-bottom: 15px;
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #0a0a0a;
        border-right: 1px solid #333;
    }
    
    /* Search Bar */
    .stTextInput input {
        background-color: #111;
        color: #00ffcc;
        border: 1px solid #333;
        font-family: 'Roboto Mono', monospace;
    }
    .stTextInput input:focus {
        border-color: #00ffcc;
        box-shadow: 0 0 5px rgba(0, 255, 204, 0.5);
    }

    /* Button Styling */
    .stButton button {
        background-color: transparent;
        border: 1px solid #00ffcc;
        color: #00ffcc;
        font-family: 'Orbitron', sans-serif;
        text-transform: uppercase;
        transition: all 0.3s;
    }
    .stButton button:hover {
        background-color: #00ffcc;
        color: #000;
        box-shadow: 0 0 15px rgba(0, 255, 204, 0.8);
    }
    
    /* Scrollbar */
    ::-webkit-scrollbar {
        width: 10px;
        background: #000;
    }
    ::-webkit-scrollbar-thumb {
        background: #333;
        border-radius: 5px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #00ffcc;
    }
</style>
""", unsafe_allow_html=True)

# --- Configuration & State ---
RSS_FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss/all.xml",
    "Bleeping Computer": "https://www.bleepingcomputer.com/feed/",
    "Threatpost": "https://threatpost.com/feed/",
    "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "Schneier on Security": "https://www.schneier.com/feed/atom/"
}

if 'news_data' not in st.session_state:
    st.session_state.news_data = []
if 'saved_articles' not in st.session_state:
    st.session_state.saved_articles = []
if 'last_updated' not in st.session_state:
    st.session_state.last_updated = None

# --- Helper Functions ---
def parse_date(entry):
    """Attempt to parse date from common RSS formats."""
    if hasattr(entry, 'published_parsed') and entry.published_parsed:
        return datetime(*entry.published_parsed[:6])
    elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
        return datetime(*entry.updated_parsed[:6])
    return datetime.now() # Fallback

def save_article(news_item):
    """Saves an article to the session state if not duplicate."""
    if not any(a['link'] == news_item['link'] for a in st.session_state.saved_articles):
        st.session_state.saved_articles.append(news_item)
        st.toast(f"Scoped: {news_item['title']} to database.", icon="💾")
    else:
        st.toast("Duplicate intel already in database.", icon="⚠️")

def remove_article(link):
    """Removes an article from saved list."""
    st.session_state.saved_articles = [a for a in st.session_state.saved_articles if a['link'] != link]
    st.rerun()

def fetch_feed_data():
    """Fetches and parses RSS feeds."""
    all_news = []
    
    with st.spinner('Scanning the grid for cached intel...'):
        progress_bar = st.progress(0)
        total_feeds = len(RSS_FEEDS)
        
        for idx, (source_name, url) in enumerate(RSS_FEEDS.items()):
            try:
                feed = feedparser.parse(url)
                for entry in feed.entries[:10]: # Limit to top 10 per feed
                    all_news.append({
                        'source': source_name,
                        'title': entry.title,
                        'link': entry.link,
                        'published': parse_date(entry),
                        'summary': entry.summary if hasattr(entry, 'summary') else (entry.description if hasattr(entry, 'description') else "No summary available."),
                    })
            except Exception as e:
                st.error(f"Failed to decrypt feed from {source_name}: {e}")
            
            progress_bar.progress((idx + 1) / total_feeds)
            
    # Sort by newest first
    all_news.sort(key=lambda x: x['published'], reverse=True)
    
    st.session_state.news_data = all_news
    st.session_state.last_updated = datetime.now()
    # time.sleep(0.5) # Aesthetic delay
    progress_bar.empty()

# --- Main Layout ---
col1, col2 = st.columns([3, 1])
with col1:
    st.title("CYBER // PULSE")
    st.markdown("### > REAL-TIME THREAT INTELLIGENCE AGGREGATOR")

with col2:
    st.markdown(f"<div style='text-align: right; padding-top: 20px; color: #00ffcc;'>STATUS: ONLINE<br>{st.session_state.last_updated.strftime('%H:%M:%S') if st.session_state.last_updated else 'OFFLINE'}</div>", unsafe_allow_html=True)
    if st.button("REFRESH FEED"):
        fetch_feed_data()
        st.rerun()

# --- Sidebar: Saved Intel ---
with st.sidebar:
    st.title("💾 SAVED INTEL")
    if not st.session_state.saved_articles:
        st.caption("No artifacts secured.")
    else:
        for saved in st.session_state.saved_articles:
            st.markdown(f"**[{saved['title']}]({saved['link']})**")
            st.caption(f"Source: {saved['source']}")
            if st.button("DELETE", key=f"del_{saved['link']}"):
                remove_article(saved['link'])
            st.markdown("---")

# Initial Load
if not st.session_state.news_data:
    fetch_feed_data()

# --- Search & Filter ---
st.markdown("---")
search_query = st.text_input("", placeholder="> SEARCH DATABASE_")

# --- News Feed Render ---
count = 0
for news in st.session_state.news_data:
    if search_query.lower() in news['title'].lower() or search_query.lower() in news['summary'].lower() or search_query.lower() in news['source'].lower():
        
        # Format date
        date_str = news['published'].strftime("%Y-%m-%d %H:%M")
        
        # Clean summary (remove HTML tags if simple)
        # For this prototype we leave HTML rendered or strip it depending on preference.
        # Streamlit markdown allows html, so we attempt to render safely or just truncate.
        summary_text = news['summary'].split('<')[0][:200] + "..." # Naive cleanup for cleaner look
        
        st.markdown(f"""
        <div class="news-card">
            <div class="news-source">{news['source']} <span class="news-date">[{date_str}]</span></div>
            <div class="news-title"><a href="{news['link']}" target="_blank">{news['title']}</a></div>
            <div class="news-summary">{summary_text}</div>
            <a href="{news['link']}" target="_blank" style="font-size: 0.8em; font-weight: bold; margin-right: 10px;">> READ_FULL_REPORT</a>
        </div>
        """, unsafe_allow_html=True)
        
        # Action Buttons
        if st.button("SAVE DATABASE", key=f"save_{news['link']}"):
            save_article(news)
        
        st.markdown("<div style='margin-bottom: 20px;'></div>", unsafe_allow_html=True)
        count += 1
        
if count == 0:
    st.info("No intelligence found matching query.")

# --- Footer ---
st.markdown("---")
st.markdown("<center><span style='color: #444;'>SYSTEM_VERSION: 1.0.0 | ENCRYPTED CONNECTION</span></center>", unsafe_allow_html=True)
