# CyberPulse – Threat Intel Dashboard

A Streamlit-based dashboard that aggregates multiple security RSS feeds,
deduplicates them into a unified timeline, enriches CVEs from NVD, and
supports filtering, search, and export.

## Local Development

```bash
conda create -n cyberpulse python=3.11 -y
conda activate cyberpulse
pip install -r requirements.txt
export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python
streamlit run app.py
