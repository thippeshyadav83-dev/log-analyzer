# Security Log Analyzer

A small web app that analyzes SSH auth logs, detects brute force attacks and username
guessing, stores alerts in SQLite, and uses an LLM (Claude) to explain the alerts and
suggest actions.

## Tech
Python, FastAPI, SQLite, HTML/JS, pytest, Anthropic API

## Run
```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your_key   # optional; Windows: set ANTHROPIC_API_KEY=your_key
uvicorn app:app --reload
```
Open http://127.0.0.1:8000 and upload `sample_auth.log`.

## Test
```bash
pytest
```

## How it works
1. `analyze()` parses log lines with regex and counts failed logins per IP.
2. IPs over the threshold (5) become alerts; 20+ is High severity.
3. Alerts are saved to SQLite (`alerts.db`).
4. Alerts are sent to an LLM for a plain-language explanation.

## Ideas to extend
Add more rules (port scans, odd-hour logins), Windows event logs, charts, Docker.
