"""Security Log Analyzer: upload an auth log, detect suspicious activity, get an AI summary."""
import os
import re
import sqlite3
from collections import defaultdict

from fastapi import FastAPI, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Security Log Analyzer")
DB = "alerts.db"
FAILED_THRESHOLD = 5  # failed logins from one IP before we raise an alert

# Matches lines like: "Failed password for root from 10.0.0.5 port 22 ssh2"
FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
INVALID_USER_RE = re.compile(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)")


def analyze(text: str) -> list[dict]:
    """Detect brute force attempts and username guessing from log text."""
    failed = defaultdict(int)
    users_tried = defaultdict(set)
    for line in text.splitlines():
        m = FAILED_RE.search(line)
        if m:
            user, ip = m.groups()
            failed[ip] += 1
            users_tried[ip].add(user)
        m = INVALID_USER_RE.search(line)
        if m:
            user, ip = m.groups()
            users_tried[ip].add(user)

    alerts = []
    for ip, count in failed.items():
        if count >= FAILED_THRESHOLD:
            alerts.append({"ip": ip, "type": "Brute force", "count": count,
                           "severity": "High" if count >= 20 else "Medium"})
    for ip, users in users_tried.items():
        if len(users) >= 4:
            alerts.append({"ip": ip, "type": "Username guessing", "count": len(users),
                           "severity": "Medium"})
    return sorted(alerts, key=lambda a: a["count"], reverse=True)


def save_alerts(alerts: list[dict]) -> None:
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS alerts (ip TEXT, type TEXT, count INT, severity TEXT)")
    con.executemany("INSERT INTO alerts VALUES (:ip, :type, :count, :severity)", alerts)
    con.commit()
    con.close()


def ai_summary(alerts: list[dict]) -> str:
    """Ask Claude to explain the alerts. Falls back to a plain summary without an API key."""
    if not alerts:
        return "No suspicious activity found."
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        return (f"{len(alerts)} alert(s) found. Set ANTHROPIC_API_KEY to get an AI explanation. "
                "Suggested action: block the listed IPs and enable fail2ban.")
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=key)
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=500,
            messages=[{"role": "user", "content":
                       "You are a SOC analyst. Explain these alerts in simple words and give "
                       f"3 concrete actions:\n{alerts}"}],
        )
        return msg.content[0].text
    except Exception as e:  # keep the demo alive even if the API fails
        return f"AI summary unavailable: {e}"


@app.post("/upload")
async def upload(file: UploadFile):
    text = (await file.read()).decode("utf-8", errors="ignore")
    alerts = analyze(text)
    if alerts:
        save_alerts(alerts)
    return {"alerts": alerts, "summary": ai_summary(alerts)}


@app.get("/")
def home():
    return FileResponse("static/index.html")


app.mount("/static", StaticFiles(directory="static"), name="static")
