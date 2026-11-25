"""
PhishTriage Scanner (DEPRECATED).

All scanning now lives in PhishTriagePlatform (`POST /analyze`), which also
serves `/analyze-message` and `/advanced-ai-scan` in this same response
format. Keep this service running only until users have updated to app
version 1.1.0 or later, then shut it down.

The MiMo AI integration has been removed; /advanced-ai-scan now returns the
basic scan result.
"""
import re

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


app = FastAPI(title="PhishTriage Scanner (deprecated)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)



class MessageRequest(BaseModel):
    message: str = Field(..., max_length=5000)


@app.get("/")
def home():
    return {
        "status": "PhishTriage AI backend running",
        "deprecated": True,
        "use_instead": "PhishTriagePlatform POST /analyze",
    }


def _has(text: str, word: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])", text) is not None


# -------------------------
# BASIC SCAN
# -------------------------
@app.post("/analyze-message")
def analyze_message(data: MessageRequest):
    text = data.message.lower()
    score = 0
    reasons = []

    for word in ["otp", "bvn", "verify", "login", "bank", "account", "click"]:
        if _has(text, word):
            score += 10
            reasons.append(f"Suspicious keyword found: {word}")

    if "http" in text or "www." in text:
        score += 20
        reasons.append("Message contains a link")

    if _has(text, "urgent") or _has(text, "immediately"):
        score += 15
        reasons.append("Uses urgency language")

    if score >= 70:
        risk = "High Risk"
    elif score >= 40:
        risk = "Medium Risk"
    else:
        risk = "Low Risk"

    return {"risk": risk, "reasons": reasons, "advice": "Do not share sensitive details. Verify before acting."}


# -------------------------
# ADVANCED SCAN
# -------------------------
# The MiMo AI integration has been removed. Old app versions still call this
# endpoint, so it returns the basic scan result.
@app.post("/advanced-ai-scan")
def advanced_ai_scan(data: MessageRequest):
    return analyze_message(data)
