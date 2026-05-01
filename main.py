import os
import re
import requests
import json as pyjson

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

MIMO_API_KEY = os.getenv("MIMO_API_KEY")
MIMO_BASE_URL = os.getenv("MIMO_BASE_URL")
MIMO_MODEL = os.getenv("MIMO_MODEL")


class MessageRequest(BaseModel):
    message: str


@app.get("/")
def home():
    return {"status": "PhishTriage AI backend running"}


# -------------------------
# BASIC SCAN
# -------------------------
@app.post("/analyze-message")
def analyze_message(data: MessageRequest):
    text = data.message.lower()

    score = 0
    reasons = []

    keywords = ["otp", "bvn", "verify", "login", "bank", "account", "click"]

    for word in keywords:
        if word in text:
            score += 10
            reasons.append(f"Suspicious keyword found: {word}")

    if "http" in text:
        score += 20
        reasons.append("Message contains a link")

    if "urgent" in text or "immediately" in text:
        score += 15
        reasons.append("Uses urgency language")

    if score >= 70:
        risk = "High Risk"
    elif score >= 40:
        risk = "Medium Risk"
    else:
        risk = "Low Risk"

    return {
        "risk": risk,
        "reasons": reasons,
        "advice": "Do not share sensitive details. Verify before acting."
    }


# -------------------------
# ADVANCED AI SCAN (MiMo)
# -------------------------
@app.post("/advanced-ai-scan")
def advanced_ai_scan(data: MessageRequest):
    text = data.message.strip()

    # 🔒 TOKEN CONTROL
    if len(text) < 10:
        return {
            "risk": "Too Short",
            "reasons": ["Message too short for AI analysis"],
            "advice": "Provide more context"
        }

    if len(text) > 500:
        text = text[:500]

    prompt = f"""
You are a cybersecurity assistant for scam detection in Nigeria.

Analyze the message below and respond ONLY in JSON format:

{{
  "risk": "High Risk | Medium Risk | Low Risk",
  "scam_type": "phishing | fraud | impersonation | unknown",
  "reasons": ["reason1", "reason2"],
  "advice": "clear user advice"
}}

Message:
{text}
"""

    try:
        response = requests.post(
            f"{MIMO_BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {MIMO_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": MIMO_MODEL,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3
            }
        )

        raw_text = response.text

        # Try to parse JSON safely
        try:
            data = response.json()
            content = data["choices"][0]["message"]["content"]

            parsed = pyjson.loads(content)

            return parsed

        except Exception as parse_error:
            return {
                "risk": "Parse Error",
                "reasons": [
                    str(parse_error),
                    f"Raw Response: {raw_text}"
                ],
                "advice": "MiMo did not return valid JSON. Adjust prompt or check API."
            }

    except Exception as e:
        return {
            "risk": "Error",
            "reasons": [
                str(e),
                f"Status Code: {response.status_code if 'response' in locals() else 'No response'}",
                f"Raw Response: {response.text if 'response' in locals() else 'No raw response'}"
            ],
            "advice": "AI scan failed. Check API key, model, or base URL."
        }