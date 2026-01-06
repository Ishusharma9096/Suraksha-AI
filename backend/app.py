import os
import re
import pickle
import math
from collections import Counter
from datetime import datetime

from flask import Flask, request, jsonify
from flask_cors import CORS
from google import genai

# ----------------- Flask App -----------------
app = Flask(__name__)
CORS(app)

# ----------------- Gemini -----------------
GENAI_API_KEY = os.getenv("GENAI_API_KEY")
if not GENAI_API_KEY:
    raise RuntimeError("GENAI_API_KEY not set")

client = genai.Client(api_key=GENAI_API_KEY)

# Pick a model
GEMINI_MODEL = "models/gemini-1.5-flash"

# ----------------- Load ML Model -----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(BASE_DIR, "model.pkl"), "rb") as f:
    model = pickle.load(f)

with open(os.path.join(BASE_DIR, "vectorizer.pkl"), "rb") as f:
    vectorizer = pickle.load(f)

# ----------------- Language Map -----------------
LANGUAGE_MAP = {
    "en": "English",
    "hi": "Hindi",
    "ta": "Tamil",
    "mni": "Manipuri"
}

# ----------------- Helpers -----------------
def calculate_entropy(data):
    if not data:
        return 0
    freq = Counter(data)
    entropy = 0
    for c in freq.values():
        p = c / len(data)
        entropy -= p * math.log2(p)
    return round(entropy, 2)

# ----------------- Gemini Explain -----------------
def gemini_explain(prompt, language):
    try:
        lang = LANGUAGE_MAP.get(language, "English")
        final_prompt = f"""
Respond ONLY in {lang}.
Keep it short (2–3 lines).
Do not mention AI or models.

{prompt}
"""
        res = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=final_prompt
        )
        return res.text.strip()
    except Exception:
        return "Explanation unavailable."

# ----------------- Routes -----------------
@app.route("/")
def home():
    return "✅ SurakshaAI backend running"

# ================= PHISHING =================
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    message = data.get("message", "").strip()
    language = data.get("language", "en")

    if not message:
        return jsonify({"error": "Message required"}), 400

    text = message.lower()

    signals = {
        "suspicious_link": bool(re.search(r"https?://", text)),
        "email_address_present": bool(re.search(r"@", text)),
        "urgent_language": any(w in text for w in ["urgent", "verify", "immediately"]),
        "impersonation": any(w in text for w in ["bank", "paypal", "amazon", "government"]),
        "credential_request": any(w in text for w in ["otp", "password", "login"])
    }

    score = sum(signals.values())
    X = vectorizer.transform([message])
    ml_pred = model.predict(X)[0]

    if ml_pred == "Dangerous":
        score += 3
    elif ml_pred == "Suspicious":
        score += 1

    if score >= 4:
        risk = "Dangerous"
        confidence = 90
    elif score >= 2:
        risk = "Suspicious"
        confidence = 65
    else:
        risk = "Safe"
        confidence = 30

    explanation = gemini_explain(
        f"""
Message: {message}
Verdict: {risk}
Confidence: {confidence}%
Indicators: {', '.join(k for k,v in signals.items() if v)}
""",
        language
    )

    return jsonify({
        "risk": risk,
        "confidence": confidence,
        "phishing_signals": signals,
        "ai_explanation": explanation,
        "recommended_action":
            "Do not click links or respond." if risk == "Dangerous"
            else "Verify sender before responding.",
        "scan_metadata": {
            "scan_id": f"PHISH-{os.urandom(4).hex().upper()}",
            "engine": "Suraksha-Phish-ML",
            "timestamp_utc": datetime.utcnow().isoformat()+"Z"
        }
    })

# ================= FILE / MALWARE =================
@app.route("/scan-file", methods=["POST"])
def scan_file():
    file = request.files.get("file")
    language = request.form.get("language", "en")

    if not file:
        return jsonify({"error": "No file"}), 400

    data = file.read()
    entropy = calculate_entropy(data)

    if entropy > 7.6:
        score, verdict = 90, "Malware"
    elif entropy > 6.8:
        score, verdict = 60, "Suspicious"
    else:
        score, verdict = 20, "Clean"

    explanation = gemini_explain(
        f"""
File entropy: {entropy}
Verdict: {verdict}
Risk score: {score}%
""",
        language
    )

    return jsonify({
        "file_name": file.filename,
        "entropy": entropy,
        "score": score,
        "verdict": verdict,
        "ai_explanation": explanation,
        "scan_metadata": {
            "scan_id": f"MAL-{os.urandom(4).hex().upper()}",
            "engine": "Suraksha-Malware",
            "timestamp_utc": datetime.utcnow().isoformat()+"Z"
        }
    })

# ----------------- Run -----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

