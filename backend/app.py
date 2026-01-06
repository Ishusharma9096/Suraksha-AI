import os
import re
import pickle
import math
from collections import Counter
from datetime import datetime

from flask import Flask, request, jsonify
from flask_cors import CORS

# ----------------- Gemini (GenAI) -----------------
from google import genai

# ----------------- Flask App -----------------
app = Flask(__name__)
CORS(app)

# ----------------- Gemini Key -----------------
GENAI_API_KEY = os.getenv("GENAI_API_KEY")
if not GENAI_API_KEY:
    raise RuntimeError("❌ GENAI_API_KEY environment variable not set")

client = genai.Client(api_key=GENAI_API_KEY)

# ----------------- Pick Gemini Model -----------------
GEMINI_MODEL = None
for m in client.models.list():
    if any(k in m.name.lower() for k in ["flash", "pro", "2.5"]):
        GEMINI_MODEL = m.name
        break

if not GEMINI_MODEL:
    raise RuntimeError("❌ No suitable Gemini model found")

print(f"✅ Using Gemini model: {GEMINI_MODEL}")

# ----------------- Load ML Model -----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(BASE_DIR, "model.pkl"), "rb") as f:
    model = pickle.load(f)

with open(os.path.join(BASE_DIR, "vectorizer.pkl"), "rb") as f:
    vectorizer = pickle.load(f)

print("✅ ML model & vectorizer loaded")

# ----------------- Language Map -----------------
LANGUAGE_MAP = {
    "en": "English",
    "hi": "Hindi",
    "ta": "Tamil",
    "mni": "Manipuri"
}

# ----------------- Helpers -----------------
def calculate_entropy(file_bytes):
    if not file_bytes:
        return 0
    counts = Counter(file_bytes)
    entropy = 0
    for count in counts.values():
        p = count / len(file_bytes)
        entropy -= p * math.log2(p)
    return round(entropy, 2)


# ----------------- Gemini: File / Malware Explain -----------------
def gemini_explain_file(entropy, risk_score, verdict, language="en"):
    try:
        lang_name = LANGUAGE_MAP.get(language, "English")

        prompt = f"""
You are a cybersecurity expert.

IMPORTANT:
- Respond ONLY in {lang_name}
- Keep the explanation simple (2–3 lines)
- Do NOT mention AI, ML, models, or internal systems

Analysis Result:
Entropy: {entropy}
Risk Score: {risk_score}
Verdict: {verdict}
"""
        res = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt
        )
        return res.text.strip()

    except Exception as e:
        print("Gemini error:", e)
        return "Explanation unavailable."


# ----------------- Gemini: Phishing Explain -----------------
def gemini_explain_phishing(message, risk, confidence, signals, language="en"):
    try:
        lang_name = LANGUAGE_MAP.get(language, "English")

        prompt = f"""
You are a cybersecurity expert.

IMPORTANT:
- Respond ONLY in {lang_name}
- Keep it simple (2–3 lines)
- Do NOT mention AI, ML, files, entropy, or models

Message:
\"\"\"{message}\"\"\"

Detected indicators:
{', '.join(signals)}

Final Verdict: {risk}
Confidence: {confidence}%
"""
        res = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt
        )
        return res.text.strip()

    except Exception as e:
        print("Gemini phishing error:", e)
        return "Explanation unavailable."


# ----------------- Routes -----------------
@app.route("/")
def home():
    return "✅ SurakshaAI Backend is running!"


# ================= PHISHING ANALYSIS =================
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    message = data.get("message", "").strip()
    language = data.get("language", "en")

    if not message:
        return jsonify({"error": "Message is required"}), 400

    text = message.lower()

    phishing_signals = {
        "suspicious_link": bool(re.search(r"https?://\S+", text)),
        "email_address_present": bool(re.search(r"[\w\.-]+@[\w\.-]+\.\w+", text)),
        "urgent_language": any(w in text for w in ["urgent", "immediately", "act now", "verify now"]),
        "impersonation": any(w in text for w in ["bank", "paypal", "government", "admin", "amazon"]),
        "credential_request": any(w in text for w in ["otp", "password", "login", "verify account"])
    }

    active_signals = [k.replace("_", " ") for k, v in phishing_signals.items() if v]
    score = sum(phishing_signals.values())

    X = vectorizer.transform([message])
    ml_pred = model.predict(X)[0]

    if ml_pred == "Dangerous":
        score += 3
    elif ml_pred == "Suspicious":
        score += 1

    if score >= 4:
        risk = "Dangerous"
        confidence = min(95, 70 + score * 5)
    elif score >= 2:
        risk = "Suspicious"
        confidence = min(85, 55 + score * 5)
    else:
        risk = "Safe"
        confidence = max(30, 85 - score * 10)

    ai_explanation = gemini_explain_phishing(
        message,
        risk,
        confidence,
        active_signals or ["ML-based classification"],
        language
    )

    return jsonify({
        "risk": risk,
        "confidence": confidence,
        "phishing_signals": phishing_signals,
        "ai_explanation": ai_explanation,
        "recommended_action": (
            "Do not click any links or respond. Report and delete this message immediately."
            if risk == "Dangerous"
            else "Verify the sender before responding and avoid sharing sensitive information."
        ),
        "scan_metadata": {
            "scan_id": f"PHISH-{os.urandom(4).hex().upper()}",
            "engine": "Suraksha-Phish-ML v1.0",
            "timestamp_utc": datetime.utcnow().isoformat() + "Z"
        }
    })


# ================= VAULT ANALYSIS =================
@app.route("/vault-analyze", methods=["POST"])
def vault_analyze():
    file = request.files.get("file")
    language = request.form.get("language", "en")

    if not file:
        return jsonify({"error": "No file received"}), 400

    file_bytes = file.read()
    entropy = calculate_entropy(file_bytes)

    if entropy > 7.6:
        risk_score = 85
        verdict = "Malicious"
    elif entropy > 6.6:
        risk_score = 55
        verdict = "Suspicious"
    else:
        risk_score = 20
        verdict = "Safe"

    explanation = gemini_explain_file(entropy, risk_score, verdict, language)

    return jsonify({
        "risk_score": risk_score,
        "verdict": verdict,
        "gemini_explanation": explanation
    })


# ================= MALWARE SCANNER =================
@app.route("/scan-file", methods=["POST"])
def scan_file():
    file = request.files.get("file")
    language = request.form.get("language", "en")

    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    file_bytes = file.read()
    entropy = calculate_entropy(file_bytes)

    if entropy > 7.6:
        risk_score = 90
        verdict = "Malicious"
    elif entropy > 6.8:
        risk_score = 60
        verdict = "Suspicious"
    else:
        risk_score = 20
        verdict = "Clean"

    explanation = gemini_explain_file(entropy, risk_score, verdict, language)

    return jsonify({
        "file_name": file.filename,
        "entropy": entropy,
        "risk_score": risk_score,
        "status": "Complete",
        "verdict": verdict,
        "gemini_explanation": explanation,
        "scan_metadata": {
            "scan_id": f"MAL-{os.urandom(4).hex().upper()}",
            "engine": "Suraksha-Malware-Entropy v1.0",
            "timestamp_utc": datetime.utcnow().isoformat() + "Z"
        }
    })


# ----------------- Run Server -----------------
if __name__ == "__main__":
    print("🚀 Starting SurakshaAI backend on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)

