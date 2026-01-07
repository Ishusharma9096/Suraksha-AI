import os, re, pickle, math, time
from collections import Counter
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from google import genai

# ================= FLASK =================
app = Flask(__name__)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# ================= GEMINI =================
GENAI_API_KEY = os.getenv("GENAI_API_KEY")
client = genai.Client(api_key=GENAI_API_KEY) if GENAI_API_KEY else None
GEMINI_MODEL = "models/gemini-2.5-flash"

LAST_GEMINI_CALL = 0
GEMINI_COOLDOWN = 5   # 👈 reduced for judge demo

def gemini_allowed():
    global LAST_GEMINI_CALL
    now = time.time()
    if not client:
        return False
    if now - LAST_GEMINI_CALL < GEMINI_COOLDOWN:
        return False
    LAST_GEMINI_CALL = now
    return True

# ================= ML =================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model = pickle.load(open(os.path.join(BASE_DIR, "model.pkl"), "rb"))
vectorizer = pickle.load(open(os.path.join(BASE_DIR, "vectorizer.pkl"), "rb"))

# ================= LANGUAGE =================
LANGUAGE_MAP = {
    "en": "English",
    "hi": "Hindi",
    "ta": "Tamil",
    "mni": "Manipuri"
}

SAFE_TEXT = {
    "en": "No immediate security threat detected.",
    "hi": "कोई तात्कालिक सुरक्षा खतरा नहीं मिला।",
    "ta": "உடனடி பாதுகாப்பு ஆபத்து இல்லை.",
    "mni": "Immediate security threat ama leitre."
}

# ================= HELPERS =================
def gemini_generate(prompt):
    if not gemini_allowed():
        return None
    try:
        res = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt
        )
        return res.text.strip()
    except:
        return None

# ================= ENTROPY =================
def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0
    counts = Counter(data)
    total = len(data)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())

# ================= MALWARE =================
SUSPICIOUS_EXT = {".exe",".dll",".js",".bat",".cmd",".ps1",".vbs",".jar"}
SIGNATURES = [b"powershell -enc", b"cmd.exe /c", b"CreateRemoteThread", b"/bin/bash"]

def malware_scan(data: bytes, filename: str):
    score, findings = 0, []
    ext = os.path.splitext(filename.lower())[1]

    if ext in SUSPICIOUS_EXT:
        score += 30
        findings.append(f"Suspicious extension {ext}")

    for sig in SIGNATURES:
        if sig in data:
            score += 40
            findings.append("Malicious signature detected")

    verdict = "Malicious" if score >= 70 else "Suspicious" if score >= 40 else "Clean"
    return verdict, score, findings

# ================= GEMINI EXPLANATIONS =================
def explain(prompt, lang):
    full_prompt = f"""
Reply ONLY in {LANGUAGE_MAP.get(lang,"English")}.
Max 2 lines.

{prompt}
"""
    return gemini_generate(full_prompt) or SAFE_TEXT.get(lang, SAFE_TEXT["en"])

# ================= ROUTES =================
@app.route("/")
def home():
    return "✅ SurakshaAI backend running"

# -------- PHISHING --------
@app.route("/analyze", methods=["POST"])
def analyze():
    d = request.get_json()
    msg = d.get("message","")
    lang = d.get("language","en")

    X = vectorizer.transform([msg])
    ml = model.predict(X)[0]

    verdict = "Dangerous" if ml=="Dangerous" else "Suspicious" if ml=="Suspicious" else "Safe"
    conf = 90 if verdict=="Dangerous" else 65 if verdict=="Suspicious" else 30

    explanation = explain(
        f"Message: {msg}\nVerdict: {verdict}\nConfidence: {conf}%",
        lang
    )

    return jsonify({
        "risk": verdict,
        "confidence": conf,
        "ai_explanation": explanation
    })

# -------- VAULT --------
@app.route("/vault-analyze", methods=["POST"])
def vault():
    file = request.files["file"]
    lang = request.form.get("language","en")

    data = file.read(4096)
    entropy = round(calculate_entropy(data),2)

    verdict = "Malicious" if entropy > 7.5 else "Suspicious" if entropy > 6.8 else "Safe"

    explanation = explain(
        f"File: {file.filename}\nEntropy: {entropy}\nVerdict: {verdict}",
        lang
    )

    return jsonify({
        "file_name": file.filename,
        "entropy": entropy,
        "verdict": verdict,
        "gemini_explanation": explanation
    })

# -------- MALWARE --------
@app.route("/malware-scan", methods=["POST"])
def malware_scan_api():
    file = request.files["file"]
    lang = request.form.get("language","en")

    data = file.read()
    verdict, score, findings = malware_scan(data, file.filename)

    explanation = explain(
        f"File: {file.filename}\nVerdict: {verdict}\nFindings: {findings}",
        lang
    )

    return jsonify({
        "file_name": file.filename,
        "risk_score": min(score+10,100),
        "verdict": verdict,
        "gemini_explanation": explanation,
        "malware_scan": {
            "score": score,
            "findings": findings
        }
    })

# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
