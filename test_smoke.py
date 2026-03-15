"""
PhishEye — Quick Smoke Test
Fastest possible sanity check before deploying to Cloud Run.
Hits every route once with a real request.

Run: python3 test_smoke.py
"""

import requests, base64, io, sys, time, json
from PIL import Image

BASE = "http://localhost:8080"

def img():
    buf = io.BytesIO()
    Image.new("RGB", (100, 100), (200, 50, 50)).save(buf, "JPEG")
    return base64.b64encode(buf.getvalue()).decode()

ok = True

print("🔥 PhishEye Smoke Test\n")

checks = [
    ("GET  /         → 200",
     lambda: requests.get(BASE, timeout=10)),

    ("POST /analyze  → 200 + threat_level",
     lambda: requests.post(f"{BASE}/analyze", json={"image": img()}, timeout=20)),

    ("POST /chat     → 200 + reply",
     lambda: requests.post(f"{BASE}/chat", json={"message": "Is this a scam?"}, timeout=15)),

    ("POST /voice-analyze → 200 + threat_level",
     lambda: requests.post(f"{BASE}/voice-analyze",
                           json={"transcript": "Your SSN is suspended. Call us now."},
                           timeout=20)),

    ("POST /tts      → not 500",
     lambda: requests.post(f"{BASE}/tts", json={"text": "Test"}, timeout=10)),
]

for label, fn in checks:
    try:
        r = fn()
        if r.status_code >= 500:
            print(f"  ❌ {label}  [{r.status_code}]")
            ok = False
        else:
            body = r.json() if "json" in r.headers.get("Content-Type","") else {}
            note = ""
            if "threat_level" in body:
                note = f" → {body['threat_level']}"
            elif "reply" in body:
                note = f" → \"{body['reply'][:40]}...\""
            print(f"  ✅ {label}  [{r.status_code}]{note}")
    except Exception as e:
        print(f"  ❌ {label}  — {e}")
        ok = False

print()
print("✅ ALL SMOKE TESTS PASSED — ready to deploy!" if ok else "❌ SOME TESTS FAILED — fix before deploying.")
sys.exit(0 if ok else 1)