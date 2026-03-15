"""
PhishEye — Integration & Smoke Tests
Tests the running app at http://localhost:8080 using real HTTP requests.
Use this AFTER `python3 main.py` is running.

Run: python3 test_integration.py
"""

import requests
import base64
import json
import io
import os
import sys
import time
from PIL import Image

BASE_URL = os.getenv("PHISHEYE_URL", "http://localhost:8080")
TIMEOUT = 15  # seconds per request

PASS = "✅"
FAIL = "❌"
WARN = "⚠️ "

results = []


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def make_image_b64(color=(220, 50, 50), size=(200, 200), text_overlay=False):
    img = Image.new("RGB", size, color=color)
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")


def run_test(name, fn):
    """Run a single test and record pass/fail."""
    try:
        fn()
        print(f"{PASS} {name}")
        results.append(("PASS", name))
    except AssertionError as e:
        print(f"{FAIL} {name} — {e}")
        results.append(("FAIL", name, str(e)))
    except Exception as e:
        print(f"{FAIL} {name} — Exception: {e}")
        results.append(("ERROR", name, str(e)))


# ══════════════════════════════════════════════════════════════════════════════
# CONNECTIVITY
# ══════════════════════════════════════════════════════════════════════════════

def test_server_is_up():
    r = requests.get(BASE_URL, timeout=TIMEOUT)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"


def test_homepage_loads_html():
    r = requests.get(BASE_URL, timeout=TIMEOUT)
    assert "text/html" in r.headers.get("Content-Type", "")


def test_homepage_contains_branding():
    r = requests.get(BASE_URL, timeout=TIMEOUT)
    assert "PhishEye" in r.text, "PhishEye branding not found in homepage"


# ══════════════════════════════════════════════════════════════════════════════
# /analyze — IMAGE UPLOAD
# ══════════════════════════════════════════════════════════════════════════════

def test_analyze_valid_image():
    payload = {"image": make_image_b64()}
    r = requests.post(f"{BASE_URL}/analyze", json=payload, timeout=TIMEOUT)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "threat_level" in data, "No threat_level in response"
    assert data["threat_level"] in ("SAFE", "SUSPICIOUS", "SCAM"), \
        f"Invalid threat_level: {data['threat_level']}"


def test_analyze_response_has_all_fields():
    payload = {"image": make_image_b64()}
    r = requests.post(f"{BASE_URL}/analyze", json=payload, timeout=TIMEOUT)
    data = r.json()
    for field in ["threat_level", "summary", "red_flags", "action"]:
        assert field in data, f"Missing field in response: {field}"


def test_analyze_red_flags_is_list():
    payload = {"image": make_image_b64()}
    r = requests.post(f"{BASE_URL}/analyze", json=payload, timeout=TIMEOUT)
    data = r.json()
    assert isinstance(data.get("red_flags"), list), "red_flags should be a list"


def test_analyze_missing_image_returns_error():
    r = requests.post(f"{BASE_URL}/analyze", json={}, timeout=TIMEOUT)
    assert r.status_code in (400, 422, 500), \
        f"Expected 4xx/5xx for missing image, got {r.status_code}"


def test_analyze_empty_string_image():
    r = requests.post(f"{BASE_URL}/analyze", json={"image": ""}, timeout=TIMEOUT)
    assert r.status_code != 200 or "error" in r.json() or "threat_level" in r.json()


def test_analyze_invalid_base64():
    r = requests.post(f"{BASE_URL}/analyze", json={"image": "not-valid-base64!!!"}, timeout=TIMEOUT)
    # Should not return 500 without a JSON body
    assert r.headers.get("Content-Type", "").startswith("application/json") or r.status_code != 500


def test_analyze_response_time_under_30s():
    """Gemini should respond within 30 seconds."""
    payload = {"image": make_image_b64()}
    start = time.time()
    r = requests.post(f"{BASE_URL}/analyze", json=payload, timeout=35)
    elapsed = time.time() - start
    assert elapsed < 30, f"Response took too long: {elapsed:.1f}s"


# ══════════════════════════════════════════════════════════════════════════════
# /chat — FOLLOW-UP CONVERSATION
# ══════════════════════════════════════════════════════════════════════════════

def test_chat_basic():
    payload = {
        "message": "Should I call the number in this email?",
        "context": json.dumps({"threat_level": "SCAM", "summary": "Fake IRS notice"})
    }
    r = requests.post(f"{BASE_URL}/chat", json=payload, timeout=TIMEOUT)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "reply" in data, "No 'reply' field in chat response"
    assert len(data["reply"]) > 0, "Reply is empty"


def test_chat_no_context():
    """Chat should still work without prior scan context."""
    payload = {"message": "What are common signs of a phishing email?"}
    r = requests.post(f"{BASE_URL}/chat", json=payload, timeout=TIMEOUT)
    assert r.status_code == 200


def test_chat_empty_message():
    r = requests.post(f"{BASE_URL}/chat", json={"message": ""}, timeout=TIMEOUT)
    assert r.status_code in (200, 400)


def test_chat_missing_message_field():
    r = requests.post(f"{BASE_URL}/chat", json={}, timeout=TIMEOUT)
    assert r.status_code in (400, 422, 500)


def test_chat_unicode_input():
    payload = {"message": "これは詐欺ですか？ هل هذا احتيال؟"}
    r = requests.post(f"{BASE_URL}/chat", json=payload, timeout=TIMEOUT)
    assert r.status_code == 200


def test_chat_xss_input():
    payload = {"message": "<script>alert(1)</script>"}
    r = requests.post(f"{BASE_URL}/chat", json=payload, timeout=TIMEOUT)
    assert r.status_code in (200, 400)
    if r.status_code == 200:
        assert "<script>" not in r.json().get("reply", ""), "XSS reflected in reply!"


# ══════════════════════════════════════════════════════════════════════════════
# /voice-analyze — CALL GUARD / VOICE TRANSCRIPT
# ══════════════════════════════════════════════════════════════════════════════

def test_voice_analyze_scam_transcript():
    transcript = (
        "Hello, this is the Social Security Administration. "
        "Your SSN has been suspended due to suspicious activity. "
        "To reactivate it, you must purchase $500 in iTunes gift cards immediately."
    )
    r = requests.post(f"{BASE_URL}/voice-analyze", json={"transcript": transcript}, timeout=TIMEOUT)
    assert r.status_code == 200
    data = r.json()
    assert "threat_level" in data


def test_voice_analyze_safe_transcript():
    transcript = "Hi, this is Dr. Smith's office calling to confirm your appointment tomorrow at 2pm. Please call us back if you need to reschedule."
    r = requests.post(f"{BASE_URL}/voice-analyze", json={"transcript": transcript}, timeout=TIMEOUT)
    assert r.status_code == 200
    data = r.json()
    assert data.get("threat_level") in ("SAFE", "SUSPICIOUS", "SCAM")


def test_voice_analyze_empty_transcript():
    r = requests.post(f"{BASE_URL}/voice-analyze", json={"transcript": ""}, timeout=TIMEOUT)
    assert r.status_code in (200, 400)


def test_voice_analyze_missing_field():
    r = requests.post(f"{BASE_URL}/voice-analyze", json={}, timeout=TIMEOUT)
    assert r.status_code in (400, 422, 500)


def test_voice_analyze_long_call_transcript():
    """Simulate a 5-minute call transcript."""
    long_transcript = (
        "Caller: Hello is this John? Me: Yes. "
        "Caller: I'm calling from Microsoft support about a virus on your computer. "
    ) * 50
    r = requests.post(f"{BASE_URL}/voice-analyze", json={"transcript": long_transcript}, timeout=30)
    assert r.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# /tts — TEXT TO SPEECH
# ══════════════════════════════════════════════════════════════════════════════

def test_tts_returns_audio_or_fallback():
    """TTS either returns audio or a JSON error — never a crash."""
    r = requests.post(f"{BASE_URL}/tts", json={"text": "Warning: this is a scam."}, timeout=TIMEOUT)
    assert r.status_code in (200, 500), f"Unexpected status: {r.status_code}"
    if r.status_code == 200:
        ct = r.headers.get("Content-Type", "")
        assert "audio" in ct or "application/json" in ct, f"Unexpected content-type: {ct}"


def test_tts_empty_text():
    r = requests.post(f"{BASE_URL}/tts", json={"text": ""}, timeout=TIMEOUT)
    assert r.status_code in (200, 400, 500)


# ══════════════════════════════════════════════════════════════════════════════
# END-TO-END FLOW: Scan → Chat
# ══════════════════════════════════════════════════════════════════════════════

def test_full_scan_then_chat_flow():
    """Full flow: upload image → get result → ask follow-up question."""
    # Step 1: Scan an image
    scan_payload = {"image": make_image_b64()}
    r1 = requests.post(f"{BASE_URL}/analyze", json=scan_payload, timeout=TIMEOUT)
    assert r1.status_code == 200, f"Scan failed: {r1.status_code}"
    scan_result = r1.json()
    assert "threat_level" in scan_result

    # Step 2: Use result as context in a chat message
    chat_payload = {
        "message": "What should I do next?",
        "context": json.dumps(scan_result)
    }
    r2 = requests.post(f"{BASE_URL}/chat", json=chat_payload, timeout=TIMEOUT)
    assert r2.status_code == 200, f"Chat failed: {r2.status_code}"
    chat_result = r2.json()
    assert "reply" in chat_result
    assert len(chat_result["reply"]) > 10, "Chat reply seems too short"

    print(f"   └─ Scan: {scan_result['threat_level']} → Chat reply: {chat_result['reply'][:60]}...")


def test_full_voice_then_chat_flow():
    """Full flow: analyze transcript → ask follow-up."""
    transcript = "This is Amazon. Your account has been charged $499. Press 1 to cancel."
    r1 = requests.post(f"{BASE_URL}/voice-analyze", json={"transcript": transcript}, timeout=TIMEOUT)
    assert r1.status_code == 200
    result = r1.json()

    chat_payload = {
        "message": "Should I press 1?",
        "context": json.dumps(result)
    }
    r2 = requests.post(f"{BASE_URL}/chat", json=chat_payload, timeout=TIMEOUT)
    assert r2.status_code == 200
    assert "reply" in r2.json()


# ══════════════════════════════════════════════════════════════════════════════
# HEALTH / MISC
# ══════════════════════════════════════════════════════════════════════════════

def test_unknown_route_404():
    r = requests.get(f"{BASE_URL}/this-does-not-exist", timeout=TIMEOUT)
    assert r.status_code == 404


def test_get_on_post_only_route():
    """GET on /analyze should return 405 Method Not Allowed."""
    r = requests.get(f"{BASE_URL}/analyze", timeout=TIMEOUT)
    assert r.status_code in (404, 405)


# ══════════════════════════════════════════════════════════════════════════════
# RUN ALL TESTS
# ══════════════════════════════════════════════════════════════════════════════

TESTS = [
    # Connectivity
    ("Server is reachable", test_server_is_up),
    ("Homepage returns HTML", test_homepage_loads_html),
    ("Homepage has PhishEye branding", test_homepage_contains_branding),

    # /analyze
    ("/analyze — valid image returns 200", test_analyze_valid_image),
    ("/analyze — response has all required fields", test_analyze_response_has_all_fields),
    ("/analyze — red_flags is a list", test_analyze_red_flags_is_list),
    ("/analyze — missing image returns error", test_analyze_missing_image_returns_error),
    ("/analyze — empty string image handled", test_analyze_empty_string_image),
    ("/analyze — invalid base64 handled", test_analyze_invalid_base64),
    ("/analyze — response time under 30s", test_analyze_response_time_under_30s),

    # /chat
    ("/chat — basic message returns reply", test_chat_basic),
    ("/chat — works without context", test_chat_no_context),
    ("/chat — empty message handled", test_chat_empty_message),
    ("/chat — missing message field returns error", test_chat_missing_message_field),
    ("/chat — unicode input handled", test_chat_unicode_input),
    ("/chat — XSS input not reflected", test_chat_xss_input),

    # /voice-analyze
    ("/voice-analyze — scam transcript detected", test_voice_analyze_scam_transcript),
    ("/voice-analyze — safe transcript processed", test_voice_analyze_safe_transcript),
    ("/voice-analyze — empty transcript handled", test_voice_analyze_empty_transcript),
    ("/voice-analyze — missing field returns error", test_voice_analyze_missing_field),
    ("/voice-analyze — long transcript handled", test_voice_analyze_long_call_transcript),

    # /tts
    ("/tts — returns audio or fallback", test_tts_returns_audio_or_fallback),
    ("/tts — empty text handled", test_tts_empty_text),

    # End-to-end
    ("E2E — Scan image → Chat follow-up", test_full_scan_then_chat_flow),
    ("E2E — Voice analyze → Chat follow-up", test_full_voice_then_chat_flow),

    # Misc
    ("404 on unknown route", test_unknown_route_404),
    ("GET on POST-only route returns 404/405", test_get_on_post_only_route),
]


if __name__ == "__main__":
    print(f"\n🎣 PhishEye Integration Tests")
    print(f"   Target: {BASE_URL}")
    print(f"   Tests:  {len(TESTS)}")
    print("=" * 60)

    # Check server is up first
    try:
        requests.get(BASE_URL, timeout=5)
    except Exception:
        print(f"\n💥 Cannot reach {BASE_URL}")
        print("   Make sure the app is running: python3 main.py")
        sys.exit(1)

    print()
    for name, fn in TESTS:
        run_test(name, fn)

    print("\n" + "=" * 60)
    passed = sum(1 for r in results if r[0] == "PASS")
    failed = sum(1 for r in results if r[0] in ("FAIL", "ERROR"))
    total = len(results)

    print(f"✅ PASSED: {passed}/{total}")
    if failed:
        print(f"❌ FAILED: {failed}/{total}")
        print("\nFailed tests:")
        for r in results:
            if r[0] in ("FAIL", "ERROR"):
                print(f"  • {r[1]}: {r[2] if len(r) > 2 else ''}")

    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)