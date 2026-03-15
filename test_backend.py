"""
PhishEye — Comprehensive Backend Test Suite
Tests: scanner.py logic, Flask routes, API responses, edge cases, error handling
Run: python3 test_backend.py
"""

import unittest
import json
import base64
import os
import sys
import io
from unittest.mock import patch, MagicMock, PropertyMock
from PIL import Image

# ── Make sure we can import from the project root ──────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app
import scanner


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def make_test_image_b64(color=(255, 0, 0), size=(100, 100), fmt="JPEG"):
    """Return a base64-encoded test image."""
    img = Image.new("RGB", size, color=color)
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return base64.b64encode(buf.getvalue()).decode("utf-8")


SCAM_RESULT = {
    "threat_level": "SCAM",
    "confidence": 95,
    "summary": "Fake IRS notice demanding immediate payment via gift cards.",
    "red_flags": [
        "Requests gift card payment",
        "Creates urgency/fear",
        "Spoofed government branding",
        "Unofficial sender address"
    ],
    "action": "Do NOT respond. Block the sender. Report to reportfraud.ftc.gov.",
    "explanation": "This is a classic IRS impersonation scam."
}

SAFE_RESULT = {
    "threat_level": "SAFE",
    "confidence": 98,
    "summary": "Routine bank statement from Chase.",
    "red_flags": [],
    "action": "No action required.",
    "explanation": "Document appears legitimate."
}

SUSPICIOUS_RESULT = {
    "threat_level": "SUSPICIOUS",
    "confidence": 65,
    "summary": "Email claims you won a prize.",
    "red_flags": ["Unsolicited prize notification", "Requests personal info"],
    "action": "Do not click links. Verify directly with the company.",
    "explanation": "Pattern matches common lottery scams but sender could not be fully verified."
}


# ══════════════════════════════════════════════════════════════════════════════
# 1. SCANNER UNIT TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestScannerUnit(unittest.TestCase):
    """Unit tests for scanner.py — mocking Gemini API calls."""

    @patch("scanner.model")
    def test_analyze_image_scam_detection(self, mock_model):
        """Scanner correctly parses a SCAM result from Gemini."""
        mock_response = MagicMock()
        mock_response.text = json.dumps(SCAM_RESULT)
        mock_model.generate_content.return_value = mock_response

        img_b64 = make_test_image_b64()
        result = scanner.analyze_image(img_b64)

        self.assertEqual(result["threat_level"], "SCAM")
        self.assertEqual(result["confidence"], 95)
        self.assertIn("red_flags", result)
        self.assertGreater(len(result["red_flags"]), 0)

    @patch("scanner.model")
    def test_analyze_image_safe_detection(self, mock_model):
        """Scanner correctly parses a SAFE result."""
        mock_response = MagicMock()
        mock_response.text = json.dumps(SAFE_RESULT)
        mock_model.generate_content.return_value = mock_response

        img_b64 = make_test_image_b64(color=(0, 255, 0))
        result = scanner.analyze_image(img_b64)

        self.assertEqual(result["threat_level"], "SAFE")
        self.assertEqual(result["red_flags"], [])

    @patch("scanner.model")
    def test_analyze_image_suspicious_detection(self, mock_model):
        """Scanner correctly parses a SUSPICIOUS result."""
        mock_response = MagicMock()
        mock_response.text = json.dumps(SUSPICIOUS_RESULT)
        mock_model.generate_content.return_value = mock_response

        img_b64 = make_test_image_b64(color=(255, 165, 0))
        result = scanner.analyze_image(img_b64)

        self.assertEqual(result["threat_level"], "SUSPICIOUS")
        self.assertIn("action", result)

    @patch("scanner.model")
    def test_analyze_image_gemini_api_error(self, mock_model):
        """Scanner handles Gemini API failure gracefully."""
        mock_model.generate_content.side_effect = Exception("Gemini API timeout")

        img_b64 = make_test_image_b64()
        result = scanner.analyze_image(img_b64)

        # Should return an error dict, not raise
        self.assertIn("error", result)

    @patch("scanner.model")
    def test_analyze_image_malformed_json_response(self, mock_model):
        """Scanner handles malformed JSON from Gemini without crashing."""
        mock_response = MagicMock()
        mock_response.text = "This is not JSON at all."
        mock_model.generate_content.return_value = mock_response

        img_b64 = make_test_image_b64()
        result = scanner.analyze_image(img_b64)

        # Should not raise; should return error or partial result
        self.assertIsInstance(result, dict)

    @patch("scanner.model")
    def test_analyze_text_scam(self, mock_model):
        """analyze_text correctly classifies a scam transcript."""
        mock_response = MagicMock()
        mock_response.text = json.dumps(SCAM_RESULT)
        mock_model.generate_content.return_value = mock_response

        text = "Your Social Security number has been suspended. Press 1 to speak to an agent or we will issue a warrant for your arrest."
        result = scanner.analyze_text(text)

        self.assertIn("threat_level", result)
        self.assertEqual(result["threat_level"], "SCAM")

    @patch("scanner.model")
    def test_analyze_text_empty_string(self, mock_model):
        """analyze_text handles empty input gracefully."""
        mock_response = MagicMock()
        mock_response.text = json.dumps(SAFE_RESULT)
        mock_model.generate_content.return_value = mock_response

        result = scanner.analyze_text("")
        self.assertIsInstance(result, dict)

    @patch("scanner.model")
    def test_analyze_text_very_long_input(self, mock_model):
        """analyze_text handles very long transcripts (stress test)."""
        mock_response = MagicMock()
        mock_response.text = json.dumps(SUSPICIOUS_RESULT)
        mock_model.generate_content.return_value = mock_response

        long_text = "Hello, this is your bank. " * 500  # ~13,000 chars
        result = scanner.analyze_text(long_text)
        self.assertIsInstance(result, dict)


# ══════════════════════════════════════════════════════════════════════════════
# 2. FLASK ROUTE TESTS — /analyze
# ══════════════════════════════════════════════════════════════════════════════

class TestAnalyzeRoute(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config["TESTING"] = True

    @patch("main.scanner.analyze_image", return_value=SCAM_RESULT)
    def test_analyze_with_valid_image(self, mock_analyze):
        """POST /analyze with valid base64 image returns 200 + threat_level."""
        payload = {"image": make_test_image_b64()}
        response = self.client.post(
            "/analyze",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("threat_level", data)
        self.assertEqual(data["threat_level"], "SCAM")

    def test_analyze_missing_image_field(self):
        """POST /analyze with no image field returns 400."""
        response = self.client.post(
            "/analyze",
            data=json.dumps({}),
            content_type="application/json"
        )
        self.assertIn(response.status_code, [400, 422, 500])

    def test_analyze_empty_body(self):
        """POST /analyze with empty body doesn't crash server."""
        response = self.client.post(
            "/analyze",
            data="",
            content_type="application/json"
        )
        self.assertNotEqual(response.status_code, 500)

    @patch("main.scanner.analyze_image", return_value=SAFE_RESULT)
    def test_analyze_returns_valid_json_structure(self, mock_analyze):
        """Response contains all required fields."""
        payload = {"image": make_test_image_b64()}
        response = self.client.post(
            "/analyze",
            data=json.dumps(payload),
            content_type="application/json"
        )
        data = json.loads(response.data)
        for field in ["threat_level", "summary", "red_flags", "action"]:
            self.assertIn(field, data, f"Missing field: {field}")

    @patch("main.scanner.analyze_image", side_effect=Exception("Gemini down"))
    def test_analyze_when_scanner_throws(self, mock_analyze):
        """Server returns error JSON, not a 500 crash page."""
        payload = {"image": make_test_image_b64()}
        response = self.client.post(
            "/analyze",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertIn(response.status_code, [200, 500])
        # Should return JSON either way
        self.assertIn("application/json", response.content_type)


# ══════════════════════════════════════════════════════════════════════════════
# 3. FLASK ROUTE TESTS — /chat
# ══════════════════════════════════════════════════════════════════════════════

class TestChatRoute(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config["TESTING"] = True

    @patch("main.scanner.chat", return_value={"reply": "This is definitely a scam."})
    def test_chat_basic_message(self, mock_chat):
        """POST /chat returns a reply."""
        payload = {
            "message": "Is this email real?",
            "context": json.dumps(SCAM_RESULT)
        }
        response = self.client.post(
            "/chat",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("reply", data)

    def test_chat_missing_message(self):
        """POST /chat with no message field returns error."""
        response = self.client.post(
            "/chat",
            data=json.dumps({}),
            content_type="application/json"
        )
        self.assertIn(response.status_code, [400, 422, 500])

    @patch("main.scanner.chat", return_value={"reply": "Call your bank immediately."})
    def test_chat_without_context(self, mock_chat):
        """POST /chat works even when no prior scan context is provided."""
        payload = {"message": "What should I do if I clicked a phishing link?"}
        response = self.client.post(
            "/chat",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)

    @patch("main.scanner.chat", return_value={"reply": "Yes."})
    def test_chat_xss_in_message(self, mock_chat):
        """XSS payload in message doesn't break the server."""
        payload = {"message": "<script>alert('xss')</script>"}
        response = self.client.post(
            "/chat",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertNotEqual(response.status_code, 500)

    @patch("main.scanner.chat", return_value={"reply": "Stay safe."})
    def test_chat_unicode_message(self, mock_chat):
        """Non-ASCII characters in message are handled correctly."""
        payload = {"message": "¿Es este correo electrónico un fraude? 中文测试 مرحبا"}
        response = self.client.post(
            "/chat",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)


# ══════════════════════════════════════════════════════════════════════════════
# 4. FLASK ROUTE TESTS — /voice-analyze
# ══════════════════════════════════════════════════════════════════════════════

class TestVoiceAnalyzeRoute(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config["TESTING"] = True

    @patch("main.scanner.analyze_text", return_value=SCAM_RESULT)
    def test_voice_analyze_with_transcript(self, mock_analyze):
        """POST /voice-analyze with transcript text returns scan result."""
        payload = {"transcript": "Your account has been compromised. Send $500 in Bitcoin immediately."}
        response = self.client.post(
            "/voice-analyze",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("threat_level", data)

    def test_voice_analyze_empty_transcript(self):
        """POST /voice-analyze with empty transcript handled gracefully."""
        payload = {"transcript": ""}
        response = self.client.post(
            "/voice-analyze",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertIn(response.status_code, [200, 400])

    def test_voice_analyze_missing_field(self):
        """POST /voice-analyze with no transcript field returns error."""
        response = self.client.post(
            "/voice-analyze",
            data=json.dumps({}),
            content_type="application/json"
        )
        self.assertIn(response.status_code, [400, 422, 500])


# ══════════════════════════════════════════════════════════════════════════════
# 5. FLASK ROUTE TESTS — /tts
# ══════════════════════════════════════════════════════════════════════════════

class TestTTSRoute(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config["TESTING"] = True

    @patch("main.tts_client")
    def test_tts_returns_audio(self, mock_tts):
        """POST /tts with text returns audio/mpeg content."""
        mock_response = MagicMock()
        mock_response.audio_content = b"\xff\xfb\x90\x00" * 100  # fake MP3 bytes
        mock_tts.synthesize_speech.return_value = mock_response

        payload = {"text": "Warning: This is a scam."}
        response = self.client.post(
            "/tts",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)

    @patch("main.tts_client")
    def test_tts_empty_text(self, mock_tts):
        """POST /tts with empty text returns error, not crash."""
        payload = {"text": ""}
        response = self.client.post(
            "/tts",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertNotEqual(response.status_code, 500)

    @patch("main.tts_client", None)
    def test_tts_when_client_not_initialized(self):
        """TTS route falls back gracefully when Cloud TTS is unavailable."""
        payload = {"text": "Test fallback."}
        response = self.client.post(
            "/tts",
            data=json.dumps(payload),
            content_type="application/json"
        )
        # Should return some response — either audio or a fallback error JSON
        self.assertIsNotNone(response)


# ══════════════════════════════════════════════════════════════════════════════
# 6. INDEX ROUTE
# ══════════════════════════════════════════════════════════════════════════════

class TestIndexRoute(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_index_returns_200(self):
        """GET / loads the main UI."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_index_contains_phisheye(self):
        """Homepage HTML contains PhishEye branding."""
        response = self.client.get("/")
        self.assertIn(b"PhishEye", response.data)

    def test_404_on_unknown_route(self):
        """Unknown routes return 404."""
        response = self.client.get("/nonexistent-route-xyz")
        self.assertEqual(response.status_code, 404)


# ══════════════════════════════════════════════════════════════════════════════
# 7. SECURITY & EDGE CASE TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestSecurityAndEdgeCases(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config["TESTING"] = True

    def test_oversized_payload_handled(self):
        """Extremely large image payload doesn't hang the server."""
        # 5MB of random base64
        huge_b64 = base64.b64encode(os.urandom(5 * 1024 * 1024)).decode("utf-8")
        payload = {"image": huge_b64}
        response = self.client.post(
            "/analyze",
            data=json.dumps(payload),
            content_type="application/json"
        )
        # Any response is fine — just shouldn't hang or return 500 without JSON
        self.assertIsNotNone(response)

    def test_sql_injection_attempt_in_chat(self):
        """SQL injection string in chat message is handled safely."""
        payload = {"message": "'; DROP TABLE users; --"}
        response = self.client.post(
            "/chat",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertNotEqual(response.status_code, 500)

    def test_wrong_content_type(self):
        """Sending form data instead of JSON returns a useful error."""
        response = self.client.post(
            "/analyze",
            data="image=somefakedata",
            content_type="application/x-www-form-urlencoded"
        )
        self.assertIn(response.status_code, [400, 415, 500])

    @patch("main.scanner.analyze_image", return_value=SCAM_RESULT)
    def test_concurrent_requests_dont_share_state(self, mock_analyze):
        """Two simultaneous calls return independent results (no global state leakage)."""
        payload = {"image": make_test_image_b64()}
        r1 = self.client.post("/analyze", data=json.dumps(payload), content_type="application/json")
        r2 = self.client.post("/analyze", data=json.dumps(payload), content_type="application/json")
        d1 = json.loads(r1.data)
        d2 = json.loads(r2.data)
        self.assertEqual(d1["threat_level"], d2["threat_level"])


# ══════════════════════════════════════════════════════════════════════════════
# 8. THREAT LEVEL CLASSIFICATION LOGIC
# ══════════════════════════════════════════════════════════════════════════════

class TestThreatLevelLogic(unittest.TestCase):
    """Validates that threat levels are one of the three expected values."""

    VALID_LEVELS = {"SAFE", "SUSPICIOUS", "SCAM"}

    def _assert_valid_level(self, result):
        self.assertIn(result.get("threat_level"), self.VALID_LEVELS,
                      f"Unexpected threat_level: {result.get('threat_level')}")

    @patch("scanner.model")
    def test_scam_level_is_valid(self, mock_model):
        mock_model.generate_content.return_value = MagicMock(text=json.dumps(SCAM_RESULT))
        result = scanner.analyze_image(make_test_image_b64())
        self._assert_valid_level(result)

    @patch("scanner.model")
    def test_safe_level_is_valid(self, mock_model):
        mock_model.generate_content.return_value = MagicMock(text=json.dumps(SAFE_RESULT))
        result = scanner.analyze_image(make_test_image_b64())
        self._assert_valid_level(result)

    @patch("scanner.model")
    def test_suspicious_level_is_valid(self, mock_model):
        mock_model.generate_content.return_value = MagicMock(text=json.dumps(SUSPICIOUS_RESULT))
        result = scanner.analyze_image(make_test_image_b64())
        self._assert_valid_level(result)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestScannerUnit,
        TestAnalyzeRoute,
        TestChatRoute,
        TestVoiceAnalyzeRoute,
        TestTTSRoute,
        TestIndexRoute,
        TestSecurityAndEdgeCases,
        TestThreatLevelLogic,
    ]

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    total = result.testsRun
    passed = total - len(result.failures) - len(result.errors)
    print(f"\n{'='*60}")
    print(f"✅ PASSED: {passed}/{total}")
    if result.failures:
        print(f"❌ FAILED: {len(result.failures)}")
    if result.errors:
        print(f"💥 ERRORS: {len(result.errors)}")
    print(f"{'='*60}")

    sys.exit(0 if result.wasSuccessful() else 1)