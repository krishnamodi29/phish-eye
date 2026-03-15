import os
import base64
from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

SCAM_DETECTION_PROMPT = """
You are PhishEye, an expert cybersecurity AI that detects scams.

Analyze this image carefully and look for these red flags:
- Fake urgency ("act now", "expires in 24 hours", "immediate action required")
- Suspicious sender addresses that impersonate legitimate companies
- Requests for passwords, OTPs, or sensitive information
- Suspicious links or URLs
- Poor grammar or spelling
- Fake logos or branding
- Too good to be true offers
- Threats or fear tactics
- Impersonation of banks, government, or tech companies

Respond in this exact format:
THREAT_LEVEL: [SAFE / SUSPICIOUS / SCAM]
CONFIDENCE: [HIGH / MEDIUM / LOW]
SUMMARY: [One sentence summary]
RED_FLAGS: [List each red flag found, or "None detected"]
ACTION: [Exactly what the user should do]
EXPLANATION: [Plain English explanation for non-technical users]
"""

def analyze_image(image_data: bytes, mime_type: str = "image/jpeg") -> dict:
    """Analyze an image for scam content using Gemini vision."""
    
    image_part = types.Part.from_bytes(
        data=image_data,
        mime_type=mime_type
    )
    
    response = client.models.generate_content(
        model="gemini-3.1-pro-preview",
        contents=[SCAM_DETECTION_PROMPT, image_part]
    )
    
    return parse_response(response.text)

def parse_response(text: str) -> dict:
    """Parse Gemini response into structured data."""
    result = {
        "threat_level": "UNKNOWN",
        "confidence": "LOW", 
        "summary": "",
        "red_flags": [],
        "action": "",
        "explanation": "",
        "raw": text
    }
    
    lines = text.strip().split('\n')
    for line in lines:
        if line.startswith("THREAT_LEVEL:"):
            result["threat_level"] = line.split(":", 1)[1].strip()
        elif line.startswith("CONFIDENCE:"):
            result["confidence"] = line.split(":", 1)[1].strip()
        elif line.startswith("SUMMARY:"):
            result["summary"] = line.split(":", 1)[1].strip()
        elif line.startswith("RED_FLAGS:"):
            flags = line.split(":", 1)[1].strip()
            result["red_flags"] = [f.strip() for f in flags.split(",")]
        elif line.startswith("ACTION:"):
            result["action"] = line.split(":", 1)[1].strip()
        elif line.startswith("EXPLANATION:"):
            result["explanation"] = line.split(":", 1)[1].strip()
    
    return result