"""
Phish Eye — ADK Multi-Agent System v2
Orchestrator + 3 specialist agents with anti-hallucination grounding.
All agents are grounded in verified FTC/FBI/AARP scam data via facts.py.
"""

import os
import base64
import json
from google.adk.agents import Agent
from google import genai
from facts import VERIFIED_FACTS, format_facts_for_prompt, get_facts_for_scam_type

# ─────────────────────────────────────────────
# GROUNDING CONTEXT — injected into all agents
# ─────────────────────────────────────────────
GROUNDING_CONTEXT = format_facts_for_prompt()

# ─────────────────────────────────────────────
# TOOLS
# ─────────────────────────────────────────────

def get_verified_facts(topic: str) -> dict:
    """
    Retrieves verified, factual information about scam types from the
    FTC, FBI IC3, and AARP Fraud Watch Network databases.
    Use this tool BEFORE making any claim about how a scam works.

    Args:
        topic: The scam type or topic to look up
               (e.g. "IRS scam", "gift cards", "voice cloning", "phishing")
    Returns:
        dict with verified facts, red flags, and reporting resources
    """
    topic_lower = topic.lower()

    # Check scam types
    facts = get_facts_for_scam_type(topic_lower)
    if facts:
        return {
            "status": "found",
            "source": "FTC/FBI IC3 verified data",
            "facts": facts,
            "reporting": VERIFIED_FACTS["reporting_resources"]
        }

    # Check payment methods
    if any(word in topic_lower for word in ["gift card", "wire", "crypto", "bitcoin", "venmo", "zelle"]):
        return {
            "status": "found",
            "source": "FTC verified data",
            "facts": {
                "key_fact": "Legitimate organizations NEVER request these payment methods",
                "never_pay_via": VERIFIED_FACTS["payment_methods_never_used_by_legitimate_entities"],
                "if_asked": "This is ALWAYS a scam. Hang up immediately."
            },
            "reporting": VERIFIED_FACTS["reporting_resources"]
        }

    # General safety rules
    return {
        "status": "general_safety",
        "source": "FTC/AARP verified safety guidelines",
        "facts": {
            "safety_rules": VERIFIED_FACTS["safety_rules"],
            "statistics": VERIFIED_FACTS["statistics"][:3]
        },
        "reporting": VERIFIED_FACTS["reporting_resources"]
    }


def scan_image_for_scams(image_b64: str) -> dict:
    """
    Analyzes a base64-encoded image for scam indicators using Gemini vision.
    Returns threat_level (SAFE/SUSPICIOUS/SCAM), red_flags, summary, and action.

    Args:
        image_b64: Base64-encoded image string
    Returns:
        dict with threat_level, confidence, summary, red_flags, action, explanation
    """
    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

    PROMPT = f"""You are an expert scam detection AI. Analyze this image for phishing, scams, or fraud.

{GROUNDING_CONTEXT}

Look for these verified red flags:
- Requests for gift card payments (ALWAYS a scam)
- Urgency tactics ("act now", "account suspended", "you've been selected")
- Suspicious sender addresses (misspellings, lookalike domains)
- Requests for passwords, SSN, bank details
- Prize/lottery winnings for contests never entered
- IRS/government demanding immediate payment
- Links that don't match the displayed text

Respond ONLY with valid JSON:
{{
  "threat_level": "SAFE" or "SUSPICIOUS" or "SCAM",
  "confidence": 85,
  "summary": "One sentence summary",
  "red_flags": ["specific flag 1", "specific flag 2"],
  "action": "What the user should do right now",
  "explanation": "Simple explanation for non-tech users",
  "report_to": "Where to report this if it's a scam"
}}"""

    try:
        image_bytes = base64.b64decode(image_b64)
        image_part = {
            "inline_data": {
                "mime_type": "image/jpeg",
                "data": base64.b64encode(image_bytes).decode()
            }
        }
        response = client.models.generate_content(
            model="gemini-3.1-pro-preview",
            contents=[PROMPT, image_part]
        )
        text = response.text.strip()
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())
    except Exception as e:
        return {
            "threat_level": "SUSPICIOUS",
            "confidence": 50,
            "summary": "Could not fully analyze — treat with caution",
            "red_flags": ["Analysis encountered an error — verify manually"],
            "action": "When in doubt, do not click any links or provide personal info",
            "explanation": "We had trouble analyzing this. If it asks for money, gift cards, or personal info — it's a scam.",
            "report_to": "reportfraud.ftc.gov"
        }


def analyze_call_transcript(transcript: str) -> dict:
    """
    Analyzes a phone call transcript for scam patterns using verified data.
    Detects urgency tactics, impersonation, gift card requests, and AI voice cloning.

    Args:
        transcript: Text of what the caller said
    Returns:
        dict with threat_level, scam_type, red_flags, and action
    """
    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

    PROMPT = f"""You are a scam call detection expert with access to verified FTC and FBI data.

{GROUNDING_CONTEXT}

Analyze this phone call transcript for scam patterns:

Transcript: "{transcript}"

Check for these VERIFIED scam indicators:
- IRS/SSA/Medicare impersonation (government agencies contact by mail first)
- Gift card payment requests (ALWAYS a scam — no exceptions)
- Urgency tactics: "act now", "don't hang up", "you'll be arrested"
- Bank fraud alerts asking to "move money to a safe account"
- Tech support claiming your computer has a virus
- Prize/lottery requiring upfront payment
- AI voice cloning patterns (unnatural speech, can't answer personal questions)
- Grandparent scam (family emergency, requests secrecy)

Respond ONLY with valid JSON:
{{
  "threat_level": "SAFE" or "SUSPICIOUS" or "SCAM",
  "confidence": 90,
  "scam_type": "Specific type or None",
  "summary": "One sentence",
  "red_flags": ["specific flag 1", "specific flag 2"],
  "action": "What to do RIGHT NOW — be direct",
  "explanation": "Plain English explanation",
  "verified_fact": "One verified fact that proves this is/isn't a scam",
  "report_to": "Specific reporting resource"
}}"""

    try:
        response = client.models.generate_content(
            model="gemini-3.1-pro-preview",
            contents=PROMPT
        )
        text = response.text.strip()
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())
    except Exception as e:
        return {
            "threat_level": "SUSPICIOUS",
            "confidence": 50,
            "scam_type": "Unknown",
            "summary": "Could not fully analyze",
            "red_flags": ["Analysis error — treat with caution"],
            "action": "Do not provide personal information or money. Hang up and call back on an official number.",
            "verified_fact": "Legitimate organizations never demand immediate payment by phone.",
            "report_to": "reportfraud.ftc.gov"
        }


def get_scam_education(scam_type: str, user_question: str) -> dict:
    """
    Provides verified educational information about scam types.
    All responses are grounded in FTC, FBI IC3, and AARP data.

    Args:
        scam_type: Type of scam (e.g. "IRS impersonation", "phishing email")
        user_question: The user's specific question
    Returns:
        dict with verified answer, facts, and reporting guidance
    """
    # First get verified facts
    verified = get_facts_for_scam_type(scam_type)
    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

    verified_context = ""
    if verified:
        verified_context = f"""
Verified facts about {scam_type}:
- Description: {verified.get('description', '')}
- Key fact: {verified.get('fact', '')}
- Report to: {verified.get('report_to', 'reportfraud.ftc.gov')}
- Red flags: {', '.join(verified.get('red_flags', []))}
"""

    PROMPT = f"""You are a scam education expert. Answer this question using ONLY verified information.
If you don't know something for certain, say "I'm not certain — please verify with the FTC at ftc.gov."
NEVER make up statistics or facts.

{GROUNDING_CONTEXT}
{verified_context}

Question: "{user_question}"
About: {scam_type}

Respond ONLY with valid JSON:
{{
  "answer": "Direct answer in plain English, citing verified sources",
  "how_it_works": "Brief verified description of how this scam operates",
  "who_is_targeted": "Who scammers typically target",
  "how_to_report": "Specific verified reporting channel",
  "prevention_tips": ["tip1 (verified)", "tip2 (verified)", "tip3 (verified)"],
  "source": "FTC/FBI IC3/AARP"
}}"""

    try:
        response = client.models.generate_content(
            model="gemini-3.1-pro-preview",
            contents=PROMPT
        )
        text = response.text.strip()
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())
    except Exception as e:
        return {
            "answer": "I had trouble processing that. Please visit ftc.gov/scams for verified information.",
            "how_it_works": "",
            "who_is_targeted": "",
            "how_to_report": "reportfraud.ftc.gov",
            "prevention_tips": ["Never share personal info with unsolicited callers", "Verify by calling official numbers"],
            "source": "FTC"
        }


def check_url_safety(url: str) -> dict:
    """
    Checks if a URL looks safe or suspicious based on verified phishing indicators.

    Args:
        url: The URL to analyze
    Returns:
        dict with risk_level, reasons, and recommendation
    """
    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

    PROMPT = f"""You are a cybersecurity expert. Analyze this URL for phishing indicators.
Only report what you can verify from the URL itself — do NOT make up information.

URL: {url}

Check for VERIFIED phishing indicators:
- Misspelled brand names (paypa1.com, amaz0n.com, g00gle.com)
- Lookalike domains (paypal-security.com, amazon-support.net)
- Suspicious TLDs for well-known brands (.xyz, .tk, .ml)
- IP addresses instead of domain names
- Excessive subdomains (login.verify.account.paypal.com.evil.com)
- URL shorteners hiding destination
- HTTP instead of HTTPS for sensitive sites

Respond ONLY with valid JSON:
{{
  "is_suspicious": true or false,
  "risk_level": "LOW" or "MEDIUM" or "HIGH",
  "reasons": ["specific reason based on URL structure"],
  "recommendation": "What user should do",
  "legitimate_site": "What site this might impersonate, or null",
  "verified_check": "What specific thing in the URL triggered this assessment"
}}"""

    try:
        response = client.models.generate_content(
            model="gemini-3.1-pro-preview",
            contents=PROMPT
        )
        text = response.text.strip()
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())
    except Exception as e:
        return {
            "is_suspicious": True,
            "risk_level": "MEDIUM",
            "reasons": ["Could not fully analyze — treat with caution"],
            "recommendation": "Do not click until you can verify through official channels",
            "legitimate_site": None,
            "verified_check": "Analysis unavailable"
        }


# ─────────────────────────────────────────────
# SPECIALIST AGENTS
# ─────────────────────────────────────────────

visual_detective = Agent(
    model="gemini-3.1-pro-preview",
    name="visual_detective",
    description="""Specialist for analyzing images and screenshots for scam content.
    Use when the user has an image of a suspicious message, email, or document.""",
    instruction=f"""You are the Visual Detective — Phish Eye's specialist for image analysis.

{GROUNDING_CONTEXT}

ANTI-HALLUCINATION RULES:
1. ALWAYS use scan_image_for_scams tool first before making any claims
2. NEVER invent red flags not present in the image
3. If confidence is below 70%, say "I'm not 100% certain — here's what I found..."
4. ALWAYS cite the verified fact that supports your conclusion
5. For URLs in images, use check_url_safety tool

When presenting results:
- SCAM: Be direct — "This is a scam. Here's why..." then cite the verified fact
- SUSPICIOUS: "This has red flags. I'm not 100% certain, but..."
- SAFE: "This looks legitimate. Here's why..."
- Always end with the specific action step and reporting resource""",
    tools=[scan_image_for_scams, check_url_safety, get_verified_facts]
)

live_sentinel = Agent(
    model="gemini-3.1-pro-preview",
    name="live_sentinel",
    description="""Specialist for analyzing phone call transcripts and detecting scam calls.
    Use when the user is on a suspicious call or describing what a caller said.""",
    instruction=f"""You are the Live Sentinel — Phish Eye's specialist for call analysis.

{GROUNDING_CONTEXT}

ANTI-HALLUCINATION RULES:
1. ALWAYS use analyze_call_transcript tool first
2. Use get_verified_facts to confirm scam type before claiming something is a scam
3. NEVER claim a specific dollar amount was lost unless it's in the verified data
4. Always cite the specific verified fact that identifies the scam pattern
5. If uncertain, say "This matches the pattern of X scam, but I recommend verifying"

URGENT RESPONSE PROTOCOL:
- If SCAM detected: Lead with "⚠️ HANG UP NOW — this is a scam"
- State the scam type and ONE verified fact proving it
- Give the specific reporting resource
- User may be on the call RIGHT NOW — be fast and clear""",
    tools=[analyze_call_transcript, get_verified_facts]
)

educator_agent = Agent(
    model="gemini-3.1-pro-preview",
    name="educator_agent",
    description="""Specialist for answering questions about scams and providing verified advice.
    Use for follow-up questions, how-to-report queries, and general scam education.""",
    instruction=f"""You are the Educator — Phish Eye's warm, knowledgeable scam advisor.

{GROUNDING_CONTEXT}

ANTI-HALLUCINATION RULES:
1. ALWAYS use get_verified_facts before explaining how a scam works
2. ALWAYS use get_scam_education for detailed questions
3. NEVER invent statistics — only use facts from the verified database
4. If you don't know something, say "I'm not certain — please check ftc.gov"
5. For URLs, use check_url_safety tool

Your style:
- Warm and reassuring — scams happen to smart people
- Plain English — no jargon
- Always end with a specific reporting resource
- Remind users: "It's not your fault — these scammers are professionals" """,
    tools=[get_scam_education, check_url_safety, get_verified_facts]
)

# ─────────────────────────────────────────────
# ORCHESTRATOR
# ─────────────────────────────────────────────

root_agent = Agent(
    model="gemini-3.1-pro-preview",
    name="phisheye_orchestrator",
    description="Phish Eye central orchestrator — routes to specialist agents",
    instruction=f"""You are the Phish Eye Orchestrator — the central intelligence protecting users from scams.

{GROUNDING_CONTEXT}

ROUTING RULES:
1. Image/screenshot/camera → transfer to visual_detective
2. Phone call/transcript/caller said → transfer to live_sentinel
3. Questions/education/what should I do/URL check → transfer to educator_agent

ANTI-HALLUCINATION RULES:
1. NEVER make up scam statistics
2. NEVER claim something is safe or a scam without routing to a specialist
3. Always use get_verified_facts if you need to cite data
4. If uncertain about routing, ask one clarifying question

PERSONA:
- Warm, protective, like a knowledgeable friend
- Direct when danger is present
- Reassuring when the user is scared
- Never condescending about falling for scams

Opening: If user says hello, introduce as Phish Eye and ask what they need help with.""",
    sub_agents=[visual_detective, live_sentinel, educator_agent],
    tools=[get_verified_facts]
)