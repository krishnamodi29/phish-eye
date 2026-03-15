"""
Phish Eye — ADK Multi-Agent System
Orchestrator + 3 specialist agents: Visual Detective, Live Sentinel, Educator
"""

import os
import base64
from google.adk.agents import Agent
from google import genai

# ─────────────────────────────────────────────
# TOOLS — these are what the agents can call
# ─────────────────────────────────────────────

def scan_image_for_scams(image_b64: str) -> dict:
    """
    Analyzes a base64-encoded image for scam indicators.
    Returns threat_level (SAFE/SUSPICIOUS/SCAM), red_flags, summary, and action.
    
    Args:
        image_b64: Base64-encoded image string
    Returns:
        dict with threat_level, confidence, summary, red_flags, action, explanation
    """
    import json
    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
    
    PROMPT = """You are an expert scam detection AI. Analyze this image for phishing, scams, or fraud.

Respond ONLY with valid JSON in this exact format:
{
  "threat_level": "SAFE" or "SUSPICIOUS" or "SCAM",
  "confidence": 85,
  "summary": "One sentence summary",
  "red_flags": ["flag1", "flag2"],
  "action": "What the user should do",
  "explanation": "Simple explanation for non-tech users"
}"""

    try:
        image_bytes = base64.b64decode(image_b64)
        image_part = {"inline_data": {"mime_type": "image/jpeg", "data": base64.b64encode(image_bytes).decode()}}
        response = client.models.generate_content(
            model="gemini-3.1-pro-preview",
            contents=[PROMPT, image_part]
        )
        text = response.text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())
    except Exception as e:
        return {
            "threat_level": "SUSPICIOUS",
            "confidence": 50,
            "summary": "Could not fully analyze — treat with caution",
            "red_flags": ["Analysis error — verify manually"],
            "action": "When in doubt, do not click any links or provide personal info",
            "explanation": f"Analysis encountered an issue: {str(e)}"
        }


def analyze_call_transcript(transcript: str) -> dict:
    """
    Analyzes a phone call transcript for scam patterns including
    urgency tactics, impersonation, AI voice cloning signals, and money requests.
    
    Args:
        transcript: Text of what the caller said
    Returns:
        dict with threat_level, scam_type, red_flags, and recommended_action
    """
    import json
    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
    
    PROMPT = f"""You are a scam call detection expert. Analyze this phone call transcript for scam patterns.

Look for: urgency tactics, gift card requests, impersonation (IRS/bank/police), 
AI voice cloning signals, prize scams, grandparent scams, tech support scams.

Transcript: "{transcript}"

Respond ONLY with valid JSON:
{{
  "threat_level": "SAFE" or "SUSPICIOUS" or "SCAM",
  "confidence": 90,
  "scam_type": "Type of scam detected or None",
  "summary": "One sentence summary",
  "red_flags": ["flag1", "flag2"],
  "action": "What to do right now",
  "explanation": "Simple explanation"
}}"""

    try:
        response = client.models.generate_content(
            model="gemini-3.1-pro-preview",
            contents=PROMPT
        )
        text = response.text.strip()
        if text.startswith("```"):
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
            "red_flags": ["Analysis error"],
            "action": "Do not provide personal information or money",
            "explanation": str(e)
        }


def get_scam_education(scam_type: str, user_question: str) -> dict:
    """
    Provides educational information about a specific scam type.
    Explains how the scam works, who is targeted, and how to report it.
    
    Args:
        scam_type: Type of scam (e.g. "IRS impersonation", "phishing email", "AI voice cloning")
        user_question: The user's specific question
    Returns:
        dict with explanation, how_it_works, who_is_targeted, how_to_report, and prevention_tips
    """
    import json
    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
    
    PROMPT = f"""You are a friendly scam education expert. Answer this question about {scam_type} scams.

User question: "{user_question}"

Respond ONLY with valid JSON:
{{
  "answer": "Direct answer to the question in plain English",
  "how_it_works": "Brief explanation of how this scam operates",
  "who_is_targeted": "Who scammers typically target",
  "how_to_report": "Where and how to report this scam",
  "prevention_tips": ["tip1", "tip2", "tip3"]
}}"""

    try:
        response = client.models.generate_content(
            model="gemini-3.1-pro-preview",
            contents=PROMPT
        )
        text = response.text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())
    except Exception as e:
        return {
            "answer": "I had trouble processing that question. Please try again.",
            "how_it_works": "",
            "who_is_targeted": "",
            "how_to_report": "Report to FTC at reportfraud.ftc.gov",
            "prevention_tips": ["Stay cautious", "Never share personal info"]
        }


def check_url_safety(url: str) -> dict:
    """
    Checks if a URL looks safe or suspicious based on common phishing patterns.
    
    Args:
        url: The URL to check
    Returns:
        dict with is_suspicious, risk_level, reasons, and recommendation
    """
    import json
    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
    
    PROMPT = f"""You are a cybersecurity expert analyzing URLs for phishing/scam indicators.

Analyze this URL: {url}

Check for: misspellings, lookalike domains, suspicious TLDs, IP addresses instead of domains,
excessive subdomains, URL shorteners hiding destinations, and other red flags.

Respond ONLY with valid JSON:
{{
  "is_suspicious": true or false,
  "risk_level": "LOW" or "MEDIUM" or "HIGH",
  "reasons": ["reason1", "reason2"],
  "recommendation": "What the user should do",
  "legitimate_site": "What site this might be trying to impersonate, or null"
}}"""

    try:
        response = client.models.generate_content(
            model="gemini-3.1-pro-preview",
            contents=PROMPT
        )
        text = response.text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())
    except Exception as e:
        return {
            "is_suspicious": True,
            "risk_level": "MEDIUM",
            "reasons": ["Could not fully analyze URL"],
            "recommendation": "Treat with caution — do not click until verified",
            "legitimate_site": None
        }


# ─────────────────────────────────────────────
# SPECIALIST AGENTS
# ─────────────────────────────────────────────

visual_detective = Agent(
    model="gemini-3.1-pro-preview",
    name="visual_detective",
    description="""Specialist agent for analyzing images and screenshots for scam content.
    Use this agent when the user has uploaded or captured an image of a suspicious message,
    email, text, or document that needs visual analysis.""",
    instruction="""You are the Visual Detective — a specialist in analyzing images for scam content.
    
When given an image to analyze:
1. Use the scan_image_for_scams tool to analyze it
2. Present the results clearly and compassionately
3. If it's a SCAM, be direct but calm — don't panic the user
4. If SUSPICIOUS, explain what's concerning
5. If SAFE, reassure the user
6. Always end with a clear action step

Remember: users are often scared or embarrassed. Be warm and supportive.""",
    tools=[scan_image_for_scams, check_url_safety]
)

live_sentinel = Agent(
    model="gemini-3.1-pro-preview",
    name="live_sentinel",
    description="""Specialist agent for analyzing phone call transcripts and detecting
    scam calls in real time. Use when the user is on a suspicious call or describing
    what a caller said.""",
    instruction="""You are the Live Sentinel — a specialist in detecting scam phone calls.

When analyzing a call:
1. Use analyze_call_transcript to check for scam patterns
2. Be URGENT if it's a SCAM — the user may be on the call RIGHT NOW
3. Tell them clearly: "This is a scam. Hang up now."
4. Explain what type of scam it is
5. Tell them what to do next (report, block, etc.)

Common scams to watch for: IRS impersonation, bank fraud alerts, grandparent scams,
tech support scams, prize/lottery scams, AI voice cloning of family members.""",
    tools=[analyze_call_transcript, get_scam_education]
)

educator_agent = Agent(
    model="gemini-3.1-pro-preview",
    name="educator_agent",
    description="""Specialist agent for answering questions about scams, explaining how
    they work, and providing advice on what to do after encountering a scam.""",
    instruction="""You are the Educator — a warm, patient expert who explains scams simply.

Your job:
1. Answer questions about specific scam types using get_scam_education
2. Explain scams in plain language — no jargon
3. Provide clear reporting guidance
4. Check suspicious URLs using check_url_safety
5. Be encouraging — scams happen to everyone, it's not the user's fault

Always remind users: Report scams to reportfraud.ftc.gov (USA) or their local authority.""",
    tools=[get_scam_education, check_url_safety]
)


# ─────────────────────────────────────────────
# ORCHESTRATOR — the main agent
# ─────────────────────────────────────────────

root_agent = Agent(
    model="gemini-3.1-pro-preview",
    name="phisheye_orchestrator",
    description="Phish Eye AI orchestrator — routes scam detection requests to specialist agents",
    instruction="""You are the Phish Eye Orchestrator — the central intelligence of the Phish Eye scam detection system.

Your role is to understand what the user needs and route to the right specialist:

1. **Image/screenshot analysis** → transfer to visual_detective
   - User uploaded an image, screenshot, photo
   - User captured something with their camera
   - User says "look at this" with an image

2. **Phone call analysis** → transfer to live_sentinel  
   - User is on a suspicious call right now
   - User describes what a caller said
   - User pastes a call transcript
   - User mentions getting a call from IRS, bank, Microsoft, etc.

3. **Questions and education** → transfer to educator_agent
   - User asks "is this a scam?"
   - User asks "what should I do?"
   - User wants to know how to report
   - User asks about a suspicious URL or link
   - General scam questions

Always be warm, clear, and direct. The people using Phish Eye may be scared or
confused. Your job is to protect them and make them feel supported.

Opening message if the user just says hello: Introduce yourself as Phish Eye and
ask what they need help with — image to analyze, suspicious call, or a question.""",
    sub_agents=[visual_detective, live_sentinel, educator_agent]
)