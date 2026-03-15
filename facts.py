"""
Phish Eye — Verified Scam Facts Database
All facts sourced from FTC, FBI IC3, and AARP Fraud Watch Network.
Used to ground ADK agents and prevent hallucinations.
"""

VERIFIED_FACTS = {
    "statistics": [
        "Americans lost $12.5 billion to scams in 2024 (FTC Consumer Sentinel Network)",
        "Imposter scams were the #1 fraud category in 2024 with $2.95 billion lost (FTC)",
        "People aged 60+ lost more money per person to scams than any other age group (FTC 2024)",
        "Investment scams caused the highest individual losses, averaging $21,000 per victim (FTC 2024)",
        "Phone calls are the #1 contact method for scammers targeting people over 60 (FTC)",
        "Gift card scams cost Americans $217 million in 2023 (FTC)",
        "AI voice cloning scams increased 300% in 2023-2024 (McAfee/AARP)",
        "Only 3 seconds of audio is needed to clone someone's voice with AI tools (McAfee 2023)",
        "1 in 4 Americans who received a scam contact lost money (FTC 2024)",
        "The FBI's IC3 received 880,418 complaints in 2023 with $12.5 billion in losses",
    ],

    "scam_types": {
        "irs_impersonation": {
            "description": "Scammers pretend to be IRS agents threatening arrest or legal action",
            "red_flags": [
                "IRS demands immediate payment by gift card, wire transfer, or cryptocurrency",
                "Threatens arrest, deportation, or license revocation",
                "Demands you stay on the phone until payment is made",
                "Calls about 'unpaid taxes' without sending a written notice first"
            ],
            "fact": "The IRS ALWAYS contacts taxpayers by mail first before calling. The IRS never demands gift cards.",
            "report_to": "reportphishing@irs.gov or 1-800-366-4484"
        },
        "bank_impersonation": {
            "description": "Scammers pretend to be from your bank's fraud department",
            "red_flags": [
                "Asks for your full account number, PIN, or online banking password",
                "Tells you to move money to a 'safe account'",
                "Says your account has been compromised and you must act immediately",
                "Asks you to buy gift cards to protect your money"
            ],
            "fact": "Banks NEVER ask you to move money to protect it. Banks NEVER ask for your PIN or full password.",
            "report_to": "Your bank's official fraud number on the back of your card"
        },
        "tech_support": {
            "description": "Scammers claim your computer has a virus and offer to fix it",
            "red_flags": [
                "Unsolicited call claiming to be from Microsoft, Apple, or Google",
                "Pop-up warning telling you to call a number immediately",
                "Asks for remote access to your computer",
                "Requests payment via gift cards or wire transfer for 'repairs'"
            ],
            "fact": "Microsoft, Apple, and Google NEVER make unsolicited calls about computer problems.",
            "report_to": "reportfraud.ftc.gov"
        },
        "grandparent_scam": {
            "description": "Scammers impersonate a grandchild or family member in distress",
            "red_flags": [
                "Urgent call saying 'Grandma/Grandpa, it's me, I'm in trouble'",
                "Asks you not to tell other family members",
                "Requests immediate cash, gift cards, or wire transfer",
                "Often followed by a 'lawyer' or 'police officer' call asking for bail money"
            ],
            "fact": "Always hang up and call the family member directly on their known number to verify.",
            "report_to": "reportfraud.ftc.gov or local police"
        },
        "lottery_prize": {
            "description": "Scammers claim you've won a prize or lottery you never entered",
            "red_flags": [
                "You must pay taxes or fees upfront to claim your prize",
                "Asks for your bank account to deposit winnings",
                "Creates urgency — 'claim within 24 hours'",
                "Prize from a lottery or contest you never entered"
            ],
            "fact": "You cannot win a contest or lottery you never entered. Legitimate prizes NEVER require upfront fees.",
            "report_to": "reportfraud.ftc.gov"
        },
        "phishing_email": {
            "description": "Fraudulent emails impersonating legitimate companies to steal credentials",
            "red_flags": [
                "Sender email address doesn't match the company's official domain",
                "Generic greeting like 'Dear Customer' instead of your name",
                "Urgent language: 'Your account will be suspended'",
                "Links that hover to show a different URL than displayed",
                "Asks for password, SSN, or credit card number via email"
            ],
            "fact": "Legitimate companies NEVER ask for passwords or full SSN via email.",
            "report_to": "reportphishing@apwg.org or forward to spam@uce.gov"
        },
        "ai_voice_cloning": {
            "description": "Scammers use AI to clone a family member's voice in distress calls",
            "red_flags": [
                "Voice sounds slightly robotic or unnatural",
                "Unexpected call from a family member claiming emergency",
                "Asks for immediate money transfer without verifying identity",
                "Refuses or is unable to answer personal questions only they would know",
                "Background noise sounds artificial or inconsistent"
            ],
            "fact": "AI can clone a voice from just 3 seconds of audio. Always verify by calling back on a known number.",
            "report_to": "reportfraud.ftc.gov and FBI IC3 at ic3.gov"
        },
        "romance_scam": {
            "description": "Scammers build fake romantic relationships to steal money",
            "red_flags": [
                "Met online and relationship progressed very quickly",
                "Never willing to meet in person or video call",
                "Asks for money for emergencies, travel, or medical bills",
                "Profile photos are too perfect (often stolen from models/military)"
            ],
            "fact": "Romance scammers cost Americans $1.3 billion in 2022 alone (FTC).",
            "report_to": "reportfraud.ftc.gov and FBI IC3 at ic3.gov"
        }
    },

    "payment_methods_never_used_by_legitimate_entities": [
        "Gift cards (iTunes, Google Play, Amazon, Steam)",
        "Wire transfers to unknown accounts",
        "Cryptocurrency (Bitcoin, Ethereum) for government or utility payments",
        "Zelle or Venmo payments to strangers",
        "Cash sent via overnight mail",
        "Money orders to claim prizes"
    ],

    "reporting_resources": {
        "usa_general": "reportfraud.ftc.gov",
        "fbi_ic3": "ic3.gov",
        "irs_scams": "reportphishing@irs.gov",
        "phishing_emails": "reportphishing@apwg.org",
        "medicare_fraud": "1-800-MEDICARE (1-800-633-4227)",
        "social_security": "oig.ssa.gov/report",
        "aarp_helpline": "1-877-908-3360 (AARP Fraud Watch Network Helpline)",
        "elder_fraud": "1-833-FRAUD-11 (DOJ Elder Fraud Hotline)"
    },

    "safety_rules": [
        "NEVER give out your Social Security Number over the phone unless YOU initiated the call",
        "NEVER pay anyone who demands gift cards as payment — this is ALWAYS a scam",
        "NEVER give remote access to your computer to someone who called you",
        "NEVER wire money to someone you've only met online",
        "ALWAYS hang up and call back on an official number to verify",
        "ALWAYS take 24 hours before making any large financial decision under pressure",
        "NEVER stay on hold while someone tells you to drive to the bank",
        "ALWAYS verify a family member emergency by calling them directly on their known number"
    ]
}


def get_facts_for_scam_type(scam_type: str) -> dict:
    """Get verified facts for a specific scam type."""
    scam_type_lower = scam_type.lower().replace(" ", "_")
    for key, value in VERIFIED_FACTS["scam_types"].items():
        if key in scam_type_lower or scam_type_lower in key:
            return value
    return {}


def get_safety_rules() -> list:
    """Get the core safety rules."""
    return VERIFIED_FACTS["safety_rules"]


def get_reporting_resource(country: str = "usa") -> dict:
    """Get reporting resources."""
    return VERIFIED_FACTS["reporting_resources"]


def format_facts_for_prompt() -> str:
    """Format key facts for injection into agent prompts."""
    rules = "\n".join(f"• {r}" for r in VERIFIED_FACTS["safety_rules"][:5])
    payment = "\n".join(f"• {p}" for p in VERIFIED_FACTS["payment_methods_never_used_by_legitimate_entities"][:4])
    return f"""
VERIFIED FACTS (use these to ground your responses):

Golden Rules — these are ALWAYS true:
{rules}

Legitimate organizations NEVER request payment via:
{payment}

Key statistic: Americans lost $12.5 billion to scams in 2024 (FTC).

Reporting: Always direct users to reportfraud.ftc.gov (USA) or ic3.gov for cybercrime.
"""