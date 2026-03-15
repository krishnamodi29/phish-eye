
# Phish Eye — AI Scam Guardian

> Real-time scam detection powered by Gemini AI. Point your camera at a suspicious message, upload a screenshot, talk to the voice agent, or analyze a suspicious call — Phish Eye tells you instantly if it's a scam.

**🌐 Live Demo:** https://phisheyes-277004506145.us-central1.run.app

---

## 🏆 Built For
**Gemini Live Agent Challenge** — Google & Devpost
Track: Live Agents | Deadline: March 16, 2026

---

## 🎯 The Problem

Americans lost $12.5 billion to scams in 2024. The elderly and non-tech-savvy are the most targeted. At Telstra, I watched a customer lose $60,000 to a phishing email. She walked in crying, asking if it was real. By then it was too late.

**Phish Eye means nobody hears "I'm sorry, it's too late" ever again.**

---

## ✨ Features

| Tab | What It Does |
|-----|-------------|
| 📁 **Upload** | Drag & drop a screenshot → instant scam analysis |
| 📸 **Camera** | Point camera at suspicious message → live analysis |
| 🎙️ **Live Agent** | Voice conversation with Phish Eye AI |
| 📞 **Call Guard** | Paste call transcript → detect scam patterns |

Every scan returns:
- 🟢 SAFE / 🟡 SUSPICIOUS / 🔴 SCAM verdict
- Confidence score
- Red flags list
- Action card (what to do next)
- AI chat panel for follow-up questions
- Read aloud via Google Cloud TTS

---

## 🏗️ Architecture

```
User (browser)
    ↓ image / voice / text
Flask Backend (Google Cloud Run)
    ↓
Gemini 3.1 Pro Preview (vision + text)
    ↓
JSON response (threat_level, red_flags, action)
    ↓
Google Cloud TTS (Journey-F voice)
    ↓
User (voice + visual result)
```

---

## 🔧 Tech Stack

- **Gemini 3.1 Pro Preview** — vision + text AI (Google GenAI SDK)
- **Flask** — Python backend
- **Google Cloud Run** — serverless deployment
- **Google Cloud TTS** — natural voice (Journey-F)
- **Web Speech API** — voice input (Chrome)
- **Python 3.13**

---

## 🚀 Run Locally

### Prerequisites
- Python 3.10+
- A Gemini API key from [Google AI Studio](https://aistudio.google.com/app/apikey)

### Setup

```bash
# Clone the repo
git clone https://github.com/krishnamodi29/phish-eye.git
cd phish-eye

# Install dependencies
pip3 install -r requirements.txt

# Create .env file
echo "GEMINI_API_KEY=your_key_here" > .env

# Run the app
python3 main.py
```

Open **http://localhost:8080** in Chrome.

> ⚠️ Voice features require Chrome browser (Web Speech API)

---

## 📦 Requirements

```
flask
google-genai
google-cloud-texttospeech
python-dotenv
Pillow
```

---

## ☁️ Deploy to Google Cloud Run

```bash
# Authenticate
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

# Deploy
gcloud run deploy phisheyes \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars GEMINI_API_KEY=your_key_here
```

---

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main UI |
| `/analyze` | POST | Analyze image for scams |
| `/chat` | POST | AI follow-up chat |
| `/voice-analyze` | POST | Analyze voice transcript |
| `/tts` | POST | Text to speech |
| `/health` | GET | Health check |

---

## 🧪 Testing

```bash
# Quick smoke test (requires app running)
python3 test_smoke.py

# Full integration tests
python3 test_integration.py

# Unit tests (mocked)
python3 test_backend.py
```

---

## 👤 Built By

**Krishna Modi** — CS, Cybersecurity & Data Science student  
University of Western Australia | Based in New Jersey, USA  
GDG Member — Colonia, New Jersey

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

*Built with ❤️ and a lot of ☕ for the Gemini Live Agent Challenge 2026*