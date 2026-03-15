import os
import base64
import asyncio
from flask import Flask, request, jsonify, render_template
from scanner import analyze_image
from dotenv import load_dotenv
from google import genai

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# ── ADK — loaded lazily on first /agent call ───────────────────────────────────
_adk_runner = None
_session_service = None
APP_NAME = "phisheye"

def get_adk():
    """Initialize ADK runner on first use — avoids startup crash if import fails."""
    global _adk_runner, _session_service
    if _adk_runner is None:
        from google.adk.runners import Runner
        from google.adk.sessions import InMemorySessionService
        from phisheye_agent.agent import root_agent
        _session_service = InMemorySessionService()
        _adk_runner = Runner(
            agent=root_agent,
            app_name=APP_NAME,
            session_service=_session_service
        )
    return _adk_runner, _session_service


async def run_adk_agent(user_id: str, session_id: str, message: str) -> str:
    from google.genai import types as genai_types
    runner, session_service = get_adk()

    try:
        session = await session_service.get_session(
            app_name=APP_NAME, user_id=user_id, session_id=session_id
        )
        if session is None:
            await session_service.create_session(
                app_name=APP_NAME, user_id=user_id, session_id=session_id
            )
    except Exception:
        await session_service.create_session(
            app_name=APP_NAME, user_id=user_id, session_id=session_id
        )

    content = genai_types.Content(
        role="user",
        parts=[genai_types.Part(text=message)]
    )
    final_response = ""
    async for event in runner.run_async(
        user_id=user_id, session_id=session_id, new_message=content
    ):
        if event.is_final_response():
            if event.content and event.content.parts:
                final_response = event.content.parts[0].text
    return final_response


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/health')
def health():
    return jsonify({
        'status': 'Phish Eye is running!',
        'version': '2.0',
        'adk': 'enabled',
        'agents': ['phisheye_orchestrator', 'visual_detective', 'live_sentinel', 'educator_agent']
    })


@app.route('/analyze', methods=['POST'])
def analyze():
    if request.files and 'image' in request.files:
        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        image_data = file.read()
        mime_type = file.content_type or 'image/jpeg'
    elif request.is_json:
        data = request.get_json()
        if not data or 'image' not in data:
            return jsonify({'error': 'No image provided'}), 400
        try:
            image_data = base64.b64decode(data['image'])
        except Exception:
            return jsonify({'error': 'Invalid base64 image data'}), 400
        mime_type = data.get('mime_type', 'image/jpeg')
    else:
        return jsonify({'error': 'No image provided'}), 400

    try:
        result = analyze_image(image_data, mime_type)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/voice-analyze', methods=['POST'])
def voice_analyze():
    data = request.get_json()
    question = data.get('question', '')
    history = data.get('history', [])

    system = """You are Phish Eye, a friendly spoken AI scam assistant.
Answer in 1-2 SHORT punchy sentences ONLY — your response will be read aloud.
Be warm, direct, and conversational. No bullet points, no markdown, no lists."""

    conversation = system + "\n\n"
    for entry in history[-6:]:
        if entry.get('role') in ('user', 'assistant'):
            role = "User" if entry['role'] == 'user' else "Phish Eye"
            conversation += f"{role}: {entry['content']}\n"
    conversation += f"User: {question}\nPhish Eye:"

    try:
        response = client.models.generate_content(
            model="gemini-3.1-pro-preview",
            contents=conversation
        )
        return jsonify({'answer': response.text.strip()})
    except Exception as e:
        return jsonify({'answer': "Sorry, I had trouble with that. Could you repeat?"})


@app.route('/tts', methods=['POST'])
def text_to_speech():
    data = request.get_json()
    if not data or not data.get('text'):
        return jsonify({'error': 'No text provided', 'fallback': True}), 400

    text = data['text']
    try:
        from google.cloud import texttospeech
        tts_client = texttospeech.TextToSpeechClient()
        synthesis_input = texttospeech.SynthesisInput(text=text)
        voice = texttospeech.VoiceSelectionParams(
            language_code="en-US",
            name="en-US-Journey-F",
            ssml_gender=texttospeech.SsmlVoiceGender.FEMALE
        )
        audio_config = texttospeech.AudioConfig(
            audio_encoding=texttospeech.AudioEncoding.MP3,
            speaking_rate=1.05,
            pitch=1.0
        )
        response = tts_client.synthesize_speech(
            input=synthesis_input, voice=voice, audio_config=audio_config
        )
        audio_b64 = base64.b64encode(response.audio_content).decode('utf-8')
        return jsonify({'audio': audio_b64})
    except Exception as e:
        return jsonify({'fallback': True, 'reason': str(e)}), 200


@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    message = data.get('message', '')
    history = data.get('history', [])
    scan_context = data.get('scan_context', {})

    system_prompt = f"""You are Phish Eye, a friendly AI scam detection assistant.
Threat Level: {scan_context.get('threat_level', 'UNKNOWN')}
Summary: {scan_context.get('summary', '')}
Red Flags: {', '.join(scan_context.get('red_flags', [])) or 'None'}
Action: {scan_context.get('action', '')}
Answer in plain English. Be warm, clear, 2-4 sentences max."""

    conversation = system_prompt + "\n\n"
    for entry in history[-8:]:
        if entry.get('role') in ('user', 'assistant'):
            role = "User" if entry['role'] == 'user' else "Phish Eye"
            conversation += f"{role}: {entry['content']}\n"
    conversation += f"User: {message}\nPhish Eye:"

    try:
        response = client.models.generate_content(
            model="gemini-3.1-pro-preview",
            contents=conversation
        )
        reply = response.text.strip()
    except Exception as e:
        reply = "I'm having trouble connecting right now. Please try again."

    return jsonify({'reply': reply})


# ── ADK AGENT ENDPOINT ─────────────────────────────────────────────────────────

@app.route('/agent', methods=['POST'])
def agent():
    """ADK Multi-Agent endpoint — routes through the Phish Eye orchestrator."""
    data = request.get_json()
    if not data or not data.get('message'):
        return jsonify({'error': 'No message provided'}), 400

    message = data.get('message', '')
    user_id = data.get('user_id', 'default_user')
    session_id = data.get('session_id', 'default_session')

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        response = loop.run_until_complete(
            run_adk_agent(user_id, session_id, message)
        )
        loop.close()
        return jsonify({
            'reply': response,
            'agent': 'phisheye_orchestrator',
            'adk_powered': True
        })
    except Exception as e:
        return jsonify({
            'reply': "I'm having trouble with the agent. Please try again.",
            'error': str(e)
        }), 500


@app.route('/agent/call', methods=['POST'])
def agent_call():
    """ADK Live Sentinel — analyze a call transcript."""
    data = request.get_json()
    transcript = data.get('transcript', '')
    if not transcript:
        return jsonify({'error': 'No transcript provided'}), 400

    user_id = data.get('user_id', 'default_user')
    session_id = data.get('session_id', 'call_session')
    message = f"I'm getting a suspicious phone call. Here's what they said: {transcript}"

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        response = loop.run_until_complete(
            run_adk_agent(user_id, session_id, message)
        )
        loop.close()
        return jsonify({'reply': response, 'adk_powered': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)