import os
from flask import Flask, request, jsonify, render_template
from scanner import analyze_image
from dotenv import load_dotenv
from google import genai

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({'status': 'PhishEyes is running!', 'version': '1.0'})

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'image' not in request.files:
        return jsonify({'error': 'No image provided'}), 400
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    image_data = file.read()
    mime_type = file.content_type or 'image/jpeg'
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

    system = """You are PhishEyes, a friendly spoken AI scam assistant.
Answer in 1-2 SHORT punchy sentences ONLY — your response will be read aloud.
Be warm, direct, and conversational. No bullet points, no markdown, no lists."""

    conversation = system + "\n\n"
    for entry in history[-6:]:
        if entry.get('role') in ('user', 'assistant'):
            role = "User" if entry['role'] == 'user' else "PhishEyes"
            conversation += f"{role}: {entry['content']}\n"
    conversation += f"User: {question}\nPhishEyes:"

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
    """Convert text to speech using Google Cloud TTS for better voice quality."""
    import base64
    from google.cloud import texttospeech
    
    data = request.get_json()
    text = data.get('text', '')
    
    try:
        tts_client = texttospeech.TextToSpeechClient()
        synthesis_input = texttospeech.SynthesisInput(text=text)
        voice = texttospeech.VoiceSelectionParams(
            language_code="en-US",
            name="en-US-Journey-F",  # Natural, expressive female voice
            ssml_gender=texttospeech.SsmlVoiceGender.FEMALE
        )
        audio_config = texttospeech.AudioConfig(
            audio_encoding=texttospeech.AudioEncoding.MP3,
            speaking_rate=1.05,
            pitch=1.0
        )
        response = tts_client.synthesize_speech(
            input=synthesis_input,
            voice=voice,
            audio_config=audio_config
        )
        audio_b64 = base64.b64encode(response.audio_content).decode('utf-8')
        return jsonify({'audio': audio_b64})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    message = data.get('message', '')
    history = data.get('history', [])
    scan_context = data.get('scan_context', {})

    system_prompt = f"""You are PhishEyes, a friendly AI scam detection assistant.
You just analyzed a message for the user. Here are your findings:
Threat Level: {scan_context.get('threat_level', 'UNKNOWN')}
Summary: {scan_context.get('summary', '')}
Red Flags: {', '.join(scan_context.get('red_flags', [])) or 'None'}
Action: {scan_context.get('action', '')}
Explanation: {scan_context.get('explanation', '')}

Answer in plain English. Users are NOT tech-savvy. Be warm, clear, 2-4 sentences max."""

    conversation = system_prompt + "\n\n"
    for entry in history[-8:]:
        if entry.get('role') in ('user', 'assistant'):
            role = "User" if entry['role'] == 'user' else "PhishEyes"
            conversation += f"{role}: {entry['content']}\n"
    conversation += f"User: {message}\nPhishEyes:"

    try:
        response = client.models.generate_content(
            model="gemini-3.1-pro-preview",
            contents=conversation
        )
        reply = response.text.strip()
    except Exception as e:
        reply = "I'm having trouble connecting right now. Please try again."

    return jsonify({'reply': reply})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)