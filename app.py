import os
import json
import base64
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp3', 'wav'}
SECRET_KEY = os.urandom(16)  # Generate a random key for AES encryption
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = os.urandom(24)  # Set a secret key for session management
CORS(app, resources={r"/socket.io/*": {"origins": "*"}})  # Allow all origins
socketio = SocketIO(app)

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Helper function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# AES encryption/decryption
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return json.dumps({'iv': iv, 'ciphertext': ct})

def decrypt_message(enc_message, key):
    enc_message = json.loads(enc_message)
    iv = base64.b64decode(enc_message['iv'])
    ct = base64.b64decode(enc_message['ciphertext'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

# Routes
@app.route('/')
def index():
    # Redirect to login if not logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html')  # Render the chat page

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        session['username'] = username  # Store username in session
        return redirect(url_for('index'))  # Redirect to the chat page
    return render_template('login.html')  # Render login page

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'message': 'File uploaded successfully', 'filename': filename}), 200
    return jsonify({'error': 'File type not allowed'}), 400

@socketio.on('message')
def handle_message(data):
    # Decrypt incoming message
    try:
        decrypted_message = decrypt_message(data['message'], SECRET_KEY)
        print(f'Received message: {decrypted_message}')
        # Broadcast encrypted message
        encrypted_message = encrypt_message(decrypted_message, SECRET_KEY)
        emit('message', {'message': encrypted_message}, broadcast=True)
    except Exception as e:
        print(f'Error decrypting message: {e}')
        emit('message', {'error': 'Failed to decrypt message'}, broadcast=True)

# Main entry point
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
