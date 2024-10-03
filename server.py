from flask import Flask, render_template, request, redirect, session, send_from_directory, jsonify
from flask_socketio import SocketIO, emit
import os
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
import base64
import json
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a strong secret key
socketio = SocketIO(app)

# Setup upload directories
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp3', 'wav', 'txt', 'pdf'}  # Add other allowed file types

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# AES encryption/decryption
def encrypt_message(message):
    key = hashlib.sha256(app.secret_key.encode()).digest()  # Use SHA-256 for the key
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return json.dumps({
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(tag).decode()
    })

def decrypt_message(enc_message):
    enc_data = json.loads(enc_message)
    nonce = base64.b64decode(enc_data['nonce'])
    ciphertext = base64.b64decode(enc_data['ciphertext'])
    tag = base64.b64decode(enc_data['tag'])
    key = hashlib.sha256(app.secret_key.encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode()

@app.route('/')
def index():
    if 'username' not in session:
        return redirect('/login')
    return render_template('chat.html', username=session['username'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        session['username'] = username
        return redirect('/')
    return render_template('login.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        return jsonify({'message': 'File uploaded successfully', 'filename': filename})
    return jsonify({'error': 'File type not allowed'})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@socketio.on('message')
def handle_message(data):
    try:
        decrypted_message = decrypt_message(data['message'])
        print(f"Received message: {decrypted_message}")
        # Broadcast the encrypted message to all connected clients
        encrypted_message = encrypt_message(decrypted_message)
        emit('message', {'message': encrypted_message}, broadcast=True)
    except Exception as e:
        print(f"Error decrypting message: {e}")
        emit('message', {'error': 'Failed to decrypt message'})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
