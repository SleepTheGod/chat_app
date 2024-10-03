from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random secret key
socketio = SocketIO(app)

# Generate a key for encryption (In a real app, store and manage keys securely)
key = Fernet.generate_key()
cipher = Fernet(key)

# File upload folder
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('message')
def handle_message(data):
    decrypted_message = cipher.decrypt(data['message'].encode()).decode()
    emit('message', {'message': decrypted_message}, broadcast=True)

@socketio.on('file_upload')
def handle_file_upload(data):
    file_data = data['file']
    filename = data['filename']
    
    # Save the file securely
    with open(os.path.join(UPLOAD_FOLDER, filename), 'wb') as file:
        file.write(cipher.decrypt(file_data.encode()))
    
    emit('file_uploaded', {'filename': filename}, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True)

