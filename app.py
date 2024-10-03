from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from cryptography.fernet import Fernet
import os
import logging
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Use a secure secret key
socketio = SocketIO(app)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# User management
users = {}  # A simple user store; consider using a database in a real application

# Logging setup
logging.basicConfig(level=logging.INFO, filename='chat.log', 
                    format='%(asctime)s %(levelname)s:%(message)s')

class User(UserMixin):
    def __init__(self, username):
        self.username = username

@login_manager.user_loader
def load_user(username):
    return users.get(username)

# Generate a key for encryption (In a real app, store and manage keys securely)
key = Fernet.generate_key()
cipher = Fernet(key)

# File upload folder
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        if username not in users:
            users[username] = User(username)
        login_user(users[username])
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@socketio.on('message')
@login_required
def handle_message(data):
    decrypted_message = cipher.decrypt(data['message'].encode()).decode()
    logging.info(f"{current_user.username}: {decrypted_message}")
    emit('message', {'message': decrypted_message, 'username': current_user.username}, broadcast=True)

@socketio.on('file_upload')
@login_required
def handle_file_upload(data):
    file_data = data['file']
    filename = data['filename']
    
    # Save the file securely
    with open(os.path.join(UPLOAD_FOLDER, filename), 'wb') as file:
        file.write(cipher.decrypt(file_data.encode()))
    
    logging.info(f"{current_user.username} uploaded: {filename}")
    emit('file_uploaded', {'filename': filename, 'username': current_user.username}, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
