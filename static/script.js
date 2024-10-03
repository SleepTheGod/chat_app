const socket = io.connect('http://127.0.0.1:5000');

document.getElementById('send-button').onclick = function () {
    const messageInput = document.getElementById('message-input');
    const message = messageInput.value;

    // Encrypt the message
    const encryptedMessage = encryptMessage(message);

    socket.emit('message', { message: encryptedMessage });

    messageInput.value = '';
};

document.getElementById('upload-button').onclick = function () {
    const fileInput = document.getElementById('file-input');
    const file = fileInput.files[0];
    
    const reader = new FileReader();
    reader.onload = function (event) {
        // Encrypt the file data
        const encryptedFileData = encryptFile(event.target.result);
        socket.emit('file_upload', { file: encryptedFileData, filename: file.name });
    };

    if (file) {
        reader.readAsArrayBuffer(file);
    }
};

socket.on('message', function (data) {
    const messagesDiv = document.getElementById('messages');
    messagesDiv.innerHTML += `<div><strong>${data.username}:</strong> ${data.message}</div>`;
});

socket.on('file_uploaded', function (data) {
    const messagesDiv = document.getElementById('messages');
    messagesDiv.innerHTML += `<div><strong>${data.username}</strong> uploaded: ${data.filename}</div>`;
});

// Logout function
function logout() {
    window.location.href = '/logout';
}

// Encrypt message (real encryption function)
function encryptMessage(message) {
    const encoder = new TextEncoder();
    const data = encoder
