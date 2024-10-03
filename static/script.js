const socket = io.connect('http://localhost:5000');

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
    messagesDiv.innerHTML += '<div>' + data.message + '</div>';
});

socket.on('file_uploaded', function (data) {
    const messagesDiv = document.getElementById('messages');
    messagesDiv.innerHTML += '<div>File uploaded: ' + data.filename + '</div>';
});

// Encrypt message (dummy function for demonstration, implement proper encryption)
function encryptMessage(message) {
    return btoa(message); // Base64 encoding as a placeholder
}

// Encrypt file (dummy function for demonstration, implement proper encryption)
function encryptFile(fileData) {
    return btoa(fileData); // Base64 encoding as a placeholder
}

