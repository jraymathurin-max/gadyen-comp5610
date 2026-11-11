const chatBox = document.getElementById("chat-box")
const userInput = document.getElementById("user-input")
const sendBtn = document.getElementById("send-btn")

function addMessage(message, className) {
    const msgDiv = document.createElement("div")
    msgDiv.classList.add("message", className);
    msgDiv.textContent = message;
    chatBox.appendChild(msgDiv);
    chatBox.scrollTop = chatBox.scrollHeight;
}

function showTyping() {
    const typingDiv = document.createElement("div");
    typingDiv.classList.add("message", "bot-message");
    typingDiv.textContent = "AI is typing";
    chatBox.appendChild(typingDiv);
    chatBox.scrollTop = chatBox.scrollHeight;
    return typingDiv
}

async function getBotReply(msg){
    const res = await fetch("/chat", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({message: msg})

    })
    if (res.status === 401) {
        window.location.href = "/"
        return ""
    }
    const data = await res.json()
    return data.reply
}

sendBtn.onclick = async () => {
    const message = userInput.value.trim()
    if (message === "") return;
    addMessage(message, "user-message");
    userInput.value = "";

    const typingDiv = showTyping();
    const botReply = await getBotReply(message);
    typingDiv.remove();
    addMessage(botReply, "bot-message");

    localStorage.setItem("chatHistory", chatBox.innerHTML);
}

userInput.addEventListener('keypress', (e) => {
    if (e.key === "Enter") sendBtn.click();
})

