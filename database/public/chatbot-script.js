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

    try {
        const botReply = await getBotReply(message);
        typingDiv.remove();
        if (botReply) {
            addMessage(botReply, "bot-message");
        }
    } catch(error) {
         typingDiv.remove();
         addMessage(
            "Sorry, something went wrong. Please try again.",
            "bot-message"
         );
         console.error(error)
    }

    localStorage.setItem("chatHistory", chatBox.innerHTML);
}

userInput.addEventListener('keypress', (e) => {
    if (e.key === "Enter") sendBtn.click();
})

async function loadChatHistory() {
    chatBox.innerHTML = "";
    try {
        const res = await fetch("/chat/history");
        if (res.status === 401) {
            window.location.href = "/";
            return;
        }

        if (!res.ok) {
            throw new Error("Could not generate greeting");
        }
        
        const history = await res.json();
        if (history.length > 0) {
            history.forEach(chat => {
                addMessage(
                    chat.content,
                    chat.role === "user"
                        ? "user-message"
                        : "bot-message"
                );
            });
        } else {
            await loadInitialGreeting();
        }
    } catch (error) {
        console.error(error);
        addMessage(
            "Unable to load chat. Please refresh the page.",
            "bot-message"
        );
    }
}

// Initial bot greeting when the page loads
async function loadInitialGreeting() {
    const typingDiv = showTyping();

    try {
        const res = await fetch("chat/welcome");
        if (res.status === 401) {
            window.location.href = "/";
            return;
        }
        if (!res.ok) {
            throw new Error("Could not generate greeting");
        }
        const data = await res.join();

        typingDiv.remove();
        if (data.reply) {
            addMessage(data.reply, "bot-message");
        }
    } catch {
        typingDiv.remove();
        addMessage(
            "Welcome to Gayden Safeguard! What language would you prefer to use?", "bot-message"
        );
        console.error(error);
    }
    window.addEventListener("DOMContentLoaded", loadChatHistory);
}

