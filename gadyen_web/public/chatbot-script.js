"use strict";

const chatBox = document.getElementById("chat-box");
const userInput = document.getElementById("user-input");
const sendBtn = document.getElementById("send-btn");
const langSelect = document.getElementById("lang-select");
const langPicker = document.getElementById("lang-picker");
const langOptions = document.getElementById("lang-options");
const sidebar = document.getElementById("sidebar");
const historyList = document.getElementById("history-list");
const historyEmpty = document.getElementById("history-empty");
const historyTitle = document.getElementById("history-title");
const newChatBtn = document.getElementById("new-chat-btn");
const historyToggle = document.getElementById("history-toggle");

/* ------------------------------------------------------------------
   Languages. The codes must match gadyen_web/languages.py on the server.
   ------------------------------------------------------------------ */
const LANGUAGES = [
    { code: "en", name: "English" },
    { code: "es", name: "Español" },
    { code: "zh", name: "中文" },
    { code: "tl", name: "Tagalog" },
    { code: "vi", name: "Tiếng Việt" },
    { code: "ar", name: "العربية", rtl: true },
    { code: "fr", name: "Français" },
    { code: "ko", name: "한국어" },
    { code: "pt", name: "Português" },
    { code: "ht", name: "Kreyòl Ayisyen" },
];

const UI = {
    en: {
        newChat: "New conversation", history: "Earlier conversations", noHistory: "No earlier conversations yet.",
        deleteChat: "Delete conversation", confirmDelete: "Delete?", showHistory: "Show conversations",
        placeholder: "Type your message", send: "Send", typing: "Gadyen is writing",
        language: "Language", note: "Language set to English.",
        unavailable: "The assistant could not answer. Wait a moment, then send your message again.",
        rate_limited: "Too many requests right now. Wait one minute, then send your message again.",
        empty: "The assistant could not answer that message. Try wording it differently.",
        network: "No connection to the server. Check your internet and try again.",
        too_long: "That message is too long. Shorten it and send it again.",
        load: "The conversation could not be loaded. Refresh the page.",
    },
    es: {
        newChat: "Nueva conversación", history: "Conversaciones anteriores", noHistory: "Aún no hay conversaciones anteriores.",
        deleteChat: "Eliminar conversación", confirmDelete: "¿Eliminar?", showHistory: "Ver conversaciones",
        placeholder: "Escriba su mensaje", send: "Enviar", typing: "Gadyen está escribiendo",
        language: "Idioma", note: "Idioma cambiado a español.",
        unavailable: "El asistente no pudo responder. Espere un momento y envíe su mensaje otra vez.",
        rate_limited: "Hay demasiadas solicitudes en este momento. Espere un minuto y envíe su mensaje otra vez.",
        empty: "El asistente no pudo responder a ese mensaje. Intente escribirlo de otra manera.",
        network: "No hay conexión con el servidor. Revise su internet e intente de nuevo.",
        too_long: "El mensaje es demasiado largo. Acórtelo y envíelo de nuevo.",
        load: "No se pudo cargar la conversación. Actualice la página.",
    },
    zh: {
        newChat: "新对话", history: "以前的对话", noHistory: "还没有以前的对话。",
        deleteChat: "删除对话", confirmDelete: "删除？", showHistory: "查看对话",
        placeholder: "请输入您的消息", send: "发送", typing: "Gadyen 正在输入",
        language: "语言", note: "语言已切换为中文。",
        unavailable: "助手暂时无法回答。请稍等片刻，然后重新发送您的消息。",
        rate_limited: "当前请求过多。请等待一分钟，然后重新发送您的消息。",
        empty: "助手无法回答这条消息。请换一种说法再试。",
        network: "无法连接到服务器。请检查网络后重试。",
        too_long: "消息太长。请缩短后重新发送。",
        load: "无法加载对话。请刷新页面。",
    },
    tl: {
        newChat: "Bagong usapan", history: "Mga nakaraang usapan", noHistory: "Wala pang nakaraang usapan.",
        deleteChat: "Burahin ang usapan", confirmDelete: "Burahin?", showHistory: "Ipakita ang mga usapan",
        placeholder: "I-type ang inyong mensahe", send: "Ipadala", typing: "Nagsusulat si Gadyen",
        language: "Wika", note: "Tagalog na ang wika.",
        unavailable: "Hindi nakasagot ang assistant. Maghintay sandali, pagkatapos ay ipadala muli ang inyong mensahe.",
        rate_limited: "Masyadong maraming kahilingan ngayon. Maghintay ng isang minuto, pagkatapos ay ipadala muli ang inyong mensahe.",
        empty: "Hindi nasagot ng assistant ang mensaheng iyon. Subukang isulat ito sa ibang paraan.",
        network: "Walang koneksyon sa server. Suriin ang inyong internet at subukang muli.",
        too_long: "Masyadong mahaba ang mensahe. Paikliin ito at ipadala muli.",
        load: "Hindi ma-load ang usapan. I-refresh ang page.",
    },
    vi: {
        newChat: "Cuộc trò chuyện mới", history: "Các cuộc trò chuyện trước", noHistory: "Chưa có cuộc trò chuyện nào trước đây.",
        deleteChat: "Xóa cuộc trò chuyện", confirmDelete: "Xóa?", showHistory: "Xem các cuộc trò chuyện",
        placeholder: "Nhập tin nhắn của bạn", send: "Gửi", typing: "Gadyen đang soạn",
        language: "Ngôn ngữ", note: "Đã chuyển sang tiếng Việt.",
        unavailable: "Trợ lý chưa trả lời được. Vui lòng chờ một lát rồi gửi lại tin nhắn.",
        rate_limited: "Hiện có quá nhiều yêu cầu. Vui lòng chờ một phút rồi gửi lại tin nhắn.",
        empty: "Trợ lý không trả lời được tin nhắn đó. Hãy thử diễn đạt theo cách khác.",
        network: "Không kết nối được với máy chủ. Hãy kiểm tra mạng và thử lại.",
        too_long: "Tin nhắn quá dài. Hãy rút ngắn rồi gửi lại.",
        load: "Không tải được cuộc trò chuyện. Hãy tải lại trang.",
    },
    ar: {
        newChat: "محادثة جديدة", history: "المحادثات السابقة", noHistory: "لا توجد محادثات سابقة بعد.",
        deleteChat: "حذف المحادثة", confirmDelete: "حذف؟", showHistory: "عرض المحادثات",
        placeholder: "اكتب رسالتك", send: "إرسال", typing: "Gadyen يكتب",
        language: "اللغة", note: "تم تغيير اللغة إلى العربية.",
        unavailable: "تعذّر على المساعد الرد. انتظر قليلًا ثم أرسل رسالتك مرة أخرى.",
        rate_limited: "الطلبات كثيرة الآن. انتظر دقيقة واحدة ثم أرسل رسالتك مرة أخرى.",
        empty: "تعذّر على المساعد الرد على هذه الرسالة. حاول صياغتها بطريقة أخرى.",
        network: "لا يوجد اتصال بالخادم. تحقق من الإنترنت وحاول مرة أخرى.",
        too_long: "الرسالة طويلة جدًا. اختصرها ثم أرسلها مرة أخرى.",
        load: "تعذّر تحميل المحادثة. حدّث الصفحة.",
    },
    fr: {
        newChat: "Nouvelle conversation", history: "Conversations précédentes", noHistory: "Aucune conversation précédente pour le moment.",
        deleteChat: "Supprimer la conversation", confirmDelete: "Supprimer ?", showHistory: "Afficher les conversations",
        placeholder: "Écrivez votre message", send: "Envoyer", typing: "Gadyen écrit",
        language: "Langue", note: "Langue changée : français.",
        unavailable: "L'assistant n'a pas pu répondre. Attendez un instant, puis renvoyez votre message.",
        rate_limited: "Trop de demandes en ce moment. Attendez une minute, puis renvoyez votre message.",
        empty: "L'assistant n'a pas pu répondre à ce message. Essayez de le formuler autrement.",
        network: "Pas de connexion au serveur. Vérifiez votre connexion internet et réessayez.",
        too_long: "Ce message est trop long. Raccourcissez-le et renvoyez-le.",
        load: "La conversation n'a pas pu être chargée. Actualisez la page.",
    },
    ko: {
        newChat: "새 대화", history: "이전 대화", noHistory: "이전 대화가 아직 없습니다.",
        deleteChat: "대화 삭제", confirmDelete: "삭제할까요?", showHistory: "대화 목록 보기",
        placeholder: "메시지를 입력하세요", send: "보내기", typing: "Gadyen이 작성 중입니다",
        language: "언어", note: "언어가 한국어로 변경되었습니다.",
        unavailable: "어시스턴트가 답변하지 못했습니다. 잠시 후 메시지를 다시 보내 주세요.",
        rate_limited: "지금 요청이 너무 많습니다. 1분 후 메시지를 다시 보내 주세요.",
        empty: "어시스턴트가 이 메시지에 답변하지 못했습니다. 다른 표현으로 다시 써 보세요.",
        network: "서버에 연결할 수 없습니다. 인터넷 연결을 확인한 후 다시 시도하세요.",
        too_long: "메시지가 너무 깁니다. 줄여서 다시 보내 주세요.",
        load: "대화를 불러오지 못했습니다. 페이지를 새로 고치세요.",
    },
    pt: {
        newChat: "Nova conversa", history: "Conversas anteriores", noHistory: "Ainda não há conversas anteriores.",
        deleteChat: "Excluir conversa", confirmDelete: "Excluir?", showHistory: "Ver conversas",
        placeholder: "Escreva a sua mensagem", send: "Enviar", typing: "Gadyen está escrevendo",
        language: "Idioma", note: "Idioma alterado para português.",
        unavailable: "O assistente não conseguiu responder. Aguarde um momento e envie a mensagem novamente.",
        rate_limited: "Há pedidos demais neste momento. Aguarde um minuto e envie a mensagem novamente.",
        empty: "O assistente não conseguiu responder a essa mensagem. Tente escrevê-la de outra forma.",
        network: "Sem conexão com o servidor. Verifique a internet e tente novamente.",
        too_long: "A mensagem é longa demais. Encurte-a e envie novamente.",
        load: "Não foi possível carregar a conversa. Atualize a página.",
    },
    ht: {
        newChat: "Nouvo konvèsasyon", history: "Ansyen konvèsasyon yo", noHistory: "Poko gen ansyen konvèsasyon.",
        deleteChat: "Efase konvèsasyon an", confirmDelete: "Efase?", showHistory: "Montre konvèsasyon yo",
        placeholder: "Ekri mesaj ou", send: "Voye", typing: "Gadyen ap ekri",
        language: "Lang", note: "Lang lan chanje: Kreyòl Ayisyen.",
        unavailable: "Asistan an pa t kapab reponn. Tann yon ti moman, epi voye mesaj ou a ankò.",
        rate_limited: "Gen twòp demann kounye a. Tann yon minit, epi voye mesaj ou a ankò.",
        empty: "Asistan an pa t kapab reponn mesaj sa a. Eseye ekri li yon lòt jan.",
        network: "Pa gen koneksyon ak sèvè a. Verifye entènèt ou epi eseye ankò.",
        too_long: "Mesaj la twò long. Fè li pi kout epi voye li ankò.",
        load: "Konvèsasyon an pa t kapab chaje. Aktyalize paj la.",
    },
};

const STORAGE_KEY = "gadyen.language";
let currentLang = null;
let onlyWelcomeShown = false;   // true while the chat holds nothing but the welcome text
let busy = false;
let currentConversationId = null;   // null = a new conversation, not saved yet

function t(key) {
    return (UI[currentLang] || UI.en)[key] || UI.en[key];
}

function readStoredLanguage() {
    try {
        const code = localStorage.getItem(STORAGE_KEY);
        return LANGUAGES.some(l => l.code === code) ? code : null;
    } catch (e) {
        return null;    // storage blocked (private mode): ask again next visit
    }
}

function storeLanguage(code) {
    try { localStorage.setItem(STORAGE_KEY, code); } catch (e) { /* not critical */ }
}

/* ------------------------------------------------------------------
   Message rendering. Text is placed with textContent / createElement
   only (never innerHTML), so nothing the model or a user writes can
   run as HTML or script.
   ------------------------------------------------------------------ */
function appendInline(parent, text) {
    // **bold** is the only inline formatting the agent may use
    const parts = text.split(/\*\*(.+?)\*\*/g);
    parts.forEach((part, i) => {
        if (!part) return;
        if (i % 2 === 1) {
            const strong = document.createElement("strong");
            strong.textContent = part;
            parent.appendChild(strong);
        } else {
            parent.appendChild(document.createTextNode(part));
        }
    });
}

// Safety net: if the agent still writes "A) ... B) ... C) ..." on one line,
// put each choice on its own line.
function splitInlineChoices(line) {
    const found = [...line.matchAll(/(^|\s)([A-H])\)\s/g)];
    if (found.length < 2) return [line];
    const inOrder = found.every((m, i) => m[2] === String.fromCharCode(65 + i));
    if (!inOrder) return [line];
    const pieces = [];
    let start = 0;
    found.forEach(m => {
        const at = m.index + m[1].length;
        if (at > start) pieces.push(line.slice(start, at).trim());
        start = at;
    });
    pieces.push(line.slice(start).trim());
    return pieces.filter(Boolean);
}

function renderStructured(container, text) {
    const lines = text.replace(/\r\n?/g, "\n").split("\n").flatMap(splitInlineChoices);
    let previousWasGap = true;
    lines.forEach(raw => {
        const line = raw.trim();
        if (!line) {
            if (!previousWasGap) {
                const gap = document.createElement("div");
                gap.className = "gap";
                container.appendChild(gap);
            }
            previousWasGap = true;
            return;
        }
        previousWasGap = false;

        const row = document.createElement("div");
        // Lettered choices start with a Latin "A)", so pick the direction from
        // the text itself to keep Arabic lines right-to-left.
        row.dir = /[\u0590-\u08FF]/.test(line) ? "rtl" : "auto";
        let m;
        if ((m = line.match(/^#{1,6}\s+(.*)$/))) {
            row.className = "line title";
            appendInline(row, m[1].replace(/\*\*/g, ""));
        } else if ((m = line.match(/^[-*•]\s+(.*)$/))) {
            row.className = "item";
            addMarker(row, "•");
            addBody(row, m[1]);
        } else if ((m = line.match(/^(\d{1,2}[.)]|[A-Za-z]\))\s+(.*)$/))) {
            row.className = "item";
            addMarker(row, m[1]);
            addBody(row, m[2]);
        } else {
            row.className = "line";
            appendInline(row, line);
        }
        container.appendChild(row);
    });
}

function addMarker(row, label) {
    const marker = document.createElement("span");
    marker.className = "marker";
    marker.textContent = label;
    row.appendChild(marker);
}

function addBody(row, text) {
    const body = document.createElement("span");
    appendInline(body, text);
    row.appendChild(body);
}

function addMessage(message, className) {
    const msgDiv = document.createElement("div");
    className.split(" ").forEach(c => msgDiv.classList.add(c));
    msgDiv.classList.add("message");
    msgDiv.dir = "auto";
    if (msgDiv.classList.contains("bot-message")) {
        renderStructured(msgDiv, String(message));
    } else {
        msgDiv.textContent = message;
    }
    chatBox.appendChild(msgDiv);
    chatBox.scrollTop = chatBox.scrollHeight;
    return msgDiv;
}

function showTyping() {
    const typingDiv = document.createElement("div");
    typingDiv.classList.add("message", "bot-message");
    const inner = document.createElement("span");
    inner.className = "typing";
    const label = document.createElement("span");
    label.textContent = t("typing");
    const dots = document.createElement("span");
    dots.className = "dots";
    for (let i = 0; i < 3; i++) dots.appendChild(document.createElement("i"));
    inner.appendChild(label);
    inner.appendChild(dots);
    typingDiv.appendChild(inner);
    chatBox.appendChild(typingDiv);
    chatBox.scrollTop = chatBox.scrollHeight;
    return typingDiv;
}

/* ------------------------------------------------------------------
   Talking to the server
   ------------------------------------------------------------------ */
class ChatFailure extends Error {
    constructor(code, conversationId) {
        super(code);
        this.code = code;
        this.conversationId = conversationId || null;
    }
}

async function getBotReply(msg) {
    let res;
    try {
        res = await fetch("/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                message: msg,
                language: currentLang,
                conversation_id: currentConversationId,
            }),
        });
    } catch (e) {
        throw new ChatFailure("network");
    }
    if (res.status === 401) {
        window.location.href = "/";
        return null;
    }
    let data = null;
    try { data = await res.json(); } catch (e) { /* e.g. an HTML error page from the host */ }
    if (!res.ok || !data || typeof data.reply !== "string") {
        const code = data && typeof data.error === "string" ? data.error : "unavailable";
        throw new ChatFailure(code, data && data.conversation_id);
    }
    return data;
}

function setBusy(state) {
    busy = state;
    sendBtn.disabled = state;
    userInput.disabled = state;
    if (!state) userInput.focus();
}

async function sendMessage() {
    const message = userInput.value.trim();
    if (message === "" || busy || !currentLang) return;

    addMessage(message, "user-message");
    userInput.value = "";
    onlyWelcomeShown = false;
    setBusy(true);
    const typingDiv = showTyping();

    try {
        const data = await getBotReply(message);
        typingDiv.remove();
        if (data) {
            addMessage(data.reply, "bot-message");
            noteConversation(data.conversation_id);
        }
    } catch (error) {
        typingDiv.remove();
        noteConversation(error.conversationId);
        const key = UI.en[error.code] ? error.code : "unavailable";
        addMessage(t(key), "bot-message error-message");
        if (key === "too_long") userInput.value = message;
        console.error("chat error:", error.code || error);
    } finally {
        setBusy(false);
    }
}

sendBtn.addEventListener("click", sendMessage);
userInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.isComposing) sendMessage();
});

/* ------------------------------------------------------------------
   Conversations: the chat starts empty at every visit; earlier
   conversations are listed in the side panel and can be reopened.
   ------------------------------------------------------------------ */
let conversations = [];

// After a message: remember which conversation we are in and refresh the list
function noteConversation(id) {
    if (!id) return;
    const isNew = currentConversationId !== id;
    currentConversationId = id;
    if (isNew || conversations.length === 0 || conversations[0].id !== id) {
        loadConversations();
    }
}

function formatDay(seconds) {
    if (!seconds) return "";
    try {
        return new Date(seconds * 1000).toLocaleDateString(currentLang || "en",
            { month: "short", day: "numeric" });
    } catch (e) {
        return "";
    }
}

function renderConversations() {
    historyList.replaceChildren();
    historyEmpty.hidden = conversations.length > 0;
    conversations.forEach(conv => {
        const item = document.createElement("li");
        if (conv.id === currentConversationId) item.classList.add("active");

        const open = document.createElement("button");
        open.type = "button";
        open.className = "history-open";
        const title = document.createElement("span");
        title.className = "history-name";
        title.dir = "auto";
        title.textContent = conv.title;
        const day = document.createElement("span");
        day.className = "history-day";
        day.textContent = formatDay(conv.updated_at);
        open.appendChild(title);
        open.appendChild(day);
        open.addEventListener("click", () => openConversation(conv.id));

        // Deleting takes two clicks: the first turns the button into "Delete?"
        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "history-delete";
        remove.textContent = "×";
        remove.setAttribute("aria-label", t("deleteChat"));
        remove.title = t("deleteChat");
        const disarm = () => {
            remove.classList.remove("armed");
            remove.textContent = "×";
        };
        remove.addEventListener("click", () => {
            if (remove.classList.contains("armed")) {
                deleteConversation(conv.id);
            } else {
                remove.classList.add("armed");
                remove.textContent = t("confirmDelete");
            }
        });
        remove.addEventListener("blur", disarm);
        item.addEventListener("mouseleave", disarm);

        item.appendChild(open);
        item.appendChild(remove);
        historyList.appendChild(item);
    });
}

async function loadConversations() {
    try {
        const res = await fetch("/conversations");
        if (res.status === 401) {
            window.location.href = "/";
            return;
        }
        if (!res.ok) throw new Error("conversation list failed");
        const list = await res.json();
        conversations = Array.isArray(list) ? list : [];
        renderConversations();
    } catch (error) {
        console.error(error);
    }
}

async function startNewConversation() {
    if (busy || !currentLang) return;
    currentConversationId = null;
    renderConversations();
    closeSidebar();
    await loadInitialGreeting();
    userInput.focus();
}

async function openConversation(id) {
    if (busy || !currentLang) return;
    closeSidebar();
    chatBox.replaceChildren();
    try {
        const res = await fetch("/conversations/" + encodeURIComponent(id) + "/messages");
        if (res.status === 401) {
            window.location.href = "/";
            return;
        }
        if (!res.ok) throw new Error("conversation request failed");
        const messages = await res.json();
        currentConversationId = id;
        onlyWelcomeShown = false;
        messages.forEach(m => {
            addMessage(m.content, m.role === "user" ? "user-message" : "bot-message");
        });
        renderConversations();
        userInput.focus();
    } catch (error) {
        console.error(error);
        addMessage(t("load"), "bot-message error-message");
    }
}

async function deleteConversation(id) {
    try {
        const res = await fetch("/conversations/" + encodeURIComponent(id), { method: "DELETE" });
        if (res.status === 401) {
            window.location.href = "/";
            return;
        }
        if (!res.ok && res.status !== 404) throw new Error("delete failed");
        conversations = conversations.filter(c => c.id !== id);
        if (currentConversationId === id) {
            currentConversationId = null;
            renderConversations();
            await loadInitialGreeting();
        } else {
            renderConversations();
        }
    } catch (error) {
        console.error(error);
    }
}

function closeSidebar() {
    sidebar.classList.remove("open");
    historyToggle.setAttribute("aria-expanded", "false");
}

newChatBtn.addEventListener("click", startNewConversation);
historyToggle.addEventListener("click", () => {
    const open = sidebar.classList.toggle("open");
    historyToggle.setAttribute("aria-expanded", open ? "true" : "false");
});

// Welcome text in the chosen language, shown when there is no conversation yet
async function loadInitialGreeting() {
    chatBox.replaceChildren();
    onlyWelcomeShown = true;
    const typingDiv = showTyping();
    try {
        const res = await fetch("/chat/welcome?lang=" + encodeURIComponent(currentLang));
        if (res.status === 401) {
            window.location.href = "/";
            return;
        }
        if (!res.ok) throw new Error("welcome request failed");
        const data = await res.json();
        typingDiv.remove();
        if (data.reply) addMessage(data.reply, "bot-message");
    } catch (error) {
        typingDiv.remove();
        addMessage("**Gadyen Safeguard**", "bot-message");
        console.error(error);
    }
}

/* ------------------------------------------------------------------
   Language choice
   ------------------------------------------------------------------ */
function applyLanguage(code) {
    currentLang = code;
    const lang = LANGUAGES.find(l => l.code === code);
    document.documentElement.lang = code;
    langSelect.value = code;
    userInput.placeholder = t("placeholder");
    userInput.setAttribute("aria-label", t("placeholder"));
    userInput.dir = lang && lang.rtl ? "rtl" : "auto";
    sendBtn.textContent = t("send");
    document.getElementById("lang-label").textContent = t("language");
    newChatBtn.textContent = "+ " + t("newChat");
    historyTitle.textContent = t("history");
    historyEmpty.textContent = t("noHistory");
    historyToggle.setAttribute("aria-label", t("showHistory"));
    historyToggle.title = t("showHistory");
    renderConversations();
}

async function chooseLanguage(code) {
    const firstChoice = currentLang === null;
    if (code === currentLang) return;
    storeLanguage(code);
    applyLanguage(code);

    if (firstChoice) {
        langPicker.hidden = true;
        chatBox.hidden = false;
        setBusy(false);
        newChatBtn.disabled = false;
        loadConversations();
        await loadInitialGreeting();
    } else if (onlyWelcomeShown) {
        await loadInitialGreeting();
    } else {
        addMessage(t("note"), "note-message");
    }
}

function init() {
    LANGUAGES.forEach(lang => {
        const option = document.createElement("option");
        option.value = lang.code;
        option.textContent = lang.name;
        langSelect.appendChild(option);

        const button = document.createElement("button");
        button.type = "button";
        button.lang = lang.code;
        button.textContent = lang.name;
        button.addEventListener("click", () => chooseLanguage(lang.code));
        langOptions.appendChild(button);
    });
    langSelect.addEventListener("change", () => chooseLanguage(langSelect.value));

    // Remove the old copy of the chat that earlier versions kept in the browser
    try { localStorage.removeItem("chatHistory"); } catch (e) { /* ignore */ }

    const stored = readStoredLanguage();
    if (stored) {
        // Every visit starts with an empty chat; earlier ones are in the side panel
        applyLanguage(stored);
        loadConversations();
        loadInitialGreeting();
    } else {
        // First visit: the customer picks a language before anything else
        langSelect.selectedIndex = -1;
        chatBox.hidden = true;
        langPicker.hidden = false;
        sendBtn.disabled = true;
        userInput.disabled = true;
        newChatBtn.disabled = true;
    }
}

window.addEventListener("DOMContentLoaded", init);
