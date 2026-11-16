"""Languages the customer can pick in the chat interface.

The browser sends a language CODE; only codes listed here are accepted, so
nothing typed by a user can end up inside the agent's system instructions.
"""

DEFAULT_LANGUAGE = "en"

# code -> (English name given to the model, name shown to the customer)
LANGUAGES = {
    "en": ("English", "English"),
    "es": ("Spanish", "Español"),
    "zh": ("Simplified Chinese", "中文"),
    "tl": ("Tagalog", "Tagalog"),
    "vi": ("Vietnamese", "Tiếng Việt"),
    "ar": ("Arabic", "العربية"),
    "fr": ("French", "Français"),
    "ko": ("Korean", "한국어"),
    "pt": ("Portuguese", "Português"),
    "ht": ("Haitian Creole", "Kreyòl Ayisyen"),
}


def normalize_language(code) -> str:
    """Return a supported language code, falling back to English."""
    if isinstance(code, str):
        code = code.strip().lower()[:5]
        if code in LANGUAGES:
            return code
    return DEFAULT_LANGUAGE


def language_name(code) -> str:
    return LANGUAGES[normalize_language(code)][0]


WELCOME = {
    "en": (
        "**Welcome to Gadyen Safeguard.**\n\n"
        "I help your office prepare its Written Information Security Plan (WISP), "
        "one question at a time.\n\n"
        "- About 15 questions, around 15 minutes\n"
        "- I ask only about your office, never about your clients\n"
        "- You get a draft plan for the owner to review\n\n"
        "When you are ready, write \"start\"."
    ),
    "es": (
        "**Bienvenido a Gadyen Safeguard.**\n\n"
        "Ayudo a su oficina a preparar su Plan Escrito de Seguridad de la Información (WISP), "
        "una pregunta a la vez.\n\n"
        "- Unas 15 preguntas, alrededor de 15 minutos\n"
        "- Solo pregunto sobre su oficina, nunca sobre sus clientes\n"
        "- Usted recibe un borrador del plan para que el dueño lo revise\n\n"
        "Cuando esté listo, escriba \"empezar\"."
    ),
    "zh": (
        "**欢迎使用 Gadyen Safeguard。**\n\n"
        "我会一次问一个问题，帮助您的办公室准备书面信息安全计划（WISP）。\n\n"
        "- 大约 15 个问题，约 15 分钟\n"
        "- 我只询问您办公室的情况，绝不询问客户的信息\n"
        "- 您会得到一份计划草稿，供负责人审阅\n\n"
        "准备好后，请输入“开始”。"
    ),
    "tl": (
        "**Maligayang pagdating sa Gadyen Safeguard.**\n\n"
        "Tinutulungan ko ang inyong opisina na ihanda ang Written Information Security Plan (WISP) "
        "nito, isang tanong sa bawat pagkakataon.\n\n"
        "- Mga 15 tanong, humigit-kumulang 15 minuto\n"
        "- Tungkol lamang sa inyong opisina ang mga tanong ko, hindi kailanman tungkol sa inyong mga kliyente\n"
        "- Makakatanggap kayo ng draft ng plano na susuriin ng may-ari\n\n"
        "Kapag handa na kayo, i-type ang \"simulan\"."
    ),
    "vi": (
        "**Chào mừng bạn đến với Gadyen Safeguard.**\n\n"
        "Tôi giúp văn phòng của bạn soạn Kế hoạch Bảo mật Thông tin bằng văn bản (WISP), "
        "mỗi lần một câu hỏi.\n\n"
        "- Khoảng 15 câu hỏi, mất chừng 15 phút\n"
        "- Tôi chỉ hỏi về văn phòng của bạn, không bao giờ hỏi về khách hàng\n"
        "- Bạn sẽ nhận được bản nháp kế hoạch để chủ văn phòng xem lại\n\n"
        "Khi đã sẵn sàng, hãy gõ \"bắt đầu\"."
    ),
    "ar": (
        "**مرحبًا بك في Gadyen Safeguard.**\n\n"
        "أساعد مكتبك في إعداد خطة أمن المعلومات المكتوبة (WISP)، سؤالًا واحدًا في كل مرة.\n\n"
        "- نحو 15 سؤالًا في حوالي 15 دقيقة\n"
        "- أسأل عن مكتبك فقط، ولا أسأل أبدًا عن عملائك\n"
        "- تحصل على مسودة خطة ليراجعها صاحب المكتب\n\n"
        "عندما تكون جاهزًا، اكتب \"ابدأ\"."
    ),
    "fr": (
        "**Bienvenue sur Gadyen Safeguard.**\n\n"
        "J'aide votre bureau à préparer son plan écrit de sécurité de l'information (WISP), "
        "une question à la fois.\n\n"
        "- Environ 15 questions, à peu près 15 minutes\n"
        "- Mes questions portent uniquement sur votre bureau, jamais sur vos clients\n"
        "- Vous recevez un projet de plan que le propriétaire devra relire\n\n"
        "Quand vous êtes prêt, écrivez « commencer »."
    ),
    "ko": (
        "**Gadyen Safeguard에 오신 것을 환영합니다.**\n\n"
        "한 번에 한 가지씩 질문하며 사무실의 서면 정보 보안 계획(WISP) 작성을 도와드립니다.\n\n"
        "- 질문 약 15개, 15분 정도 소요\n"
        "- 사무실에 대해서만 질문하며 고객에 대해서는 절대 묻지 않습니다\n"
        "- 대표자가 검토할 계획 초안을 받게 됩니다\n\n"
        "준비되면 \"시작\"이라고 입력하세요."
    ),
    "pt": (
        "**Bem-vindo ao Gadyen Safeguard.**\n\n"
        "Ajudo o seu escritório a preparar o Plano Escrito de Segurança da Informação (WISP), "
        "uma pergunta de cada vez.\n\n"
        "- Cerca de 15 perguntas, aproximadamente 15 minutos\n"
        "- Pergunto apenas sobre o seu escritório, nunca sobre os seus clientes\n"
        "- Você recebe um rascunho do plano para o proprietário revisar\n\n"
        "Quando estiver pronto, escreva \"começar\"."
    ),
    "ht": (
        "**Byenveni nan Gadyen Safeguard.**\n\n"
        "Mwen ede biwo ou prepare Plan Ekri Sekirite Enfòmasyon li (WISP), yon kesyon alafwa.\n\n"
        "- Anviwon 15 kesyon, apeprè 15 minit\n"
        "- Mwen poze kesyon sou biwo ou sèlman, pa janm sou kliyan ou yo\n"
        "- Ou resevwa yon bouyon plan pou pwopriyetè a revize\n\n"
        "Lè ou pare, ekri \"kòmanse\"."
    ),
}


def welcome_message(code) -> str:
    return WELCOME[normalize_language(code)]
