"""Security controls for the Gadyen Safeguard chatbot (Flask + Gemini).

Pure-Python, no external dependencies, so every control can be unit-tested
without MySQL or a Gemini key. See SECURITY.md for the threat model.

Controls in this module:
  * redact_sensitive()      - strips SSNs, EINs, card/bank numbers, API keys,
                              passwords BEFORE text is stored or sent to the LLM.
  * looks_like_injection()  - flags direct prompt-injection / jailbreak attempts.
  * validate_memory_entry() - gate for the only write-capable LLM tool
                              (blocks memory poisoning and PII persistence).
  * filter_output()         - stops system-prompt leakage and secrets in replies.
  * RateLimiter             - sliding-window limits (login brute force, LLM cost abuse).
  * validate_registration() - username / password policy.
"""
import re
import threading
import time
from collections import defaultdict, deque

# ----------------------------------------------------------------- limits
MAX_MESSAGE_CHARS = 2000          # one chat message from the user
MAX_MEMORY_DETAIL_CHARS = 150     # one saved office-profile fact
MAX_MEMORY_ITEMS_PER_CATEGORY = 10
MAX_REPLY_CHARS = 8000            # one LLM reply shown to the user

ALLOWED_MEMORY_CATEGORIES = frozenset({
    "language", "business_type", "staff", "devices", "tax_software", "data_storage",
    "remote_work", "paper_files", "vendors", "backups", "access_controls",
    "past_incidents", "security_coordinator", "disposal",
})

# ----------------------------------------------------------------- sensitive data
def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _redact_card(match: re.Match) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    return "[REDACTED-CARD]" if 13 <= len(digits) <= 19 and _luhn_ok(digits) else match.group(0)


# Order matters: most specific patterns first.
_SENSITIVE_PATTERNS = [
    ("api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[REDACTED-API-KEY]"),          # Google
    ("api_key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{20,}\b"), "[REDACTED-API-KEY]"),  # OpenAI/Anthropic
    ("api_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED-API-KEY]"),        # AWS
    ("api_key", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "[REDACTED-API-KEY]"),       # GitHub
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
     "[REDACTED-PRIVATE-KEY]"),
    ("password", re.compile(r"(?i)\b(pass(?:word|wd|code)?|pwd|contrase[nñ]a|mot de passe|modpas)\s*[:=]\s*\S+"),
     r"\1: [REDACTED-PASSWORD]"),
    ("ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"), "[REDACTED-SSN]"),
    ("ein", re.compile(r"\b\d{2}-\d{7}\b"), "[REDACTED-EIN]"),
    ("bank_account", re.compile(r"(?i)\b(?:account|acct|routing|aba|iban)\s*(?:no\.?|number|#)?\s*[:#]?\s*\d{6,17}\b"),
     "[REDACTED-BANK]"),
]
_CARD_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
_BARE_SSN_RE = re.compile(r"(?i)\b(?:ssn|social security(?: number)?|itin)\b\D{0,15}(\d{9})\b")


def redact_sensitive(text: str):
    """Return (clean_text, sorted list of kinds that were removed)."""
    found = set()
    clean = str(text)
    for kind, pattern, repl in _SENSITIVE_PATTERNS:
        clean, n = pattern.subn(repl, clean)
        if n:
            found.add(kind)
    clean, n = _BARE_SSN_RE.subn(lambda m: m.group(0).replace(m.group(1), "[REDACTED-SSN]"), clean)
    if n:
        found.add("ssn")
    before = clean
    clean = _CARD_RE.sub(_redact_card, clean)
    if clean != before:
        found.add("card")
    return clean, sorted(found)


# ----------------------------------------------------------------- prompt injection
_INJECTION_PATTERNS = [re.compile(p, re.IGNORECASE) for p in (
    r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|all|your|system)\b.{0,20}"
    r"\b(instructions?|prompts?|rules?|guidelines?|directives?)",
    r"\b(reveal|show|print|repeat|output|display|leak|dump)\b.{0,40}\b(system|hidden|initial|internal)\s*"
    r"(prompt|instructions?|message|rules)",
    r"\byou are (now|no longer)\b",
    r"\b(developer|dan|god|jailbreak|unrestricted)\s*mode\b",
    r"\bact as (an?|the)?\s*(unfiltered|unrestricted|different|new)\b",
    r"\bnew (system )?(instructions?|rules?|role)\s*:",
    r"</?\s*(system|assistant|instructions?)\s*>",
    r"^\s*(system|assistant)\s*:",
    r"\bfrom now on,? (you|ignore|always|never)\b",
    # Spanish / French / Haitian Creole - the app's user languages
    r"\bignora\b.{0,30}\binstrucciones\b",
    r"\bignore[rz]?\b.{0,30}\binstructions?\s+pr[ée]c[ée]dentes\b",
    r"\binyore\b.{0,30}\benstriksyon\b",
)]


def looks_like_injection(text: str) -> bool:
    t = str(text)
    return any(p.search(t) for p in _INJECTION_PATTERNS)


# Words that make a stored "fact" read like an instruction to the model.
_MEMORY_INSTRUCTION_WORDS = re.compile(
    r"(?i)\b(ignore|override|disregard|system prompt|prompt|instructions?|you are|you will|"
    r"you must|you should|from now on|assistant|function call|tool call)\b")


def validate_memory_entry(category, detail):
    """Gate for save_user_preference. Returns (ok: bool, reason: str)."""
    if not isinstance(category, str) or category not in ALLOWED_MEMORY_CATEGORIES:
        return False, "unknown category"
    if not isinstance(detail, str) or not detail.strip():
        return False, "empty detail"
    if len(detail) > MAX_MEMORY_DETAIL_CHARS:
        return False, "detail too long"
    if any(ch in detail for ch in "<>{}`"):
        return False, "markup is not allowed"
    if _MEMORY_INSTRUCTION_WORDS.search(detail) or looks_like_injection(detail):
        return False, "looks like an instruction, not a fact about the office"
    _, kinds = redact_sensitive(detail)
    if kinds:
        return False, "contains sensitive data (" + ", ".join(kinds) + ")"
    return True, ""


# ----------------------------------------------------------------- output filtering
def _shingles(text: str, n: int = 8):
    words = re.findall(r"\w+", text.lower())
    return {" ".join(words[i:i + n]) for i in range(max(0, len(words) - n + 1))}


SAFE_LEAK_REPLY = ("I can't share my internal instructions, but I'm happy to keep helping "
                   "with your office's security plan.")


def quotable_spans(system_prompt: str, extra=()):
    """Text the model is SUPPOSED to repeat word for word: every "double-quoted"
    passage in the prompt (the required disclaimer, example phrasings) plus any
    extra blocks such as a message template. These are not leaks."""
    # Pair quotes strictly in order (findall consumes each pair), then keep only
    # one-line passages long enough to matter. Requiring a single line stops an
    # unbalanced quote from whitelisting real instructions between two quotes.
    pairs = re.findall(r'"([^"\n]*)"', system_prompt)
    spans = [s for s in pairs if len(s) >= 20]
    return [*spans, *extra]


def filter_output(reply: str, system_prompt: str, leak_threshold: int = 3, quotable=()):
    """Return (safe_reply, list of issues). Blocks verbatim system-prompt leakage
    (>= leak_threshold 8-word runs copied from the prompt's INSTRUCTIONS) and
    redacts secrets/PII. Runs that come from `quotable` text do not count."""
    issues = []
    reply = str(reply or "")
    secret_runs = _shingles(system_prompt)
    for text in quotable:
        secret_runs -= _shingles(text)
    if len(_shingles(reply) & secret_runs) >= leak_threshold:
        return SAFE_LEAK_REPLY, ["system_prompt_leak"]
    reply, kinds = redact_sensitive(reply)
    if kinds:
        issues.append("redacted:" + ",".join(kinds))
    if len(reply) > MAX_REPLY_CHARS:
        reply = reply[:MAX_REPLY_CHARS] + "\n[...]"
        issues.append("truncated")
    return reply, issues


# ----------------------------------------------------------------- rate limiting
class RateLimiter:
    """Thread-safe sliding-window limiter: at most `limit` hits per `window` seconds per key."""

    def __init__(self, limit: int, window: float, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, q, now):
        while q and now - q[0] >= self.window:
            q.popleft()

    def hit(self, key) -> bool:
        """Record an attempt; return False if the key is over its limit."""
        with self._lock:
            now = self.clock()
            q = self._hits[key]
            self._prune(q, now)
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True

    def blocked(self, key) -> bool:
        """True if the key is at its limit (does not record an attempt)."""
        with self._lock:
            now = self.clock()
            q = self._hits[key]
            self._prune(q, now)
            return len(q) >= self.limit

    def reset(self, key):
        with self._lock:
            self._hits.pop(key, None)

    def retry_after(self, key) -> int:
        with self._lock:
            q = self._hits.get(key)
            if not q:
                return 0
            return max(1, int(self.window - (self.clock() - q[0])) + 1)


# ----------------------------------------------------------------- account policy
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,32}$")


def validate_registration(username: str, password: str):
    """Return an error message, or '' if the credentials meet policy."""
    if not _USERNAME_RE.match(username or ""):
        return "Username must be 3-32 letters, digits, '.', '_' or '-'."
    if len(password or "") < 12:
        return "Password must be at least 12 characters."
    if len(password.encode("utf-8")) > 72:   # bcrypt hard limit; bcrypt>=5 raises otherwise
        return "Password must be at most 72 bytes."
    if password.lower() == username.lower() or username.lower() in password.lower():
        return "Password must not contain the username."
    if len(set(password)) < 5:
        return "Password is too simple."
    return ""
