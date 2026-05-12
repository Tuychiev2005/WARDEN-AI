import re
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta

logging.basicConfig(
    filename='warden.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ═══════════════════════════════════════════════════════════════
#  RULE SETS
# ═══════════════════════════════════════════════════════════════

SCAM_KEYWORDS = {
    # Crypto / finance
    "free nitro", "telegram premium", "crypto giveaway", "airdrop",
    "wallet connect", "claim reward", "urgent verify", "login now",
    "you won", "click here", "verify account", "limited offer",
    "investment opportunity", "double your money", "100x profit",
    "guaranteed profit", "no risk", "passive income", "get rich",
    "withdraw funds", "send crypto", "btc giveaway", "eth giveaway",
    "usdt giveaway", "nft giveaway", "seed phrase", "private key",
    "recovery phrase", "metamask support", "trust wallet support",
    # Account threats
    "your account will be banned", "account suspended", "verify immediately",
    "confirm identity", "update payment", "unusual activity detected",
    "security breach", "your account is at risk",
    # Prize / lottery
    "you have been selected", "congratulations you won", "claim your prize",
    "lucky winner", "special reward", "exclusive offer expires",
    # Fake job
    "work from home earn", "make money online", "easy money",
    "hiring urgently", "no experience needed earn",
    # Russian / CIS scam phrases
    "бесплатно по ссылке", "получи бесплатно", "перейди по ссылке",
    "кликай сюда", "забери приз", "срочно верифицируй",
    "аккаунт заблокируют", "успей получить", "только сегодня бесплатно",
    "первым 100 пользователям", "халява", "бесплатный доступ",
    "заработок без вложений", "пассивный доход", "инвестируй и получи",
    "утроим депозит", "удвоим депозит", "криптовалюта бесплатно",
    "нфт бесплатно", "токены бесплатно", "дроп бесплатно",
    # Uzbek / CIS
    "bepul oling", "bepul link", "havola orqali oling",
    "tekin", "sovga oling", "yutib oldingiz",
}

PHISHING_DOMAINS = {
    # URL shorteners / IP loggers
    "grabify", "bit.ly", "tinyurl", "iplogger", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bc.vc", "cutt.ly",
    "rb.gy", "shorturl", "tiny.cc", "t2m.io", "clck.ru",
    "vk.cc", "goo.gl", "short.cm", "bl.ink", "gg.gg",
    "lnkd.in", "trib.al", "spoti.fi", "youtu.be",
    # IP-loggers / trackers
    "ipgrabber", "blasze", "canarytokens", "interactsh",
    "webhook.site", "requestbin", "pipedream", "grabify.link",
    "loggly", "sematext", "trackurl", "urltracker",
    "2no.co", "ps.kz", "clk.sh", "ez4.me",
    # Clearly malicious patterns
    "scam", "freegift", "free-gift", "claimreward",
    "claim-reward", "getreward", "get-reward", "walletconnect-",
    "metamask-", "trustwallet-", "binance-", "coinbase-",
    "telegram-premium", "tg-premium", "telegrm", "telegramm",
    "get-free", "free-crypto", "airdrop-claim", "win-prize",
    "verify-account", "account-verify", "login-telegram",
    "telegram-login", "tg-login", "tglogin", "tg-verify",
    "secure-login", "auth-telegram", "telegram-auth",
    # Typosquatting popular services
    "g00gle", "g0ogle", "gooogle", "paypa1", "paypai",
    "faceb00k", "inst4gram", "twitterr", "telegarm",
    "you-tube", "youtub3", "netfl1x", "amaz0n", "steampowerd",
    "discordapp.io", "discordgift", "discord-nitro",
    # Crypto-specific phishing
    "metamask.io-", "uniswap-", "pancakeswap-", "opensea-",
    "rarible-", "nftclaim", "tokendrop", "crypto-claim",
    "wallet-connect", "defi-claim", "staking-reward",
}

SUSPICIOUS_URL_PATTERNS = [
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",      # raw IP instead of domain
    r"https?://[^/]+@",                                      # user@host trick
    r"\.(tk|ml|ga|cf|gq|pw|cc|xyz|top|icu|buzz|fun|club|shop|store|online|site|live)/",  # sketchy free TLDs
    r"[a-z0-9]{30,}\.(com|net|org|ru|io)",                 # suspiciously long random domains
    r"free[-_]?(gift|crypto|money|coin|token|nft|drop)",    # free-X in URL path
    r"(claim|get|win|reward|prize|bonus)[-_]?(now|free|today)",
    r"t\.me/\+[A-Za-z0-9_-]{10,}",                        # private Telegram group invite links
    r"https?://[^/]{3,15}\.[a-z]{2,4}/[a-zA-Z0-9]{15,}$", # short domain + long hash = tracking link
    r"(login|verify|confirm|secure|account)[-.]?(telegram|tg|crypto|wallet)",
    r"https?://[^/]+\.(ru|cn|tk|ml)/.{0,10}(login|auth|verify|confirm)",  # CIS + suspicious path
    r"bit\.ly|tinyurl\.com|is\.gd|rb\.gy|ow\.ly|clck\.ru|vk\.cc",        # common shorteners (regex)
    r"[а-яА-Я]{2,}\.(com|ru|net|org)",                    # Cyrillic punycode-like domain
    r"xn--[a-z0-9-]{4,}\.",                               # Punycode international domain (homograph attack)
]

SCAM_PATTERNS = [
    r"\b\d+\s*(?:usdt|btc|eth|ton|usdc|sol|bnb)\s*(?:free|giveaway|airdrop)\b",
    r"\bsend\s+\d+\s*(?:usdt|btc|eth|ton)\b",
    r"\b(?:double|triple|10x|100x|x10|x100)\s+(?:your\s+)?(?:money|crypto|btc|eth)\b",
    r"\bclick\s+(?:here|below|link)\s+(?:to\s+)?(?:claim|get|receive|verify)\b",
    r"\bexpires?\s+in\s+\d+\s*(?:hour|minute|second|hr|min|час|минут)\b",
    r"\b(?:t\.me|telegram\.me)/\+[A-Za-z0-9_-]{10,}\b",
    r"получи\s+бесплатн\w*\s+.{0,30}по\s+ссылк",
    r"бесплатн\w*\s+.{0,20}(?:по ссылке|перейди|кликни)",
    r"\bget\s+free\s+\w+\s+(?:by|via|through|at)\s+(?:this\s+)?link\b",
    r"\bclaim\s+your\s+free\s+\w+",
    r"\bfree\s+\w+\s+(?:for|to)\s+(?:first|everyone|all)\b",
]

# ── NEW: Impersonation patterns ────────────────────────────────
IMPERSONATION_PATTERNS = [
    r"\b(?:official|support|admin|team|service)\s+(?:telegram|tg|crypto|btc|eth)\b",
    r"\btelegram\s+(?:support|team|admin|official|staff|help)\b",
    r"\b(?:support|admin|help)\s+(?:desk|center|team|bot|agent)\b",
    r"(?:official|verified)\s+(?:account|channel|bot|support)",
    r"\bwe\s+(?:detected|noticed|found)\s+(?:suspicious|unusual|unauthorized)\s+(?:activity|access|login)\b",
    r"\byour\s+(?:account|wallet|funds|crypto)\s+(?:is|are)\s+(?:at risk|compromised|suspended|frozen)\b",
]

# ── NEW: Social engineering patterns ──────────────────────────
SOCIAL_ENGINEERING_PATTERNS = [
    r"\bdon\'?t\s+(?:tell|show|share)\s+(?:anyone|others|your friends)\b",
    r"\bkeep\s+(?:this|it)\s+(?:secret|between us|private|confidential)\b",
    r"\bonly\s+(?:you|we)\s+(?:know|can see|have access)\b",
    r"\bact\s+(?:now|fast|quickly|immediately|urgently)\b",
    r"\blimited\s+(?:time|spots|slots|offer|access)\b",
    r"\bonly\s+\d+\s+(?:spots?|slots?|places?|seats?)\s+(?:left|remaining|available)\b",
    r"\bверифицируй\s+(?:сейчас|немедленно|срочно)\b",
    r"\bне\s+(?:говори|рассказывай|показывай)\s+(?:никому|другим)\b",
]

# ── NEW: Malware/RAT delivery patterns ────────────────────────
MALWARE_PATTERNS = [
    r"\b(?:download|install|run|execute|open)\s+(?:this|the|our)\s+(?:file|app|software|tool|bot|program)\b",
    r"\.(?:exe|bat|cmd|scr|pif|vbs|js|jar|apk|ipa)\b",
    r"\binstall\s+(?:apk|ipa|app)\s+(?:from|via|at|using)\b",
    r"\brun\s+(?:as|with)\s+(?:admin|administrator|root)\b",
    r"\bgive\s+(?:me|us)\s+(?:access|remote|control|your screen)\b",
    r"\bteamviewer|anydesk|remote\s*(?:desktop|access|control)\b",
]

# ═══════════════════════════════════════════════════════════════
#  SETTINGS  (per user_id, updated via API from dashboard)
# ═══════════════════════════════════════════════════════════════

DEFAULT_SETTINGS: dict = {
    "scam_detection":            True,
    "phishing_detection":        True,
    "flood_detection":           True,
    "free_link_detection":       True,
    "impersonation_detection":   True,   # NEW
    "social_engineering":        True,   # NEW
    "malware_detection":         True,   # NEW
    "mention_spam_detection":    True,   # NEW
    "bot_notifications":         True,
    "stealth_mode":              True,   # anti-ban delays & read-receipt suppression
    "alert_cooldown":            60,     # FIXED: increased from 30 to 60 seconds
    "max_alerts_window":         3,      # FIXED: reduced from 5 to 3 per window
    "alert_window_seconds":      300,    # seconds for the alert count window
    "flood_threshold":           5,      # msgs in 10s to trigger flood alert
    "flood_alert_once":          True,   # NEW: only alert once per flood burst
}

_settings_cache: dict[int, dict] = {}


def get_settings(user_id: int) -> dict:
    if user_id not in _settings_cache:
        _settings_cache[user_id] = dict(DEFAULT_SETTINGS)
    return _settings_cache[user_id]


def update_settings(user_id: int, patch: dict) -> dict:
    s = get_settings(user_id)
    for k, v in patch.items():
        if k not in DEFAULT_SETTINGS:
            continue
        if isinstance(DEFAULT_SETTINGS[k], bool):
            s[k] = bool(v)
        elif isinstance(DEFAULT_SETTINGS[k], int):
            s[k] = max(1, int(v))
    logging.info(f"Settings updated user={user_id}: {patch}")
    return s


# ═══════════════════════════════════════════════════════════════
#  ANTI-SPAM BOT PROTECTION  (FIXED)
# ═══════════════════════════════════════════════════════════════

message_log:       dict[int, deque]       = defaultdict(lambda: deque(maxlen=50))
flood_alerted:     dict[tuple, datetime]  = {}   # NEW: tracks if flood was already alerted

_last_alert_time:    dict[tuple, datetime] = {}
_alert_count:        dict[tuple, int]      = defaultdict(int)
_alert_window_start: dict[tuple, datetime] = {}


def should_send_alert(user_id: int, sender_id: int) -> bool:
    """
    FIXED: Robust cooldown system.
    - Enforces per-sender cooldown (default 60s)
    - Enforces max N alerts per 5-min window per sender
    - Returns False when limits are hit, preventing bot spam loops
    """
    key = (user_id, sender_id)
    s   = get_settings(user_id)
    cooldown     = s.get("alert_cooldown", 60)
    max_alerts   = s.get("max_alerts_window", 3)
    window_secs  = s.get("alert_window_seconds", 300)
    now = datetime.now()

    # --- Per-message cooldown ---
    last = _last_alert_time.get(key)
    if last and (now - last).total_seconds() < cooldown:
        logging.debug(f"Alert suppressed (cooldown {cooldown}s) sender={sender_id}")
        return False

    # --- Window rate limit ---
    win_start = _alert_window_start.get(key)
    if win_start and (now - win_start).total_seconds() < window_secs:
        if _alert_count[key] >= max_alerts:
            logging.debug(f"Alert suppressed (window limit {max_alerts}) sender={sender_id}")
            return False
    else:
        # Reset window
        _alert_window_start[key] = now
        _alert_count[key] = 0

    _last_alert_time[key] = now
    _alert_count[key] += 1
    return True


def reset_sender_cooldown(user_id: int, sender_id: int) -> None:
    key = (user_id, sender_id)
    _last_alert_time.pop(key, None)
    _alert_count.pop(key, None)
    _alert_window_start.pop(key, None)
    flood_alerted.pop(key, None)


# ═══════════════════════════════════════════════════════════════
#  UTILS
# ═══════════════════════════════════════════════════════════════

URL_REGEX = r"(https?://[^\s<>\"'\)]+)"


def extract_urls(text: str) -> list:
    return re.findall(URL_REGEX, text, re.IGNORECASE) if text else []


def _normalize(text: str) -> str:
    # Remove zero-width and invisible chars
    text = re.sub(r'[\u200b\u200c\u200d\u2060\ufeff\u00ad]', '', text)
    # Homoglyph map (Cyrillic → Latin lookalikes)
    hg = {'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','у':'y','і':'i','ѕ':'s'}
    return ''.join(hg.get(c, c) for c in text.lower())


# ═══════════════════════════════════════════════════════════════
#  DETECTORS
# ═══════════════════════════════════════════════════════════════

def detect_scam(text: str) -> dict:
    if not text:
        return {"detected": False}
    t = _normalize(text)

    for kw in SCAM_KEYWORDS:
        if kw in t:
            return {"detected": True, "type": "SCAM", "risk": "HIGH",
                    "reason": f'keyword: "{kw}"'}

    for pat in SCAM_PATTERNS:
        m = re.search(pat, t, re.IGNORECASE)
        if m:
            return {"detected": True, "type": "SCAM", "risk": "HIGH",
                    "reason": f'pattern: "{m.group(0)[:60]}"'}

    return {"detected": False}


def detect_phishing(text: str) -> dict:
    if not text:
        return {"detected": False}

    t_norm = _normalize(text)

    # 1. Check explicit http/https URLs
    for url in extract_urls(text):
        ul = url.lower()
        for dom in PHISHING_DOMAINS:
            if dom in ul:
                return {"detected": True, "type": "PHISHING", "risk": "HIGH",
                        "reason": f'suspicious domain "{dom}" in {url[:80]}'}
        for pat in SUSPICIOUS_URL_PATTERNS:
            if re.search(pat, ul, re.IGNORECASE):
                return {"detected": True, "type": "PHISHING", "risk": "HIGH",
                        "reason": f'suspicious URL pattern: {url[:80]}'}

    # 2. Masked markdown/HTML links where display text differs from href
    for lt, lu in re.findall(r'\[([^\]]+)\]\((https?://[^\)]+)\)', text):
        if any(d in lu.lower() for d in PHISHING_DOMAINS):
            return {"detected": True, "type": "PHISHING", "risk": "HIGH",
                    "reason": f'masked link [{lt}]({lu[:60]})'}
        # Display says "telegram.org" but href goes elsewhere
        lt_lower = lt.lower()
        lu_lower = lu.lower()
        if any(safe in lt_lower for safe in ["telegram", "google", "youtube", "binance", "metamask"]):
            if not any(safe in lu_lower for safe in ["telegram.org", "google.com", "youtube.com", "binance.com"]):
                return {"detected": True, "type": "PHISHING", "risk": "HIGH",
                        "reason": f'spoofed trusted brand in masked link: [{lt}]'}

    # 3. Domain-without-schema (e.g. "grabify.link/abc") — common in Telegram messages
    bare_domain_hits = re.findall(
        r'(?<![/@])\b([a-zA-Z0-9-]{3,63}\.[a-zA-Z]{2,10}/[^\s]{3,})', text
    )
    for bd in bare_domain_hits:
        bd_lower = bd.lower()
        for dom in PHISHING_DOMAINS:
            if dom in bd_lower:
                return {"detected": True, "type": "PHISHING", "risk": "HIGH",
                        "reason": f'phishing domain (no-schema): {bd[:80]}'}

    # 4. Obfuscated URLs: spaces/dots replaced (e.g. "bit . ly/xxx")
    deobfuscated = re.sub(r'\s*\[\s*\.\s*\]\s*|\s+\.\s+', '.', text)
    deobfuscated = re.sub(r'\s*/\s*', '/', deobfuscated)
    if deobfuscated != text:
        for url2 in extract_urls("https://" + deobfuscated) + extract_urls(deobfuscated):
            ul2 = url2.lower()
            for dom in PHISHING_DOMAINS:
                if dom in ul2:
                    return {"detected": True, "type": "PHISHING", "risk": "HIGH",
                            "reason": f'obfuscated phishing link detected: {url2[:80]}'}

    # 5. Cyrillic homograph check — e.g. "tеlеgrаm.org" (mixed Cyrillic/Latin)
    mixed_script = re.findall(r'(?=[a-zA-Z]*[а-яА-Я][a-zA-Z]|[а-яА-Я]*[a-zA-Z][а-яА-Я])[^\s]{5,}', text)
    if mixed_script:
        return {"detected": True, "type": "PHISHING", "risk": "HIGH",
                "reason": f'homograph/mixed-script domain attack: {mixed_script[0][:60]}'}

    return {"detected": False}


def detect_free_link(text: str) -> dict:
    """
    Detects 'get FREE X via LINK' patterns in Russian, English, Uzbek.
    """
    if not text:
        return {"detected": False}

    t       = _normalize(text)
    has_url = bool(extract_urls(text))

    free_words   = ["бесплатно","бесплатн","free","халява","даром","bepul","tekin","gratis"]
    link_words   = ["по ссылке","по линку","by link","via link","перейди","кликни","жми",
                    "click","tap here","go to","havola","ссылк"]
    action_words = ["получи","забери","скачай","активируй","get","claim","grab",
                    "download","oling","olib"]

    has_free   = any(w in t for w in free_words)
    has_link_w = any(w in t for w in link_words)
    has_action = any(w in t for w in action_words)

    if has_free and has_link_w:
        return {"detected": True, "type": "SCAM", "risk": "HIGH",
                "reason": "free-by-link bait"}

    if has_action and has_free and has_url:
        return {"detected": True, "type": "SCAM", "risk": "HIGH",
                "reason": "free item via URL bait"}

    if has_url and has_free:
        return {"detected": True, "type": "PHISHING", "risk": "MEDIUM",
                "reason": "URL with free offer"}

    return {"detected": False}


def detect_flood(sender_id: int, user_id: int = 0, threshold: int = 5) -> dict:
    """
    FIXED: Flood detection with once-per-burst alerting.
    Tracks flood state per (user_id, sender_id) pair.
    Only alerts ONCE per flood burst — won't spam alerts for every message.
    """
    key = (user_id, sender_id)
    now = datetime.now()
    log = message_log[sender_id]
    log.append(now)

    # Remove messages older than 10 seconds
    while log and (now - log[0]) > timedelta(seconds=10):
        log.popleft()

    count = len(log)

    # Check if we're still in an active flood alert cooldown
    last_flood = flood_alerted.get(key)
    if last_flood and (now - last_flood).total_seconds() < 30:
        # Flood is ongoing, don't re-alert
        return {"detected": False, "type": "FLOOD_ONGOING", "risk": "LOW",
                "reason": "flood ongoing, alert already sent"}

    if count >= threshold * 2:
        flood_alerted[key] = now
        return {"detected": True, "type": "FLOOD", "risk": "HIGH",
                "reason": f"extreme spam: {count} msgs/10s"}
    if count >= threshold:
        flood_alerted[key] = now
        return {"detected": True, "type": "FLOOD", "risk": "MEDIUM",
                "reason": f"flood: {count} msgs/10s"}

    # If count dropped below threshold, reset flood alert state
    if count < max(2, threshold // 2):
        flood_alerted.pop(key, None)

    return {"detected": False}


# ── NEW: Impersonation detector ────────────────────────────────────────────────
def detect_impersonation(text: str) -> dict:
    """
    Detects messages impersonating official Telegram support, admins, or services.
    """
    if not text:
        return {"detected": False}
    t = _normalize(text)

    for pat in IMPERSONATION_PATTERNS:
        m = re.search(pat, t, re.IGNORECASE)
        if m:
            return {"detected": True, "type": "IMPERSONATION", "risk": "HIGH",
                    "reason": f'impersonation pattern: "{m.group(0)[:60]}"'}

    return {"detected": False}


# ── NEW: Social engineering detector ──────────────────────────────────────────
def detect_social_engineering(text: str) -> dict:
    """
    Detects urgency, secrecy, and manipulation tactics commonly used in scams.
    """
    if not text:
        return {"detected": False}
    t = _normalize(text)

    hits = []
    for pat in SOCIAL_ENGINEERING_PATTERNS:
        m = re.search(pat, t, re.IGNORECASE)
        if m:
            hits.append(m.group(0)[:40])

    if len(hits) >= 2:
        return {"detected": True, "type": "SOCIAL_ENG", "risk": "HIGH",
                "reason": f'manipulation tactics: {", ".join(hits[:2])}'}
    if len(hits) == 1:
        return {"detected": True, "type": "SOCIAL_ENG", "risk": "MEDIUM",
                "reason": f'manipulation tactic: "{hits[0]}"'}

    return {"detected": False}


# ── NEW: Malware/RAT delivery detector ────────────────────────────────────────
def detect_malware(text: str) -> dict:
    """
    Detects attempts to deliver malware, RATs, or unauthorized remote access tools.
    """
    if not text:
        return {"detected": False}
    t = _normalize(text)

    for pat in MALWARE_PATTERNS:
        m = re.search(pat, t, re.IGNORECASE)
        if m:
            return {"detected": True, "type": "MALWARE", "risk": "HIGH",
                    "reason": f'malware delivery attempt: "{m.group(0)[:60]}"'}

    return {"detected": False}


# ── NEW: Mention/tag spam detector ────────────────────────────────────────────
def detect_mention_spam(text: str) -> dict:
    """
    Detects mass @mention spam (common bot/spam pattern in Telegram).
    """
    if not text:
        return {"detected": False}

    mentions = re.findall(r'@[A-Za-z0-9_]{4,}', text)
    if len(mentions) >= 5:
        return {"detected": True, "type": "MENTION_SPAM", "risk": "MEDIUM",
                "reason": f"mass mention spam: {len(mentions)} @mentions"}

    # Also detect repeated identical content (copy-paste spam)
    words = text.split()
    if len(words) >= 10:
        unique_ratio = len(set(words)) / len(words)
        if unique_ratio < 0.3:
            return {"detected": True, "type": "MENTION_SPAM", "risk": "LOW",
                    "reason": f"repetitive content (unique ratio: {unique_ratio:.0%})"}

    return {"detected": False}


# ═══════════════════════════════════════════════════════════════
#  MAIN ANALYZER
# ═══════════════════════════════════════════════════════════════

def analyze_message(sender_id: int, text: str, user_id: int = 0,
                    sender_username: str = "", sender_name: str = "") -> dict:
    """
    Main security engine. Respects per-user settings.
    Enabled modules run in priority order; first HIGH-risk hit wins,
    then MEDIUM. LOW risks only reported if nothing else found.

    FIXED anti-spam: flood detection uses once-per-burst logic,
    and the global cooldown prevents bot notification loops entirely.

    sender_username / sender_name — passed through to alerts for spam tracking.
    """
    try:
        s = get_settings(user_id)
        results = []

        # --- Run enabled detectors ---
        if s.get("flood_detection", True):
            r = detect_flood(sender_id, user_id=user_id,
                             threshold=s.get("flood_threshold", 5))
            # If flood is ongoing (already alerted), return safe immediately
            if r.get("type") == "FLOOD_ONGOING":
                return {"detected": False, "type": "SAFE", "risk": "LOW",
                        "reason": "flood ongoing, suppressed"}
            if r.get("detected"):
                results.append(r)

        if s.get("scam_detection", True):
            results.append(detect_scam(text))

        if s.get("phishing_detection", True):
            results.append(detect_phishing(text))

        if s.get("free_link_detection", True):
            results.append(detect_free_link(text))

        if s.get("impersonation_detection", True):
            results.append(detect_impersonation(text))

        if s.get("social_engineering", True):
            results.append(detect_social_engineering(text))

        if s.get("malware_detection", True):
            results.append(detect_malware(text))

        if s.get("mention_spam_detection", True):
            results.append(detect_mention_spam(text))

        # --- Priority: HIGH first, then MEDIUM, then LOW ---
        detected = [r for r in results if r.get("detected")]
        for risk_level in ("HIGH", "MEDIUM", "LOW"):
            for check in detected:
                if check.get("risk") == risk_level:
                    # --- Global alert cooldown check ---
                    if not should_send_alert(user_id, sender_id):
                        logging.debug(
                            f"Alert suppressed (global cooldown) "
                            f"sender={sender_id} type={check.get('type')}"
                        )
                        return {"detected": False, "type": "SAFE",
                                "risk": "LOW", "reason": "cooldown active"}

                    logging.info(
                        f"Threat | user={user_id} sender={sender_id} "
                        f"sender_username={sender_username} "
                        f"type={check.get('type')} risk={check.get('risk')} "
                        f"reason={check.get('reason')}"
                    )
                    # Attach sender info to every alert
                    return {
                        **check,
                        "sender_id":       sender_id,
                        "sender_username": sender_username,
                        "sender_name":     sender_name,
                    }

        return {"detected": False, "type": "SAFE", "risk": "LOW",
                "reason": "clean message"}

    except Exception as e:
        logging.error(f"analyze_message error sender={sender_id}: {e}")
        return {"detected": False, "type": "SAFE", "risk": "LOW",
                "reason": "analysis error"}