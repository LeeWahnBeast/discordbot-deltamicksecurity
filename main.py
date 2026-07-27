import os
import re
import json
import time
import asyncio
import logging
import unicodedata
import datetime
from collections import defaultdict, deque, Counter
from typing import Optional
import discord
from discord import app_commands
from discord.ext import commands
from keep_alive import keep_alive
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("securitybot")
TOKEN = os.getenv("DISCORD_TOKEN")
OWNER_IDS = {int(x) for x in os.getenv("OWNER_IDS", "").split(",") if x.strip().isdigit()}
PREFIX = os.getenv("PREFIX", "!")

# ── Firestore setup ──────────────────────────────────────────────────────
# Yêu cầu biến môi trường GOOGLE_APPLICATION_CREDENTIALS_JSON (nội dung JSON
# của service account key) HOẶC GOOGLE_APPLICATION_CREDENTIALS (đường dẫn file).
# Collection layout:
#   settings/{guild_id}      -> toàn bộ config của guild
#   backups/{guild_id}       -> snapshot backup gần nhất
#   stats/{guild_id}/days/{YYYY-MM-DD} -> thống kê theo ngày
from google.cloud import firestore as _firestore
from google.oauth2 import service_account as _service_account

def _make_firestore_client():
    raw_json = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON")
    if raw_json:
        info = json.loads(raw_json)
        creds = _service_account.Credentials.from_service_account_info(info)
        return _firestore.Client(credentials=creds, project=info.get("project_id"))
    return _firestore.Client()

db = _make_firestore_client()
SETTINGS_COLLECTION = "settings"
BACKUP_COLLECTION = "backups"
STATS_COLLECTION = "stats"
DEFAULTS = {
    "log_channel_id": None,
    "log_webhook_url": None,
    "alert_owner_on_critical": True,
    "raid_join_threshold": 6,
    "raid_join_window": 10,
    "raid_min_account_age_days": 3,
    "raid_cooldown_seconds": 300,
    "nuke_action_threshold": 3,
    "nuke_action_window": 15,
    "spam_msg_threshold": 6,
    "spam_msg_window": 7,
    "spam_timeout_seconds": 300,
    "slow_spam_duplicate_threshold": 4,
    "slow_spam_window": 120,
    "slow_spam_timeout_seconds": 600,
    "raid_channel_spam_threshold": 5,
    "raid_channel_spam_window": 10,
    "raid_softban_delete_seconds": 3600,
    "intermittent_spam_burst_size": 3,
    "intermittent_spam_burst_gap": 4,
    "intermittent_spam_quiet_gap": 6,
    "intermittent_spam_burst_count": 3,
    "intermittent_spam_window": 180,
    "intermittent_spam_timeout_seconds": 900,
    "mass_mention_threshold": 6,
    "mass_mention_timeout_seconds": 600,
    "invite_new_account_days": 3,
    "badwords": [],
    "scam_domains": [],
    "blocked_bot_ids": [],
    "auto_ban_suspicious_bots": True,
    "suspicion_ban_threshold": 100,
    "suspicion_timeout_threshold": 50,
    "suspicion_warning_threshold": 20,
    "suspicion_decay_seconds": 600,
    "zalgo_max_combining_chars": 8,
    "lockdown_active": False,
    "protected_role_ids": [],
    "backup_snapshot_interval_seconds": 1800,
    "dangerous_perm_names": [
        "administrator", "manage_guild", "manage_roles", "manage_webhooks",
        "manage_channels", "ban_members", "kick_members",
    ],
    "role_escalation_audit_wait_seconds": 3,
    "whitelist_user_ids": [],
    "whitelist_role_ids": [],
    "whitelist_bot_ids": [],
    "whitelist_webhook_ids": [],
    "token_grabber_keywords": [
        "discord_desktop_core", "inject.js", "webhook spammer",
        "password stealer", "token grabber", "token logger",
        "steal token", "grab token",
    ],
    "max_webhooks_per_guild": 15,
    "webhook_create_threshold": 3,
    "webhook_create_window": 30,
    "join_pattern_window": 30,
    "join_pattern_min_count": 4,
    "join_pattern_name_similarity_ratio": 0.6,
    "mass_role_grant_threshold": 5,
    "mass_role_grant_window": 15,
    "mass_ban_threshold": 5,
    "mass_ban_window": 10,
    "mass_kick_threshold": 5,
    "mass_kick_window": 10,
    "perm_wipe_threshold": 5,
    "perm_wipe_window": 15,
    "vanity_url_protection": True,
    "guild_identity_protection": True,
    "auto_ban_unauthorized_bot_adder": True,
    "emoji_sticker_nuke_threshold": 4,
    "emoji_sticker_nuke_window": 15,
    "automod_delete_threshold": 2,
    "automod_delete_window": 20,
    "integration_delete_threshold": 2,
    "integration_delete_window": 20,
    "oauth_suspicious_keywords": [
        "grabber", "nuker", "raid", "selfbot", "token", "stealer", "nitro sniper",
    ],
    "adaptive_detection_enabled": True,
    "adaptive_trusted_action_count": 30,
    "adaptive_trusted_min_age_days": 14,
    "adaptive_threshold_multiplier": 1.5,
    "audit_log_cache_ttl_seconds": 30,
}
CONFIGURABLE_INT_KEYS = [
    "raid_join_threshold", "raid_join_window", "raid_min_account_age_days", "raid_cooldown_seconds",
    "nuke_action_threshold", "nuke_action_window",
    "spam_msg_threshold", "spam_msg_window", "spam_timeout_seconds",
    "slow_spam_duplicate_threshold", "slow_spam_window", "slow_spam_timeout_seconds",
    "raid_channel_spam_threshold", "raid_channel_spam_window", "raid_softban_delete_seconds",
    "intermittent_spam_burst_size", "intermittent_spam_burst_gap", "intermittent_spam_quiet_gap",
    "intermittent_spam_burst_count", "intermittent_spam_window", "intermittent_spam_timeout_seconds",
    "mass_mention_threshold", "mass_mention_timeout_seconds", "invite_new_account_days",
    "suspicion_ban_threshold", "suspicion_timeout_threshold", "suspicion_warning_threshold", "suspicion_decay_seconds",
    "zalgo_max_combining_chars", "backup_snapshot_interval_seconds",
    "max_webhooks_per_guild", "webhook_create_threshold", "webhook_create_window",
    "join_pattern_window", "join_pattern_min_count",
    "mass_role_grant_threshold", "mass_role_grant_window",
    "mass_ban_threshold", "mass_ban_window", "mass_kick_threshold", "mass_kick_window",
    "perm_wipe_threshold", "perm_wipe_window",
    "emoji_sticker_nuke_threshold", "emoji_sticker_nuke_window",
    "automod_delete_threshold", "automod_delete_window",
    "integration_delete_threshold", "integration_delete_window",
    "adaptive_trusted_action_count", "adaptive_trusted_min_age_days",
    "audit_log_cache_ttl_seconds",
]
SUSPICION_WEIGHTS = {
    "badword": 10,
    "zalgo": 15,
    "mass_mention": 30,
    "invite_spam": 15,
    "spam_fast": 20,
    "spam_slow": 15,
    "spam_intermittent": 25,
    "scam": 40,
    "nuke": 100,
    "mass_ban": 80,
    "mass_kick": 60,
    "role_escalation": 90,
    "token_grabber": 70,
    "webhook_spam": 50,
    "perm_wipe": 90,
    "vanity_hijack": 100,
    "guild_identity": 85,
    "unauthorized_bot_add": 90,
    "emoji_sticker_nuke": 70,
    "automod_delete": 75,
    "integration_delete": 75,
    "oauth_suspicious": 60,
    "selfbot": 40,
}
SUSPICIOUS_BOT_NAME_PATTERN = re.compile(
    r"^(none|null|undefined|nan|unknown)$", re.IGNORECASE
)
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at",
    "rebrand.ly", "grabify.link", "iplogger.org", "ow.ly",
}
TRUSTED_BRAND_DOMAINS = ["discord.com", "discord.gg", "discordapp.com", "steamcommunity.com"]
REDIRECT_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at",
    "rebrand.ly", "ow.ly", "buff.ly", "shorte.st", "adf.ly",
}
# ── In-RAM cache, backed by Firestore ────────────────────────────────────
# Toàn bộ code cũ đọc/ghi trực tiếp vào 3 dict này (settings/backups/stats).
# Để không phải viết lại hàng trăm chỗ, ta giữ nguyên dict làm cache RAM,
# nhưng nguồn sự thật (source of truth) là Firestore: load 1 lần khi khởi
# động, và mỗi lần save() sẽ ghi thẳng lên Firestore (không còn file .json).
settings: dict = {}
backups: dict = {}
stats: dict = {}
_dirty_stats_guilds: set[str] = set()

def _load_all_sync():
    global settings, backups, stats
    settings = {}
    for doc in db.collection(SETTINGS_COLLECTION).stream():
        settings[doc.id] = doc.to_dict() or {}
    backups = {}
    for doc in db.collection(BACKUP_COLLECTION).stream():
        backups[doc.id] = doc.to_dict() or {}
    stats = {}
    for guild_doc in db.collection(STATS_COLLECTION).stream():
        gid = guild_doc.id
        stats[gid] = {}
        for day_doc in db.collection(STATS_COLLECTION).document(gid).collection("days").stream():
            stats[gid][day_doc.id] = day_doc.to_dict() or {}

def cfg(guild_id: int) -> dict:
    g = settings.setdefault(str(guild_id), {})
    merged = {**DEFAULTS, **g}
    settings[str(guild_id)] = merged
    return merged

def _save_guild_settings_sync(guild_id: str, data: dict):
    db.collection(SETTINGS_COLLECTION).document(guild_id).set(data)

def _save_all_settings_sync():
    for gid, data in settings.items():
        db.collection(SETTINGS_COLLECTION).document(gid).set(data)

def _save_backup_sync():
    for gid, data in backups.items():
        db.collection(BACKUP_COLLECTION).document(gid).set(data)

def _save_stats_sync():
    # Chỉ ghi những guild/ngày có thay đổi (tránh ghi tràn lan -> tiết kiệm CPU/quota).
    for gid in list(_dirty_stats_guilds):
        guild_stats = stats.get(gid, {})
        for day_key, day_data in guild_stats.items():
            db.collection(STATS_COLLECTION).document(gid).collection("days").document(day_key).set(day_data)
    _dirty_stats_guilds.clear()

async def save():
    try:
        await asyncio.to_thread(_save_all_settings_sync)
    except Exception:
        logger.exception("Không thể lưu settings lên Firestore")
async def save_guild_settings(guild_id: int):
    try:
        await asyncio.to_thread(_save_guild_settings_sync, str(guild_id), settings.get(str(guild_id), {}))
    except Exception:
        logger.exception("Không thể lưu settings guild %s lên Firestore", guild_id)
async def save_backup():
    try:
        await asyncio.to_thread(_save_backup_sync)
    except Exception:
        logger.exception("Không thể lưu backup lên Firestore")
def _save_guild_backup_sync(guild_id: str, data: dict):
    db.collection(BACKUP_COLLECTION).document(guild_id).set(data)
async def save_guild_backup(guild_id: int):
    try:
        await asyncio.to_thread(_save_guild_backup_sync, str(guild_id), backups.get(str(guild_id), {}))
    except Exception:
        logger.exception("Không thể lưu backup guild %s lên Firestore", guild_id)
async def save_stats():
    if not _dirty_stats_guilds:
        return
    try:
        await asyncio.to_thread(_save_stats_sync)
    except Exception:
        logger.exception("Không thể lưu stats lên Firestore")
async def set_and_save(guild_id: int, key: str, value) -> None:
    s = cfg(guild_id)
    s[key] = value
    settings[str(guild_id)] = s
    await save_guild_settings(guild_id)
def _today_key() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%d")
def bump_stat(guild_id: int, metric: str, amount: int = 1):
    gid = str(guild_id)
    g = stats.setdefault(gid, {})
    day = g.setdefault(_today_key(), {})
    day[metric] = day.get(metric, 0) + amount
    _dirty_stats_guilds.add(gid)
async def stats_save_loop():
    await bot.wait_until_ready()
    while not bot.is_closed():
        await asyncio.sleep(60)
        await save_stats()
intents = discord.Intents.default()
intents.members = True
intents.message_content = True
intents.bans = True
intents.moderation = True
bot = commands.Bot(command_prefix=PREFIX, intents=intents)
bot.start_time = time.time()
recent_joins = defaultdict(deque)
recent_join_members = defaultdict(deque)
recent_nuke_actions = defaultdict(deque)
recent_messages = defaultdict(deque)
recent_message_contents = defaultdict(deque)
message_timeline = defaultdict(deque)
raid_state = {}
suspicion_scores: dict[tuple[int, int], list] = {}
_webhook_cache: dict[str, discord.Webhook] = {}
recent_role_grants = defaultdict(deque)
recent_bans = defaultdict(deque)
recent_kicks = defaultdict(deque)
recent_perm_updates = defaultdict(deque)
recent_webhook_creates = defaultdict(deque)
recent_emoji_sticker_actions = defaultdict(deque)
recent_automod_deletes = defaultdict(deque)
recent_integration_deletes = defaultdict(deque)
processed_audit_entries: dict[int, float] = {}
guild_identity_snapshot: dict[int, dict] = {}
actor_clean_action_count: dict[tuple[int, int], int] = defaultdict(int)
def _prune_empty(d: defaultdict, key):
    if key in d and not d[key]:
        del d[key]
def _audit_entry_already_processed(entry_id: int, ttl_seconds: int) -> bool:
    now = time.time()
    if len(processed_audit_entries) > 500:
        stale = [k for k, ts in processed_audit_entries.items() if now - ts > ttl_seconds]
        for k in stale:
            del processed_audit_entries[k]
    last_ts = processed_audit_entries.get(entry_id)
    if last_ts is not None and now - last_ts <= ttl_seconds:
        return True
    processed_audit_entries[entry_id] = now
    return False
def is_actor_adaptively_trusted(guild: discord.Guild, actor, member, s: dict) -> bool:
    if not s.get("adaptive_detection_enabled", True):
        return False
    if member is None or not isinstance(member, discord.Member):
        return False
    key = (guild.id, actor.id)
    clean_count = actor_clean_action_count.get(key, 0)
    if clean_count < s.get("adaptive_trusted_action_count", 30):
        return False
    joined_at = member.joined_at
    if joined_at is None:
        return False
    age_days = (discord.utils.utcnow() - joined_at).days
    if age_days < s.get("adaptive_trusted_min_age_days", 14):
        return False
    return True
def note_clean_actor_action(guild_id: int, actor_id: int):
    actor_clean_action_count[(guild_id, actor_id)] += 1
def adaptive_threshold(base_threshold: int, guild: discord.Guild, actor, member, s: dict) -> int:
    if is_actor_adaptively_trusted(guild, actor, member, s):
        return max(base_threshold, int(round(base_threshold * s.get("adaptive_threshold_multiplier", 1.5))))
    return base_threshold
def detect_intermittent_spam(items: list, s: dict):
    if not items:
        return None
    burst_gap = s["intermittent_spam_burst_gap"]
    burst_size = s["intermittent_spam_burst_size"]
    quiet_gap = s["intermittent_spam_quiet_gap"]
    burst_count = s["intermittent_spam_burst_count"]
    clusters = []
    current = [items[0]]
    for item in items[1:]:
        if item[0] - current[-1][0] <= burst_gap:
            current.append(item)
        else:
            clusters.append(current)
            current = [item]
    clusters.append(current)
    bursts = [c for c in clusters if len(c) >= burst_size]
    if len(bursts) < burst_count:
        return None
    valid_gaps = sum(
        1 for i in range(1, len(bursts))
        if bursts[i][0][0] - bursts[i - 1][-1][0] >= quiet_gap
    )
    if valid_gaps >= burst_count - 1:
        return bursts
    return None
SCAM_PATTERN = re.compile(
    r"discord\W?nitro|dlscord|discrod|discocl|steamcommunlty|steamcommunnity|free.?nitro",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://([^\s/]+)(/[^\s]*)?", re.IGNORECASE)
INVITE_RE = re.compile(r"(?:discord\.gg|discord(?:app)?\.com/invite)/([a-z0-9-]+)", re.IGNORECASE)
LEET_MAP = str.maketrans({
    "4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "|": "i",
    "0": "o", "5": "s", "$": "s", "7": "t", "+": "t", "8": "b",
    "9": "g",
})
VN_MAP = str.maketrans({"đ": "d", "Đ": "d"})
SHORT_WORD_BOUNDARY_LEN = 4
INVISIBLE_CHARS_RE = re.compile(
    "["
    "\u200b"
    "\u200c"
    "\u200d"
    "\u2060"
    "\ufeff"
    "\u202a-\u202e"
    "\u2066-\u2069"
    "]"
)
def strip_invisible_chars(text: str) -> str:
    return INVISIBLE_CHARS_RE.sub("", text)
MORSE_TABLE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
    "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
    "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
    "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
}
MORSE_CHAR_RE = re.compile(r"^[.\-\s/]+$")
def looks_like_morse(text: str) -> bool:
    stripped = text.strip()
    if len(stripped) < 6:
        return False
    if not MORSE_CHAR_RE.match(stripped):
        return False
    tokens = [t for t in re.split(r"[\s/]+", stripped) if t]
    return len(tokens) >= 3
def decode_morse(text: str) -> str | None:
    stripped = text.strip()
    words = stripped.split("/")
    decoded_words = []
    total_tokens = 0
    failed_tokens = 0
    for word in words:
        tokens = word.split()
        letters = []
        for tok in tokens:
            total_tokens += 1
            letter = MORSE_TABLE.get(tok)
            if letter:
                letters.append(letter)
            else:
                failed_tokens += 1
        decoded_words.append("".join(letters))
    if total_tokens == 0 or failed_tokens / total_tokens > 0.3:
        return None
    return " ".join(w for w in decoded_words if w).strip()
def normalize(text: str) -> str:
    text = strip_invisible_chars(text)
    text = text.lower()
    text = text.translate(VN_MAP)
    text = unicodedata.normalize("NFD", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Mn")
    text = text.translate(LEET_MAP)
    return text
def _strip_non_alnum(text: str) -> str:
    text = re.sub(r"[^a-z0-9\s]", "", text)
    text = re.sub(r"(.)\1+", r"\1", text)
    return text
def contains_badword(content: str, badwords: list[str]) -> str | None:
    base = normalize(content)
    spaced = _strip_non_alnum(base)
    squashed = re.sub(r"\s+", "", spaced)
    for w in badwords:
        norm_word = normalize(w)
        norm_word = re.sub(r"[^a-z0-9]", "", norm_word)
        norm_word = re.sub(r"(.)\1+", r"\1", norm_word)
        if not norm_word:
            continue
        if len(norm_word) < SHORT_WORD_BOUNDARY_LEN:
            if re.search(rf"(?<![a-z0-9]){re.escape(norm_word)}(?![a-z0-9])", spaced):
                return w
        else:
            if norm_word in squashed:
                return w
    return None
_DEDUPE_NOISE_RE = re.compile(
    r"[^\w\s]|[\U0001F000-\U0001FFFF\u2600-\u27BF]", re.UNICODE
)
_DEDUPE_REPEAT_RE = re.compile(r"(.)\1{1,}")
_DEDUPE_DIGIT_RE = re.compile(r"\d+")
def normalize_for_dedupe(content: str) -> str:
    # Fingerprint chống né lọc: bỏ emoji/dấu câu (mồi để phá exact-match),
    # thay số bằng "#" (chống kiểu đếm 1,2,3... để né trùng lặp), và co
    # ký tự lặp liên tiếp về 1 (chống "spammmm" / "sppaaam" biến thể).
    # Vẫn là O(n), không tốn thêm CPU đáng kể so với bản cũ.
    text = strip_invisible_chars(content).strip().lower()
    text = _DEDUPE_NOISE_RE.sub("", text)
    text = _DEDUPE_DIGIT_RE.sub("#", text)
    text = _DEDUPE_REPEAT_RE.sub(r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text
def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]
def looks_like_typosquat(host: str) -> str | None:
    host = host.lower()
    for brand in TRUSTED_BRAND_DOMAINS:
        if host == brand or host.endswith("." + brand):
            return None
        dist = _levenshtein(host, brand)
        if 0 < dist <= 2 and len(host) >= len(brand) - 3:
            return brand
    return None
def is_shortener(host: str) -> bool:
    return host.lower() in URL_SHORTENERS
def count_combining_chars(text: str) -> int:
    return sum(1 for c in text if unicodedata.category(c) == "Mn")
def is_zalgo(text: str, max_combining: int) -> bool:
    return count_combining_chars(text) > max_combining
async def unwrap_redirect(url: str, max_hops: int = 3) -> str:
    current = url
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            for _ in range(max_hops):
                try:
                    async with session.head(current, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=4)) as resp:
                        if resp.status in (301, 302, 303, 307, 308) and "Location" in resp.headers:
                            nxt = resp.headers["Location"]
                            if nxt.startswith("/"):
                                break
                            current = nxt
                        else:
                            break
                except (asyncio.TimeoutError, Exception):
                    break
    except ImportError:
        logger.warning("aiohttp không sẵn có — bỏ qua unwrap redirect")
    return current
def is_whitelisted_user(guild_id: int, user_id: int) -> bool:
    s = cfg(guild_id)
    return user_id in set(s.get("whitelist_user_ids", []))
def is_whitelisted_member_by_role(guild_id: int, member: discord.Member) -> bool:
    s = cfg(guild_id)
    wl_roles = set(s.get("whitelist_role_ids", []))
    if not wl_roles:
        return False
    return any(r.id in wl_roles for r in member.roles)
def is_whitelisted_bot(guild_id: int, bot_id: int) -> bool:
    s = cfg(guild_id)
    return bot_id in set(s.get("whitelist_bot_ids", []))
def is_whitelisted_webhook(guild_id: int, webhook_id: int) -> bool:
    s = cfg(guild_id)
    return webhook_id in set(s.get("whitelist_webhook_ids", []))
def is_protected(member: discord.abc.User, guild_id: int | None = None) -> bool:
    if member.id in OWNER_IDS:
        return True
    if guild_id is not None and is_whitelisted_user(guild_id, member.id):
        return True
    if not isinstance(member, discord.Member):
        return False
    if member.guild and member.id == member.guild.owner_id:
        return True
    if guild_id is not None and is_whitelisted_member_by_role(guild_id, member):
        return True
    return member.guild_permissions.administrator
def add_suspicion(guild_id: int, user_id: int, category: str, decay_seconds: int) -> int:
    points = SUSPICION_WEIGHTS.get(category, 10)
    key = (guild_id, user_id)
    now = time.time()
    entry = suspicion_scores.get(key)
    if entry is None:
        score, last_ts = 0.0, now
    else:
        score, last_ts = entry
    if decay_seconds > 0:
        elapsed = now - last_ts
        decay = (elapsed / decay_seconds) * 10
        score = max(0.0, score - decay)
    score += points
    suspicion_scores[key] = [score, now]
    return int(score)
_warned_users: set[tuple[int, int]] = set()
def cleanup_suspicion_scores(max_age_seconds: int = 3600):
    now = time.time()
    stale = [k for k, (_, ts) in suspicion_scores.items() if now - ts > max_age_seconds]
    for k in stale:
        del suspicion_scores[k]
        _warned_users.discard(k)
async def apply_suspicion_consequence(guild: discord.Guild, member: discord.Member, score: int, s: dict):
    key = (guild.id, member.id)
    if score >= s["suspicion_ban_threshold"]:
        _warned_users.discard(key)
        await safe_action(member.ban(reason=f"Suspicion score vượt ngưỡng ({score})"), action_name="ban high suspicion user", guild_id=guild.id)
        bump_stat(guild.id, "ban", 1)
        await log(guild, f"⛔ {member.mention} bị ban do điểm nghi ngờ tích lũy vượt ngưỡng (**{score}** điểm)", discord.Color.dark_red(), critical=True)
    elif score >= s["suspicion_timeout_threshold"]:
        _warned_users.discard(key)
        until = discord.utils.utcnow() + datetime.timedelta(minutes=15)
        await safe_action(member.timeout(until, reason=f"Suspicion score cao ({score})"), action_name="timeout high suspicion user", guild_id=guild.id)
        bump_stat(guild.id, "timeout", 1)
        await log(guild, f"⏱️ {member.mention} bị timeout do điểm nghi ngờ cao (**{score}** điểm)", discord.Color.orange())
    elif score >= s.get("suspicion_warning_threshold", 20):
        # Bậc "Nhẹ": chỉ cảnh cáo, KHÔNG mute/kick/ban — đúng thang hình phạt của server.
        if key not in _warned_users:
            _warned_users.add(key)
            bump_stat(guild.id, "warning", 1)
            await log(guild, f"🟢 {member.mention} nhận **cảnh cáo** do có dấu hiệu vi phạm (**{score}** điểm, chưa đủ ngưỡng phạt)", discord.Color.green())
            await dm_warning(member, "bạn vừa nhận một cảnh cáo do vi phạm nội quy. Vi phạm tiếp sẽ bị cách ly (timeout) hoặc nặng hơn.")
    else:
        _warned_users.discard(key)
async def get_log_webhook(url: str) -> Optional[discord.Webhook]:
    if url in _webhook_cache:
        return _webhook_cache[url]
    try:
        wh = discord.Webhook.from_url(url, client=bot)
        _webhook_cache[url] = wh
        return wh
    except (ValueError, discord.HTTPException):
        logger.warning("Webhook URL không hợp lệ")
        return None
async def log(guild: discord.Guild, text: str, color=discord.Color.blurple(), *, critical: bool = False):
    s = cfg(guild.id)
    embed = discord.Embed(description=text, color=color, timestamp=discord.utils.utcnow())
    if critical:
        embed.set_footer(text="⚠️ SỰ CỐ NGHIÊM TRỌNG")
    sent = False
    if s.get("log_webhook_url"):
        wh = await get_log_webhook(s["log_webhook_url"])
        if wh:
            try:
                await wh.send(embed=embed, username="Security Bot")
                sent = True
            except discord.HTTPException:
                logger.exception("Gửi log qua webhook thất bại ở guild %s", guild.id)
    if not sent and s["log_channel_id"]:
        channel = guild.get_channel(s["log_channel_id"])
        if channel is None:
            logger.warning("Log channel %s không tồn tại/không truy cập được ở guild %s", s["log_channel_id"], guild.id)
        else:
            try:
                await channel.send(embed=embed)
                sent = True
            except discord.Forbidden:
                logger.warning("Thiếu quyền gửi tin nhắn vào log channel ở guild %s", guild.id)
            except discord.HTTPException:
                logger.exception("Gửi log thất bại ở guild %s", guild.id)
    if critical and s.get("alert_owner_on_critical", True):
        await alert_owners(guild, text)
async def alert_owners(guild: discord.Guild, text: str):
    for owner_id in OWNER_IDS:
        user = bot.get_user(owner_id)
        if user is None:
            user = await safe_action(bot.fetch_user(owner_id), action_name="fetch owner for DM")
        if user is None:
            continue
        try:
            await user.send(f"🚨 **[{guild.name}]** {text}")
        except discord.HTTPException:
            logger.warning("Không thể DM owner %s", owner_id)
async def safe_action(coro, *, action_name: str, guild_id: int | None = None):
    try:
        return await coro
    except discord.Forbidden:
        logger.warning("Thiếu quyền để thực hiện '%s' (guild=%s). Kiểm tra role/permissions của bot.", action_name, guild_id)
    except discord.HTTPException:
        logger.exception("Lỗi HTTP khi thực hiện '%s' (guild=%s)", action_name, guild_id)
    return None
async def softban(guild: discord.Guild, user: discord.abc.Snowflake, reason: str, delete_seconds: int = 3600):
    banned = await safe_action(
        guild.ban(user, reason=reason, delete_message_seconds=delete_seconds),
        action_name="softban (ban step)",
        guild_id=guild.id,
    )
    await safe_action(
        guild.unban(user, reason="Softban: gỡ ban sau khi đã xóa tin nhắn"),
        action_name="softban (unban step)",
        guild_id=guild.id,
    )
    return banned is not None
async def snapshot_guild(guild: discord.Guild):
    roles_data = []
    for role in guild.roles:
        if role.is_default():
            continue
        roles_data.append({
            "id": role.id,
            "name": role.name,
            "permissions": role.permissions.value,
            "color": role.color.value,
            "hoist": role.hoist,
            "mentionable": role.mentionable,
            "position": role.position,
        })
    categories_data = []
    for cat in guild.categories:
        categories_data.append({
            "id": cat.id,
            "name": cat.name,
            "position": cat.position,
        })
    channels_data = []
    for channel in guild.channels:
        if isinstance(channel, discord.CategoryChannel):
            continue
        overwrites = {}
        for target, ow in channel.overwrites.items():
            allow, deny = ow.pair()
            overwrites[str(target.id)] = {
                "allow": allow.value, "deny": deny.value,
                "type": "role" if isinstance(target, discord.Role) else "member",
            }
        channels_data.append({
            "id": channel.id,
            "name": channel.name,
            "type": str(channel.type),
            "category_id": channel.category_id,
            "position": channel.position,
            "topic": getattr(channel, "topic", None),
            "overwrites": overwrites,
        })
    backups[str(guild.id)] = {
        "timestamp": time.time(),
        "roles": roles_data,
        "categories": categories_data,
        "channels": channels_data,
    }
    await save_guild_backup(guild.id)
async def backup_snapshot_loop():
    await bot.wait_until_ready()
    while not bot.is_closed():
        for guild in bot.guilds:
            s = cfg(guild.id)
            last = backups.get(str(guild.id), {}).get("timestamp", 0)
            if time.time() - last >= s["backup_snapshot_interval_seconds"]:
                await snapshot_guild(guild)
        await asyncio.sleep(300)
async def restore_roles(guild: discord.Guild, data: dict) -> int:
    existing_ids = {r.id for r in guild.roles}
    restored = 0
    for r in data["roles"]:
        if r["id"] in existing_ids:
            continue
        new_role = await safe_action(
            guild.create_role(
                name=r["name"],
                permissions=discord.Permissions(r["permissions"]),
                colour=discord.Colour(r["color"]),
                hoist=r["hoist"],
                mentionable=r["mentionable"],
                reason="Auto-restore sau nuke",
            ),
            action_name="restore deleted role",
            guild_id=guild.id,
        )
        if new_role:
            restored += 1
        await asyncio.sleep(0.5)
    return restored
async def restore_categories(guild: discord.Guild, data: dict) -> dict:
    existing_ids = {c.id for c in guild.categories}
    id_map = {}
    for cat in sorted(data.get("categories", []), key=lambda c: c["position"]):
        if cat["id"] in existing_ids:
            continue
        new_cat = await safe_action(
            guild.create_category(name=cat["name"], reason="Auto-restore sau nuke"),
            action_name="restore deleted category",
            guild_id=guild.id,
        )
        if new_cat:
            id_map[cat["id"]] = new_cat
        await asyncio.sleep(0.5)
    return id_map
async def restore_channels(guild: discord.Guild, data: dict, category_map: dict) -> int:
    existing_ids = {c.id for c in guild.channels}
    role_by_id = {r.id: r for r in guild.roles}
    restored = 0
    for ch in sorted(data["channels"], key=lambda c: c["position"]):
        if ch["id"] in existing_ids:
            continue
        category = None
        if ch["category_id"] and ch["category_id"] in category_map:
            category = category_map[ch["category_id"]]
        elif ch["category_id"]:
            category = guild.get_channel(ch["category_id"])
        overwrites = {}
        for target_id_str, ow in ch.get("overwrites", {}).items():
            target_id = int(target_id_str)
            allow = discord.Permissions(ow["allow"])
            deny = discord.Permissions(ow["deny"])
            perm_ow = discord.PermissionOverwrite.from_pair(allow, deny)
            if ow["type"] == "role":
                target = role_by_id.get(target_id)
            else:
                target = guild.get_member(target_id)
            if target:
                overwrites[target] = perm_ow
        kwargs = {"name": ch["name"], "category": category, "overwrites": overwrites, "reason": "Auto-restore sau nuke"}
        if ch["type"] == "text" and ch.get("topic"):
            kwargs["topic"] = ch["topic"]
        new_channel = None
        if ch["type"] == "voice":
            new_channel = await safe_action(guild.create_voice_channel(**kwargs), action_name="restore voice channel", guild_id=guild.id)
        else:
            new_channel = await safe_action(guild.create_text_channel(**kwargs), action_name="restore text channel", guild_id=guild.id)
        if new_channel:
            restored += 1
        await asyncio.sleep(0.5)
    return restored
async def cleanup_loop():
    await bot.wait_until_ready()
    while not bot.is_closed():
        cleanup_suspicion_scores()
        now = time.time()
        for d, max_window in (
            (recent_joins, 3600),
            (recent_join_members, 3600),
            (recent_nuke_actions, 3600),
            (recent_messages, 3600),
            (recent_message_contents, 3600),
            (recent_role_grants, 3600),
            (recent_bans, 3600),
            (recent_kicks, 3600),
            (recent_perm_updates, 3600),
            (recent_webhook_creates, 3600),
        ):
            stale_keys = []
            for k, bucket in d.items():
                if not bucket:
                    stale_keys.append(k)
                    continue
                first = bucket[0]
                ts = first[0] if isinstance(first, tuple) else first
                if now - ts > max_window:
                    stale_keys.append(k)
            for k in stale_keys:
                del d[k]
        await asyncio.sleep(900)
@bot.event
async def on_ready():
    logger.info("Logged in as %s", bot.user)
    try:
        synced = await bot.tree.sync()
        logger.info("Đã sync %d slash command(s)", len(synced))
    except Exception:
        logger.exception("Sync slash command lỗi")
    for guild in bot.guilds:
        guild_identity_snapshot[guild.id] = {
            "name": guild.name,
            "icon": guild.icon.key if guild.icon else None,
            "banner": guild.banner.key if guild.banner else None,
            "vanity": getattr(guild, "vanity_url_code", None),
            "verification_level": str(guild.verification_level),
        }
@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.MissingPermissions):
        msg = "❌ Bạn cần quyền Administrator để dùng lệnh này."
    else:
        logger.exception("Lỗi app command '%s'", interaction.command.name if interaction.command else "?", exc_info=error)
        msg = "❌ Có lỗi xảy ra khi chạy lệnh. Đã ghi log để kiểm tra."
    try:
        if interaction.response.is_done():
            await interaction.followup.send(msg, ephemeral=True)
        else:
            await interaction.response.send_message(msg, ephemeral=True)
    except discord.HTTPException:
        pass
def _is_suspicious_bot(member: discord.Member) -> str | None:
    if not member.bot:
        return None
    name = (member.name or "").strip()
    global_name = (member.global_name or "").strip() if member.global_name else ""
    if not name and not global_name:
        return "tên rỗng"
    if SUSPICIOUS_BOT_NAME_PATTERN.match(name) or SUSPICIOUS_BOT_NAME_PATTERN.match(global_name):
        return "tên hiển thị 'None/null/undefined'"
    return None
def _is_discord_verified_bot(member: discord.Member) -> bool:
    if not member.bot:
        return False
    flags = getattr(member, "public_flags", None)
    return bool(flags and getattr(flags, "verified_bot", False))
def _username_looks_random(name: str) -> bool:
    name = name.lower()
    if re.fullmatch(r"[a-z]*\d{4,}", name):
        return True
    if re.fullmatch(r"[a-z0-9]{6,}", name) and sum(c.isdigit() for c in name) >= 3:
        return True
    return False
async def analyze_join_pattern(guild: discord.Guild, s: dict) -> str | None:
    now = time.time()
    bucket = recent_join_members[guild.id]
    while bucket and now - bucket[0][0] > s["join_pattern_window"]:
        bucket.popleft()
    if len(bucket) < s["join_pattern_min_count"]:
        return None
    members = [m for _, m in bucket]
    total = len(members)
    avatar_hashes = Counter(m.avatar.key if m.avatar else "default" for m in members)
    most_common_avatar, avatar_count = avatar_hashes.most_common(1)[0]
    random_name_count = sum(1 for m in members if _username_looks_random(m.name))
    creation_times = sorted(m.created_at.timestamp() for m in members)
    close_creation_count = 1
    max_close = 1
    for i in range(1, len(creation_times)):
        if creation_times[i] - creation_times[i - 1] <= 3600:
            close_creation_count += 1
            max_close = max(max_close, close_creation_count)
        else:
            close_creation_count = 1
    ratio = s["join_pattern_name_similarity_ratio"]
    reasons = []
    if avatar_count / total >= ratio and most_common_avatar != "default":
        reasons.append(f"{avatar_count}/{total} tài khoản dùng chung avatar")
    if random_name_count / total >= ratio:
        reasons.append(f"{random_name_count}/{total} username dạng ngẫu nhiên")
    if max_close / total >= ratio:
        reasons.append(f"{max_close}/{total} tài khoản được tạo gần cùng thời điểm")
    if reasons:
        return "; ".join(reasons)
    return None
@bot.event
async def on_member_join(member: discord.Member):
    guild = member.guild
    s = cfg(guild.id)
    if is_whitelisted_user(guild.id, member.id) or is_whitelisted_member_by_role(guild.id, member):
        return
    if s.get("lockdown_active"):
        account_age = (discord.utils.utcnow() - member.created_at).days
        if account_age < s["raid_min_account_age_days"]:
            await safe_action(member.kick(reason="Lockdown: tài khoản quá mới"), action_name="kick during lockdown", guild_id=guild.id)
            return
    if member.bot:
        if is_whitelisted_bot(guild.id, member.id):
            return
        if member.id in set(s["blocked_bot_ids"]):
            await safe_action(
                member.ban(reason=f"Blocklist: bot ID {member.id} bị chặn cứng"),
                action_name="ban blocklisted bot",
                guild_id=guild.id,
            )
            await log(guild, f"🤖⛔ Đã ban bot bị chặn `{member.id}` (`{member}`)", discord.Color.dark_red())
            bump_stat(guild.id, "bot_banned", 1)
            return
        if _is_discord_verified_bot(member):
            await log(
                guild,
                f"🤖✅ Bot đã xác minh (Verified ✓) `{member}` (`{member.id}`) tham gia — bỏ qua kiểm tra nghi ngờ/raid.",
                discord.Color.green(),
            )
            return
        if s.get("auto_ban_suspicious_bots", True):
            reason = _is_suspicious_bot(member)
            if reason:
                await safe_action(
                    member.ban(reason=f"Anti-raid: bot khả nghi ({reason})"),
                    action_name="ban suspicious bot",
                    guild_id=guild.id,
                )
                await log(guild, f"🤖⛔ Đã ban bot khả nghi `{member.id}` — lý do: {reason}", discord.Color.dark_red())
                bump_stat(guild.id, "bot_banned", 1)
                return
        await log(
            guild,
            f"🤖 Bot mới tham gia: `{member}` (`{member.id}`) — chưa có badge Verified, chưa nằm trong whitelist/blocklist. "
            f"Dùng `/whitelistbot` nếu tin tưởng, hoặc `/blockbot` nếu muốn chặn.",
            discord.Color.blurple(),
        )
        return
    now = time.time()
    joins = recent_joins[guild.id]
    joins.append(now)
    while joins and now - joins[0] > s["raid_join_window"]:
        joins.popleft()
    recent_join_members[guild.id].append((now, member))
    account_age = (discord.utils.utcnow() - member.created_at).days
    if len(joins) >= s["raid_join_threshold"]:
        state = raid_state.get(guild.id)
        if not state or not state.get("active"):
            raid_state[guild.id] = {
                "active": True,
                "last_seen": now,
                "old_level": guild.verification_level,
            }
            if guild.verification_level != discord.VerificationLevel.high:
                await safe_action(
                    guild.edit(verification_level=discord.VerificationLevel.high),
                    action_name="raise verification level",
                    guild_id=guild.id,
                )
            await log(guild,
                      f"🚨 **Raid detected** — {len(joins)} joins trong {s['raid_join_window']}s. "
                      f"Verification level đã nâng lên High.",
                      discord.Color.red(), critical=True)
            bump_stat(guild.id, "raid_blocked", 1)
        else:
            state["last_seen"] = now
        if account_age < s["raid_min_account_age_days"]:
            await safe_action(
                member.kick(reason="Anti-raid: tài khoản quá mới trong lúc raid"),
                action_name="kick new account during raid",
                guild_id=guild.id,
            )
    pattern_reason = await analyze_join_pattern(guild, s)
    if pattern_reason:
        await log(
            guild,
            f"🕵️ **Join Pattern khả nghi phát hiện** — {pattern_reason}.\n"
            f"Khuyến nghị: kiểm tra kênh gần đây, cân nhắc `/lockdown true`.",
            discord.Color.orange(),
            critical=True,
        )
        bump_stat(guild.id, "raid_blocked", 1)
async def raid_cooldown_loop():
    await bot.wait_until_ready()
    while not bot.is_closed():
        now = time.time()
        for guild_id, state in list(raid_state.items()):
            if not state.get("active"):
                continue
            guild = bot.get_guild(guild_id)
            if guild is None:
                continue
            s = cfg(guild_id)
            if now - state["last_seen"] >= s["raid_cooldown_seconds"]:
                old_level = state.get("old_level", discord.VerificationLevel.medium)
                if guild.verification_level != old_level:
                    await safe_action(
                        guild.edit(verification_level=old_level),
                        action_name="restore verification level",
                        guild_id=guild_id,
                    )
                    await log(guild, "✅ Raid đã lắng xuống — verification level đã trở về mức cũ.", discord.Color.green())
                state["active"] = False
        await asyncio.sleep(30)
DANGEROUS_PERMS_ATTRS = [
    "administrator", "manage_guild", "manage_roles", "manage_webhooks",
    "manage_channels", "ban_members", "kick_members",
]
def _role_has_dangerous_perms(role: discord.Role, dangerous_names: list[str]) -> list[str]:
    hits = []
    for name in dangerous_names:
        if getattr(role.permissions, name, False):
            hits.append(name)
    return hits
@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    guild = after.guild
    s = cfg(guild.id)
    added_roles = [r for r in after.roles if r not in before.roles]
    if not added_roles:
        return
    dangerous_names = s.get("dangerous_perm_names", DANGEROUS_PERMS_ATTRS)
    dangerous_added = []
    for role in added_roles:
        hits = _role_has_dangerous_perms(role, dangerous_names)
        if hits:
            dangerous_added.append((role, hits))
    if not dangerous_added:
        return
    if is_protected(after, guild.id):
        return
    await asyncio.sleep(s.get("role_escalation_audit_wait_seconds", 3))
    actor = None
    try:
        async for entry in guild.audit_logs(action=discord.AuditLogAction.member_role_update, limit=5):
            if entry.target and entry.target.id == after.id:
                actor = entry.user
                break
    except discord.Forbidden:
        logger.warning("Thiếu quyền View Audit Log để xác định người cấp role ở guild %s", guild.id)
    actor_member = guild.get_member(actor.id) if actor else None
    actor_authorized = actor and (is_protected(actor, guild.id) if actor_member is None else is_protected(actor_member, guild.id))
    role_names = ", ".join(r.name for r, _ in dangerous_added)
    if actor_authorized:
        await log(guild, f"ℹ️ {after.mention} được cấp role nguy hiểm ({role_names}) bởi {actor.mention if actor else 'không rõ'} (đã xác thực quyền hợp lệ)", discord.Color.blurple())
        return
    await safe_action(
        after.remove_roles(*[r for r, _ in dangerous_added], reason="Anti Role Escalation: cấp quyền nguy hiểm trái phép"),
        action_name="remove escalated roles",
        guild_id=guild.id,
    )
    bump_stat(guild.id, "role_escalation_blocked", 1)
    if actor and actor.id != bot.user.id:
        await safe_action(
            guild.ban(actor, reason="Anti Role Escalation: cấp quyền nguy hiểm trái phép cho thành viên khác"),
            action_name="ban unauthorized role granter",
            guild_id=guild.id,
        )
        score = add_suspicion(guild.id, actor.id, "role_escalation", s["suspicion_decay_seconds"])
        await log(
            guild,
            f"🛑 **Anti Role Escalation** — {after.mention} bị cấp role nguy hiểm ({role_names}) trái phép "
            f"bởi {actor.mention} (`{actor.id}`). Đã gỡ role + ban người cấp.",
            discord.Color.dark_red(),
            critical=True,
        )
    else:
        await log(
            guild,
            f"🛑 **Anti Role Escalation** — {after.mention} được cấp role nguy hiểm ({role_names}) nhưng "
            f"không xác định được người cấp qua audit log. Đã gỡ role — kiểm tra thủ công.",
            discord.Color.dark_red(),
            critical=True,
        )
WATCHED_ACTIONS = {
    discord.AuditLogAction.channel_delete,
    discord.AuditLogAction.channel_create,
    discord.AuditLogAction.channel_update,
    discord.AuditLogAction.role_delete,
    discord.AuditLogAction.role_update,
    discord.AuditLogAction.role_create,
    discord.AuditLogAction.member_role_update,
    discord.AuditLogAction.ban,
    discord.AuditLogAction.kick,
    discord.AuditLogAction.webhook_create,
    discord.AuditLogAction.webhook_update,
    discord.AuditLogAction.emoji_delete,
    discord.AuditLogAction.integration_create,
    discord.AuditLogAction.guild_update,
    discord.AuditLogAction.bot_add,
    discord.AuditLogAction.sticker_delete,
    discord.AuditLogAction.automod_rule_delete,
    discord.AuditLogAction.integration_delete,
}
CRITICAL_ACTIONS = {
    discord.AuditLogAction.channel_delete,
    discord.AuditLogAction.role_delete,
    discord.AuditLogAction.webhook_create,
    discord.AuditLogAction.bot_add,
    discord.AuditLogAction.sticker_delete,
    discord.AuditLogAction.automod_rule_delete,
    discord.AuditLogAction.integration_delete,
}
FORUM_CHANNEL_TYPES = {discord.ChannelType.forum}
@bot.event
async def on_audit_log_entry(entry: discord.AuditLogEntry):
    if entry.action not in WATCHED_ACTIONS:
        return
    actor = entry.user
    if actor is None or actor.id == bot.user.id:
        return
    guild = entry.guild
    s = cfg(guild.id)
    if _audit_entry_already_processed(entry.id, s.get("audit_log_cache_ttl_seconds", 30)):
        return
    member = guild.get_member(actor.id)
    if member and is_protected(member, guild.id):
        return
    if is_whitelisted_user(guild.id, actor.id):
        return
    now = time.time()
    if entry.action in (discord.AuditLogAction.role_delete, discord.AuditLogAction.role_update):
        target_id = getattr(entry.target, "id", None)
        if target_id in set(s.get("protected_role_ids", [])):
            await log(guild, f"⚠️ Phát hiện thay đổi role được bảo vệ (`{target_id}`) bởi {actor.mention} — kiểm tra ngay!", discord.Color.dark_red(), critical=True)
    if entry.action == discord.AuditLogAction.ban:
        bucket = recent_bans[guild.id]
        bucket.append((now, actor.id))
        while bucket and now - bucket[0][0] > s["mass_ban_window"]:
            bucket.popleft()
        actor_bans = sum(1 for _, aid in bucket if aid == actor.id)
        if actor_bans >= s["mass_ban_threshold"]:
            bucket.clear()
            _prune_empty(recent_bans, guild.id)
            await handle_mod_abuse(guild, actor, member, "mass_ban", f"{actor_bans} lượt ban trong {s['mass_ban_window']}s")
            return
    if entry.action == discord.AuditLogAction.kick:
        bucket = recent_kicks[guild.id]
        bucket.append((now, actor.id))
        while bucket and now - bucket[0][0] > s["mass_kick_window"]:
            bucket.popleft()
        actor_kicks = sum(1 for _, aid in bucket if aid == actor.id)
        if actor_kicks >= s["mass_kick_threshold"]:
            bucket.clear()
            _prune_empty(recent_kicks, guild.id)
            await handle_mod_abuse(guild, actor, member, "mass_kick", f"{actor_kicks} lượt kick trong {s['mass_kick_window']}s")
            return
    if entry.action == discord.AuditLogAction.channel_update:
        key = (guild.id, actor.id)
        bucket = recent_perm_updates[key]
        bucket.append(now)
        while bucket and now - bucket[0] > s["perm_wipe_window"]:
            bucket.popleft()
        if len(bucket) >= s["perm_wipe_threshold"]:
            bucket.clear()
            _prune_empty(recent_perm_updates, key)
            await log(guild, f"⚠️ **Channel Permission Wipe phát hiện** — {actor.mention} sửa quyền hàng loạt kênh. Dùng `/restoreall` để khôi phục overwrite từ backup.", discord.Color.dark_red(), critical=True)
            await handle_mod_abuse(guild, actor, member, "perm_wipe", f"sửa quyền {len(bucket)}+ kênh trong {s['perm_wipe_window']}s", skip_role_strip=False)
            return
    if entry.action == discord.AuditLogAction.webhook_create:
        key = (guild.id, actor.id)
        bucket = recent_webhook_creates[key]
        bucket.append(now)
        while bucket and now - bucket[0] > s["webhook_create_window"]:
            bucket.popleft()
        if len(bucket) >= s["webhook_create_threshold"]:
            bucket.clear()
            _prune_empty(recent_webhook_creates, key)
            await handle_mod_abuse(guild, actor, member, "webhook_spam", f"tạo {s['webhook_create_threshold']}+ webhook trong {s['webhook_create_window']}s")
            return
        try:
            webhooks = await guild.webhooks()
            if len(webhooks) > s["max_webhooks_per_guild"]:
                target = getattr(entry, "target", None)
                if target and not is_whitelisted_webhook(guild.id, target.id):
                    await safe_action(target.delete(reason="Vượt giới hạn số webhook cho phép"), action_name="delete excess webhook", guild_id=guild.id)
                    await log(guild, f"🪝 Đã xóa webhook lạ do vượt giới hạn ({len(webhooks)}/{s['max_webhooks_per_guild']}) — tạo bởi {actor.mention}", discord.Color.gold())
        except discord.Forbidden:
            pass
    if entry.action == discord.AuditLogAction.guild_update:
        snap = guild_identity_snapshot.get(guild.id)
        before = getattr(entry, "before", None)
        after = getattr(entry, "after", None)
        if s.get("vanity_url_protection", True):
            before_vanity = getattr(before, "vanity_url_code", None)
            after_vanity = getattr(after, "vanity_url_code", None)
            if before_vanity is not None and after_vanity is not None and before_vanity != after_vanity:
                await log(guild, f"🔗 **Vanity URL bị đổi** từ `{before_vanity}` → `{after_vanity}` bởi {actor.mention}!", discord.Color.dark_red(), critical=True)
                await handle_mod_abuse(guild, actor, member, "vanity_hijack", f"đổi vanity URL `{before_vanity}` → `{after_vanity}`")
                return
        if s.get("guild_identity_protection", True):
            changed = []
            for attr, label in (("name", "tên server"), ("icon", "icon server"), ("banner", "banner server"), ("verification_level", "verification level")):
                b_val = getattr(before, attr, None)
                a_val = getattr(after, attr, None)
                if b_val is not None and a_val is not None and b_val != a_val:
                    changed.append(label)
            if changed:
                threshold = adaptive_threshold(1, guild, actor, member, s)
                key = (guild.id, actor.id)
                bucket = recent_perm_updates[("identity", *key)]
                bucket.append(now)
                while bucket and now - bucket[0] > 60:
                    bucket.popleft()
                if len(bucket) >= threshold:
                    bucket.clear()
                    await log(guild, f"🏷️ **Guild identity bị thay đổi** ({', '.join(changed)}) bởi {actor.mention}. Kiểm tra `/restoreall` nếu cần khôi phục.", discord.Color.dark_red(), critical=True)
                    await handle_mod_abuse(guild, actor, member, "guild_identity", f"đổi {', '.join(changed)}")
                    return
                else:
                    note_clean_actor_action(guild.id, actor.id)
        if snap is not None:
            guild_identity_snapshot[guild.id] = {
                "name": guild.name,
                "icon": guild.icon.key if guild.icon else None,
                "banner": guild.banner.key if guild.banner else None,
                "vanity": getattr(guild, "vanity_url_code", None),
                "verification_level": str(guild.verification_level),
            }
    if entry.action == discord.AuditLogAction.bot_add:
        target = getattr(entry, "target", None)
        target_id = getattr(target, "id", None)
        if target_id and not is_whitelisted_bot(guild.id, target_id):
            if s.get("auto_ban_unauthorized_bot_adder", True):
                await log(guild, f"🤖 **Bot lạ bị thêm vào server**: `{getattr(target, 'name', target_id)}` bởi {actor.mention} — không nằm trong whitelist!", discord.Color.dark_red(), critical=True)
                await handle_mod_abuse(guild, actor, member, "unauthorized_bot_add", f"thêm bot lạ `{target_id}` không whitelist")
                bot_member = guild.get_member(target_id)
                if bot_member:
                    await safe_action(bot_member.kick(reason="Anti-nuke: bot lạ không whitelist"), action_name="kick unauthorized bot", guild_id=guild.id)
                return
            else:
                note_clean_actor_action(guild.id, actor.id)
        else:
            note_clean_actor_action(guild.id, actor.id)
    if entry.action in (discord.AuditLogAction.emoji_delete, discord.AuditLogAction.sticker_delete):
        key = (guild.id, actor.id)
        bucket = recent_emoji_sticker_actions[key]
        bucket.append(now)
        while bucket and now - bucket[0] > s["emoji_sticker_nuke_window"]:
            bucket.popleft()
        threshold = adaptive_threshold(s["emoji_sticker_nuke_threshold"], guild, actor, member, s)
        if len(bucket) >= threshold:
            bucket.clear()
            _prune_empty(recent_emoji_sticker_actions, key)
            kind = "sticker" if entry.action == discord.AuditLogAction.sticker_delete else "emoji"
            await handle_mod_abuse(guild, actor, member, "emoji_sticker_nuke", f"xóa hàng loạt {kind} ({len(bucket)}+ trong {s['emoji_sticker_nuke_window']}s)")
            return
        else:
            note_clean_actor_action(guild.id, actor.id)
    if entry.action == discord.AuditLogAction.automod_rule_delete:
        key = (guild.id, actor.id)
        bucket = recent_automod_deletes[key]
        bucket.append(now)
        while bucket and now - bucket[0] > s["automod_delete_window"]:
            bucket.popleft()
        threshold = adaptive_threshold(s["automod_delete_threshold"], guild, actor, member, s)
        if len(bucket) >= threshold:
            bucket.clear()
            _prune_empty(recent_automod_deletes, key)
            await handle_mod_abuse(guild, actor, member, "automod_delete", f"xóa {len(bucket)}+ AutoMod rule trong {s['automod_delete_window']}s")
            return
        else:
            note_clean_actor_action(guild.id, actor.id)
    if entry.action == discord.AuditLogAction.integration_delete:
        key = (guild.id, actor.id)
        bucket = recent_integration_deletes[key]
        bucket.append(now)
        while bucket and now - bucket[0] > s["integration_delete_window"]:
            bucket.popleft()
        threshold = adaptive_threshold(s["integration_delete_threshold"], guild, actor, member, s)
        if len(bucket) >= threshold:
            bucket.clear()
            _prune_empty(recent_integration_deletes, key)
            await handle_mod_abuse(guild, actor, member, "integration_delete", f"xóa {len(bucket)}+ integration trong {s['integration_delete_window']}s")
            return
        else:
            note_clean_actor_action(guild.id, actor.id)
    if entry.action == discord.AuditLogAction.integration_create:
        target = getattr(entry, "target", None)
        app_name = (getattr(target, "name", "") or "").lower()
        keywords = s.get("oauth_suspicious_keywords", [])
        hit = next((kw for kw in keywords if kw in app_name), None)
        if hit:
            await log(guild, f"🔐 **OAuth2/Integration khả nghi**: `{app_name}` (khớp từ khóa `{hit}`) được thêm bởi {actor.mention} — kiểm tra ngay!", discord.Color.dark_red(), critical=True)
            add_suspicion(guild.id, actor.id, "oauth_suspicious", s["suspicion_decay_seconds"])
            bump_stat(guild.id, "oauth_suspicious_blocked", 1)
        else:
            note_clean_actor_action(guild.id, actor.id)
    if entry.action == discord.AuditLogAction.channel_delete:
        target = getattr(entry, "target", None)
        ch_type = getattr(target, "type", None)
        if ch_type in FORUM_CHANNEL_TYPES:
            key = ("forum", guild.id, actor.id)
            bucket = recent_perm_updates[key]
            bucket.append(now)
            while bucket and now - bucket[0] > s["nuke_action_window"]:
                bucket.popleft()
            threshold = adaptive_threshold(max(2, s["nuke_action_threshold"] - 1), guild, actor, member, s)
            if len(bucket) >= threshold:
                bucket.clear()
                _prune_empty(recent_perm_updates, key)
                await handle_mod_abuse(guild, actor, member, "nuke", f"xóa hàng loạt forum channel ({len(bucket)}+ trong {s['nuke_action_window']}s)")
                return
    key = (guild.id, actor.id)
    bucket = recent_nuke_actions[key]
    bucket.append(now)
    while bucket and now - bucket[0] > s["nuke_action_window"]:
        bucket.popleft()
    is_critical_action = entry.action in CRITICAL_ACTIONS
    base_threshold = max(2, s["nuke_action_threshold"] - 1) if is_critical_action else s["nuke_action_threshold"]
    threshold = adaptive_threshold(base_threshold, guild, actor, member, s)
    if len(bucket) >= threshold:
        bucket.clear()
        _prune_empty(recent_nuke_actions, key)
        await handle_mod_abuse(guild, actor, member, "nuke", f"spam `{entry.action.name}`")
    else:
        _prune_empty(recent_nuke_actions, key)
        note_clean_actor_action(guild.id, actor.id)
async def handle_mod_abuse(guild: discord.Guild, actor, member, category: str, reason_text: str, skip_role_strip: bool = False):
    s = cfg(guild.id)
    if member and not skip_role_strip:
        dangerous = [r for r in member.roles if r != guild.default_role and (
            r.permissions.administrator or r.permissions.manage_guild or
            r.permissions.manage_channels or r.permissions.manage_roles or
            r.permissions.ban_members or r.permissions.kick_members
        )]
        if dangerous:
            await safe_action(
                member.remove_roles(*dangerous, reason=f"Anti-nuke: {reason_text}"),
                action_name="remove dangerous roles",
                guild_id=guild.id,
            )
    if member:
        await safe_action(
            guild.ban(member, reason=f"Anti-nuke: {reason_text}"),
            action_name="ban abusive mod",
            guild_id=guild.id,
        )
    score = add_suspicion(guild.id, actor.id, category, s["suspicion_decay_seconds"])
    bump_stat(guild.id, "nuke_blocked" if category == "nuke" else f"{category}_blocked", 1)
    label = {
        "nuke": "🛑 Anti-nuke",
        "mass_ban": "🛑 Mass-ban abuse",
        "mass_kick": "🛑 Mass-kick abuse",
        "perm_wipe": "🛑 Permission wipe abuse",
        "webhook_spam": "🛑 Webhook spam",
        "vanity_hijack": "🛑 Vanity URL Hijack",
        "guild_identity": "🛑 Guild Identity Change",
        "unauthorized_bot_add": "🛑 Unauthorized Bot Add",
        "emoji_sticker_nuke": "🛑 Emoji/Sticker Nuke",
        "automod_delete": "🛑 AutoMod Rule Delete Abuse",
        "integration_delete": "🛑 Integration Delete Abuse",
    }.get(category, "🛑 Hành vi phá hoại")
    await log(
        guild,
        f"**{label}** — {actor.mention} (`{actor.id}`): {reason_text}. "
        f"Đã tước quyền + ban. (Suspicion: {score})",
        discord.Color.dark_red(),
        critical=True,
    )
async def bulk_delete_messages(guild: discord.Guild, msgs: list[discord.Message]):
    by_channel: dict[int, list[discord.Message]] = defaultdict(list)
    for m in msgs:
        by_channel[m.channel.id].append(m)
    for channel_id, chan_msgs in by_channel.items():
        channel = guild.get_channel(channel_id)
        if channel is None:
            continue
        fresh_cutoff = discord.utils.utcnow() - datetime.timedelta(days=14)
        bulk_eligible = [m for m in chan_msgs if m.created_at > fresh_cutoff]
        too_old = [m for m in chan_msgs if m.created_at <= fresh_cutoff]
        if len(bulk_eligible) == 1:
            await safe_action(bulk_eligible[0].delete(), action_name="delete spam message", guild_id=guild.id)
        elif bulk_eligible:
            await safe_action(channel.delete_messages(bulk_eligible), action_name="bulk delete spam", guild_id=guild.id)
        for m in too_old:
            await safe_action(m.delete(), action_name="delete old spam message", guild_id=guild.id)
def mask_word(word: str) -> str:
    if len(word) <= 2:
        return (word[0] + "*") if word else word
    return word[0] + "*" * (len(word) - 2) + word[-1]
async def dm_warning(member: discord.Member, reason_text: str):
    try:
        await member.send(f"⚠️ Tin nhắn của bạn tại **{member.guild.name}** đã bị xóa: {reason_text}")
    except discord.HTTPException:
        pass
def contains_token_grabber_keyword(content: str, keywords: list[str]) -> str | None:
    normalized = normalize(content)
    for kw in keywords:
        kw_norm = normalize(kw)
        if kw_norm and kw_norm in normalized:
            return kw
    return None
SELFBOT_SIGNATURE_PATTERN = re.compile(
    r"(nighty|deutschbot|selfbot|discord-self|self-bot|autotype|mass\s*dm\s*tool)",
    re.IGNORECASE,
)
def looks_like_selfbot_signature(content: str) -> str | None:
    match = SELFBOT_SIGNATURE_PATTERN.search(content or "")
    return match.group(0) if match else None
@bot.event
async def on_message(message: discord.Message):
    if not message.guild or message.author.id == bot.user.id:
        return
    if isinstance(message.channel, (discord.VoiceChannel, discord.StageChannel)):
        return
    member = message.author
    if not isinstance(member, discord.Member):
        resolved = message.guild.get_member(member.id)
        if resolved is None:
            resolved = await safe_action(
                message.guild.fetch_member(member.id),
                action_name="fetch member for message author",
                guild_id=message.guild.id,
            )
        if resolved is None:
            return
        member = resolved
    is_other_bot = member.bot
    guild_id = message.guild.id
    if is_other_bot and (is_whitelisted_bot(guild_id, member.id) or _is_discord_verified_bot(member)):
        return
    if not is_other_bot and is_protected(member, guild_id):
        return
    s = cfg(guild_id)
    if not is_other_bot:
        sig = looks_like_selfbot_signature(message.content)
        if sig:
            score = add_suspicion(guild_id, member.id, "selfbot", s["suspicion_decay_seconds"])
            bump_stat(guild_id, "selfbot_flagged", 1)
            await log(message.guild, f"🕵️ **Dấu hiệu Selfbot** phát hiện ở {member.mention}: khớp `{sig}`. (Suspicion: {score})", discord.Color.orange())
            await apply_suspicion_consequence(message.guild, member, score, s)
    if s.get("lockdown_active") and not is_other_bot:
        account_age = (discord.utils.utcnow() - member.created_at).days
        if account_age < s["raid_min_account_age_days"]:
            await safe_action(message.delete(), action_name="delete message during lockdown", guild_id=guild_id)
            return
    raw_content = message.content
    clean_content = strip_invisible_chars(raw_content)
    morse_decoded = None
    if looks_like_morse(clean_content):
        morse_decoded = decode_morse(clean_content)
    check_content = f"{clean_content} {morse_decoded}" if morse_decoded else clean_content
    if not is_other_bot:
        tg_hit = contains_token_grabber_keyword(check_content, s.get("token_grabber_keywords", []))
        if tg_hit:
            await safe_action(message.delete(), action_name="delete token grabber message", guild_id=guild_id)
            until = discord.utils.utcnow() + datetime.timedelta(hours=1)
            await safe_action(member.timeout(until, reason=f"Anti-token-grabber: {tg_hit}"), action_name="timeout token grabber poster", guild_id=guild_id)
            score = add_suspicion(guild_id, member.id, "token_grabber", s["suspicion_decay_seconds"])
            morse_note = " (phát hiện qua giải mã Morse)" if morse_decoded else ""
            await log(message.guild, f"🔐⚠️ Chặn nội dung nghi token grabber (từ khóa: `{mask_word(tg_hit)}`){morse_note} từ {member.mention}", discord.Color.dark_red(), critical=True)
            bump_stat(guild_id, "token_grabber_blocked", 1)
            await apply_suspicion_consequence(message.guild, member, score, s)
            await dm_warning(member, "nội dung nghi ngờ liên quan đến token grabber/malware.")
            return
        if s["badwords"]:
            hit_word = contains_badword(check_content, s["badwords"])
            if hit_word:
                await safe_action(message.delete(), action_name="delete badword message", guild_id=guild_id)
                morse_note = " (phát hiện qua giải mã Morse)" if morse_decoded else ""
                await log(message.guild, f"🤬 Xóa tin nhắn chứa từ cấm (`{mask_word(hit_word)}`){morse_note} của {member.mention}", discord.Color.gold())
                bump_stat(guild_id, "badword_blocked", 1)
                score = add_suspicion(guild_id, member.id, "badword", s["suspicion_decay_seconds"])
                await apply_suspicion_consequence(message.guild, member, score, s)
                await dm_warning(member, "chứa từ ngữ bị cấm trong server.")
                return
        if is_zalgo(clean_content, s["zalgo_max_combining_chars"]):
            await safe_action(message.delete(), action_name="delete zalgo message", guild_id=guild_id)
            await log(message.guild, f"👾 Xóa tin nhắn chứa ký tự zalgo bất thường từ {member.mention}", discord.Color.gold())
            score = add_suspicion(guild_id, member.id, "zalgo", s["suspicion_decay_seconds"])
            await apply_suspicion_consequence(message.guild, member, score, s)
            return
        mention_count = len(message.mentions) + len(message.role_mentions)
        if raw_content != clean_content and ("@everyone" in clean_content or "@here" in clean_content):
            mention_count = max(mention_count, s["mass_mention_threshold"])
        if mention_count >= s["mass_mention_threshold"]:
            await safe_action(message.delete(), action_name="delete mass-mention message", guild_id=guild_id)
            until = discord.utils.utcnow() + datetime.timedelta(seconds=s["mass_mention_timeout_seconds"])
            await safe_action(member.timeout(until, reason="Anti-raid: mass mention"), action_name="timeout mass mentioner", guild_id=guild_id)
            await log(message.guild, f"📣⛔ {member.mention} bị timeout vì mention hàng loạt ({mention_count} lượt)", discord.Color.dark_orange())
            bump_stat(guild_id, "spam_blocked", 1)
            score = add_suspicion(guild_id, member.id, "mass_mention", s["suspicion_decay_seconds"])
            await apply_suspicion_consequence(message.guild, member, score, s)
            return
        if INVITE_RE.search(clean_content):
            account_age = (discord.utils.utcnow() - member.created_at).days
            if account_age < s["invite_new_account_days"]:
                await safe_action(message.delete(), action_name="delete invite from new account", guild_id=guild_id)
                await log(message.guild, f"🔗⚠️ Xóa invite link từ tài khoản mới ({account_age} ngày tuổi) — {member.mention}", discord.Color.gold())
                score = add_suspicion(guild_id, member.id, "invite_spam", s["suspicion_decay_seconds"])
                await apply_suspicion_consequence(message.guild, member, score, s)
                return
        urls = URL_RE.findall(clean_content)
        hit = None
        hit_reason = ""
        if SCAM_PATTERN.search(clean_content):
            hit = "known phishing pattern"
            hit_reason = "mẫu từ khóa phishing quen thuộc"
        else:
            for host, _path in urls:
                host = host.lower().split(":")[0]
                for bad in s["scam_domains"]:
                    if host == bad or host.endswith("." + bad):
                        hit = host
                        hit_reason = "domain trong blocklist"
                        break
                if hit:
                    break
                typo_target = looks_like_typosquat(host)
                if typo_target:
                    hit = host
                    hit_reason = f"domain giả mạo gần giống `{typo_target}`"
                    break
                has_lure = re.search(r"nitro|free|giveaway|airdrop|claim", clean_content, re.IGNORECASE)
                if is_shortener(host) and has_lure:
                    full_url = f"https://{host}{_path}"
                    final_url = await unwrap_redirect(full_url)
                    final_host = URL_RE.match(final_url)
                    final_host_str = final_host.group(1).lower() if final_host else host
                    if looks_like_typosquat(final_host_str) or SCAM_PATTERN.search(final_url):
                        hit = final_host_str
                        hit_reason = f"link rút gọn `{host}` trỏ tới domain scam sau khi giải nén redirect"
                    else:
                        hit = host
                        hit_reason = "link rút gọn kèm mồi nhử nghi scam"
                    break
        if hit:
            await safe_action(message.delete(), action_name="delete scam message", guild_id=guild_id)
            until = discord.utils.utcnow() + datetime.timedelta(minutes=10)
            await safe_action(member.timeout(until, reason=f"Anti-scam: {hit}"), action_name="timeout scammer", guild_id=guild_id)
            await log(message.guild, f"🎣 Chặn link scam (`{hit}` — {hit_reason}) từ {member.mention}", discord.Color.dark_gold())
            bump_stat(guild_id, "scam_blocked", 1)
            score = add_suspicion(guild_id, member.id, "scam", s["suspicion_decay_seconds"])
            await apply_suspicion_consequence(message.guild, member, score, s)
            return
    key = (guild_id, member.id)
    now = time.time()
    timeline = message_timeline[key]
    timeline.append((now, message))
    while timeline and now - timeline[0][0] > s["intermittent_spam_window"]:
        timeline.popleft()
    intermittent_bursts = detect_intermittent_spam(list(timeline), s)
    if intermittent_bursts:
        timeline.clear()
        _prune_empty(message_timeline, key)
        burst_msgs = [m for burst in intermittent_bursts for _, m in burst]
        await bulk_delete_messages(message.guild, burst_msgs)
        if is_other_bot:
            await softban(
                message.guild, member,
                reason="Anti-spam: spam ngắt quãng (bot rải-nghỉ-rải để né lọc)",
                delete_seconds=s["raid_softban_delete_seconds"],
            )
            await log(
                message.guild,
                f"⏱️🤖🔁 {member.mention} (bot) bị softban vì spam ngắt quãng "
                f"({len(intermittent_bursts)} đợt, {len(burst_msgs)} tin, cố tình nghỉ giữa các đợt để né lọc)",
                discord.Color.orange(),
            )
        else:
            until = discord.utils.utcnow() + datetime.timedelta(seconds=s["intermittent_spam_timeout_seconds"])
            await safe_action(
                member.timeout(until, reason="Anti-spam: spam ngắt quãng (rải rồi nghỉ rồi rải tiếp)"),
                action_name="timeout intermittent spammer",
                guild_id=guild_id,
            )
            await log(
                message.guild,
                f"⏱️🔁 {member.mention} bị timeout vì spam NGẮT QUÃNG — {len(intermittent_bursts)} đợt rải, "
                f"tổng {len(burst_msgs)} tin, cố tình dừng giữa các đợt để né bộ lọc spam nhanh.",
                discord.Color.orange(),
            )
            score = add_suspicion(guild_id, member.id, "spam_intermittent", s["suspicion_decay_seconds"])
            await apply_suspicion_consequence(message.guild, member, score, s)
        bump_stat(guild_id, "intermittent_spam_blocked", 1)
        bump_stat(guild_id, "spam_blocked", 1)
        return
    else:
        _prune_empty(message_timeline, key)
    bucket = recent_messages[key]
    bucket.append((now, message))
    while bucket and now - bucket[0][0] > s["spam_msg_window"]:
        bucket.popleft()
    if len(bucket) >= s["spam_msg_threshold"]:
        msgs = [m for _, m in bucket]
        bucket.clear()
        _prune_empty(recent_messages, key)
        await bulk_delete_messages(message.guild, msgs)
        hit_channels = []
        seen_ids = set()
        for m in msgs:
            if m.channel.id not in seen_ids:
                seen_ids.add(m.channel.id)
                hit_channels.append(m.channel)
        channels_note = f" — trải qua {len(hit_channels)} kênh: " + ", ".join(c.mention for c in hit_channels) if len(hit_channels) > 1 else ""
        if is_other_bot:
            await softban(message.guild, member, reason="Anti-spam: bot spam tin nhắn", delete_seconds=s["raid_softban_delete_seconds"])
            await log(message.guild, f"⏱️🤖 {member.mention} (bot) bị softban vì spam ({len(msgs)} tin){channels_note}", discord.Color.orange())
        else:
            until = discord.utils.utcnow() + datetime.timedelta(seconds=s["spam_timeout_seconds"])
            await safe_action(member.timeout(until, reason="Anti-spam: spam tin nhắn"), action_name="timeout spammer", guild_id=guild_id)
            await log(message.guild, f"⏱️ {member.mention} bị timeout vì spam ({len(msgs)} tin){channels_note}", discord.Color.orange())
            score = add_suspicion(guild_id, member.id, "spam_fast", s["suspicion_decay_seconds"])
            await apply_suspicion_consequence(message.guild, member, score, s)
        bump_stat(guild_id, "spam_blocked", 1)
        return
    else:
        _prune_empty(recent_messages, key)
    norm_content = normalize_for_dedupe(message.content)
    if norm_content:
        dup_bucket = recent_message_contents[key]
        dup_bucket.append((now, norm_content, message))
        while dup_bucket and now - dup_bucket[0][0] > s["slow_spam_window"]:
            dup_bucket.popleft()
        raid_window_msgs = [
            m for (ts, c, m) in dup_bucket
            if c == norm_content and now - ts <= s["raid_channel_spam_window"]
        ]
        raid_channels = {}
        for m in raid_window_msgs:
            raid_channels.setdefault(m.channel.id, m.channel)
        if len(raid_channels) >= s["raid_channel_spam_threshold"]:
            dup_bucket.clear()
            _prune_empty(recent_message_contents, key)
            channels_list = list(raid_channels.values())
            channels_text = ", ".join(c.mention for c in channels_list)
            event_time = discord.utils.utcnow()
            content_preview = message.content if len(message.content) <= 300 else message.content[:300] + "…"
            await bulk_delete_messages(message.guild, raid_window_msgs)
            did_softban = await softban(
                message.guild,
                member,
                reason=f"Anti-raid: spam cùng nội dung vào {len(raid_channels)} kênh trong {s['raid_channel_spam_window']}s",
                delete_seconds=s["raid_softban_delete_seconds"],
            )
            await log(
                message.guild,
                "🚨 **RAID DETECTED (cross-channel spam)**\n"
                f"• Người vi phạm: {member.mention} (`{member.id}`)\n"
                f"• Số kênh bị spam: {len(raid_channels)} — {channels_text}\n"
                f"• Thời gian: {discord.utils.format_dt(event_time, style='F')}\n"
                f"• Nội dung spam: ```{content_preview}```\n"
                f"• Hành động: {'Đã softban (ban + unban, xóa tin nhắn gần đây)' if did_softban else '⚠️ Softban thất bại — kiểm tra quyền Ban Members của bot'}",
                discord.Color.red(),
                critical=True,
            )
            bump_stat(guild_id, "raid_blocked", 1)
            return
        same_content_msgs = [m for (_, c, m) in dup_bucket if c == norm_content]
        if len(same_content_msgs) >= s["slow_spam_duplicate_threshold"]:
            dup_bucket.clear()
            _prune_empty(recent_message_contents, key)
            hit_channels = []
            seen_ids = set()
            for m in same_content_msgs:
                if m.channel.id not in seen_ids:
                    seen_ids.add(m.channel.id)
                    hit_channels.append(m.channel)
            channels_text = ", ".join(c.mention for c in hit_channels)
            cross_channel = len(hit_channels) > 1
            await bulk_delete_messages(message.guild, same_content_msgs)
            if is_other_bot:
                await softban(message.guild, member, reason="Anti-spam: bot lặp lại cùng nội dung", delete_seconds=s["raid_softban_delete_seconds"])
            else:
                score = add_suspicion(guild_id, member.id, "spam_slow", s["suspicion_decay_seconds"])
                if score >= s["suspicion_timeout_threshold"]:
                    until = discord.utils.utcnow() + datetime.timedelta(seconds=s["slow_spam_timeout_seconds"])
                    await safe_action(
                        member.timeout(until, reason="Anti-spam: lặp lại cùng 1 nội dung nhiều lần"),
                        action_name="timeout slow spammer",
                        guild_id=guild_id,
                    )
                await apply_suspicion_consequence(message.guild, member, score, s)
            verdict = (
                f"➡️ **Kết luận: cùng 1 người ({member.mention}) đã rải nội dung này qua "
                f"{len(hit_channels)} kênh khác nhau** — không phải trùng hợp ngẫu nhiên."
                if cross_channel else
                f"➡️ Rải lặp trong cùng 1 kênh ({channels_text})."
            )
            await log(
                message.guild,
                f"🐌⏱️ {member.mention} bị timeout vì spam CHẬM — lặp lại cùng nội dung "
                f"{len(same_content_msgs)} lần trong {s['slow_spam_window']}s.\n"
                f"Các kênh bị dính: {channels_text}\n"
                f"{verdict}",
                discord.Color.orange(),
            )
            bump_stat(guild_id, "spam_blocked", 1)
            return
        else:
            _prune_empty(recent_message_contents, key)
@bot.event
async def on_audit_log_entry_for_mass_role(entry: discord.AuditLogEntry):
    pass
def admin_only():
    return app_commands.checks.has_permissions(administrator=True)
@bot.tree.command(name="setlog", description="Đặt kênh nhận log cảnh báo bảo mật")
@admin_only()
async def setlog(interaction: discord.Interaction, channel: discord.TextChannel):
    await set_and_save(interaction.guild.id, "log_channel_id", channel.id)
    await interaction.response.send_message(f"✅ Đã đặt kênh log: {channel.mention}", ephemeral=True)
@bot.tree.command(name="setlogwebhook", description="Đặt webhook URL để nhận log (không cần bot có quyền trong channel)")
@admin_only()
async def setlogwebhook(interaction: discord.Interaction, url: str):
    if not url.startswith("https://discord.com/api/webhooks/") and not url.startswith("https://discordapp.com/api/webhooks/"):
        await interaction.response.send_message("❌ URL webhook không hợp lệ.", ephemeral=True)
        return
    await set_and_save(interaction.guild.id, "log_webhook_url", url)
    _webhook_cache.pop(url, None)
    await interaction.response.send_message("✅ Đã đặt webhook log.", ephemeral=True)
@bot.tree.command(name="togglealertowner", description="Bật/tắt DM cho owner khi có sự cố nghiêm trọng")
@admin_only()
async def togglealertowner(interaction: discord.Interaction):
    s = cfg(interaction.guild.id)
    new_val = not s.get("alert_owner_on_critical", True)
    await set_and_save(interaction.guild.id, "alert_owner_on_critical", new_val)
    await interaction.response.send_message(f"✅ Alert owner khi nghiêm trọng: {'Bật' if new_val else 'Tắt'}", ephemeral=True)
@bot.tree.command(name="lockdown", description="Bật/tắt lockdown thủ công (chặn account mới nhắn tin/join)")
@admin_only()
async def lockdown(interaction: discord.Interaction, active: bool):
    await set_and_save(interaction.guild.id, "lockdown_active", active)
    if active:
        await log(interaction.guild, f"🔒 **Lockdown mode BẬT** bởi {interaction.user.mention}", discord.Color.dark_red(), critical=True)
    else:
        await log(interaction.guild, f"🔓 Lockdown mode tắt bởi {interaction.user.mention}", discord.Color.green())
    await interaction.response.send_message(f"✅ Lockdown: {'BẬT' if active else 'Tắt'}", ephemeral=True)
@bot.tree.command(name="protectrole", description="Đánh dấu 1 role được bảo vệ khỏi xóa/sửa trái phép")
@admin_only()
async def protectrole(interaction: discord.Interaction, role: discord.Role):
    s = cfg(interaction.guild.id)
    ids = set(s.get("protected_role_ids", []))
    ids.add(role.id)
    await set_and_save(interaction.guild.id, "protected_role_ids", list(ids))
    await interaction.response.send_message(f"✅ Đã bảo vệ role {role.mention}", ephemeral=True)
@bot.tree.command(name="unprotectrole", description="Bỏ bảo vệ 1 role")
@admin_only()
async def unprotectrole(interaction: discord.Interaction, role: discord.Role):
    s = cfg(interaction.guild.id)
    ids = [r for r in s.get("protected_role_ids", []) if r != role.id]
    await set_and_save(interaction.guild.id, "protected_role_ids", ids)
    await interaction.response.send_message(f"✅ Đã bỏ bảo vệ role {role.mention}", ephemeral=True)
@bot.tree.command(name="backupnow", description="Chụp snapshot role/channel/permission ngay lập tức")
@admin_only()
async def backupnow(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    await snapshot_guild(interaction.guild)
    await interaction.followup.send("✅ Đã lưu snapshot role/channel/category hiện tại.", ephemeral=True)
@bot.tree.command(name="backupinfo", description="Xem thời điểm backup gần nhất và số lượng đã lưu")
@admin_only()
async def backupinfo(interaction: discord.Interaction):
    data = backups.get(str(interaction.guild.id))
    if not data:
        await interaction.response.send_message("Chưa có backup nào.", ephemeral=True)
        return
    ts = datetime.datetime.fromtimestamp(data["timestamp"], tz=datetime.timezone.utc)
    await interaction.response.send_message(
        f"📦 Backup gần nhất: {discord.utils.format_dt(ts, style='F')}\n"
        f"• Roles: {len(data['roles'])}\n"
        f"• Categories: {len(data.get('categories', []))}\n"
        f"• Channels: {len(data['channels'])}",
        ephemeral=True,
    )
@bot.tree.command(name="restorerole", description="Khôi phục quyền của 1 role từ backup gần nhất (theo tên)")
@admin_only()
async def restorerole(interaction: discord.Interaction, role: discord.Role):
    data = backups.get(str(interaction.guild.id))
    if not data:
        await interaction.response.send_message("❌ Chưa có backup nào để khôi phục.", ephemeral=True)
        return
    match = next((r for r in data["roles"] if r["id"] == role.id), None)
    if not match:
        await interaction.response.send_message("❌ Không tìm thấy role này trong backup (có thể role mới được tạo sau backup).", ephemeral=True)
        return
    perms = discord.Permissions(match["permissions"])
    await safe_action(
        role.edit(permissions=perms, colour=discord.Colour(match["color"]), hoist=match["hoist"], mentionable=match["mentionable"], reason=f"Khôi phục từ backup bởi {interaction.user}"),
        action_name="restore role from backup",
        guild_id=interaction.guild.id,
    )
    await interaction.response.send_message(f"✅ Đã khôi phục quyền cho role {role.mention} từ backup.", ephemeral=True)
@bot.tree.command(name="restoreall", description="⚠️ Khôi phục TOÀN BỘ role/category/channel bị xóa từ backup gần nhất (bán tự động, admin xác nhận)")
@admin_only()
async def restoreall(interaction: discord.Interaction, confirm: bool):
    if not confirm:
        await interaction.response.send_message("❌ Cần đặt `confirm: True` để xác nhận thực hiện khôi phục hàng loạt (có thể mất vài phút và tạo nhiều role/channel).", ephemeral=True)
        return
    data = backups.get(str(interaction.guild.id))
    if not data:
        await interaction.response.send_message("❌ Chưa có backup nào để khôi phục.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    guild = interaction.guild
    roles_restored = await restore_roles(guild, data)
    category_map = await restore_categories(guild, data)
    channels_restored = await restore_channels(guild, data, category_map)
    await log(
        guild,
        f"♻️ **Restore-all hoàn tất** bởi {interaction.user.mention}\n"
        f"• Roles khôi phục: {roles_restored}\n"
        f"• Categories khôi phục: {len(category_map)}\n"
        f"• Channels khôi phục: {channels_restored}",
        discord.Color.green(),
    )
    await interaction.followup.send(
        f"✅ Đã khôi phục: {roles_restored} role, {len(category_map)} category, {channels_restored} channel.",
        ephemeral=True,
    )
@bot.tree.command(name="suspicion", description="Xem điểm nghi ngờ hiện tại của 1 thành viên")
@admin_only()
async def suspicion(interaction: discord.Interaction, member: discord.Member):
    entry = suspicion_scores.get((interaction.guild.id, member.id))
    score = int(entry[0]) if entry else 0
    await interaction.response.send_message(f"📊 Điểm nghi ngờ của {member.mention}: **{score}**", ephemeral=True)
@bot.tree.command(name="resetsuspicion", description="Reset điểm nghi ngờ của 1 thành viên về 0")
@admin_only()
async def resetsuspicion(interaction: discord.Interaction, member: discord.Member):
    suspicion_scores.pop((interaction.guild.id, member.id), None)
    await interaction.response.send_message(f"✅ Đã reset điểm nghi ngờ của {member.mention}", ephemeral=True)
@bot.tree.command(name="whitelistuser", description="Thêm user vào whitelist (bot bỏ qua mọi kiểm tra với user này)")
@admin_only()
async def whitelistuser(interaction: discord.Interaction, user: discord.User):
    s = cfg(interaction.guild.id)
    ids = set(s.get("whitelist_user_ids", []))
    ids.add(user.id)
    await set_and_save(interaction.guild.id, "whitelist_user_ids", list(ids))
    await interaction.response.send_message(f"✅ Đã whitelist user {user.mention}", ephemeral=True)
@bot.tree.command(name="unwhitelistuser", description="Bỏ user khỏi whitelist")
@admin_only()
async def unwhitelistuser(interaction: discord.Interaction, user: discord.User):
    s = cfg(interaction.guild.id)
    ids = [u for u in s.get("whitelist_user_ids", []) if u != user.id]
    await set_and_save(interaction.guild.id, "whitelist_user_ids", ids)
    await interaction.response.send_message(f"✅ Đã bỏ whitelist user {user.mention}", ephemeral=True)
@bot.tree.command(name="whitelistrole", description="Thêm role vào whitelist (thành viên có role này được bỏ qua kiểm tra)")
@admin_only()
async def whitelistrole(interaction: discord.Interaction, role: discord.Role):
    s = cfg(interaction.guild.id)
    ids = set(s.get("whitelist_role_ids", []))
    ids.add(role.id)
    await set_and_save(interaction.guild.id, "whitelist_role_ids", list(ids))
    await interaction.response.send_message(f"✅ Đã whitelist role {role.mention}", ephemeral=True)
@bot.tree.command(name="unwhitelistrole", description="Bỏ role khỏi whitelist")
@admin_only()
async def unwhitelistrole(interaction: discord.Interaction, role: discord.Role):
    s = cfg(interaction.guild.id)
    ids = [r for r in s.get("whitelist_role_ids", []) if r != role.id]
    await set_and_save(interaction.guild.id, "whitelist_role_ids", ids)
    await interaction.response.send_message(f"✅ Đã bỏ whitelist role {role.mention}", ephemeral=True)
@bot.tree.command(name="whitelistbot", description="Thêm bot ID vào whitelist (bot đáng tin cậy, không bị auto-ban/xử lý)")
@admin_only()
async def whitelistbot(interaction: discord.Interaction, bot_id: str):
    if not bot_id.isdigit():
        await interaction.response.send_message("❌ Bot ID phải là số.", ephemeral=True)
        return
    bid = int(bot_id)
    s = cfg(interaction.guild.id)
    ids = set(s.get("whitelist_bot_ids", []))
    ids.add(bid)
    await set_and_save(interaction.guild.id, "whitelist_bot_ids", list(ids))
    await interaction.response.send_message(f"✅ Đã whitelist bot ID `{bid}`", ephemeral=True)
@bot.tree.command(name="unwhitelistbot", description="Bỏ bot ID khỏi whitelist")
@admin_only()
async def unwhitelistbot(interaction: discord.Interaction, bot_id: str):
    if not bot_id.isdigit():
        await interaction.response.send_message("❌ Bot ID phải là số.", ephemeral=True)
        return
    bid = int(bot_id)
    s = cfg(interaction.guild.id)
    ids = [b for b in s.get("whitelist_bot_ids", []) if b != bid]
    await set_and_save(interaction.guild.id, "whitelist_bot_ids", ids)
    await interaction.response.send_message(f"✅ Đã bỏ whitelist bot ID `{bid}`", ephemeral=True)
@bot.tree.command(name="whitelistwebhook", description="Thêm webhook ID vào whitelist (không bị xóa khi dọn webhook lạ)")
@admin_only()
async def whitelistwebhook(interaction: discord.Interaction, webhook_id: str):
    if not webhook_id.isdigit():
        await interaction.response.send_message("❌ Webhook ID phải là số.", ephemeral=True)
        return
    wid = int(webhook_id)
    s = cfg(interaction.guild.id)
    ids = set(s.get("whitelist_webhook_ids", []))
    ids.add(wid)
    await set_and_save(interaction.guild.id, "whitelist_webhook_ids", list(ids))
    await interaction.response.send_message(f"✅ Đã whitelist webhook ID `{wid}`", ephemeral=True)
@bot.tree.command(name="listwhitelist", description="Xem toàn bộ whitelist hiện tại")
@admin_only()
async def listwhitelist(interaction: discord.Interaction):
    s = cfg(interaction.guild.id)
    embed = discord.Embed(title="Whitelist", color=discord.Color.blurple())
    embed.add_field(name="Users", value=str(len(s.get("whitelist_user_ids", []))), inline=True)
    embed.add_field(name="Roles", value=str(len(s.get("whitelist_role_ids", []))), inline=True)
    embed.add_field(name="Bots", value=str(len(s.get("whitelist_bot_ids", []))), inline=True)
    embed.add_field(name="Webhooks", value=str(len(s.get("whitelist_webhook_ids", []))), inline=True)
    await interaction.response.send_message(embed=embed, ephemeral=True)
@bot.tree.command(name="addword", description="Thêm từ vào danh sách cấm")
@admin_only()
async def addword(interaction: discord.Interaction, word: str):
    s = cfg(interaction.guild.id)
    if word.lower() not in s["badwords"]:
        s["badwords"].append(word.lower())
        await set_and_save(interaction.guild.id, "badwords", s["badwords"])
    await interaction.response.send_message(f"✅ Đã thêm từ cấm: `{word}`", ephemeral=True)
@bot.tree.command(name="removeword", description="Xóa từ khỏi danh sách cấm")
@admin_only()
async def removeword(interaction: discord.Interaction, word: str):
    s = cfg(interaction.guild.id)
    new_list = [w for w in s["badwords"] if w != word.lower()]
    await set_and_save(interaction.guild.id, "badwords", new_list)
    await interaction.response.send_message(f"✅ Đã xóa từ cấm: `{word}`", ephemeral=True)
@bot.tree.command(name="listwords", description="Xem danh sách từ cấm")
@admin_only()
async def listwords(interaction: discord.Interaction):
    s = cfg(interaction.guild.id)
    if not s["badwords"]:
        await interaction.response.send_message("Chưa có từ cấm nào.", ephemeral=True)
        return
    text = ", ".join(f"`{w}`" for w in s["badwords"])
    await interaction.response.send_message(f"**Danh sách từ cấm ({len(s['badwords'])}):**\n{text}", ephemeral=True)
@bot.tree.command(name="addscam", description="Thêm domain vào blocklist link scam")
@admin_only()
async def addscam(interaction: discord.Interaction, domain: str):
    s = cfg(interaction.guild.id)
    domain = domain.lower().strip()
    if domain not in s["scam_domains"]:
        s["scam_domains"].append(domain)
        await set_and_save(interaction.guild.id, "scam_domains", s["scam_domains"])
    await interaction.response.send_message(f"✅ Đã thêm domain scam: `{domain}`", ephemeral=True)
@bot.tree.command(name="removescam", description="Xóa domain khỏi blocklist link scam")
@admin_only()
async def removescam(interaction: discord.Interaction, domain: str):
    s = cfg(interaction.guild.id)
    domain = domain.lower().strip()
    new_list = [d for d in s["scam_domains"] if d != domain]
    await set_and_save(interaction.guild.id, "scam_domains", new_list)
    await interaction.response.send_message(f"✅ Đã xóa domain: `{domain}`", ephemeral=True)
@bot.tree.command(name="listscam", description="Xem danh sách domain scam")
@admin_only()
async def listscam(interaction: discord.Interaction):
    s = cfg(interaction.guild.id)
    if not s["scam_domains"]:
        await interaction.response.send_message("Chưa có domain scam nào.", ephemeral=True)
        return
    text = ", ".join(f"`{d}`" for d in s["scam_domains"])
    await interaction.response.send_message(f"**Danh sách domain scam ({len(s['scam_domains'])}):**\n{text}", ephemeral=True)
@bot.tree.command(name="blockbot", description="Chặn cứng 1 bot theo ID, ban ngay nếu đang có trong server")
@admin_only()
async def blockbot(interaction: discord.Interaction, bot_id: str):
    if not bot_id.isdigit():
        await interaction.response.send_message("❌ Bot ID phải là số.", ephemeral=True)
        return
    bid = int(bot_id)
    s = cfg(interaction.guild.id)
    if bid not in s["blocked_bot_ids"]:
        s["blocked_bot_ids"].append(bid)
        await set_and_save(interaction.guild.id, "blocked_bot_ids", s["blocked_bot_ids"])
    member = interaction.guild.get_member(bid)
    if member:
        await safe_action(
            member.ban(reason=f"Blocklist: bot ID {bid} bị admin chặn thủ công"),
            action_name="ban blocklisted bot (manual)",
            guild_id=interaction.guild.id,
        )
    msg = f"✅ Đã thêm bot ID `{bid}` vào blocklist."
    if member:
        msg += " Đã ban ngay vì đang có trong server."
    await interaction.response.send_message(msg, ephemeral=True)
@bot.tree.command(name="unblockbot", description="Bỏ chặn 1 bot ID khỏi blocklist")
@admin_only()
async def unblockbot(interaction: discord.Interaction, bot_id: str):
    if not bot_id.isdigit():
        await interaction.response.send_message("❌ Bot ID phải là số.", ephemeral=True)
        return
    bid = int(bot_id)
    s = cfg(interaction.guild.id)
    new_list = [b for b in s["blocked_bot_ids"] if b != bid]
    await set_and_save(interaction.guild.id, "blocked_bot_ids", new_list)
    await interaction.response.send_message(f"✅ Đã bỏ chặn bot ID `{bid}`.", ephemeral=True)
@bot.tree.command(name="listblockedbots", description="Xem danh sách bot bị chặn")
@admin_only()
async def listblockedbots(interaction: discord.Interaction):
    s = cfg(interaction.guild.id)
    if not s["blocked_bot_ids"]:
        await interaction.response.send_message("Chưa chặn bot ID nào.", ephemeral=True)
        return
    text = ", ".join(f"`{b}`" for b in s["blocked_bot_ids"])
    await interaction.response.send_message(f"**Bot bị chặn ({len(s['blocked_bot_ids'])}):**\n{text}", ephemeral=True)
@bot.tree.command(name="listbots", description="Quét toàn bộ bot đang có trong server và gửi báo cáo lên log channel (không ban)")
@admin_only()
async def listbots(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    s = cfg(interaction.guild.id)
    blocked_ids = set(s["blocked_bot_ids"])
    bots = [m for m in interaction.guild.members if m.bot]
    if not bots:
        await interaction.followup.send("Server này không có bot nào.", ephemeral=True)
        return
    lines = []
    for member in sorted(bots, key=lambda m: m.joined_at or discord.utils.utcnow()):
        tags = []
        if _is_discord_verified_bot(member):
            tags.append("✓ Discord verified")
        if member.id in blocked_ids:
            tags.append("⛔ blocklist")
        if is_whitelisted_bot(interaction.guild.id, member.id):
            tags.append("✅ whitelist")
        if is_protected(member, interaction.guild.id):
            tags.append("🛡️ protected")
        sus = _is_suspicious_bot(member)
        if sus and not _is_discord_verified_bot(member):
            tags.append(f"⚠️ {sus}")
        joined = discord.utils.format_dt(member.joined_at, style="R") if member.joined_at else "?"
        tag_text = f" [{', '.join(tags)}]" if tags else ""
        lines.append(f"• {member.mention} `{member}` (`{member.id}`) — vào server {joined}{tag_text}")
    header = f"🤖📋 **Danh sách bot trong server** — tổng cộng **{len(bots)}** bot:\n"
    chunk = header
    chunks = []
    for line in lines:
        if len(chunk) + len(line) + 1 > 3800:
            chunks.append(chunk)
            chunk = ""
        chunk += line + "\n"
    if chunk:
        chunks.append(chunk)
    for i, c in enumerate(chunks):
        await log(interaction.guild, c, discord.Color.blurple())
    await interaction.followup.send(f"✅ Đã quét {len(bots)} bot và gửi báo cáo lên log channel.", ephemeral=True)
@bot.tree.command(name="scanbots", description="Quét bot đang có trong server, ban những bot khớp blocklist hoặc tên khả nghi")
@admin_only()
async def scanbots(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    s = cfg(interaction.guild.id)
    blocked_ids = set(s["blocked_bot_ids"])
    banned = []
    for member in interaction.guild.members:
        if not member.bot or is_protected(member, interaction.guild.id) or is_whitelisted_bot(interaction.guild.id, member.id):
            continue
        reason = None
        if member.id in blocked_ids:
            reason = f"trong blocklist (`{member.id}`)"
        elif _is_discord_verified_bot(member):
            continue
        elif s.get("auto_ban_suspicious_bots", True):
            sus = _is_suspicious_bot(member)
            if sus:
                reason = sus
        if reason:
            await safe_action(
                member.ban(reason=f"Anti-bot scan: {reason}"),
                action_name="ban bot from scan",
                guild_id=interaction.guild.id,
            )
            banned.append(f"{member} (`{member.id}`) — {reason}")
    if banned:
        text = "\n".join(banned)
        await log(interaction.guild, f"🤖⛔ **Scan bot** — đã ban {len(banned)} bot:\n{text}", discord.Color.dark_red())
        await interaction.followup.send(f"✅ Đã ban {len(banned)} bot khả nghi:\n{text}", ephemeral=True)
    else:
        await interaction.followup.send("Không tìm thấy bot nào khả nghi.", ephemeral=True)
@bot.tree.command(name="togglesuspiciousbots", description="Bật/tắt tự động ban bot có tên khả nghi (None/null/rỗng)")
@admin_only()
async def togglesuspiciousbots(interaction: discord.Interaction):
    s = cfg(interaction.guild.id)
    new_val = not s.get("auto_ban_suspicious_bots", True)
    await set_and_save(interaction.guild.id, "auto_ban_suspicious_bots", new_val)
    await interaction.response.send_message(
        f"✅ Auto-ban bot khả nghi: {'Bật' if new_val else 'Tắt'}", ephemeral=True
    )
@bot.tree.command(name="setconfig", description="Chỉnh 1 ngưỡng cấu hình bảo mật (số nguyên)")
@admin_only()
async def setconfig(interaction: discord.Interaction, key: str, value: int):
    if key not in CONFIGURABLE_INT_KEYS:
        await interaction.response.send_message(
            f"❌ `{key}` không phải là tên cấu hình hợp lệ. Gõ vài ký tự để bot gợi ý, "
            f"hoặc dùng `/exportconfig` để xem danh sách đầy đủ.",
            ephemeral=True,
        )
        return
    if value < 0:
        await interaction.response.send_message("❌ Giá trị phải >= 0.", ephemeral=True)
        return
    await set_and_save(interaction.guild.id, key, value)
    await interaction.response.send_message(f"✅ Đã đặt `{key}` = `{value}`", ephemeral=True)
@setconfig.autocomplete("key")
async def setconfig_key_autocomplete(interaction: discord.Interaction, current: str):
    current = (current or "").lower()
    matches = [k for k in CONFIGURABLE_INT_KEYS if current in k.lower()]
    return [app_commands.Choice(name=k, value=k) for k in matches[:25]]
@bot.tree.command(name="resetconfig", description="Reset toàn bộ cấu hình bảo mật của server về mặc định")
@admin_only()
async def resetconfig(interaction: discord.Interaction):
    settings[str(interaction.guild.id)] = dict(DEFAULTS)
    settings[str(interaction.guild.id)]["badwords"] = []
    settings[str(interaction.guild.id)]["scam_domains"] = []
    settings[str(interaction.guild.id)]["blocked_bot_ids"] = []
    settings[str(interaction.guild.id)]["protected_role_ids"] = []
    settings[str(interaction.guild.id)]["whitelist_user_ids"] = []
    settings[str(interaction.guild.id)]["whitelist_role_ids"] = []
    settings[str(interaction.guild.id)]["whitelist_bot_ids"] = []
    settings[str(interaction.guild.id)]["whitelist_webhook_ids"] = []
    await save_guild_settings(interaction.guild.id)
    await interaction.response.send_message(
        "✅ Đã reset cấu hình về mặc định. (Config được lưu trực tiếp trên Firestore — có thể "
        "xem/sửa thủ công trong collection `settings` trên Firebase Console nếu cần.)",
        ephemeral=True,
    )
@bot.tree.command(name="health", description="Xem tình trạng hoạt động của bot (RAM, ping, uptime, thống kê)")
@admin_only()
async def health(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    uptime_seconds = int(time.time() - bot.start_time)
    uptime_str = str(datetime.timedelta(seconds=uptime_seconds))
    ram_mb = None
    cpu_percent = None
    try:
        import psutil
        process = psutil.Process(os.getpid())
        ram_mb = process.memory_info().rss / (1024 * 1024)
        cpu_percent = process.cpu_percent(interval=0.3)
    except ImportError:
        pass
    guild_stats = stats.get(str(interaction.guild.id), {})
    today = guild_stats.get(_today_key(), {})
    embed = discord.Embed(title="🩺 Health Check", color=discord.Color.green())
    embed.add_field(name="Ping", value=f"{round(bot.latency * 1000)}ms", inline=True)
    embed.add_field(name="Uptime", value=uptime_str, inline=True)
    embed.add_field(name="RAM", value=f"{ram_mb:.1f} MB" if ram_mb else "N/A (cần cài `psutil`)", inline=True)
    embed.add_field(name="CPU", value=f"{cpu_percent:.1f}%" if cpu_percent is not None else "N/A", inline=True)
    embed.add_field(name="Servers", value=str(len(bot.guilds)), inline=True)
    embed.add_field(name="Raid chặn hôm nay", value=str(today.get("raid_blocked", 0)), inline=True)
    embed.add_field(name="Scam chặn hôm nay", value=str(today.get("scam_blocked", 0)), inline=True)
    embed.add_field(name="Bot bị ban hôm nay", value=str(today.get("bot_banned", 0)), inline=True)
    embed.add_field(name="Nuke chặn hôm nay", value=str(today.get("nuke_blocked", 0)), inline=True)
    await interaction.followup.send(embed=embed, ephemeral=True)
@bot.tree.command(name="stats", description="Xem thống kê hoạt động bảo mật theo ngày")
@admin_only()
async def statscommand(interaction: discord.Interaction, days: int = 7):
    days = max(1, min(days, 30))
    guild_stats = stats.get(str(interaction.guild.id), {})
    today = datetime.datetime.utcnow().date()
    metrics_order = [
        ("raid_blocked", "Raid bị chặn"),
        ("scam_blocked", "Scam bị chặn"),
        ("spam_blocked", "Spam bị chặn"),
        ("intermittent_spam_blocked", "Spam ngắt quãng bị chặn"),
        ("badword_blocked", "Từ cấm bị chặn"),
        ("token_grabber_blocked", "Token grabber bị chặn"),
        ("nuke_blocked", "Nuke bị chặn"),
        ("mass_ban_blocked", "Mass-ban bị chặn"),
        ("mass_kick_blocked", "Mass-kick bị chặn"),
        ("perm_wipe_blocked", "Permission wipe bị chặn"),
        ("webhook_spam_blocked", "Webhook spam bị chặn"),
        ("role_escalation_blocked", "Role escalation bị chặn"),
        ("bot_banned", "Bot bị ban"),
        ("timeout", "Timeout"),
        ("ban", "Ban"),
    ]
    totals = defaultdict(int)
    for i in range(days):
        day_key = (today - datetime.timedelta(days=i)).strftime("%Y-%m-%d")
        day_data = guild_stats.get(day_key, {})
        for metric, _ in metrics_order:
            totals[metric] += day_data.get(metric, 0)
    embed = discord.Embed(title=f"📈 Thống kê {days} ngày gần nhất", color=discord.Color.blurple())
    for metric, label in metrics_order:
        if totals[metric] > 0:
            embed.add_field(name=label, value=str(totals[metric]), inline=True)
    if not embed.fields:
        embed.description = "Chưa có dữ liệu thống kê trong khoảng thời gian này."
    await interaction.response.send_message(embed=embed, ephemeral=True)
@bot.tree.command(name="status", description="Xem cấu hình bảo mật hiện tại")
@admin_only()
async def status(interaction: discord.Interaction):
    s = cfg(interaction.guild.id)
    log_ch = interaction.guild.get_channel(s["log_channel_id"]) if s["log_channel_id"] else None
    embed = discord.Embed(title="Security status", color=discord.Color.blurple())
    embed.add_field(name="Log channel", value=log_ch.mention if log_ch else "chưa đặt", inline=False)
    embed.add_field(name="Log webhook", value="Đã đặt" if s.get("log_webhook_url") else "chưa đặt", inline=False)
    embed.add_field(name="Lockdown", value="🔒 BẬT" if s.get("lockdown_active") else "🔓 Tắt", inline=False)
    embed.add_field(name="Raid", value=f"{s['raid_join_threshold']} joins / {s['raid_join_window']}s", inline=False)
    embed.add_field(name="Nuke", value=f"{s['nuke_action_threshold']} actions / {s['nuke_action_window']}s", inline=False)
    embed.add_field(name="Spam nhanh", value=f"{s['spam_msg_threshold']} msgs / {s['spam_msg_window']}s", inline=False)
    embed.add_field(name="Spam chậm", value=f"{s['slow_spam_duplicate_threshold']} tin trùng / {s['slow_spam_window']}s", inline=False)
    embed.add_field(
        name="Spam ngắt quãng",
        value=(
            f"{s['intermittent_spam_burst_count']} đợt × {s['intermittent_spam_burst_size']} tin "
            f"(nghỉ ≥{s['intermittent_spam_quiet_gap']}s giữa đợt) trong {s['intermittent_spam_window']}s"
        ),
        inline=False,
    )
    embed.add_field(name="Raid cross-channel", value=f"{s['raid_channel_spam_threshold']} kênh / {s['raid_channel_spam_window']}s → softban", inline=False)
    embed.add_field(name="Mass mention", value=f"{s['mass_mention_threshold']} mentions/tin → timeout", inline=False)
    embed.add_field(name="Invite từ tk mới", value=f"< {s['invite_new_account_days']} ngày tuổi → xóa", inline=False)
    embed.add_field(name="Suspicion ban/timeout", value=f"{s['suspicion_ban_threshold']} / {s['suspicion_timeout_threshold']} điểm", inline=False)
    embed.add_field(name="Mass ban/kick", value=f"{s['mass_ban_threshold']}/{s['mass_ban_window']}s — {s['mass_kick_threshold']}/{s['mass_kick_window']}s", inline=False)
    embed.add_field(name="Perm wipe", value=f"{s['perm_wipe_threshold']} sửa / {s['perm_wipe_window']}s", inline=False)
    embed.add_field(name="Webhook limit", value=f"{s['max_webhooks_per_guild']} max — {s['webhook_create_threshold']}/{s['webhook_create_window']}s = spam", inline=False)
    embed.add_field(name="Badwords", value=str(len(s["badwords"])), inline=True)
    embed.add_field(name="Scam domains", value=str(len(s["scam_domains"])), inline=True)
    embed.add_field(name="Blocked bots", value=str(len(s["blocked_bot_ids"])), inline=True)
    embed.add_field(name="Protected roles", value=str(len(s.get("protected_role_ids", []))), inline=True)
    embed.add_field(name="Whitelist users/roles", value=f"{len(s.get('whitelist_user_ids', []))}/{len(s.get('whitelist_role_ids', []))}", inline=True)
    embed.add_field(name="Auto-ban bot tên None/null", value="Bật" if s.get("auto_ban_suspicious_bots", True) else "Tắt", inline=True)
    last_backup = backups.get(str(interaction.guild.id), {}).get("timestamp")
    embed.add_field(name="Backup gần nhất", value=(discord.utils.format_dt(datetime.datetime.fromtimestamp(last_backup, tz=datetime.timezone.utc), style="R") if last_backup else "chưa có"), inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)
@bot.event
async def setup_hook():
    try:
        await asyncio.to_thread(_load_all_sync)
        logger.info("Đã tải %d guild settings, %d backups, %d guild stats từ Firestore.", len(settings), len(backups), len(stats))
    except Exception:
        logger.exception("Không thể tải dữ liệu từ Firestore — bot sẽ chạy với cấu hình mặc định trống.")
    bot.loop.create_task(raid_cooldown_loop())
    bot.loop.create_task(backup_snapshot_loop())
    bot.loop.create_task(cleanup_loop())
    bot.loop.create_task(stats_save_loop())
if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Thiếu DISCORD_TOKEN trong biến môi trường.")
    keep_alive()
    bot.run(TOKEN)