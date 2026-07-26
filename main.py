import os
import re
import json
import time
import asyncio
import logging
import unicodedata
import datetime
from collections import defaultdict, deque
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands

from keep_alive import keep_alive

# ---------------------------------------------------------------- logging --
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("securitybot")

# ---------------------------------------------------------------- config ---
TOKEN = os.getenv("DISCORD_TOKEN")
OWNER_IDS = {int(x) for x in os.getenv("OWNER_IDS", "").split(",") if x.strip().isdigit()}
PREFIX = os.getenv("PREFIX", "!")

SETTINGS_FILE = "settings.json"
BACKUP_FILE = "backup.json"

DEFAULTS = {
    "log_channel_id": None,
    "log_webhook_url": None,          # NEW: webhook riêng cho log, không cần bot có quyền send
    "alert_owner_on_critical": True,  # NEW: DM cho OWNER_IDS khi có sự cố nghiêm trọng

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

    "mass_mention_threshold": 6,
    "mass_mention_timeout_seconds": 600,

    "invite_new_account_days": 3,

    "badwords": [],
    "scam_domains": [],
    "blocked_bot_ids": [],
    "auto_ban_suspicious_bots": True,

    # NEW: hệ thống điểm nghi ngờ tích lũy (trust score)
    "suspicion_ban_threshold": 100,
    "suspicion_timeout_threshold": 50,
    "suspicion_decay_seconds": 600,   # điểm giảm dần theo thời gian nếu hành vi tốt

    # NEW: chống zalgo / ký tự unicode bất thường
    "zalgo_max_combining_chars": 8,

    # NEW: lockdown thủ công
    "lockdown_active": False,

    # NEW: bảo vệ role/permission quan trọng
    "protected_role_ids": [],         # role không ai được xóa/sửa ngoài owner/admin gốc
    "backup_snapshot_interval_seconds": 1800,
}

CONFIGURABLE_INT_KEYS = [
    "raid_join_threshold", "raid_join_window", "raid_min_account_age_days", "raid_cooldown_seconds",
    "nuke_action_threshold", "nuke_action_window",
    "spam_msg_threshold", "spam_msg_window", "spam_timeout_seconds",
    "slow_spam_duplicate_threshold", "slow_spam_window", "slow_spam_timeout_seconds",
    "raid_channel_spam_threshold", "raid_channel_spam_window", "raid_softban_delete_seconds",
    "mass_mention_threshold", "mass_mention_timeout_seconds", "invite_new_account_days",
    "suspicion_ban_threshold", "suspicion_timeout_threshold", "suspicion_decay_seconds",
    "zalgo_max_combining_chars", "backup_snapshot_interval_seconds",
]

SUSPICIOUS_BOT_NAME_PATTERN = re.compile(
    r"^(none|null|undefined|nan|unknown)$", re.IGNORECASE
)

# Domain rút gọn thường bị lợi dụng để giấu link scam
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at",
    "rebrand.ly", "grabify.link", "iplogger.org", "ow.ly",
}

# Các domain Discord/Steam hợp lệ để so sánh similarity (bắt typosquat)
TRUSTED_BRAND_DOMAINS = ["discord.com", "discord.gg", "discordapp.com", "steamcommunity.com"]

if os.path.exists(SETTINGS_FILE):
    with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
        settings = json.load(f)
else:
    settings = {}

if os.path.exists(BACKUP_FILE):
    with open(BACKUP_FILE, "r", encoding="utf-8") as f:
        backups = json.load(f)
else:
    backups = {}


def cfg(guild_id: int) -> dict:
    g = settings.setdefault(str(guild_id), {})
    merged = {**DEFAULTS, **g}
    settings[str(guild_id)] = merged
    return merged


def _save_sync():
    tmp = SETTINGS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, ensure_ascii=False)
    os.replace(tmp, SETTINGS_FILE)


def _save_backup_sync():
    tmp = BACKUP_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(backups, f, indent=2, ensure_ascii=False)
    os.replace(tmp, BACKUP_FILE)


async def save():
    try:
        await asyncio.to_thread(_save_sync)
    except OSError:
        logger.exception("Không thể lưu settings.json")


async def save_backup():
    try:
        await asyncio.to_thread(_save_backup_sync)
    except OSError:
        logger.exception("Không thể lưu backup.json")


async def set_and_save(guild_id: int, key: str, value) -> None:
    s = cfg(guild_id)
    s[key] = value
    settings[str(guild_id)] = s
    await save()


# ---------------------------------------------------------------- bot ------
intents = discord.Intents.default()
intents.members = True
intents.message_content = True
intents.bans = True
intents.moderation = True

bot = commands.Bot(command_prefix=PREFIX, intents=intents)

recent_joins = defaultdict(deque)
recent_nuke_actions = defaultdict(deque)
recent_messages = defaultdict(deque)
recent_message_contents = defaultdict(deque)
raid_state = {}

# NEW: điểm nghi ngờ tích lũy per (guild_id, user_id) -> (score, last_update_ts)
suspicion_scores: dict[tuple[int, int], list] = {}

# NEW: webhook cache để không phải tạo lại mỗi lần log
_webhook_cache: dict[str, discord.Webhook] = {}


def _prune_empty(d: defaultdict, key):
    if key in d and not d[key]:
        del d[key]


SCAM_PATTERN = re.compile(
    r"discord\W?nitro|dlscord|discrod|discocl|steamcommunlty|steamcommunnity|free.?nitro",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://([^\s/]+)", re.IGNORECASE)
INVITE_RE = re.compile(r"(?:discord\.gg|discord(?:app)?\.com/invite)/([a-z0-9-]+)", re.IGNORECASE)

LEET_MAP = str.maketrans({
    "4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "|": "i",
    "0": "o", "5": "s", "$": "s", "7": "t", "+": "t", "8": "b",
    "9": "g",
})
VN_MAP = str.maketrans({"đ": "d", "Đ": "d"})

SHORT_WORD_BOUNDARY_LEN = 4


def normalize(text: str) -> str:
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


def normalize_for_dedupe(content: str) -> str:
    text = content.strip().lower()
    text = re.sub(r"\s+", " ", text)
    return text


# ------------------------------------------------------- NEW: typosquat ----
def _levenshtein(a: str, b: str) -> int:
    """Levenshtein distance đơn giản, đủ dùng cho domain ngắn (không cần numpy)."""
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
    """Phát hiện domain giả mạo gần giống discord.com/steamcommunity.com (vd: discrod.com)."""
    host = host.lower()
    for brand in TRUSTED_BRAND_DOMAINS:
        if host == brand or host.endswith("." + brand):
            return None  # domain thật, hợp lệ
        dist = _levenshtein(host, brand)
        # Gần giống (1-2 ký tự khác) nhưng không phải domain thật -> khả nghi cao
        if 0 < dist <= 2 and len(host) >= len(brand) - 3:
            return brand
    return None


def is_shortener(host: str) -> bool:
    host = host.lower()
    return host in URL_SHORTENERS


# ------------------------------------------------------- NEW: zalgo -------
def count_combining_chars(text: str) -> int:
    return sum(1 for c in text if unicodedata.category(c) == "Mn")


def is_zalgo(text: str, max_combining: int) -> bool:
    return count_combining_chars(text) > max_combining


def is_protected(member: discord.abc.User) -> bool:
    if member.id in OWNER_IDS:
        return True
    if not isinstance(member, discord.Member):
        return False
    if member.guild and member.id == member.guild.owner_id:
        return True
    return member.guild_permissions.administrator


# ------------------------------------------------------- NEW: suspicion ---
def add_suspicion(guild_id: int, user_id: int, points: int, decay_seconds: int) -> int:
    """Cộng điểm nghi ngờ, tự động decay điểm cũ theo thời gian trôi qua. Trả về điểm hiện tại."""
    key = (guild_id, user_id)
    now = time.time()
    entry = suspicion_scores.get(key)
    if entry is None:
        score, last_ts = 0.0, now
    else:
        score, last_ts = entry

    if decay_seconds > 0:
        elapsed = now - last_ts
        decay = (elapsed / decay_seconds) * 10  # giảm 10 điểm mỗi decay_seconds trôi qua
        score = max(0.0, score - decay)

    score += points
    suspicion_scores[key] = [score, now]
    return int(score)


def cleanup_suspicion_scores(max_age_seconds: int = 3600):
    """Dọn dẹp điểm nghi ngờ cũ để tránh memory leak dài hạn trên free tier."""
    now = time.time()
    stale = [k for k, (_, ts) in suspicion_scores.items() if now - ts > max_age_seconds]
    for k in stale:
        del suspicion_scores[k]


# ------------------------------------------------------- NEW: webhook log -
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
    """Ghi log ra channel hoặc webhook (nếu có), kèm timestamp. Nếu critical, DM owner."""
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
    """DM cho tất cả OWNER_IDS khi có sự cố nghiêm trọng."""
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


# ------------------------------------------------------- NEW: backup ------
async def snapshot_guild(guild: discord.Guild):
    """Lưu snapshot role + channel permission quan trọng để phục hồi nhanh sau nuke."""
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

    channels_data = []
    for channel in guild.channels:
        overwrites = {}
        for target, ow in channel.overwrites.items():
            allow, deny = ow.pair()
            overwrites[str(target.id)] = {"allow": allow.value, "deny": deny.value, "type": "role" if isinstance(target, discord.Role) else "member"}
        channels_data.append({
            "id": channel.id,
            "name": channel.name,
            "type": str(channel.type),
            "category_id": channel.category_id,
            "position": channel.position,
            "overwrites": overwrites,
        })

    backups[str(guild.id)] = {
        "timestamp": time.time(),
        "roles": roles_data,
        "channels": channels_data,
    }
    await save_backup()


async def backup_snapshot_loop():
    await bot.wait_until_ready()
    while not bot.is_closed():
        for guild in bot.guilds:
            s = cfg(guild.id)
            last = backups.get(str(guild.id), {}).get("timestamp", 0)
            if time.time() - last >= s["backup_snapshot_interval_seconds"]:
                await snapshot_guild(guild)
        await asyncio.sleep(300)


# ------------------------------------------------------- NEW: cleanup -----
async def cleanup_loop():
    """Dọn dẹp các cấu trúc dữ liệu in-memory định kỳ, giảm RAM cho free tier."""
    await bot.wait_until_ready()
    while not bot.is_closed():
        cleanup_suspicion_scores()
        now = time.time()
        for d, max_window in (
            (recent_joins, 3600),
            (recent_nuke_actions, 3600),
            (recent_messages, 3600),
            (recent_message_contents, 3600),
        ):
            stale_keys = []
            for k, bucket in d.items():
                if not bucket:
                    stale_keys.append(k)
                    continue
                # Lấy timestamp đầu tiên tùy cấu trúc (float hoặc tuple)
                first = bucket[0]
                ts = first[0] if isinstance(first, tuple) else first
                if now - ts > max_window:
                    stale_keys.append(k)
            for k in stale_keys:
                del d[k]
        await asyncio.sleep(900)


# ---------------------------------------------------------------- events ---
@bot.event
async def on_ready():
    logger.info("Logged in as %s", bot.user)
    try:
        synced = await bot.tree.sync()
        logger.info("Đã sync %d slash command(s)", len(synced))
    except Exception:
        logger.exception("Sync slash command lỗi")


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


@bot.event
async def on_member_join(member: discord.Member):
    guild = member.guild
    s = cfg(guild.id)

    # NEW: nếu đang lockdown thủ công, kick thẳng account rất mới (giảm thiệt hại)
    if s.get("lockdown_active"):
        account_age = (discord.utils.utcnow() - member.created_at).days
        if account_age < s["raid_min_account_age_days"]:
            await safe_action(member.kick(reason="Lockdown: tài khoản quá mới"), action_name="kick during lockdown", guild_id=guild.id)
            return

    if member.bot:
        if member.id in set(s["blocked_bot_ids"]):
            await safe_action(
                member.ban(reason=f"Blocklist: bot ID {member.id} bị chặn cứng"),
                action_name="ban blocklisted bot",
                guild_id=guild.id,
            )
            await log(guild, f"🤖⛔ Đã ban bot bị chặn `{member.id}` (`{member}`)", discord.Color.dark_red())
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
                return

    now = time.time()
    joins = recent_joins[guild.id]
    joins.append(now)
    while joins and now - joins[0] > s["raid_join_window"]:
        joins.popleft()

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
        else:
            state["last_seen"] = now

        if account_age < s["raid_min_account_age_days"]:
            await safe_action(
                member.kick(reason="Anti-raid: tài khoản quá mới trong lúc raid"),
                action_name="kick new account during raid",
                guild_id=guild.id,
            )


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


# NEW: mở rộng danh sách hành động theo dõi — thêm channel_update (permission wipe) và role_create
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
}

# NEW: hành động cực kỳ nguy hiểm — trigger ngay với ngưỡng thấp hơn nhiều
CRITICAL_ACTIONS = {
    discord.AuditLogAction.channel_delete,
    discord.AuditLogAction.role_delete,
    discord.AuditLogAction.webhook_create,
}


@bot.event
async def on_audit_log_entry(entry: discord.AuditLogEntry):
    if entry.action not in WATCHED_ACTIONS:
        return
    actor = entry.user
    if actor is None or actor.id == bot.user.id:
        return

    guild = entry.guild
    member = guild.get_member(actor.id)
    if member and is_protected(member):
        return

    # NEW: bảo vệ role được đánh dấu protected khỏi xóa/sửa
    s = cfg(guild.id)
    if entry.action in (discord.AuditLogAction.role_delete, discord.AuditLogAction.role_update):
        target_id = getattr(entry.target, "id", None)
        if target_id in set(s.get("protected_role_ids", [])):
            await log(guild, f"⚠️ Phát hiện thay đổi role được bảo vệ (`{target_id}`) bởi {actor.mention} — kiểm tra ngay!", discord.Color.dark_red(), critical=True)

    key = (guild.id, actor.id)
    now = time.time()
    bucket = recent_nuke_actions[key]
    bucket.append(now)
    while bucket and now - bucket[0] > s["nuke_action_window"]:
        bucket.popleft()

    # NEW: hành động nguy hiểm cộng điểm nghi ngờ mạnh, kích hoạt sớm hơn nhiều
    is_critical_action = entry.action in CRITICAL_ACTIONS
    threshold = max(2, s["nuke_action_threshold"] - 1) if is_critical_action else s["nuke_action_threshold"]

    if len(bucket) >= threshold:
        bucket.clear()
        _prune_empty(recent_nuke_actions, key)
        if member:
            dangerous = [r for r in member.roles if r != guild.default_role and (
                r.permissions.administrator or r.permissions.manage_guild or
                r.permissions.manage_channels or r.permissions.manage_roles or
                r.permissions.ban_members or r.permissions.kick_members
            )]
            if dangerous:
                await safe_action(
                    member.remove_roles(*dangerous, reason="Anti-nuke: hành động phá hoại liên tục"),
                    action_name="remove dangerous roles",
                    guild_id=guild.id,
                )
            await safe_action(
                guild.ban(member, reason=f"Anti-nuke: lặp lại {entry.action.name}"),
                action_name="ban nuker",
                guild_id=guild.id,
            )
        await log(guild,
                   f"🛑 **Anti-nuke triggered** — {actor.mention} (`{actor.id}`) spam `{entry.action.name}`. "
                   f"Đã tước quyền + ban.",
                   discord.Color.dark_red(), critical=True)
    else:
        _prune_empty(recent_nuke_actions, key)


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
    if is_protected(member):
        return

    s = cfg(message.guild.id)

    # NEW: lockdown thủ công — chặn tin nhắn từ account mới hoàn toàn
    if s.get("lockdown_active") and not is_other_bot:
        account_age = (discord.utils.utcnow() - member.created_at).days
        if account_age < s["raid_min_account_age_days"]:
            await safe_action(message.delete(), action_name="delete message during lockdown", guild_id=message.guild.id)
            return

    if not is_other_bot:
        if s["badwords"]:
            hit_word = contains_badword(message.content, s["badwords"])
            if hit_word:
                await safe_action(message.delete(), action_name="delete badword message", guild_id=message.guild.id)
                await log(message.guild, f"🤬 Xóa tin nhắn chứa từ cấm (`{hit_word}`) của {member.mention}", discord.Color.gold())
                add_suspicion(message.guild.id, member.id, 10, s["suspicion_decay_seconds"])
                return

        # NEW: chống zalgo / unicode combining char spam (thường dùng để phá giao diện/troll)
        if is_zalgo(message.content, s["zalgo_max_combining_chars"]):
            await safe_action(message.delete(), action_name="delete zalgo message", guild_id=message.guild.id)
            await log(message.guild, f"👾 Xóa tin nhắn chứa ký tự zalgo bất thường từ {member.mention}", discord.Color.gold())
            add_suspicion(message.guild.id, member.id, 15, s["suspicion_decay_seconds"])
            return

        # anti mass-mention
        mention_count = len(message.mentions) + len(message.role_mentions)
        if mention_count >= s["mass_mention_threshold"]:
            await safe_action(message.delete(), action_name="delete mass-mention message", guild_id=message.guild.id)
            until = discord.utils.utcnow() + datetime.timedelta(seconds=s["mass_mention_timeout_seconds"])
            await safe_action(member.timeout(until, reason="Anti-raid: mass mention"), action_name="timeout mass mentioner", guild_id=message.guild.id)
            await log(message.guild, f"📣⛔ {member.mention} bị timeout vì mention hàng loạt ({mention_count} lượt)", discord.Color.dark_orange())
            add_suspicion(message.guild.id, member.id, 30, s["suspicion_decay_seconds"])
            return

        # anti-invite-spam từ tài khoản mới
        if INVITE_RE.search(message.content):
            account_age = (discord.utils.utcnow() - member.created_at).days
            if account_age < s["invite_new_account_days"]:
                await safe_action(message.delete(), action_name="delete invite from new account", guild_id=message.guild.id)
                await log(message.guild, f"🔗⚠️ Xóa invite link từ tài khoản mới ({account_age} ngày tuổi) — {member.mention}", discord.Color.gold())
                add_suspicion(message.guild.id, member.id, 15, s["suspicion_decay_seconds"])
                return

        content = message.content
        urls = URL_RE.findall(content)
        hit = None
        hit_reason = ""
        if SCAM_PATTERN.search(content):
            hit = "known phishing pattern"
            hit_reason = "mẫu từ khóa phishing quen thuộc"
        else:
            for host in urls:
                host = host.lower().split(":")[0]
                for bad in s["scam_domains"]:
                    if host == bad or host.endswith("." + bad):
                        hit = host
                        hit_reason = "domain trong blocklist"
                        break
                if hit:
                    break
                # NEW: typosquat detection
                typo_target = looks_like_typosquat(host)
                if typo_target:
                    hit = host
                    hit_reason = f"domain giả mạo gần giống `{typo_target}`"
                    break
                # NEW: URL shortener + nội dung có mồi nhử (nitro/free/giveaway) -> khả nghi
                if is_shortener(host) and re.search(r"nitro|free|giveaway|airdrop|claim", content, re.IGNORECASE):
                    hit = host
                    hit_reason = "link rút gọn kèm mồi nhử nghi scam"
                    break
        if hit:
            await safe_action(message.delete(), action_name="delete scam message", guild_id=message.guild.id)
            until = discord.utils.utcnow() + datetime.timedelta(minutes=10)
            await safe_action(member.timeout(until, reason=f"Anti-scam: {hit}"), action_name="timeout scammer", guild_id=message.guild.id)
            await log(message.guild, f"🎣 Chặn link scam (`{hit}` — {hit_reason}) từ {member.mention}", discord.Color.dark_gold())
            score = add_suspicion(message.guild.id, member.id, 25, s["suspicion_decay_seconds"])
            if score >= s["suspicion_ban_threshold"]:
                await safe_action(member.ban(reason="Tích lũy điểm nghi ngờ vượt ngưỡng (scam liên tục)"), action_name="ban high suspicion user", guild_id=message.guild.id)
                await log(message.guild, f"⛔ {member.mention} bị ban do điểm nghi ngờ tích lũy vượt ngưỡng ({score})", discord.Color.dark_red(), critical=True)
            return

    key = (message.guild.id, member.id)
    now = time.time()
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
            await safe_action(member.timeout(until, reason="Anti-spam: spam tin nhắn"), action_name="timeout spammer", guild_id=message.guild.id)
            await log(message.guild, f"⏱️ {member.mention} bị timeout vì spam ({len(msgs)} tin){channels_note}", discord.Color.orange())
            add_suspicion(message.guild.id, member.id, 20, s["suspicion_decay_seconds"])
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
                until = discord.utils.utcnow() + datetime.timedelta(seconds=s["slow_spam_timeout_seconds"])
                await safe_action(
                    member.timeout(until, reason="Anti-spam: lặp lại cùng 1 nội dung nhiều lần"),
                    action_name="timeout slow spammer",
                    guild_id=message.guild.id,
                )
                add_suspicion(message.guild.id, member.id, 15, s["suspicion_decay_seconds"])

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
            return
        else:
            _prune_empty(recent_message_contents, key)


# ---------------------------------------------------------------- commands -
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


@bot.tree.command(name="backupnow", description="Chụp snapshot role/permission ngay lập tức")
@admin_only()
async def backupnow(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    await snapshot_guild(interaction.guild)
    await interaction.followup.send("✅ Đã lưu snapshot role/channel hiện tại.", ephemeral=True)


@bot.tree.command(name="backupinfo", description="Xem thời điểm backup gần nhất và số lượng role/channel đã lưu")
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


@bot.tree.command(name="scanbots", description="Quét bot đang có trong server, ban những bot khớp blocklist hoặc tên khả nghi")
@admin_only()
async def scanbots(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    s = cfg(interaction.guild.id)
    blocked_ids = set(s["blocked_bot_ids"])
    banned = []
    for member in interaction.guild.members:
        if not member.bot or is_protected(member):
            continue
        reason = None
        if member.id in blocked_ids:
            reason = f"trong blocklist (`{member.id}`)"
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
@app_commands.choices(key=[app_commands.Choice(name=k, value=k) for k in CONFIGURABLE_INT_KEYS])
async def setconfig(interaction: discord.Interaction, key: app_commands.Choice[str], value: int):
    if value < 0:
        await interaction.response.send_message("❌ Giá trị phải >= 0.", ephemeral=True)
        return
    await set_and_save(interaction.guild.id, key.value, value)
    await interaction.response.send_message(f"✅ Đã đặt `{key.value}` = `{value}`", ephemeral=True)


@bot.tree.command(name="resetconfig", description="Reset toàn bộ cấu hình bảo mật của server về mặc định")
@admin_only()
async def resetconfig(interaction: discord.Interaction):
    settings[str(interaction.guild.id)] = dict(DEFAULTS)
    settings[str(interaction.guild.id)]["badwords"] = []
    settings[str(interaction.guild.id)]["scam_domains"] = []
    settings[str(interaction.guild.id)]["blocked_bot_ids"] = []
    settings[str(interaction.guild.id)]["protected_role_ids"] = []
    await save()
    await interaction.response.send_message("✅ Đã reset cấu hình về mặc định.", ephemeral=True)


@bot.tree.command(name="exportconfig", description="Xuất toàn bộ cấu hình đã lưu (JSON) của server")
@admin_only()
async def exportconfig(interaction: discord.Interaction):
    s = cfg(interaction.guild.id)
    text = json.dumps(s, indent=2, ensure_ascii=False)
    if len(text) > 1900:
        text = text[:1900] + "\n…(cắt bớt)"
    await interaction.response.send_message(f"```json\n{text}\n```", ephemeral=True)


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
    embed.add_field(name="Raid cross-channel", value=f"{s['raid_channel_spam_threshold']} kênh / {s['raid_channel_spam_window']}s → softban", inline=False)
    embed.add_field(name="Mass mention", value=f"{s['mass_mention_threshold']} mentions/tin → timeout", inline=False)
    embed.add_field(name="Invite từ tk mới", value=f"< {s['invite_new_account_days']} ngày tuổi → xóa", inline=False)
    embed.add_field(name="Suspicion ban/timeout", value=f"{s['suspicion_ban_threshold']} / {s['suspicion_timeout_threshold']} điểm", inline=False)
    embed.add_field(name="Badwords", value=str(len(s["badwords"])), inline=True)
    embed.add_field(name="Scam domains", value=str(len(s["scam_domains"])), inline=True)
    embed.add_field(name="Blocked bots", value=str(len(s["blocked_bot_ids"])), inline=True)
    embed.add_field(name="Protected roles", value=str(len(s.get("protected_role_ids", []))), inline=True)
    embed.add_field(name="Auto-ban bot tên None/null", value="Bật" if s.get("auto_ban_suspicious_bots", True) else "Tắt", inline=True)
    last_backup = backups.get(str(interaction.guild.id), {}).get("timestamp")
    embed.add_field(name="Backup gần nhất", value=(discord.utils.format_dt(datetime.datetime.fromtimestamp(last_backup, tz=datetime.timezone.utc), style="R") if last_backup else "chưa có"), inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)


# ---------------------------------------------------------------- run ------
@bot.event
async def setup_hook():
    bot.loop.create_task(raid_cooldown_loop())
    bot.loop.create_task(backup_snapshot_loop())
    bot.loop.create_task(cleanup_loop())


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Thiếu DISCORD_TOKEN trong biến môi trường.")
    keep_alive()
    bot.run(TOKEN)
