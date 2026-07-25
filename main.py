import os
import re
import json
import time
import asyncio
import logging
import unicodedata
import datetime
from collections import defaultdict, deque

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
DEFAULTS = {
    "log_channel_id": None,
    "raid_join_threshold": 6,      # số người join...
    "raid_join_window": 10,        # ...trong X giây thì coi là raid
    "raid_min_account_age_days": 3,
    "raid_cooldown_seconds": 300,  # sau ngần này giây không còn raid -> tự hạ verification level
    "nuke_action_threshold": 3,    # số hành động phá hoại...
    "nuke_action_window": 15,      # ...trong X giây thì coi là nuke
    "spam_msg_threshold": 6,       # số tin nhắn...
    "spam_msg_window": 7,          # ...trong X giây thì coi là spam (spam NHANH)
    "spam_timeout_seconds": 300,
    "slow_spam_duplicate_threshold": 4,   # số tin GIỐNG NHAU...
    "slow_spam_window": 120,              # ...trong X giây thì coi là spam CHẬM (vd bot rải tin cách nhau 10-30s)
    "slow_spam_timeout_seconds": 600,
    "raid_channel_spam_threshold": 5,     # số KÊNH KHÁC NHAU nhận cùng 1 nội dung...
    "raid_channel_spam_window": 10,       # ...trong X giây thì coi là raid cross-channel
    "raid_softban_delete_seconds": 3600,  # softban sẽ xóa tin nhắn của người đó trong X giây gần nhất (tối đa 604800 = 7 ngày)
    "badwords": [],
    "scam_domains": [],
    "blocked_bot_ids": [],           # ID bot bị chặn cứng, ban ngay khi join
    "auto_ban_suspicious_bots": True,  # tự ban bot có username khả nghi (None/rỗng/toàn ký tự lạ)
}

# Tên hiển thị mà raid-bot hay dùng khi client không render được username (bug/null)
SUSPICIOUS_BOT_NAME_PATTERN = re.compile(
    r"^(none|null|undefined|nan|unknown)$", re.IGNORECASE
)

if os.path.exists(SETTINGS_FILE):
    with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
        settings = json.load(f)
else:
    settings = {}


def cfg(guild_id: int) -> dict:
    g = settings.setdefault(str(guild_id), {})
    merged = {**DEFAULTS, **g}
    settings[str(guild_id)] = merged
    return merged


def _save_sync():
    tmp = SETTINGS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, ensure_ascii=False)
    os.replace(tmp, SETTINGS_FILE)  # ghi an toàn, tránh hỏng file nếu crash giữa chừng


async def save():
    """Ghi settings ra đĩa mà không block event loop."""
    try:
        await asyncio.to_thread(_save_sync)
    except OSError:
        logger.exception("Không thể lưu settings.json")


# ---------------------------------------------------------------- bot ------
intents = discord.Intents.default()
intents.members = True
intents.message_content = True
intents.bans = True
intents.moderation = True  # cần cho audit-log timeout/ban events ở bản discord.py mới

bot = commands.Bot(command_prefix=PREFIX, intents=intents)

recent_joins = defaultdict(deque)         # guild_id -> [timestamps]
recent_nuke_actions = defaultdict(deque)  # (guild_id, user_id) -> [timestamps]
recent_messages = defaultdict(deque)      # (guild_id, user_id) -> [(ts, message)]
recent_message_contents = defaultdict(deque)  # (guild_id, user_id) -> [(ts, normalized_content, message)]
raid_state = {}                           # guild_id -> {"active": bool, "last_seen": ts, "old_level": VerificationLevel}


def _prune_empty(d: defaultdict, key):
    """Xóa key khỏi defaultdict khi deque của nó rỗng, tránh rò rỉ bộ nhớ dài hạn."""
    if key in d and not d[key]:
        del d[key]


SCAM_PATTERN = re.compile(
    r"discord\W?nitro|dlscord|discrod|discocl|steamcommunlty|steamcommunnity|free.?nitro",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://([^\s/]+)", re.IGNORECASE)

# --- chuẩn hóa text để bắt né luật (cách chữ, số thay chữ, dấu, lặp chữ) ---
LEET_MAP = str.maketrans({
    "4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "|": "i",
    "0": "o", "5": "s", "$": "s", "7": "t", "+": "t", "8": "b",
    "9": "g",
})
VN_MAP = str.maketrans({"đ": "d", "Đ": "d"})

# Từ ngắn hơn ngưỡng này bắt buộc phải có ranh giới từ khi so khớp,
# để tránh false positive kiểu từ cấm 2-3 ký tự dính vào giữa từ vô hại.
SHORT_WORD_BOUNDARY_LEN = 4


def normalize(text: str) -> str:
    text = text.lower()
    text = text.translate(VN_MAP)
    # bỏ dấu tiếng Việt: ế -> e, ầ -> a, ...
    text = unicodedata.normalize("NFD", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Mn")
    text = text.translate(LEET_MAP)
    return text


def _strip_non_alnum(text: str) -> str:
    text = re.sub(r"[^a-z0-9\s]", "", text)
    text = re.sub(r"(.)\1+", r"\1", text)  # gộp ký tự lặp: "dmmmm" -> "dm"
    return text


def contains_badword(content: str, badwords: list[str]) -> str | None:
    base = normalize(content)
    # bản có khoảng trắng (để check ranh giới từ) và bản không khoảng trắng (để bắt né luật)
    spaced = _strip_non_alnum(base)
    squashed = re.sub(r"\s+", "", spaced)

    for w in badwords:
        norm_word = normalize(w)
        norm_word = re.sub(r"[^a-z0-9]", "", norm_word)
        norm_word = re.sub(r"(.)\1+", r"\1", norm_word)
        if not norm_word:
            continue
        if len(norm_word) < SHORT_WORD_BOUNDARY_LEN:
            # từ ngắn: yêu cầu ranh giới từ để giảm false positive
            if re.search(rf"(?<![a-z0-9]){re.escape(norm_word)}(?![a-z0-9])", spaced):
                return w
        else:
            if norm_word in squashed:
                return w
    return None


def normalize_for_dedupe(content: str) -> str:
    """Chuẩn hóa nội dung để so trùng lặp: bỏ khoảng trắng thừa, lowercase.
    Không dùng hàm normalize() né-luật vì ở đây ta muốn so khớp gần-nguyên-văn,
    không phải bắt từ khóa."""
    text = content.strip().lower()
    text = re.sub(r"\s+", " ", text)
    return text


def is_protected(member: discord.Member) -> bool:
    if member.id in OWNER_IDS:
        return True
    if member.guild and member.id == member.guild.owner_id:
        return True
    return member.guild_permissions.administrator


async def log(guild: discord.Guild, text: str, color=discord.Color.blurple()):
    s = cfg(guild.id)
    if not s["log_channel_id"]:
        return
    channel = guild.get_channel(s["log_channel_id"])
    if channel is None:
        logger.warning("Log channel %s không tồn tại/không truy cập được ở guild %s", s["log_channel_id"], guild.id)
        return
    try:
        await channel.send(embed=discord.Embed(description=text, color=color))
    except discord.Forbidden:
        logger.warning("Thiếu quyền gửi tin nhắn vào log channel ở guild %s", guild.id)
    except discord.HTTPException:
        logger.exception("Gửi log thất bại ở guild %s", guild.id)


async def safe_action(coro, *, action_name: str, guild_id: int | None = None):
    """Chạy 1 coroutine Discord API, log lỗi rõ ràng thay vì nuốt im lặng."""
    try:
        return await coro
    except discord.Forbidden:
        logger.warning("Thiếu quyền để thực hiện '%s' (guild=%s). Kiểm tra role/permissions của bot.", action_name, guild_id)
    except discord.HTTPException:
        logger.exception("Lỗi HTTP khi thực hiện '%s' (guild=%s)", action_name, guild_id)
    return None


async def softban(guild: discord.Guild, user: discord.abc.Snowflake, reason: str, delete_seconds: int = 3600):
    """Ban rồi unban ngay để xóa hàng loạt tin nhắn gần đây của người đó, không cấm vĩnh viễn."""
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


# --- Anti-raid: theo dõi tốc độ join, tự hạ verification level khi hết raid --
def _is_suspicious_bot(member: discord.Member) -> str | None:
    """Trả về lý do nếu bot có tên khả nghi (None/rỗng/toàn ký tự đặc biệt), None nếu bình thường."""
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

    # --- chặn bot theo blocklist ID hoặc tên khả nghi, xử lý trước mọi thứ khác ---
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
            # bắt đầu 1 đợt raid mới -> lưu verification level cũ để khôi phục sau
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
                      discord.Color.red())
        else:
            state["last_seen"] = now

        if account_age < s["raid_min_account_age_days"]:
            await safe_action(
                member.kick(reason="Anti-raid: tài khoản quá mới trong lúc raid"),
                action_name="kick new account during raid",
                guild_id=guild.id,
            )


async def raid_cooldown_loop():
    """Kiểm tra định kỳ, tự hạ verification level về mức cũ khi raid đã qua."""
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


# --- Anti-nuke: theo dõi audit log ---------------------------------------
WATCHED_ACTIONS = {
    discord.AuditLogAction.channel_delete,
    discord.AuditLogAction.channel_create,
    discord.AuditLogAction.role_delete,
    discord.AuditLogAction.role_update,     # gán quyền nguy hiểm cho role
    discord.AuditLogAction.member_role_update,  # gán quyền nguy hiểm cho member
    discord.AuditLogAction.ban,
    discord.AuditLogAction.kick,
    discord.AuditLogAction.webhook_create,
    discord.AuditLogAction.emoji_delete,
    discord.AuditLogAction.integration_create,  # thêm bot/app lạ vào server
    discord.AuditLogAction.guild_update,
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

    s = cfg(guild.id)
    key = (guild.id, actor.id)
    now = time.time()
    bucket = recent_nuke_actions[key]
    bucket.append(now)
    while bucket and now - bucket[0] > s["nuke_action_window"]:
        bucket.popleft()

    if len(bucket) >= s["nuke_action_threshold"]:
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
                   discord.Color.dark_red())
    else:
        _prune_empty(recent_nuke_actions, key)


# --- Anti-spam + Anti-badword + Anti-scam: xử lý tin nhắn -----------------
async def bulk_delete_messages(guild: discord.Guild, msgs: list[discord.Message]):
    """Xóa hàng loạt tin nhắn, gom theo channel, dùng bulk delete khi có thể."""
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
    if message.author.bot or not message.guild:
        return
    # Chỉ theo dõi kênh văn bản (Text Channel, Thread, Forum post) — bỏ qua chat trong Voice/Stage
    if isinstance(message.channel, (discord.VoiceChannel, discord.StageChannel)):
        return

    member = message.author
    if not is_protected(member):
        s = cfg(message.guild.id)

        # anti-badword
        if s["badwords"]:
            hit_word = contains_badword(message.content, s["badwords"])
            if hit_word:
                await safe_action(message.delete(), action_name="delete badword message", guild_id=message.guild.id)
                await log(message.guild, f"🤬 Xóa tin nhắn chứa từ cấm (`{hit_word}`) của {member.mention}", discord.Color.gold())
                return

        # anti-scam
        content = message.content
        urls = URL_RE.findall(content)
        hit = None
        if SCAM_PATTERN.search(content):
            hit = "known phishing pattern"
        else:
            for host in urls:
                host = host.lower().split(":")[0]
                for bad in s["scam_domains"]:
                    if host == bad or host.endswith("." + bad):
                        hit = host
                        break
        if hit:
            await safe_action(message.delete(), action_name="delete scam message", guild_id=message.guild.id)
            until = discord.utils.utcnow() + datetime.timedelta(minutes=10)
            await safe_action(member.timeout(until, reason=f"Anti-scam: {hit}"), action_name="timeout scammer", guild_id=message.guild.id)
            await log(message.guild, f"🎣 Chặn link scam (`{hit}`) từ {member.mention}", discord.Color.dark_gold())
            return

        # anti-spam NHANH (nhiều tin bất kỳ trong thời gian ngắn)
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

            until = discord.utils.utcnow() + datetime.timedelta(seconds=s["spam_timeout_seconds"])
            await safe_action(member.timeout(until, reason="Anti-spam: spam tin nhắn"), action_name="timeout spammer", guild_id=message.guild.id)
            await log(message.guild, f"⏱️ {member.mention} bị timeout vì spam ({len(msgs)} tin){channels_note}", discord.Color.orange())
            return
        else:
            _prune_empty(recent_messages, key)

        # anti-spam CHẬM (cùng 1 nội dung lặp lại nhiều lần trong cửa sổ dài,
        # kể cả khi rải cách nhau 10-30s để né ngưỡng spam nhanh)
        norm_content = normalize_for_dedupe(message.content)
        if norm_content:  # bỏ qua tin rỗng/chỉ có attachment
            dup_bucket = recent_message_contents[key]
            dup_bucket.append((now, norm_content, message))
            while dup_bucket and now - dup_bucket[0][0] > s["slow_spam_window"]:
                dup_bucket.popleft()

            # --- Raid detection (cross-channel): cùng nội dung bắn vào NHIỀU KÊNH KHÁC NHAU
            # trong 1 khoảng thời gian rất ngắn -> softban ngay, ưu tiên trước spam chậm.
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
                )
                return

            same_content_msgs = [m for (_, c, m) in dup_bucket if c == norm_content]

            if len(same_content_msgs) >= s["slow_spam_duplicate_threshold"]:
                dup_bucket.clear()
                _prune_empty(recent_message_contents, key)

                # liệt kê các kênh bị dính để có bằng chứng rõ ràng đây là 1 người rải nhiều kênh
                hit_channels = []
                seen_ids = set()
                for m in same_content_msgs:
                    if m.channel.id not in seen_ids:
                        seen_ids.add(m.channel.id)
                        hit_channels.append(m.channel)
                channels_text = ", ".join(c.mention for c in hit_channels)
                cross_channel = len(hit_channels) > 1

                await bulk_delete_messages(message.guild, same_content_msgs)

                until = discord.utils.utcnow() + datetime.timedelta(seconds=s["slow_spam_timeout_seconds"])
                await safe_action(
                    member.timeout(until, reason="Anti-spam: lặp lại cùng 1 nội dung nhiều lần"),
                    action_name="timeout slow spammer",
                    guild_id=message.guild.id,
                )

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
    s = cfg(interaction.guild.id)
    s["log_channel_id"] = channel.id
    await save()
    await interaction.response.send_message(f"✅ Đã đặt kênh log: {channel.mention}", ephemeral=True)


@bot.tree.command(name="addword", description="Thêm từ vào danh sách cấm")
@admin_only()
async def addword(interaction: discord.Interaction, word: str):
    s = cfg(interaction.guild.id)
    if word.lower() not in s["badwords"]:
        s["badwords"].append(word.lower())
        await save()
    await interaction.response.send_message(f"✅ Đã thêm từ cấm: `{word}`", ephemeral=True)


@bot.tree.command(name="removeword", description="Xóa từ khỏi danh sách cấm")
@admin_only()
async def removeword(interaction: discord.Interaction, word: str):
    s = cfg(interaction.guild.id)
    s["badwords"] = [w for w in s["badwords"] if w != word.lower()]
    await save()
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
        await save()
    await interaction.response.send_message(f"✅ Đã thêm domain scam: `{domain}`", ephemeral=True)


@bot.tree.command(name="removescam", description="Xóa domain khỏi blocklist link scam")
@admin_only()
async def removescam(interaction: discord.Interaction, domain: str):
    s = cfg(interaction.guild.id)
    domain = domain.lower().strip()
    s["scam_domains"] = [d for d in s["scam_domains"] if d != domain]
    await save()
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
        await save()

    member = interaction.guild.get_member(bid)
    banned_now = False
    if member:
        result = await safe_action(
            member.ban(reason=f"Blocklist: bot ID {bid} bị admin chặn thủ công"),
            action_name="ban blocklisted bot (manual)",
            guild_id=interaction.guild.id,
        )
        banned_now = result is not None or True  # coi như đã thử; safe_action đã log lỗi nếu có

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
    s["blocked_bot_ids"] = [b for b in s["blocked_bot_ids"] if b != bid]
    await save()
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
            result = await safe_action(
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


@bot.tree.command(name="status", description="Xem cấu hình bảo mật hiện tại")
@admin_only()
async def status(interaction: discord.Interaction):
    s = cfg(interaction.guild.id)
    log_ch = interaction.guild.get_channel(s["log_channel_id"]) if s["log_channel_id"] else None
    embed = discord.Embed(title="Security status", color=discord.Color.blurple())
    embed.add_field(name="Log channel", value=log_ch.mention if log_ch else "chưa đặt", inline=False)
    embed.add_field(name="Raid", value=f"{s['raid_join_threshold']} joins / {s['raid_join_window']}s", inline=False)
    embed.add_field(name="Nuke", value=f"{s['nuke_action_threshold']} actions / {s['nuke_action_window']}s", inline=False)
    embed.add_field(name="Spam nhanh", value=f"{s['spam_msg_threshold']} msgs / {s['spam_msg_window']}s", inline=False)
    embed.add_field(name="Spam chậm", value=f"{s['slow_spam_duplicate_threshold']} tin trùng / {s['slow_spam_window']}s", inline=False)
    embed.add_field(name="Raid cross-channel", value=f"{s['raid_channel_spam_threshold']} kênh / {s['raid_channel_spam_window']}s → softban", inline=False)
    embed.add_field(name="Badwords", value=str(len(s["badwords"])), inline=True)
    embed.add_field(name="Scam domains", value=str(len(s["scam_domains"])), inline=True)
    embed.add_field(name="Blocked bots", value=str(len(s["blocked_bot_ids"])), inline=True)
    embed.add_field(name="Auto-ban bot tên None/null", value="Bật" if s.get("auto_ban_suspicious_bots", True) else "Tắt", inline=True)
    await interaction.response.send_message(embed=embed, ephemeral=True)


# ---------------------------------------------------------------- run ------
@bot.event
async def setup_hook():
    bot.loop.create_task(raid_cooldown_loop())


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Thiếu DISCORD_TOKEN trong biến môi trường.")
    keep_alive()
    bot.run(TOKEN)
