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
    "spam_msg_window": 7,          # ...trong X giây thì coi là spam
    "spam_timeout_seconds": 300,
    "badwords": [],
    "scam_domains": [],
}

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
@bot.event
async def on_member_join(member: discord.Member):
    guild = member.guild
    s = cfg(guild.id)
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
@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
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

        # anti-spam
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

            # gom theo channel để dùng bulk delete (nhanh, ít rate-limit hơn xóa từng cái)
            by_channel: dict[int, list[discord.Message]] = defaultdict(list)
            for m in msgs:
                by_channel[m.channel.id].append(m)

            for channel_id, chan_msgs in by_channel.items():
                channel = message.guild.get_channel(channel_id)
                if channel is None:
                    continue
                # bulk delete chỉ xóa được tin nhắn <14 ngày tuổi, và tối đa 100 tin/lần
                fresh_cutoff = discord.utils.utcnow() - datetime.timedelta(days=14)
                bulk_eligible = [m for m in chan_msgs if m.created_at > fresh_cutoff]
                too_old = [m for m in chan_msgs if m.created_at <= fresh_cutoff]

                if len(bulk_eligible) == 1:
                    await safe_action(bulk_eligible[0].delete(), action_name="delete spam message", guild_id=message.guild.id)
                elif bulk_eligible:
                    await safe_action(channel.delete_messages(bulk_eligible), action_name="bulk delete spam", guild_id=message.guild.id)
                for m in too_old:
                    await safe_action(m.delete(), action_name="delete old spam message", guild_id=message.guild.id)

            until = discord.utils.utcnow() + datetime.timedelta(seconds=s["spam_timeout_seconds"])
            await safe_action(member.timeout(until, reason="Anti-spam: spam tin nhắn"), action_name="timeout spammer", guild_id=message.guild.id)
            await log(message.guild, f"⏱️ {member.mention} bị timeout vì spam ({len(msgs)} tin)", discord.Color.orange())
            return
        else:
            _prune_empty(recent_messages, key)


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


@bot.tree.command(name="status", description="Xem cấu hình bảo mật hiện tại")
@admin_only()
async def status(interaction: discord.Interaction):
    s = cfg(interaction.guild.id)
    log_ch = interaction.guild.get_channel(s["log_channel_id"]) if s["log_channel_id"] else None
    embed = discord.Embed(title="Security status", color=discord.Color.blurple())
    embed.add_field(name="Log channel", value=log_ch.mention if log_ch else "chưa đặt", inline=False)
    embed.add_field(name="Raid", value=f"{s['raid_join_threshold']} joins / {s['raid_join_window']}s", inline=False)
    embed.add_field(name="Nuke", value=f"{s['nuke_action_threshold']} actions / {s['nuke_action_window']}s", inline=False)
    embed.add_field(name="Spam", value=f"{s['spam_msg_threshold']} msgs / {s['spam_msg_window']}s", inline=False)
    embed.add_field(name="Badwords", value=str(len(s["badwords"])), inline=True)
    embed.add_field(name="Scam domains", value=str(len(s["scam_domains"])), inline=True)
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
