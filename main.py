import os
import re
import json
import time
import unicodedata
import datetime
from collections import defaultdict, deque

import discord
from discord import app_commands
from discord.ext import commands

from keep_alive import keep_alive

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


def save():
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------- bot ------
intents = discord.Intents.default()
intents.members = True
intents.message_content = True
intents.bans = True

bot = commands.Bot(command_prefix=PREFIX, intents=intents)

recent_joins = defaultdict(deque)     # guild_id -> [timestamps]
recent_nuke_actions = defaultdict(deque)  # (guild_id, user_id) -> [timestamps]
recent_messages = defaultdict(deque)  # (guild_id, user_id) -> [(ts, message)]

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


def normalize(text: str) -> str:
    text = text.lower()
    text = text.translate(VN_MAP)
    # bỏ dấu tiếng Việt: ế -> e, ầ -> a, ...
    text = unicodedata.normalize("NFD", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Mn")
    text = text.translate(LEET_MAP)
    # bỏ mọi ký tự không phải chữ/số (khoảng trắng, dấu chấm, *, _, ...)
    text = re.sub(r"[^a-z0-9]", "", text)
    # gộp ký tự lặp liên tiếp: "dmmmm" -> "dm", "vcllll" -> "vcl"
    text = re.sub(r"(.)\1+", r"\1", text)
    return text


def contains_badword(content: str, badwords: list[str]) -> str | None:
    norm_content = normalize(content)
    for w in badwords:
        norm_word = normalize(w)
        if norm_word and norm_word in norm_content:
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
    if channel:
        try:
            await channel.send(embed=discord.Embed(description=text, color=color))
        except discord.HTTPException:
            pass


# ---------------------------------------------------------------- events ---
@bot.event
async def on_ready():
    print(f"Logged in as {bot.user}")
    try:
        synced = await bot.tree.sync()
        print(f"Đã sync {len(synced)} slash command(s)")
    except Exception as e:
        print(f"Sync lỗi: {e}")


# --- Anti-raid: theo dõi tốc độ join -----------------------------------
@bot.event
async def on_member_join(member: discord.Member):
    s = cfg(member.guild.id)
    now = time.time()
    joins = recent_joins[member.guild.id]
    joins.append(now)
    while joins and now - joins[0] > s["raid_join_window"]:
        joins.popleft()

    account_age = (discord.utils.utcnow() - member.created_at).days

    if len(joins) >= s["raid_join_threshold"]:
        try:
            await member.guild.edit(verification_level=discord.VerificationLevel.high)
        except discord.HTTPException:
            pass
        await log(member.guild,
                   f"🚨 **Raid detected** — {len(joins)} joins trong {s['raid_join_window']}s. "
                   f"Verification level đã nâng lên High.",
                   discord.Color.red())

        if account_age < s["raid_min_account_age_days"]:
            try:
                await member.kick(reason="Anti-raid: tài khoản quá mới trong lúc raid")
            except discord.HTTPException:
                pass


# --- Anti-nuke: theo dõi audit log ---------------------------------------
WATCHED_ACTIONS = {
    discord.AuditLogAction.channel_delete,
    discord.AuditLogAction.channel_create,
    discord.AuditLogAction.role_delete,
    discord.AuditLogAction.ban,
    discord.AuditLogAction.kick,
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

    s = cfg(guild.id)
    key = (guild.id, actor.id)
    now = time.time()
    bucket = recent_nuke_actions[key]
    bucket.append(now)
    while bucket and now - bucket[0] > s["nuke_action_window"]:
        bucket.popleft()

    if len(bucket) >= s["nuke_action_threshold"]:
        bucket.clear()
        if member:
            dangerous = [r for r in member.roles if r != guild.default_role and (
                r.permissions.administrator or r.permissions.manage_guild or
                r.permissions.manage_channels or r.permissions.manage_roles or
                r.permissions.ban_members or r.permissions.kick_members
            )]
            try:
                if dangerous:
                    await member.remove_roles(*dangerous, reason="Anti-nuke: hành động phá hoại liên tục")
                await guild.ban(member, reason=f"Anti-nuke: lặp lại {entry.action.name}")
            except discord.HTTPException:
                pass
        await log(guild,
                   f"🛑 **Anti-nuke triggered** — {actor.mention} (`{actor.id}`) spam `{entry.action.name}`. "
                   f"Đã tước quyền + ban.",
                   discord.Color.dark_red())


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
                try:
                    await message.delete()
                except discord.HTTPException:
                    pass
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
            try:
                await message.delete()
            except discord.HTTPException:
                pass
            try:
                until = discord.utils.utcnow() + datetime.timedelta(minutes=10)
                await member.timeout(until, reason=f"Anti-scam: {hit}")
            except discord.HTTPException:
                pass
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
            for m in msgs:
                try:
                    await m.delete()
                except discord.HTTPException:
                    pass
            try:
                until = discord.utils.utcnow() + datetime.timedelta(seconds=s["spam_timeout_seconds"])
                await member.timeout(until, reason="Anti-spam: spam tin nhắn")
            except discord.HTTPException:
                pass
            await log(message.guild, f"⏱️ {member.mention} bị timeout vì spam ({len(msgs)} tin)", discord.Color.orange())
            return




# ---------------------------------------------------------------- commands -
def admin_only():
    return app_commands.checks.has_permissions(administrator=True)


@bot.tree.command(name="setlog", description="Đặt kênh nhận log cảnh báo bảo mật")
@admin_only()
async def setlog(interaction: discord.Interaction, channel: discord.TextChannel):
    s = cfg(interaction.guild.id)
    s["log_channel_id"] = channel.id
    save()
    await interaction.response.send_message(f"✅ Đã đặt kênh log: {channel.mention}", ephemeral=True)


@bot.tree.command(name="addword", description="Thêm từ vào danh sách cấm")
@admin_only()
async def addword(interaction: discord.Interaction, word: str):
    s = cfg(interaction.guild.id)
    if word.lower() not in s["badwords"]:
        s["badwords"].append(word.lower())
        save()
    await interaction.response.send_message(f"✅ Đã thêm từ cấm: `{word}`", ephemeral=True)


@bot.tree.command(name="removeword", description="Xóa từ khỏi danh sách cấm")
@admin_only()
async def removeword(interaction: discord.Interaction, word: str):
    s = cfg(interaction.guild.id)
    s["badwords"] = [w for w in s["badwords"] if w != word.lower()]
    save()
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
        save()
    await interaction.response.send_message(f"✅ Đã thêm domain scam: `{domain}`", ephemeral=True)


@bot.tree.command(name="removescam", description="Xóa domain khỏi blocklist link scam")
@admin_only()
async def removescam(interaction: discord.Interaction, domain: str):
    s = cfg(interaction.guild.id)
    domain = domain.lower().strip()
    s["scam_domains"] = [d for d in s["scam_domains"] if d != domain]
    save()
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
if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Thiếu DISCORD_TOKEN trong biến môi trường.")
    keep_alive()
    bot.run(TOKEN)
