"""
proxy.py — Telegram Bot Proxy Management
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TWO-TIER PROXY SYSTEM
  Tier 1 — Per-user private pool  : any user can add their own proxies.
            Commands: /proxy, /checkproxy, /clearproxy, /myproxy
  Tier 2 — Global shared pool     : owner-managed, used as fallback when
            a user has no personal proxies.
            Commands: /gproxyadd, /gproxyclear, /gproxyreload,
                      /gproxyinfo, /gproxyexport

PROXY SELECTION FOR GATES:
  Call `await get_proxies_for_user(user_id)` — returns the user's
  personal proxies if they have any, otherwise the global pool.

RENDER DEPLOYMENT:
  1. Set DATABASE_URL as an env var in Render's dashboard
     (overrides the hardcoded DB_CONFIG in database.py).
  2. `Start Command` → python main.py
  3. No persistent disk needed — all state lives in Postgres.
  4. Health check path: not applicable for a Telegram bot (use polling).

BUGS FIXED vs. original:
  • Duplicate /checkproxy handler removed.
  • /proxy catch-all no longer shadows /gproxyadd / /gproxyclear etc.
  • Dead proxy_command / checkproxy_command / clearproxy_command /
    myproxy_command stubs replaced with real per-user logic.
  • Deprecated asyncio.get_event_loop() replaced with asyncio.to_thread().
  • gproxyexport_command properly named and scoped (/gproxyexport, owner-only).
  • Router decorators removed — main.py registers all handlers via Command().
"""

import re
import logging
import aiohttp
import asyncio
from urllib.parse import quote
from io import BytesIO

# ── aiogram ──────────────────────────────────────────────────────────────────
from aiogram import types, F, Router
from aiogram.types import BufferedInputFile

# ── local ─────────────────────────────────────────────────────────────────────
from database import (
    get_db_connection,
    PooledConn,
    add_global_proxy,
    clear_global_proxies,
    get_global_proxies,
    get_global_proxy_count,
    proxy_statistics,
)

# kept for compatibility — main.py never dp.include_router(proxy.router)
# but importing callers might reference it.
router = Router()

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONFIGURATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OWNER_IDS             = {6691884739}
MAX_CONCURRENT_CHECKS = 5          # parallel proxy-check slots
PROXY_TIMEOUT         = 8          # seconds per check
IPIFY_API_URL         = "https://api.ipify.org?format=json"
MAX_FILE_SIZE         = 5 * 1024 * 1024   # 5 MB
MAX_USER_PROXIES      = 200        # hard cap per-user personal pool


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PARSING HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def parse_proxy_input(proxy_input: str):
    """
    Parse a proxy string from ANY common format.
    Returns a dict or None on failure.

    Supported formats:
      • user:pass@ip:port
      • user:pass ip:port
      • ip:port user pass
      • user pass ip:port
      • user pass ip port
      • user:pass:ip:port
      • ip:port:user:pass
      • ip:port                (no-auth)
    Protocol prefix (http / https / socks4 / socks5) is optional.
    """
    if not proxy_input or not proxy_input.strip():
        return None

    s = proxy_input.strip().lstrip('\ufeff')
    protocol = 'http'

    m = re.match(r'^(?P<p>https?|socks[45])://', s, re.IGNORECASE)
    if m:
        protocol = m.group('p').lower()
        s = s[len(m.group('p')) + 3:]

    def valid(ip, port):
        if not ip or not port:
            return False
        if not re.match(r'^[a-zA-Z0-9\-\.]+$', ip):
            return False
        return port.isdigit() and 1 <= int(port) <= 65535

    patterns = [
        # user:pass@ip:port
        re.compile(r'^([^:@]+):([^:@]+)@([^:@]+):(\d+)$'),
        # user:pass ip:port
        re.compile(r'^([^:@]+):([^:@]+)\s+([^:@]+):(\d+)$'),
        # ip:port user pass
        re.compile(r'^([^:@]+):(\d+)\s+([^:@]+)\s+([^:@]+)$'),
        # user pass ip:port
        re.compile(r'^([^:@]+)\s+([^:@]+)\s+([^:@]+):(\d+)$'),
        # user pass ip port
        re.compile(r'^([^:@]+)\s+([^:@]+)\s+([^:@]+)\s+(\d+)$'),
        # user:pass:ip:port
        re.compile(r'^([^:@]+):([^:@]+):([^:@]+):(\d+)$'),
    ]

    for i, pat in enumerate(patterns):
        m = pat.match(s)
        if m:
            if i == 2:  # ip:port user pass
                ip, port, user, password = m.groups()
            else:
                user, password, ip, port = m.groups() if i < 2 else \
                    (m.group(1), m.group(2), m.group(3), m.group(4))
                # pattern 2 is ip:port user pass — handled above
            if valid(ip, port):
                return _build_dict(user, password, ip, port, protocol, proxy_input)

    # ip:port:user:pass
    m = re.match(r'^([^:@]+):(\d+):([^:@]+):([^:@]+)$', s)
    if m:
        ip, port, user, password = m.groups()
        if valid(ip, port):
            return _build_dict(user, password, ip, port, protocol, proxy_input)

    # ip:port  (no auth)
    m = re.match(r'^([^:@]+):(\d+)$', s)
    if m:
        ip, port = m.groups()
        if valid(ip, port):
            return _build_dict('', '', ip, port, protocol, proxy_input)

    return None


def _build_dict(user, password, ip, port, protocol, original):
    eu = quote(user,     safe='') if user     else ''
    ep = quote(password, safe='') if password else ''

    if user and password:
        url_format  = f"{protocol}://{eu}:{ep}@{ip}:{port}"
        http_format = f"http://{user}:{password}@{ip}:{port}"
        db_format   = f"{user} {password} {ip} {port}"
    else:
        url_format  = f"{protocol}://{ip}:{port}"
        http_format = f"http://{ip}:{port}"
        db_format   = f"{ip} {port}"

    return {
        "user":            user,
        "password":        password,
        "ip":              ip,
        "port":            port,
        "original_format": original,
        "url_format":      url_format,
        "db_format":       db_format,
        "http_format":     http_format,
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LIVENESS CHECK
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def check_proxy_live(proxy_url: str, session=None, timeout=PROXY_TIMEOUT):
    """
    Test a single proxy against IPIFY.
    Returns (is_alive: bool, info: dict).
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept':     'application/json',
    }
    ct           = aiohttp.ClientTimeout(total=timeout, connect=timeout / 2)
    close_self   = session is None
    if close_self:
        session  = aiohttp.ClientSession(timeout=ct, headers=headers)

    try:
        async with session.get(IPIFY_API_URL, proxy=proxy_url, ssl=False) as resp:
            if resp.status == 200:
                try:
                    data = await resp.json(content_type=None)
                    ip   = data.get('ip') if isinstance(data, dict) else None
                    if ip:
                        return True, {"ip": ip}
                    text_ip = await resp.text()
                    if text_ip.strip():
                        return True, {"ip": text_ip.strip()}
                    return False, {"error": "empty response"}
                except Exception:
                    t = await resp.text()
                    return (True, {"ip": t.strip()}) if t.strip() \
                        else (False, {"error": "empty response"})
            elif resp.status == 429:
                return False, {"error": "rate limited"}
            else:
                return False, {"error": f"HTTP {resp.status}"}

    except asyncio.TimeoutError:
        return False, {"error": "timeout"}
    except aiohttp.ClientProxyConnectionError:
        return False, {"error": "proxy connection failed"}
    except aiohttp.ClientConnectorError:
        return False, {"error": "DNS/connector error"}
    except aiohttp.ClientError as e:
        return False, {"error": f"client error: {str(e)[:60]}"}
    except Exception as e:
        return False, {"error": str(e)[:80]}
    finally:
        if close_self:
            await session.close()


async def check_proxies_parallel(proxies_list: list,
                                  max_concurrent: int = MAX_CONCURRENT_CHECKS) -> list:
    """
    Check a list of proxy dicts in parallel.
    Each dict must have a 'url_format' key.
    Returns list of (proxy_data, is_live, info) tuples.
    """
    if not proxies_list:
        return []

    sem = asyncio.Semaphore(max_concurrent)

    async def _check(pd):
        async with sem:
            live, info = await check_proxy_live(pd['url_format'])
            return pd, live, info

    results = await asyncio.gather(*[_check(p) for p in proxies_list],
                                    return_exceptions=True)
    out = []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            out.append((proxies_list[i], False, {"error": str(r)}))
        else:
            out.append(r)
    return out


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# INPUT EXTRACTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def extract_proxies_from_input(message: types.Message):
    """
    Pull proxy lines from the message: inline text, replied text, or file.
    Returns (valid_proxy_dicts, total_lines_seen, error_html | None).
    """
    raw = ""

    if message.text:
        parts = message.text.split(maxsplit=1)
        if len(parts) > 1:
            raw += parts[1].strip() + "\n"

    if message.reply_to_message:
        reply = message.reply_to_message
        if reply.text:
            raw += reply.text + "\n"
        if reply.caption:
            raw += reply.caption + "\n"

    doc = message.document or (
        message.reply_to_message.document if message.reply_to_message else None
    )
    if doc:
        if doc.file_size and doc.file_size > MAX_FILE_SIZE:
            mb = MAX_FILE_SIZE // (1024 * 1024)
            return None, 0, f"<b>❌ File too large (max {mb} MB).</b>"

        ext = (doc.file_name or "").rsplit('.', 1)[-1].lower()
        if ext not in ('txt', 'text', 'csv', 'proxy', 'list', ''):
            return None, 0, f"<b>⚠️ Unsupported file type .{ext} — use .txt</b>"

        try:
            f_obj   = await message.bot.get_file(doc.file_id)
            f_bytes = await message.bot.download_file(f_obj.file_path)
            if isinstance(f_bytes, (bytes, bytearray)):
                raw += f_bytes.decode('utf-8', errors='ignore')
            else:
                # BytesIO
                raw += f_bytes.read().decode('utf-8', errors='ignore')
        except Exception as e:
            logging.error(f"[proxy] file read error: {e}")
            return None, 0, f"<b>❌ Error reading file: {str(e)[:100]}</b>"

    if not raw.strip():
        return None, 0, (
            "<b>⚠️ No proxy data found!</b>\n\n"
            "<i>Send proxies inline, reply to a message containing them, "
            "or attach a .txt file.</i>"
        )

    lines  = raw.strip().splitlines()
    parsed = []
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        pd = parse_proxy_input(line)
        if pd:
            parsed.append(pd)
        else:
            logging.debug(f"[proxy] unparsable line {n}: {line[:60]}")

    return parsed, len(lines), None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PER-USER PROXY DATABASE HELPERS
# (uses the existing `proxies` table created by ensure_proxy_table)
# Schema: id SERIAL, user_id BIGINT, proxy TEXT, added_at TIMESTAMP
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _db_get_user_proxy_count(user_id: int) -> int:
    try:
        with PooledConn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM proxies WHERE user_id = %s", (user_id,))
            return cur.fetchone()[0] or 0
    except Exception as e:
        logging.error(f"[proxy_db] get_user_proxy_count: {e}")
        return 0


def _db_get_user_proxies(user_id: int) -> list:
    """Return all proxy strings for a user (db_format, one per row)."""
    try:
        with PooledConn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT proxy FROM proxies WHERE user_id = %s ORDER BY id",
                (user_id,)
            )
            return [row[0] for row in cur.fetchall()]
    except Exception as e:
        logging.error(f"[proxy_db] get_user_proxies: {e}")
        return []


def _db_add_user_proxy(user_id: int, proxy_str: str) -> str:
    """
    Insert one proxy for user_id.
    Returns 'added' | 'exists' | 'capped' | 'error'.
    """
    try:
        with PooledConn() as conn:
            cur = conn.cursor()
            # Check cap
            cur.execute("SELECT COUNT(*) FROM proxies WHERE user_id = %s", (user_id,))
            if (cur.fetchone()[0] or 0) >= MAX_USER_PROXIES:
                return 'capped'
            # Dedup check
            cur.execute(
                "SELECT 1 FROM proxies WHERE user_id = %s AND proxy = %s",
                (user_id, proxy_str)
            )
            if cur.fetchone():
                return 'exists'
            cur.execute(
                "INSERT INTO proxies (user_id, proxy) VALUES (%s, %s)",
                (user_id, proxy_str)
            )
            conn.commit()
            return 'added'
    except Exception as e:
        logging.error(f"[proxy_db] add_user_proxy: {e}")
        return 'error'


def _db_clear_user_proxies(user_id: int) -> int:
    """Delete all proxies for a user. Returns count deleted."""
    try:
        with PooledConn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM proxies WHERE user_id = %s", (user_id,))
            count = cur.fetchone()[0] or 0
            cur.execute("DELETE FROM proxies WHERE user_id = %s", (user_id,))
            conn.commit()
            return count
    except Exception as e:
        logging.error(f"[proxy_db] clear_user_proxies: {e}")
        return 0


def _db_remove_user_proxies_bulk(user_id: int, proxies_to_remove: list) -> int:
    """Remove specific dead proxies from a user's pool. Returns count removed."""
    if not proxies_to_remove:
        return 0
    try:
        with PooledConn() as conn:
            cur = conn.cursor()
            cur.executemany(
                "DELETE FROM proxies WHERE user_id = %s AND proxy = %s",
                [(user_id, p) for p in proxies_to_remove]
            )
            removed = cur.rowcount
            conn.commit()
            return removed
    except Exception as e:
        logging.error(f"[proxy_db] remove_user_proxies_bulk: {e}")
        return 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GLOBAL PROXY MANAGER  — singleton in-memory cache
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class GlobalProxyManager:
    """
    Caches the owner-managed global proxy pool in memory.
    Mass gates import `global_proxy_manager` and call get_all_proxies()
    to seed their per-session proxy list.
    """

    def __init__(self):
        self._proxies: list = []
        self._lock           = asyncio.Lock()
        self._loaded: bool   = False

    async def reload(self):
        """Re-read all active global proxies from the DB into the cache."""
        async with self._lock:
            try:
                self._proxies = await asyncio.to_thread(get_global_proxies)
                self._loaded  = True
                logging.info(
                    f"[GlobalProxyManager] loaded {len(self._proxies)} proxies."
                )
            except Exception as e:
                logging.error(f"[GlobalProxyManager] reload error: {e}")

    def get_all_proxies(self) -> list:
        return list(self._proxies)

    def get_count(self) -> int:
        return len(self._proxies)

    def is_loaded(self) -> bool:
        return self._loaded


# Module-level singleton — imported by mass gates and main.py
global_proxy_manager = GlobalProxyManager()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PUBLIC API — PROXY SELECTION FOR GATES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def get_proxies_for_user(user_id: int) -> list:
    """
    Return the proxy list a gate should use for `user_id`.

    Priority:
      1. User's own personal proxies (db_format strings from `proxies` table).
      2. Global pool (from GlobalProxyManager in-memory cache).

    Returns a list of http-format proxy strings, e.g.
      ["http://user:pass@1.2.3.4:8080", "http://5.6.7.8:3128"]
    Returns [] if neither pool has anything.
    """
    # Fetch personal proxies in a thread (they are db_format strings)
    raw_user_proxies = await asyncio.to_thread(_db_get_user_proxies, user_id)

    if raw_user_proxies:
        # Convert db_format → http_format for aiohttp compatibility
        http_proxies = []
        for raw in raw_user_proxies:
            pd = parse_proxy_input(raw)
            if pd:
                http_proxies.append(pd['http_format'])
            else:
                # Fallback: treat the string as-is
                http_proxies.append(raw if raw.startswith('http') else f"http://{raw}")
        return http_proxies

    # Fall back to global pool
    global_raw = global_proxy_manager.get_all_proxies()
    if not global_raw:
        return []

    http_proxies = []
    for raw in global_raw:
        pd = parse_proxy_input(raw)
        if pd:
            http_proxies.append(pd['http_format'])
        else:
            http_proxies.append(raw if raw.startswith('http') else f"http://{raw}")
    return http_proxies


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _is_owner(user_id: int) -> bool:
    return user_id in OWNER_IDS


_USAGE_NO_PROXY = (
    "<b>⚠️ No proxy data found!</b>\n\n"
    "<i>Supported formats:\n"
    "• <code>ip:port</code>\n"
    "• <code>user:pass@ip:port</code>\n"
    "• <code>user:pass:ip:port</code>\n"
    "• <code>ip:port:user:pass</code>\n"
    "• <code>user:pass ip:port</code>\n"
    "\nSend them inline, reply to a message, or attach a .txt file.</i>"
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ╔══════════════════════════════════════════════════════╗
# ║          PER-USER PROXY COMMANDS  (all users)       ║
# ╚══════════════════════════════════════════════════════╝
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def proxy_command(message: types.Message):
    """
    /proxy  — add proxies to your personal private pool.

    Usage:
      /proxy user:pass@ip:port ...    (inline)
      /proxy                          (attach a .txt file)
      /proxy                          (reply to a message with proxies)
    """
    user_id = message.from_user.id

    # Current pool count
    current_count = await asyncio.to_thread(_db_get_user_proxy_count, user_id)
    slots_left    = MAX_USER_PROXIES - current_count

    if slots_left <= 0:
        await message.reply(
            f"<b>❌ Your personal proxy pool is full ({MAX_USER_PROXIES} max).</b>\n"
            f"Use /clearproxy to wipe it, or /checkproxy to remove dead ones.",
            parse_mode="HTML"
        )
        return

    parsed, total_lines, err = await extract_proxies_from_input(message)
    if err:
        await message.reply(err, parse_mode="HTML")
        return

    if not parsed:
        await message.reply(_USAGE_NO_PROXY, parse_mode="HTML")
        return

    # Only check and add up to available slots
    parsed = parsed[:slots_left]

    status_msg = await message.reply(
        f"⏳ <b>Checking {len(parsed)} proxies...</b>",
        parse_mode="HTML"
    )

    results = await check_proxies_parallel(parsed)
    live    = [pd for pd, alive, _ in results if alive]
    dead    = len(parsed) - len(live)

    added = clones = capped = 0

    def _save():
        nonlocal added, clones, capped
        for pd in live:
            r = _db_add_user_proxy(user_id, pd['db_format'])
            if   r == 'added':  added  += 1
            elif r == 'exists': clones += 1
            elif r == 'capped': capped += 1

    await asyncio.to_thread(_save)

    new_count = await asyncio.to_thread(_db_get_user_proxy_count, user_id)

    caption = (
        f"<b>✅ Done!</b>\n\n"
        f"<b>Parsed  ➠</b> <code>{len(parsed)}</code>\n"
        f"<b>Live    ➠</b> <b>{len(live)}</b> ✅\n"
        f"<b>Added   ➠</b> <b>{added}</b> 💾\n"
        f"<b>Dupes   ➠</b> <b>{clones}</b> 🔁\n"
        f"<b>Dead    ➠</b> <b>{dead}</b> ❌\n"
    )
    if capped:
        caption += f"<b>Capped  ➠</b> <b>{capped}</b> 🚫 (pool full)\n"
    caption += f"\n<b>Your pool ➠</b> <code>{new_count}</code> / {MAX_USER_PROXIES} proxies"

    try:
        await status_msg.edit_text(caption, parse_mode="HTML")
    except Exception:
        await message.reply(caption, parse_mode="HTML")


async def myproxy_command(message: types.Message):
    """
    /myproxy — show your personal proxy pool info.
    """
    user_id = message.from_user.id
    count   = await asyncio.to_thread(_db_get_user_proxy_count, user_id)

    if count == 0:
        await message.reply(
            "<b>📭 Your personal proxy pool is empty.</b>\n\n"
            "Use <code>/proxy</code> to add your own proxies.\n"
            "If you have no proxies, the bot uses the shared global pool.",
            parse_mode="HTML"
        )
        return

    global_count = global_proxy_manager.get_count()

    await message.reply(
        f"<b>🔒 Your Private Proxy Pool</b>\n\n"
        f"<b>Personal proxies ➠</b> <code>{count}</code> / {MAX_USER_PROXIES}\n"
        f"<b>Global pool      ➠</b> <code>{global_count}</code> (fallback)\n\n"
        f"<i>Your personal proxies take priority over the global pool.\n"
        f"Use /checkproxy to verify & clean dead ones.\n"
        f"Use /clearproxy to wipe your pool.</i>",
        parse_mode="HTML"
    )


async def clearproxy_command(message: types.Message):
    """
    /clearproxy — delete ALL proxies from your personal pool.
    """
    user_id = message.from_user.id
    deleted = await asyncio.to_thread(_db_clear_user_proxies, user_id)

    if deleted == 0:
        await message.reply(
            "<b>📭 Your personal proxy pool is already empty.</b>",
            parse_mode="HTML"
        )
        return

    await message.reply(
        f"<b>✅ Personal proxy pool cleared.</b>\n"
        f"<b>Removed ➠</b> <code>{deleted}</code> proxies.\n\n"
        f"<i>The bot will now fall back to the global shared pool.</i>",
        parse_mode="HTML"
    )


async def checkproxy_command(message: types.Message):
    """
    /checkproxy — retest your personal proxies; remove dead ones automatically.
    """
    user_id    = message.from_user.id
    raw_list   = await asyncio.to_thread(_db_get_user_proxies, user_id)

    if not raw_list:
        await message.reply(
            "<b>📭 Your personal proxy pool is empty.</b>\n"
            "Use /proxy to add proxies first.",
            parse_mode="HTML"
        )
        return

    # Convert db_format → proxy dict for checking
    proxy_dicts = []
    for raw in raw_list:
        pd = parse_proxy_input(raw)
        if pd:
            proxy_dicts.append(pd)
        else:
            # Build a minimal dict so we can still try
            proxy_dicts.append({
                "db_format":    raw,
                "url_format":   raw if raw.startswith("http") else f"http://{raw}",
                "http_format":  raw if raw.startswith("http") else f"http://{raw}",
                "original_format": raw,
            })

    status_msg = await message.reply(
        f"⏳ <b>Rechecking {len(proxy_dicts)} personal proxies...</b>",
        parse_mode="HTML"
    )

    results    = await check_proxies_parallel(proxy_dicts)
    live_dbs   = {pd['db_format'] for pd, alive, _ in results if alive}
    dead_dbs   = [pd['db_format'] for pd, alive, _ in results if not alive]
    dead_count = len(dead_dbs)
    live_count = len(live_dbs)

    removed = 0
    if dead_dbs:
        removed = await asyncio.to_thread(
            _db_remove_user_proxies_bulk, user_id, dead_dbs
        )

    new_count = await asyncio.to_thread(_db_get_user_proxy_count, user_id)

    caption = (
        f"<b>🔍 Proxy Recheck Complete</b>\n\n"
        f"<b>Checked ➠</b> <code>{len(results)}</code>\n"
        f"<b>Live    ➠</b> <b>{live_count}</b> ✅\n"
        f"<b>Dead    ➠</b> <b>{dead_count}</b> ❌\n"
        f"<b>Removed ➠</b> <b>{removed}</b> 🗑\n\n"
        f"<b>Pool now ➠</b> <code>{new_count}</code> / {MAX_USER_PROXIES} proxies"
    )

    try:
        await status_msg.edit_text(caption, parse_mode="HTML")
    except Exception:
        await message.reply(caption, parse_mode="HTML")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ╔══════════════════════════════════════════════════════╗
# ║          GLOBAL POOL COMMANDS  (owner only)         ║
# ╚══════════════════════════════════════════════════════╝
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def gproxyadd_command(message: types.Message):
    """
    /gproxyadd — add proxies to the shared global pool (owner only).
    """
    if not _is_owner(message.from_user.id):
        await message.reply("❌ Owner-only command.")
        return

    parsed, total_lines, err = await extract_proxies_from_input(message)
    if err:
        await message.reply(err, parse_mode="HTML")
        return
    if not parsed:
        await message.reply(_USAGE_NO_PROXY, parse_mode="HTML")
        return

    status_msg = await message.reply(
        f"⏳ <b>Checking {len(parsed)} proxies for global pool...</b>",
        parse_mode="HTML"
    )

    results = await check_proxies_parallel(parsed)
    live    = [pd for pd, alive, _ in results if alive]
    dead    = len(parsed) - len(live)

    added = clones = 0

    def _save():
        nonlocal added, clones
        for pd in live:
            r = add_global_proxy(pd['db_format'])
            if r == 'added':  added  += 1
            else:             clones += 1

    try:
        await asyncio.to_thread(_save)
    except Exception as e:
        logging.error(f"[gproxyadd] DB error: {e}")

    await global_proxy_manager.reload()

    caption = (
        f"<b>✅ Global Pool Updated!</b>\n\n"
        f"<b>Parsed  ➠</b> <code>{len(parsed)}</code>\n"
        f"<b>Live    ➠</b> <b>{len(live)}</b> ✅\n"
        f"<b>Added   ➠</b> <b>{added}</b> 💾\n"
        f"<b>Dupes   ➠</b> <b>{clones}</b> 🔁\n"
        f"<b>Dead    ➠</b> <b>{dead}</b> ❌\n\n"
        f"<b>Global pool ➠</b> <code>{global_proxy_manager.get_count()}</code> proxies"
    )

    try:
        await status_msg.edit_text(caption, parse_mode="HTML")
    except Exception:
        await message.reply(caption, parse_mode="HTML")


async def gproxyclear_command(message: types.Message):
    """
    /gproxyclear — wipe the entire global proxy pool (owner only).
    """
    if not _is_owner(message.from_user.id):
        await message.reply("❌ Owner-only command.")
        return

    try:
        deleted = await asyncio.to_thread(clear_global_proxies)
        await global_proxy_manager.reload()
        await message.reply(
            f"<b>✅ Global proxy pool cleared.</b>\n"
            f"<b>Deleted ➠</b> <code>{deleted}</code> proxies.",
            parse_mode="HTML"
        )
    except Exception as e:
        logging.error(f"[gproxyclear] error: {e}")
        await message.reply("<b>❌ Error clearing global proxies.</b>", parse_mode="HTML")


async def gproxyreload_command(message: types.Message):
    """
    /gproxyreload — refresh the in-memory global proxy cache from the DB (owner only).
    """
    if not _is_owner(message.from_user.id):
        await message.reply("❌ Owner-only command.")
        return

    await global_proxy_manager.reload()
    await message.reply(
        f"<b>✅ Global proxy cache refreshed.</b>\n"
        f"<b>Pool size ➠</b> <code>{global_proxy_manager.get_count()}</code> proxies.",
        parse_mode="HTML"
    )


async def gproxyinfo_command(message: types.Message):
    """
    /gproxyinfo — show global proxy pool statistics (owner only).
    """
    if not _is_owner(message.from_user.id):
        await message.reply("❌ Owner-only command.")
        return

    try:
        db_count = await asyncio.to_thread(get_global_proxy_count)
        stats    = await asyncio.to_thread(proxy_statistics)
        cached   = global_proxy_manager.get_count()

        msg = (
            f"<b>📊 Global Proxy Pool</b>\n\n"
            f"<b>DB total         ➠</b> <code>{db_count}</code>\n"
            f"<b>Cached (memory)  ➠</b> <code>{cached}</code>\n"
        )
        if stats:
            msg += (
                f"\n<b>Breakdown:</b>\n"
                f"  Active     ➠ <code>{stats.get('active', 0)}</code>\n"
                f"  On cooldown➠ <code>{stats.get('on_cooldown', 0)}</code>\n"
                f"  Avg fails  ➠ <code>{stats.get('avg_fail_count', 0):.1f}</code>\n"
            )
        msg += "\n<i>/gproxyreload — refresh cache | /gproxyexport — export live proxies</i>"

        await message.reply(msg, parse_mode="HTML")
    except Exception as e:
        logging.error(f"[gproxyinfo] error: {e}")
        await message.reply("<b>❌ Error fetching global proxy info.</b>", parse_mode="HTML")


async def gproxyexport_command(message: types.Message):
    """
    /gproxyexport — recheck every global proxy and export live ones as a .txt (owner only).
    """
    if not _is_owner(message.from_user.id):
        await message.reply("❌ Owner-only command.")
        return

    raw_global = global_proxy_manager.get_all_proxies()
    if not raw_global:
        await message.reply("<b>📭 Global proxy pool is empty.</b>", parse_mode="HTML")
        return

    proxy_dicts = []
    for raw in raw_global:
        pd = parse_proxy_input(raw)
        if pd:
            proxy_dicts.append(pd)
        else:
            proxy_dicts.append({
                "db_format":    raw,
                "url_format":   raw if raw.startswith("http") else f"http://{raw}",
                "http_format":  raw if raw.startswith("http") else f"http://{raw}",
                "original_format": raw,
            })

    status_msg = await message.reply(
        f"⏳ <b>Rechecking {len(proxy_dicts)} global proxies...</b>",
        parse_mode="HTML"
    )

    results    = await check_proxies_parallel(proxy_dicts)
    live_data  = [pd for pd, alive, _ in results if alive]

    if not live_data:
        try:
            await status_msg.edit_text(
                "<b>❌ No live proxies found in the global pool.</b>",
                parse_mode="HTML"
            )
        except Exception:
            await message.reply(
                "<b>❌ No live proxies found in the global pool.</b>",
                parse_mode="HTML"
            )
        return

    lines        = [pd['http_format'] for pd in live_data]
    file_content = "\n".join(lines) + "\n"
    txt_file     = BufferedInputFile(
        file=file_content.encode('utf-8'),
        filename=f"global_live_{len(live_data)}.txt"
    )

    # Edit status first, then send file
    try:
        await status_msg.edit_text(
            f"<b>✅ Done — sending {len(live_data)} live proxies...</b>",
            parse_mode="HTML"
        )
    except Exception:
        pass

    await message.reply_document(
        document=txt_file,
        caption=(
            f"<b>✅ Live Global Proxies</b>\n"
            f"<b>Checked ➠</b> <code>{len(proxy_dicts)}</code>\n"
            f"<b>Live    ➠</b> <code>{len(live_data)}</code>"
        ),
        parse_mode="HTML"
    )
