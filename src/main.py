# app.py
from flask import Flask, request, jsonify, render_template, session
import json
import math
import statistics
import secrets
import time
import hashlib
from collections import defaultdict

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ─── In-Memory Stores ─────────────────────────────────────────────────────────

# {ip: [timestamps]...}
ip_request_log = defaultdict(list)

# {username: [timestamps]...}
username_attempts = defaultdict(list)

# {ip: block_until_timestamp}
ip_blocklist = {}

# {username: block_until_timestamp}
username_blocklist = {}

# {ip: {endpoint: [timestamps]...}}
ip_endpoint_log = defaultdict(lambda: defaultdict(list))

# IPs that hit the honeypot
honeypot_hits = set()

# {ip: set of usernames attempted}
ip_login_set = defaultdict(set)

# {ip: {"attempts": int, "failures": int}}
ip_behavior_stats = defaultdict(lambda: {"attempts": 0, "failures": 0})

# {ip: [{"combo": str, "timestamp": float}]}
ip_combo_log = defaultdict(list)

# {ip: [{"combo_hash": str, "timestamp": float}]}
ip_submission = defaultdict(list)

# Add to In-Memory Stores
# {ip: set of endpoints visited}
ip_endpoint_set = defaultdict(set)

# for global request tracking
ip_global_log = defaultdict(list)

# Configuration
RATE_LIMIT_WINDOW        = 60
RATE_LIMIT_MAX           = 5
LOCKOUT_THRESHOLD        = 10
BLOCK_DURATION           = 300
ENDPOINT_RATE_WINDOW     = 10
ENDPOINT_RATE_MAX        = 8
USERNAME_DIVERSITY_MAX   = 5
FAILURE_RATIO_THRESHOLD  = 0.8
COMBO_WINDOW             = 60
COMBO_MAX                = 5
SPAM_SUBMISSION_WINDOW   = 60
GLOBAL_RATE_WINDOW       = 10
GLOBAL_RATE_MAX          = 20
ENUMERATION_MAX          = 6
PAYLOAD_MAX_BYTES        = 10240

# Known scraper user agents
SCRAPER_USER_AGENTS = [
    "python-requests", "curl", "wget", "bot", "spider",
    "crawler", "scraper", "httpclient", "java", "ruby",
    "php", "go-http-client", "libwww-perl", "httpx",
    "axios", "fetch", "okhttp", "httpie", "postmanruntime"
]

# Common breached passwords
BREACHED_PASSWORDS = {
    "password123", "123456", "qwerty", "letmein", "admin",
    "welcome", "iloveyou", "monkey", "abc123", "password1",
    "12345678", "sunshine", "princess", "goodbye", "password",
    "123456789", "12345", "1234567", "football", "shadow",
    "master", "666666", "mustang", "1234567890", "michael",
    "superman", "batman", "trustno1", "pass", "test", "guest"
}

# Known disposable email domains
DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "temp-mail.org", "yopmail.com", "trashmail.com",
    "fakeinbox.com", "getnada.com", "dispostable.com",
    "maildrop.cc", "tempmail.net", "mytemp.email",
    "disposablemail.com", "spambog.com", "mailnesia.com",
    "throwawaymail.com", "temp-mail.io", "mailcatch.com",
    "mail-temporaire.fr", "temp-mail.fr", "mail-temp.com",
    "temp-mail.com", "mail-temp.net", "tempmailo.com",
    "spam4.me", "mail-temporaire.com", "tempmail.org"
}

# ------ API Abuse Helpers -----------------------------------------------------

def is_missing_browser_headers() -> bool:
    accept = request.headers.get("Accept", "")
    accept_language = request.headers.get("Accept-Language", "")
    accept_encoding = request.headers.get("Accept-Encoding", "")
    return not accept or not accept_language or not accept_encoding

def is_payload_suspicious() -> bool:
    content_length = request.content_length or 0
    if content_length > PAYLOAD_MAX_BYTES:
        return True
    content_type = request.headers.get("Content-Type", "")
    if "application/json" in content_type:
        try:
            data = request.get_json(silent=True)
            if data is None:
                return True
        except Exception:
            return True
    return False

def is_enumerating_endpoints(ip: str, endpoint: str) -> bool:
    ip_endpoint_set[ip].add(endpoint)
    return len(ip_endpoint_set[ip]) > ENUMERATION_MAX

def is_globally_rate_limited(ip: str) -> bool:
    now = time.time()
    ip_global_log[ip] = [t for t in ip_global_log[ip] if now - t < GLOBAL_RATE_WINDOW]
    ip_global_log[ip].append(now)
    return len(ip_global_log[ip]) > GLOBAL_RATE_MAX

def check_api_abuse(ip: str, endpoint: str) -> dict | None:
    # 1. Global rate limit - Fastest check, do it first
    if is_globally_rate_limited(ip):
        print(f"[BotDetector] Global rate limit hit by {ip} on {endpoint}")
        ip_blocklist[ip] = time.time() + BLOCK_DURATION
        return {
            "blocked": True,
            "reason": "Too many requests. Slow down!",
            "api_abuse": True,
            "score": 100
        }
    # 2. Missing browser headers
    if is_missing_browser_headers():
        print(f"Missing browder headers from {ip} on {endpoint}")
        return {
            "blocked": True,
            "reason": "Invalid request headers",
            "api_abuse": True,
            "score": 90
        }
    # 3. Suspicious payload
    if is_payload_suspicious():
        print(f"Suspicious payload from {ip}")
        return {
            "blocked": True,
            "reason": "Invalid or oversized payload",
            "api_abuse": True,
            "score": 80
        }
    # 4. Endpoint enumeration
    if is_enumerating_endpoints(ip, endpoint):
        print(f"Endpoint enumeration from {ip}")
        ip_blocklist[ip] = time.time() + BLOCK_DURATION
        return {
            "blocked": True,
            "reason": "Suspicious endpoint scanning detected",
            "api_abuse": True,
            "score": 100
        }
    return None

# ─── Rate Limiting & Lockout Helpers ──────────────────────────────────────────

def is_ip_blocked(ip: str) -> bool:
    if ip in ip_blocklist:
        if time.time() < ip_blocklist[ip]:
            return True
        else:
            del ip_blocklist[ip]
    return False


def is_username_blocked(username: str) -> bool:
    if username in username_blocklist:
        if time.time() < username_blocklist[username]:
            return True
        else:
            del username_blocklist[username]
    return False


def is_rate_limited(ip: str) -> bool:
    now = time.time()
    ip_request_log[ip] = [t for t in ip_request_log[ip] if now - t < RATE_LIMIT_WINDOW]
    return len(ip_request_log[ip]) >= RATE_LIMIT_MAX


def record_attempt(ip: str, username: str):
    now = time.time()
    ip_request_log[ip].append(now)
    username_attempts[username].append(now)


def record_failed_attempt(ip: str, username: str):
    now = time.time()
    ip_behavior_stats[ip]["failures"] += 1
    ip_recent = [t for t in ip_request_log[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(ip_recent) >= LOCKOUT_THRESHOLD:
        ip_blocklist[ip] = now + BLOCK_DURATION
        print(f"[BotDetector] IP {ip} blocked until {time.ctime(ip_blocklist[ip])}")
    username_recent = [t for t in username_attempts[username] if now - t < RATE_LIMIT_WINDOW]
    if len(username_recent) >= LOCKOUT_THRESHOLD:
        username_blocklist[username] = now + BLOCK_DURATION
        print(f"[BotDetector] Username '{username}' blocked until {time.ctime(username_blocklist[username])}")


def time_remaining(block_until: float) -> int:
    return max(0, int(block_until - time.time()))


# ─── Scraper Detection Helpers ────────────────────────────────────────────────

def is_bad_user_agent(ua: str) -> bool:
    if not ua or ua.strip() == "":
        return True
    ua_lower = ua.lower()
    return any(bot in ua_lower for bot in SCRAPER_USER_AGENTS)


def has_no_referer(referer: str) -> bool:
    return not referer or referer.strip() == ""


def is_endpoint_abused(ip: str, endpoint: str) -> bool:
    now = time.time()
    ip_endpoint_log[ip][endpoint] = [t for t in ip_endpoint_log[ip][endpoint] if now - t < ENDPOINT_RATE_WINDOW]
    ip_endpoint_log[ip][endpoint].append(now)
    return len(ip_endpoint_log[ip][endpoint]) >= ENDPOINT_RATE_MAX


def check_scraper(ip: str, endpoint: str) -> dict | None:
    ua      = request.headers.get("User-Agent", "")
    referer = request.headers.get("Referer", "")

    if ip in honeypot_hits:
        print(f"[BotDetector] Honeypot-flagged IP attempt: {ip} on {endpoint}")
        return {"blocked": True, "reason": "Suspicious activity detected.", "score": 100}

    if is_bad_user_agent(ua):
        print(f"[BotDetector] Bad User-Agent from {ip}: '{ua}'")
        ip_blocklist[ip] = time.time() + BLOCK_DURATION
        return {"blocked": True, "reason": "Suspicious client detected.", "score": 100}

    if endpoint == "/login" and has_no_referer(referer):
        print(f"[BotDetector] No referer on login from {ip}")

    if is_endpoint_abused(ip, endpoint):
        print(f"[BotDetector] Endpoint abuse from {ip} on {endpoint}")
        ip_blocklist[ip] = time.time() + BLOCK_DURATION
        return {"blocked": True, "reason": "Too many requests to this endpoint.", "score": 100}

    return None


# ─── Credential Stuffing Helpers ──────────────────────────────────────────────

def is_username_diverse(ip: str, username: str) -> bool:
    ip_login_set[ip].add(username)
    return len(ip_login_set[ip]) > USERNAME_DIVERSITY_MAX


def is_failure_ratio_high(ip: str) -> bool:
    stats    = ip_behavior_stats[ip]
    attempts = stats["attempts"]
    failures = stats["failures"]
    if attempts < 5:
        return False
    return (failures / attempts) >= FAILURE_RATIO_THRESHOLD


def is_combo_stuffing(ip: str, username: str, password: str) -> bool:
    now = time.time()
    ip_combo_log[ip] = [c for c in ip_combo_log[ip] if now - c["timestamp"] < COMBO_WINDOW]
    combo_key = f"{username}:{password}"
    if not any(c["combo"] == combo_key for c in ip_combo_log[ip]):
        ip_combo_log[ip].append({"combo": combo_key, "timestamp": now})
    return len(ip_combo_log[ip]) >= COMBO_MAX


def is_breached_password(password: str) -> bool:
    return password.lower().strip() in BREACHED_PASSWORDS


def check_credential_stuffing(ip: str, username: str, password: str) -> dict | None:
    ip_behavior_stats[ip]["attempts"] += 1

    if is_username_diverse(ip, username):
        print(f"[BotDetector] High username diversity from {ip}")
        ip_blocklist[ip] = time.time() + BLOCK_DURATION
        return {
            "blocked": True,
            "reason": "Too many different usernames attempted.",
            "stuffing": True,
            "score": 100
        }

    if is_failure_ratio_high(ip):
        print(f"[BotDetector] High failure ratio from {ip}")
        ip_blocklist[ip] = time.time() + BLOCK_DURATION
        return {
            "blocked": True,
            "reason": "Too many failed login attempts.",
            "stuffing": True,
            "score": 100
        }

    if is_combo_stuffing(ip, username, password):
        print(f"[BotDetector] Combo stuffing from {ip}")
        ip_blocklist[ip] = time.time() + BLOCK_DURATION
        return {
            "blocked": True,
            "reason": "Credential stuffing detected.",
            "stuffing": True,
            "score": 100
        }

    if is_breached_password(password):
        print(f"[BotDetector] Breached password from {ip} for '{username}'")
        return {
            "blocked": False,
            "warning": True,
            "breached_password": True,
            "message": "This password has been exposed in a data breach. Please change it.",
            "score": 40
        }

    return None


# ─── Spam Bot Helpers ─────────────────────────────────────────────────────────

def is_honeypot_filled(form_data: dict) -> bool:
    return bool(form_data.get("website", "").strip())


def is_disposable_email(email: str) -> bool:
    if not email or "@" not in email:
        return False
    domain = email.strip().lower().split("@")[-1]
    return domain in DISPOSABLE_EMAIL_DOMAINS


def is_duplicate_submission(ip: str, username: str, password: str) -> bool:
    now        = time.time()
    combo_hash = hashlib.sha256(f"{username}:{password}".encode()).hexdigest()
    ip_submission[ip] = [e for e in ip_submission[ip] if now - e["timestamp"] < SPAM_SUBMISSION_WINDOW]
    if any(e["combo_hash"] == combo_hash for e in ip_submission[ip]):
        print(f"[BotDetector] Duplicate submission from {ip}")
        return True
    ip_submission[ip].append({"combo_hash": combo_hash, "timestamp": now})
    return False


def check_spam_bot(ip: str, username: str, password: str, email: str, form_data: dict) -> dict | None:
    if is_honeypot_filled(form_data):
        print(f"[BotDetector] Honeypot field filled from {ip}")
        ip_blocklist[ip] = time.time() + BLOCK_DURATION
        return {"blocked": True, "reason": "Spam behavior detected.", "spam": True, "score": 100}

    if email and is_disposable_email(email):
        print(f"[BotDetector] Disposable email from {ip}: {email}")
        return {
            "blocked": True,
            "reason": "Disposable email addresses are not allowed.",
            "spam": True,
            "disposable_email": True,
            "score": 80
        }

    if is_duplicate_submission(ip, username, password):
        ip_blocklist[ip] = time.time() + BLOCK_DURATION
        return {"blocked": True, "reason": "Duplicate submission detected.", "spam": True, "score": 100}

    focus_time  = form_data.get("formFocusTime")
    submit_time = form_data.get("formSubmitTime")
    if focus_time and submit_time:
        if (submit_time - focus_time) < 500:
            print(f"[BotDetector] Instant spam submission from {ip}")
            ip_blocklist[ip] = time.time() + BLOCK_DURATION
            return {"blocked": True, "reason": "Submission too fast.", "spam": True, "score": 100}

    return None


# ─── Scoring Engine ───────────────────────────────────────────────────────────

def score_behavior(data: dict, ip: str) -> dict:
    score = 0
    flags = []

    mouse_moves     = data.get("mouseMoves", [])
    key_intervals   = data.get("keyIntervals", [])
    click_positions = data.get("clickPositions", [])
    focus_time      = data.get("formFocusTime")
    submit_time     = data.get("formSubmitTime")
    referer         = request.headers.get("Referer", "")

    # 1. Mouse movement checks
    if len(mouse_moves) == 0:
        score += 30
        flags.append("no_mouse_movement")
    elif len(mouse_moves) >= 3:
        linearity = check_linearity(mouse_moves)
        if linearity > 0.98:
            score += 20
            flags.append("linear_mouse_movement")
        speeds = compute_speeds(mouse_moves)
        if speeds and coefficient_of_variation(speeds) < 0.05:
            score += 15
            flags.append("constant_mouse_speed")

    # 2. Keystroke timing checks
    if len(key_intervals) == 0:
        score += 20
        flags.append("no_keystrokes")
    elif len(key_intervals) >= 3:
        avg_interval = statistics.mean(key_intervals)
        cv = coefficient_of_variation(key_intervals)
        if cv < 0.1:
            score += 25
            flags.append("uniform_typing_speed")
        if avg_interval < 20:
            score += 20
            flags.append("superhuman_typing_speed")

    # 3. Time-on-form checks
    if focus_time and submit_time:
        time_on_form = submit_time - focus_time
        if time_on_form < 2000:
            score += 25
            flags.append("instant_submission")
        elif time_on_form > 300000:
            score += 10
            flags.append("very_slow_submission")
    else:
        score += 15
        flags.append("missing_timing_data")

    # 4. Click behavior checks
    if len(click_positions) == 0:
        score += 10
        flags.append("no_clicks_recorded")

    # 5. No referer penalty
    if not referer.strip():
        score += 10
        flags.append("no_referer")

    # 6. Headless browser checks
    headless_data = data.get("headless", {})
    if headless_data:
        headless_score, headless_flags = check_headless(headless_data)
        score += headless_score
        flags.extend(headless_flags)

    return {"score": min(score, 100), "flags": flags}

# ___________________________ Headless Browser Detection _______________________

def check_headless(headless: dict) -> tuple[int, list]:
    score = 0
    flags = []

    # 1. navigator.webdriver check - strongest signal
    if headless.get("webdriver") is True:
        score += 50
        flags.append("webdriver_detected")
    
    # 2. No Plugins - real browsers always have some
    if headless.get("pluginCount", 1) == 0:
        score += 15
        flags.append("no_plugins")
    
    # 3. Screen properly anomalies
    outer_width = headless.get("outerWidth", 1)
    outer_height = headless.get("outerHeight", 1)
    if outer_width == 0 or outer_height == 0:
        score += 20
        flags.append("zero_outer_dimensions")
    
    # 4. No languages set
    if headless.get("languages", 1) == 0:
        score += 10
        flags.append("no_languages")
    
    # 5. Missing window.chrome (Puppeteer often missing this)
    if not headless.get("hasChrome", True):
        score += 10
        flags.append("no_window_chrome")
    
    # 6. No localStorage access
    if not headless.get("hasLocalStorage", True):
        score += 10
        flags.append("no_local_storage")
    
    # 7. Suspicious hardware concurrency 
    if headless.get("hardwareConcurrency", 1) == 0:
        score += 10
        flags.append("zero_hardware_concurrency")
    
    # Color depth anomaly
    if headless.get("colorDepth", 24) < 16:
        score += 10
        flags.append("low_color_depth")
    
    return score, flags


# ─── Math Helpers ─────────────────────────────────────────────────────────────

def check_linearity(points: list) -> float:
    if len(points) < 3:
        return 0.0
    xs = [p['x'] for p in points]
    ys = [p['y'] for p in points]
    n = len(xs)
    mean_x, mean_y = sum(xs) / n, sum(ys) / n
    numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    denom_x = math.sqrt(sum((x - mean_x)**2 for x in xs))
    denom_y = math.sqrt(sum((y - mean_y)**2 for y in ys))
    if denom_x == 0 or denom_y == 0:
        return 1.0
    return abs(numerator / (denom_x * denom_y))


def compute_speeds(points: list) -> list:
    speeds = []
    for i in range(1, len(points)):
        dx = points[i]["x"] - points[i-1]["x"]
        dy = points[i]["y"] - points[i-1]["y"]
        dt = points[i]["t"] - points[i-1]["t"]
        if dt > 0:
            speeds.append(math.sqrt(dx**2 + dy**2) / dt)
    return speeds


def coefficient_of_variation(data: list) -> float:
    if len(data) < 2:
        return 0.0
    mean = statistics.mean(data)
    if mean == 0:
        return 0.0
    return statistics.stdev(data) / mean


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("login.html")


@app.route("/honeypot-api")
@app.route("/api/data")
@app.route("/admin/users")
@app.route("/config")
def honeypot():
    ip = request.remote_addr
    honeypot_hits.add(ip)
    print(f"[BotDetector] Honeypot hit: {ip} on {request.path}")
    return jsonify({"message": "This endpoint does not exist."}), 404


@app.route("/login", methods=["POST"])
def login():
    ip           = request.remote_addr
    username     = request.form.get("username", "").strip()
    password     = request.form.get("password", "")
    raw_behavior = request.form.get("behavior_data", "{}")
    email        = request.form.get("email", "")

    # API abuse check
    api_result = check_api_abuse(ip, "/login")
    if api_result:
        return jsonify(api_result), 403

    # 1. Scraper check
    scraper_result = check_scraper(ip, "/login")
    if scraper_result:
        return jsonify(scraper_result), 403

    # 2. IP block check
    if is_ip_blocked(ip):
        sec = time_remaining(ip_blocklist[ip])
        print(f"[BotDetector] Blocked IP attempt: {ip}")
        return jsonify({
            "blocked": True,
            "reason": f"IP blocked. Try again in {sec} seconds.",
            "lockout": True,
            "time_remaining": sec
        }), 429

    # 3. Account block check
    if username and is_username_blocked(username):
        sec = time_remaining(username_blocklist[username])
        print(f"[BotDetector] Blocked account attempt: {username}")
        return jsonify({
            "blocked": True,
            "reason": f"Account locked. Try again in {sec} seconds.",
            "lockout": True,
            "time_remaining": sec
        }), 429

    # 4. Rate limit check
    if is_rate_limited(ip):
        print(f"[BotDetector] Rate limited IP: {ip}")
        return jsonify({
            "blocked": True,
            "reason": "Too many attempts. Please slow down.",
            "rate_limited": True,
            "retry_after": RATE_LIMIT_WINDOW
        }), 429

    # 5. Credential stuffing check
    stuffing_result = check_credential_stuffing(ip, username, password)
    if stuffing_result:
        if stuffing_result.get("blocked"):
            return jsonify(stuffing_result), 403
        else:
            return jsonify(stuffing_result), 200

    # 6. Parse behavior data
    try:
        behavior_data = json.loads(raw_behavior)
    except json.JSONDecodeError:
        behavior_data = {}

    # 7. Spam bot check
    spam_result = check_spam_bot(ip, username, password, email, behavior_data)
    if spam_result:
        if spam_result.get("blocked"):
            return jsonify(spam_result), 403
        else:
            return jsonify(spam_result), 200

    # 8. Record attempt
    record_attempt(ip, username)

    # 9. Score behavior
    result = score_behavior(behavior_data, ip)
    score  = result["score"]
    flags  = result["flags"]

    print(f"[BotDetector] IP: {ip} | User: {username} | Score: {score} | Flags: {flags}")

    if score >= 60:
        record_failed_attempt(ip, username)
        return jsonify({
            "blocked": True,
            "reason": "Suspicious behavior detected",
            "score": score,
            "flags": flags
        }), 403

    elif score >= 35:
        return jsonify({
            "blocked": False,
            "warning": True,
            "message": "Behavior is somewhat suspicious",
            "score": score,
            "flags": flags
        }), 200

    else:
        return jsonify({
            "blocked": False,
            "message": "Behavior looks normal",
            "score": score,
        }), 200


if __name__ == "__main__":
    app.run(debug=True)
