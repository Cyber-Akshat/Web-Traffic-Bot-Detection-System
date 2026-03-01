# app.py
from flask import Flask, request, jsonify, render_template, session
import json
import math
import statistics
import secrets
import time
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

# Configuration
RATE_LIMIT_WINDOW  = 60   # seconds
RATE_LIMIT_MAX     = 5    # max attempts per window
LOCKOUT_THRESHOLD  = 10   # max attempts before block
BLOCK_DURATION     = 300  # seconds (5 min)

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


# ─── Scoring Engine ───────────────────────────────────────────────────────────

def score_behavior(data: dict) -> dict:
    score = 0
    flags = []

    mouse_moves     = data.get("mouseMoves", [])
    key_intervals   = data.get("keyIntervals", [])
    click_positions = data.get("clickPositions", [])
    focus_time      = data.get("formFocusTime")
    submit_time     = data.get("formSubmitTime")

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
        if time_on_form < 2000:      # Less than 2 seconds
            score += 25
            flags.append("instant_submission")
        elif time_on_form > 300000:  # More than 5 minutes
            score += 10
            flags.append("very_slow_submission")
    else:
        score += 15
        flags.append("missing_timing_data")

    # 4. Click behavior checks
    if len(click_positions) == 0:
        score += 10
        flags.append("no_clicks_recorded")

    return {"score": min(score, 100), "flags": flags}


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


@app.route("/login", methods=["POST"])
def login():
    ip       = request.remote_addr
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    raw_behavior = request.form.get("behavior_data", "{}")

    # 1. IP block check
    if is_ip_blocked(ip):
        sec = time_remaining(ip_blocklist[ip])
        print(f"[BotDetector] Blocked IP attempt: {ip}")
        return jsonify({
            "blocked": True,
            "reason": f"IP blocked due to suspicious activity. Try again in {sec} seconds.",
            "lockout": True,
            "time_remaining": sec
        }), 429

    # 2. Account block check
    if username and is_username_blocked(username):
        sec = time_remaining(username_blocklist[username])
        print(f"[BotDetector] Blocked account attempt: {username}")
        return jsonify({
            "blocked": True,
            "reason": f"Account locked due to suspicious activity. Try again in {sec} seconds.",
            "lockout": True,
            "time_remaining": sec
        }), 429

    # 3. Rate limit check
    if is_rate_limited(ip):
        print(f"[BotDetector] Rate limited IP: {ip}")
        return jsonify({
            "blocked": True,
            "reason": "Too many attempts. Please slow down.",
            "rate_limited": True,
            "retry_after": RATE_LIMIT_WINDOW
        }), 429

    # 4. Record attempt
    record_attempt(ip, username)

    # 5. Parse behavior data
    try:
        behavior_data = json.loads(raw_behavior)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid behavior data format", "blocked": True}), 400

    # 6. Score behavior
    result = score_behavior(behavior_data)
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
