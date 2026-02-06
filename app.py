import os
import re
import json
import time
import hmac
import base64
import hashlib
import secrets
import asyncio
import threading
import random
import requests

from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, flash, abort, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from playwright.async_api import async_playwright

import psycopg2
from psycopg2.extras import RealDictCursor

# ---------------- App config ----------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

DATABASE_URL = os.environ.get("DATABASE_URL")

SUPER_ADMIN_EMAIL = "ashaari777@gmail.com"
NOTIFICATION_EMAIL = "ashaari777in@gmail.com" 

CRON_TOKEN = os.environ.get("CRON_TOKEN", "")
PLAYWRIGHT_LOCALE = os.environ.get("PLAYWRIGHT_LOCALE", "en-US")
PLAYWRIGHT_TIMEOUT_MS = int(os.environ.get("PLAYWRIGHT_TIMEOUT_MS", "30000"))
BLOCK_HEAVY_RESOURCES = os.environ.get("BLOCK_HEAVY_RESOURCES", "1") == "1"

SCRAPE_LOCK = threading.Lock()

# Email disabled by request (no helper functions included)
ENABLE_EMAIL = False

USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1"
]

SCRAPE_LOCK = threading.Lock()

# ---------------- DB helpers ----------------


def db_conn():
    if not DATABASE_URL:
        print("CRITICAL ERROR: DATABASE_URL not set.")
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

def init_db():
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL,
            last_login_at TEXT,
            ip_address TEXT,
            device_name TEXT,
            location TEXT,
            is_paused BOOLEAN DEFAULT FALSE,
            is_approved BOOLEAN DEFAULT FALSE,
            item_limit INTEGER DEFAULT 20
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            asin TEXT NOT NULL,
            url TEXT NOT NULL,
            target_price REAL,
            last_alert_sent TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, asin),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS price_history (
            id SERIAL PRIMARY KEY,
            item_id INTEGER NOT NULL,
            ts TEXT NOT NULL,
            item_name TEXT,
            price_text TEXT,
            price_value REAL,
            coupon_text TEXT,
            rating REAL,
            reviews_count INTEGER,
            discount_percent INTEGER,
            error TEXT,
            FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE CASCADE
        );
    """)
    cur.execute("CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT);")
    conn.commit()
    conn.close()

try:
    init_db()
except Exception as e:
    print("DB init warning:", e)


# ---------------- Helpers ----------------


    def clean(t):
    return re.sub(r"\s+", " ", t).strip() if t else None

def extract_asin(text):
    text = (text or "").strip()
    if re.fullmatch(r"[A-Z0-9]{10}", text): return text
    m = re.search(r"/dp/([A-Z0-9]{10})", text)
    return m.group(1) if m else None

def canonical_url(asin):
    return f"https://www.amazon.sa/dp/{asin}"

def parse_money_value(t):
    if not t: return None
    m = re.search(r"([\d,]+(?:\.\d+)?)", t)
    return float(m.group(1).replace(",", "")) if m else None

def get_location_from_ip(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = r.json()
        if data.get("status") == "success":
            return f"{data.get('city')}, {data.get('country')}"
    except Exception: pass
    return "Unknown"

def get_setting(key, default=None):
    try:
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT value FROM system_settings WHERE key=%s", (key,))
        row = cur.fetchone()
        conn.close()
        return row["value"] if row else default
    except Exception: return default

def get_system_announcement():
    return get_setting("announcement", None)

# ---------------- Scraping ----------------

async def scrape_one_with_context(browser, asin):
    ua = random.choice(USER_AGENTS)
    context = await browser.new_context(locale=PLAYWRIGHT_LOCALE, user_agent=ua)
    if BLOCK_HEAVY_RESOURCES:
        async def route_handler(route):
            if route.request.resource_type in ("image", "media", "font"): await route.abort()
            else: await route.continue_()
        await context.route("**/*", route_handler)
    page = await context.new_page()
    await page.set_extra_http_headers({"Accept-Language": "en-US,en;q=0.9,ar;q=0.8"})
    page.set_default_timeout(PLAYWRIGHT_TIMEOUT_MS)
    data = {"timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "asin": asin, "url": canonical_url(asin), "error": None, "item_name": None, "price_text": None, "price_value": None, "coupon_text": None, "discount_percent": None}
    try:
        await page.goto(canonical_url(asin), wait_until="domcontentloaded")
        try:
            await page.wait_for_selector("#productTitle", timeout=6000)
            data["item_name"] = (await page.locator("#productTitle").first.text_content()).strip()
        except Exception:
            try: data["item_name"] = (await page.locator("h1").first.text_content()).strip()
            except: pass
        if not data["item_name"]: raise Exception("Blocked/No Title")
        for sel in ["#corePrice_feature_div .a-price .a-offscreen", "#corePriceDisplay_desktop_feature_div .a-price .a-offscreen", "#newBuyBoxPrice .a-offscreen", ".priceToPay .a-offscreen", ".a-price .a-offscreen"]:
            try:
                txt = clean(await page.locator(sel).first.text_content())
                if txt:
                    data["price_text"] = txt
                    val = parse_money_value(txt)
                    if val is not None:
                        data["price_value"] = val
                        break
            except: pass
        percents = []
        try:
            promo_texts = await page.locator("#promoPriceBlockMessage_feature_div, .promoPriceBlockMessage, .a-section.a-spacing-small span").all_inner_texts()
            for t in promo_texts:
                for m in re.findall(r"(\d{1,3})\s*%", clean(t)):
                    if 1 <= int(m) <= 95: percents.append(int(m))
        except: pass
        if percents: data["coupon_text"] = " | ".join([f"%{p}" for p in sorted(set(percents))])
    except Exception as e: data["error"] = str(e)
    finally:
        await page.close()
        await context.close()
    return data

async def scrape_many_sequential_with_delays(asins):
    results = {}
    for batch in [asins[i:i + 4] for i in range(0, len(asins), 4)]:
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
                for asin in batch:
                    await asyncio.sleep(random.uniform(3.0, 6.0))
                    results[asin] = await scrape_one_with_context(browser, asin)
                await browser.close()
        except: pass
    return results

def run_async(coro, *args):
    try: asyncio.get_running_loop(); running = True
    except RuntimeError: running = False
    if not running: return asyncio.run(coro(*args))
    out = {"result": None, "error": None}
    def worker():
        try: out["result"] = asyncio.run(coro(*args))
        except Exception as e: out["error"] = e
    t = threading.Thread(target=worker, daemon=True)
    t.start(); t.join()
    if out["error"]: raise out["error"]
    return out["result"]


# ---------------- DB Write Logic ----------------


def write_history(item_id, data):
    if not data.get("price_value"):
        if data.get("coupon_text"):
            conn = db_conn(); cur = conn.cursor()
            cur.execute("SELECT id FROM price_history WHERE item_id=%s ORDER BY ts DESC LIMIT 1", (item_id,))
            latest_row = cur.fetchone()
            if latest_row: cur.execute("UPDATE price_history SET coupon_text=%s WHERE id=%s", (data["coupon_text"], latest_row["id"]))
            conn.commit(); conn.close()
        return
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM price_history WHERE item_id=%s ORDER BY ts DESC LIMIT 1", (item_id,))
    latest = cur.fetchone()
    interval_sec = int(get_setting("update_interval", "3600"))
    insert = True
    if latest and latest.get("price_value") == data.get("price_value"):
        try:
            diff = (datetime.utcnow() - datetime.strptime(str(latest["ts"]), "%Y-%m-%d %H:%M:%S")).total_seconds()
            if diff < interval_sec:
                insert = False
                cur.execute("UPDATE price_history SET ts=%s, coupon_text=%s WHERE id=%s", (data["timestamp"], data.get("coupon_text"), latest["id"]))
                conn.commit()
        except: insert = True
    if insert:
        cur.execute("INSERT INTO price_history(item_id, ts, item_name, price_text, price_value, coupon_text, error) VALUES(%s, %s, %s, %s, %s, %s, %s)", (item_id, data.get("timestamp"), data.get("item_name"), data.get("price_text"), data.get("price_value"), data.get("coupon_text"), data.get("error")))
        conn.commit()
    conn.close()

# ---------------- Auth Wrappers ----------------

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"): return redirect(url_for("login"))
        conn = db_conn(); cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id=%s", (session.get("user_id"),))
        user = cur.fetchone(); conn.close()
        if not user: session.clear(); return redirect(url_for("login"))
        if (user.get("email") or "").lower() == SUPER_ADMIN_EMAIL.lower(): return fn(*args, **kwargs)
        if user.get("is_paused"): session.clear(); flash("Suspended", "error"); return redirect(url_for("login"))
        if not user.get("is_approved") and request.endpoint != "waitlist_page": return redirect(url_for("waitlist_page"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id") or session.get("role") != "admin": abort(403)
        return fn(*args, **kwargs)
    return wrapper

# ---------------- Routes ----------------

@app.route("/")
@login_required
def index():
    conn = db_conn(); cur = conn.cursor(); uid = session.get("user_id")
    cur.execute("SELECT is_approved FROM users WHERE id=%s", (uid,))
    row = cur.fetchone()
    if not row or not row.get("is_approved"): conn.close(); return redirect(url_for("waitlist_page"))
    cur.execute("SELECT * FROM items WHERE user_id=%s ORDER BY created_at DESC", (uid,))
    items = cur.fetchall()
    cur.execute("SELECT MAX(ts) as last_run FROM price_history")
    lr = cur.fetchone()
    last_update = lr["last_run"] if lr and lr.get("last_run") else "Pending..."
    enriched = []
    for it in items:
        cur.execute("SELECT * FROM price_history WHERE item_id = %s ORDER BY ts DESC LIMIT 1", (it["id"],))
        latest = cur.fetchone() or {}
        cur.execute("SELECT MIN(price_value) as min_p FROM price_history WHERE item_id=%s AND price_value > 0", (it["id"],))
        min_row = cur.fetchone()
        is_lowest = bool(latest.get("price_value") and min_row and min_row.get("min_p") and latest["price_value"] <= min_row["min_p"])
        enriched.append({"id": it["id"], "asin": it["asin"], "url": it["url"], "target_price": it.get("target_price"), "latest_name": latest.get("item_name"), "latest_price_text": latest.get("price_text"), "latest_price_value": latest.get("price_value"), "coupon_text": latest.get("coupon_text"), "latest_ts": latest.get("ts"), "is_lowest": is_lowest})
    conn.close()
    return render_template("index.html", items=enriched, announcement=get_system_announcement(), is_admin=(session.get("role") == "admin"), last_global_update=last_update)

@app.route("/add", methods=["POST"])
@login_required
def add():
    asin = extract_asin(request.form.get("item", ""))
    if not asin: flash("Invalid Link", "error"); return redirect(url_for("index"))
    conn = db_conn(); cur = conn.cursor()
    cur.execute("INSERT INTO items(user_id, asin, url, created_at) VALUES(%s, %s, %s, %s) ON CONFLICT DO NOTHING", (session.get("user_id"), asin, canonical_url(asin), datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit(); conn.close()
    flash("Item Added", "ok"); return redirect(url_for("index"))

@app.route("/delete/<asin>", methods=["POST"])
@login_required
def delete(asin):
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM items WHERE user_id=%s AND asin=%s", (session.get("user_id"), asin))
    item = cur.fetchone()
    if item:
        cur.execute("DELETE FROM price_history WHERE item_id=%s", (item["id"],))
        cur.execute("DELETE FROM items WHERE id=%s", (item["id"],))
    conn.commit(); conn.close()
    return redirect(url_for("index"))

@app.route("/history/<asin>.json")
@login_required
def history_json(asin):
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT ph.ts, ph.price_value FROM price_history ph JOIN items i ON ph.item_id = i.id WHERE i.asin = %s AND ph.price_value > 0 ORDER BY ph.ts ASC LIMIT 200", (asin,))
    rows = cur.fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/set-target/<int:item_id>", methods=["POST"])
@login_required
def set_target_price(item_id):
    target = request.form.get("target_price")
    conn = db_conn(); cur = conn.cursor()
    cur.execute("UPDATE items SET target_price=%s WHERE id=%s AND user_id=%s", (float(target) if target else None, item_id, session.get("user_id")))
    conn.commit(); conn.close()
    return redirect(url_for("index"))

# ---------------- Admin routes ----------------
@app.route("/admin")
@admin_required
def admin_portal():
    tab = request.args.get("tab", "dashboard")
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM users WHERE is_approved = FALSE")
    pending_count = cur.fetchone()["c"]
    data = {}
    if tab == "dashboard":
        cur.execute("SELECT COUNT(*) as c FROM users"); data["total_users"] = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM items"); data["total_items"] = cur.fetchone()["c"]
        cur.execute("SELECT asin, COUNT(*) as c FROM items GROUP BY asin ORDER BY c DESC LIMIT 5"); data["trending"] = cur.fetchall()
        cur.execute("SELECT MAX(ts) as last_run FROM price_history"); lr = cur.fetchone()
        data["last_run"] = lr["last_run"] if lr else "Never"
        data["announcement"] = get_system_announcement()
    elif tab == "active_users":
        cur.execute("SELECT * FROM users WHERE is_approved = TRUE ORDER BY created_at DESC"); data["users"] = cur.fetchall()
    elif tab == "pending_users":
        cur.execute("SELECT * FROM users WHERE is_approved = FALSE ORDER BY created_at DESC"); data["users"] = cur.fetchall()
    elif tab == "items":
        f = request.args.get("user_filter")
        q = "SELECT i.*, u.email AS user_email, (SELECT ph.item_name FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_name, (SELECT ph.price_text FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_price_text FROM items i JOIN users u ON u.id=i.user_id"
        if f: cur.execute(q + " WHERE u.id=%s ORDER BY i.created_at DESC", (f,))
        else: cur.execute(q + " ORDER BY i.created_at DESC")
        data["items"] = cur.fetchall()
        cur.execute("SELECT id, email FROM users ORDER BY email"); data["all_users"] = cur.fetchall()
        data["current_filter"] = f
    conn.close()
    return render_template("admin.html", tab=tab, data=data, pending_count=pending_count)

# ---------------- Admin Action Redirects ----------------

@app.route("/admin/set-announcement", methods=["POST"])
@admin_required
def set_announcement():
    conn = db_conn(); cur = conn.cursor()
    cur.execute("INSERT INTO system_settings (key, value) VALUES ('announcement', %s) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value", (request.form.get("text", ""),))
    conn.commit(); conn.close()
    flash("Updated", "ok")
    return redirect(url_for("admin_portal", tab="dashboard"))

@app.route("/admin/force-update", methods=["POST"])
@admin_required
def force_update():
    threading.Thread(target=run_global_scrape, daemon=True).start()
    flash("Update Started", "ok")
    return redirect(url_for("admin_portal", tab="dashboard"))

@app.route("/admin/cleanup-ghosts", methods=["POST"])
@admin_required
def cleanup_ghosts():
    conn = db_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM items WHERE user_id IN (SELECT id FROM users WHERE last_login_at < %s)", ((datetime.utcnow() - timedelta(days=90)).strftime("%Y-%m-%d"),))
    conn.commit(); conn.close()
    return redirect(url_for("admin_portal", tab="dashboard"))

@app.route("/admin/user/<int:user_id>/approve", methods=["POST"])
@admin_required
def admin_user_approve(user_id):
    conn = db_conn(); cur = conn.cursor()
    cur.execute("UPDATE users SET is_approved = TRUE WHERE id=%s", (user_id,))
    conn.commit(); conn.close()
    return redirect(url_for("admin_portal", tab="pending_users"))

@app.route("/admin/user/<int:user_id>/pause", methods=["POST"])
@admin_required
def admin_user_pause(user_id):
    conn = db_conn(); cur = conn.cursor()
    cur.execute("UPDATE users SET is_paused = NOT is_paused WHERE id=%s", (user_id,))
    conn.commit(); conn.close()
    return redirect(url_for("admin_portal", tab="active_users"))

@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_user_delete(user_id):
    conn = db_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=%s", (user_id,)); conn.commit(); conn.close()
    return redirect(url_for("admin_portal", tab="active_users"))

@app.route("/admin/item/<int:item_id>/delete", methods=["POST"])
@admin_required
def admin_delete_item_by_id(item_id):
    conn = db_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM price_history WHERE item_id=%s", (item_id,))
    cur.execute("DELETE FROM items WHERE id=%s", (item_id,))
    conn.commit(); conn.close()
    return redirect(url_for("admin_portal", tab="items"))

# ---------------- Auth routes ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET": return render_template("register.html")
    email = (request.form.get("email") or "").strip().lower()
    pw = request.form.get("password")
    if not email or not pw: flash("Missing fields", "error"); return redirect(url_for("register"))
    conn = db_conn(); cur = conn.cursor()
    role = "admin" if email == SUPER_ADMIN_EMAIL.lower() else "user"
    approved = (role == "admin")
    try:
        cur.execute("INSERT INTO users(email, password_hash, role, created_at, is_approved) VALUES(%s, %s, %s, %s, %s)", (email, generate_password_hash(pw), role, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), approved))
        conn.commit()
    except: flash("Email exists", "error"); return redirect(url_for("login"))
    finally: conn.close()
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET": return render_template("login.html")
    email = (request.form.get("email") or "").strip().lower()
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    if not user or not check_password_hash(user["password_hash"], request.form.get("password")):
        conn.close(); flash("Invalid", "error"); return redirect(url_for("login"))
    
    if email == SUPER_ADMIN_EMAIL.lower():
        cur.execute("UPDATE users SET role='admin', is_approved=TRUE WHERE id=%s", (user["id"],))
        conn.commit(); user["role"] = "admin"; user["is_approved"] = True

    session["user_id"] = user["id"]; session["role"] = user["role"]
    if not user["is_approved"]: conn.close(); return redirect(url_for("waitlist_page"))
    
    ip = (request.headers.get("X-Forwarded-For", request.remote_addr) or "").split(",")[0].strip()
    cur.execute("UPDATE users SET last_login_at=%s, ip_address=%s, device_name=%s, location=%s WHERE id=%s", (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), ip, request.user_agent.string, get_location_from_ip(ip), user["id"]))
    conn.commit(); conn.close()
    
    return redirect(url_for("admin_portal") if user["role"] == "admin" else url_for("index"))

@app.route("/logout", methods=["POST"])
def logout():
    session.clear(); return redirect("/")

@app.route("/waitlist")
def waitlist_page(): return render_template("waitlist.html")

@app.route("/forgot")
def forgot(): return render_template("forgot.html")


# ---------------- Cron / Global scrape ----------------

def run_global_scrape():
    if not SCRAPE_LOCK.acquire(blocking=False): return
    try:
        conn = db_conn(); cur = conn.cursor()
        cur.execute("SELECT MAX(ts) as last_run FROM price_history")
        row = cur.fetchone()
        int_sec = int(get_setting("update_interval", "3600"))
        if row and row["last_run"]:
            if (datetime.utcnow() - datetime.strptime(str(row["last_run"]), "%Y-%m-%d %H:%M:%S")).total_seconds() < int_sec:
                conn.close(); return
        cur.execute("SELECT DISTINCT asin FROM items")
        asins = [r["asin"] for r in cur.fetchall()]; conn.close()
        if not asins: return
        results = run_async(scrape_many_sequential_with_delays, asins)
        conn = db_conn(); cur = conn.cursor()
        for asin, data in results.items():
            cur.execute("SELECT id FROM items WHERE asin=%s", (asin,))
            for it in cur.fetchall(): write_history(it["id"], data)
        conn.close()
    finally: SCRAPE_LOCK.release()

@app.route("/cron/update-all")
def cron():
    if request.args.get("token") != CRON_TOKEN: return "401", 401
    threading.Thread(target=run_global_scrape, daemon=True).start()
    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

# ---------------- Main ----------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
