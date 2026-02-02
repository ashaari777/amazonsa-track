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
# import smtplib  <-- Disabled for now to prevent crashes
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
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASS = os.environ.get("EMAIL_PASS")

SUPER_ADMIN_EMAIL = "ashaari777@gmail.com"
NOTIFICATION_EMAIL = "ashaari777in@gmail.com"

CRON_TOKEN = os.environ.get("CRON_TOKEN", "")
PLAYWRIGHT_LOCALE = os.environ.get("PLAYWRIGHT_LOCALE", "en-US")
PLAYWRIGHT_TIMEOUT_MS = int(os.environ.get("PLAYWRIGHT_TIMEOUT_MS", "20000")) 
BLOCK_HEAVY_RESOURCES = os.environ.get("BLOCK_HEAVY_RESOURCES", "1") == "1"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
]

# GLOBAL LOCK to prevent duplicate scrapes
SCRAPE_LOCK = threading.Lock()

# ---------------- DB helpers ----------------

def db_conn():
    if not DATABASE_URL:
        print("CRITICAL ERROR: DATABASE_URL not set.")
        exit(1)
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

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

    cur.execute("""
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    """)

    conn.commit()
    conn.close()

try: init_db()
except: pass

# ---------------- Email Helper (DISABLED FOR FREE TIER) ----------------

def send_alert_email(to_email, asin, item_name, price, is_coupon=False):
    # EMAIL IS DISABLED to prevent crash on Render Free Tier
    print(f"Skipping Email Alert for {to_email} (SMTP blocked on free tier)")
    pass

def send_new_user_alert(new_user_email):
    pass

def get_setting(key, default=None):
    try:
        conn = db_conn(); cur = conn.cursor()
        cur.execute("SELECT value FROM system_settings WHERE key=%s", (key,))
        row = cur.fetchone(); conn.close()
        return row['value'] if row else default
    except: return default

# ---------------- Scraping ----------------

async def pick_first_text_async(page, selectors):
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            txt = await loc.text_content()
            txt = clean(txt)
            if txt: return txt
        except: pass
    return None

async def wait_for_any_title_async(page, timeout_ms=8000):
    selectors = ["#productTitle", "h1 span", "h1", "[data-cy='title-recipe']"]
    for sel in selectors:
        try:
            await page.wait_for_selector(sel, timeout=timeout_ms)
            return
        except: pass
    raise TimeoutError("Title not found")

async def auto_nudge_async(page):
    try:
        await page.evaluate("window.scrollTo(0, 500)")
        await page.wait_for_timeout(200)
    except: pass

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
    page.set_default_timeout(20000)
    
    url = f"https://www.amazon.sa/dp/{asin}"
    data = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "asin": asin, "url": url, "error": None,
        "item_name": None, "price_text": None, "price_value": None,
        "coupon_text": None, "discount_percent": None
    }

    try:
        await page.goto(url, wait_until="domcontentloaded")
        try: 
            await page.wait_for_selector("#productTitle", timeout=10000)
            el = page.locator("#productTitle").first
            data["item_name"] = (await el.text_content()).strip()
        except: pass

        if not data["item_name"]: raise Exception("Blocked/No Title")

        for sel in [".priceToPay .a-offscreen", ".apexPriceToPay .a-offscreen", "#corePrice_feature_div .a-price .a-offscreen", "#corePriceDisplay_desktop_feature_div .a-price .a-offscreen"]:
            try:
                el = page.locator(sel).first
                txt = await el.text_content()
                if txt:
                    data["price_text"] = txt.strip()
                    m = re.search(r"([\d,]+(?:\.\d+)?)", txt)
                    if m: data["price_value"] = float(m.group(1).replace(",", ""))
                    break
            except: pass

        coupons_found = []
        try:
            coupon_els = page.locator("label[id*='coupon']").all_inner_texts()
            for c in await coupon_els:
                m = re.search(r"(\d+%)|(SAR\s?\d+)", c)
                if m: coupons_found.append(m.group(0))
        except: pass
        try:
            promos = page.locator("span:has-text('promo code'), span:has-text('Save %'), span:has-text('Savings')")
            count = await promos.count()
            for i in range(count):
                txt = await promos.nth(i).text_content()
                m = re.search(r"(\d+%)|(SAR\s?\d+)", txt)
                if m: coupons_found.append(m.group(0))
        except: pass
        if coupons_found: data["coupon_text"] = " | ".join(list(set(coupons_found)))

        try:
            disc = page.locator(".savingsPercentage").first
            txt = await disc.text_content()
            if txt:
                m = re.search(r"(\d{1,3})\s*%", txt)
                if m: data["discount_percent"] = int(m.group(1))
        except: pass

    except Exception as e: data["error"] = str(e)
    finally:
        try: await page.close()
        except: pass
        try: await context.close()
        except: pass

    if data["price_value"] and data["price_value"] < 1: data["price_value"] = None
    if data["price_value"] and not data["price_text"]: data["price_text"] = f"SAR {data['price_value']:.2f}"

    return data

async def scrape_many_sequential_with_delays(asins):
    results = {}
    BATCH_SIZE = 4 
    def chunked(l, n):
        for i in range(0, len(l), n): yield l[i:i + n]

    for batch in chunked(asins, BATCH_SIZE):
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True, 
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--disable-extensions", "--disable-setuid-sandbox"]
                )
                for asin in batch:
                    print(f"Scraping {asin}...") 
                    await asyncio.sleep(random.uniform(2.0, 5.0))
                    results[asin] = await scrape_one_with_context(browser, asin)
                await browser.close()
        except Exception as e: print(f"Batch failed: {e}")
            
    return results

def run_async(coro, *args):
    try: asyncio.get_running_loop(); running = True
    except RuntimeError: running = False
    if not running: return asyncio.run(coro(*args))
    def worker(out):
        try: out["result"] = asyncio.run(coro(*args))
        except Exception as e: out["error"] = e
    out = {"result": None, "error": None}
    t = threading.Thread(target=worker, args=(out,), daemon=True)
    t.start(); t.join()
    if out["error"]: raise out["error"]
    return out["result"]

# ---------------- DB Write Logic ----------------

def write_history(item_id, data):
    if not data["price_value"]: return
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM price_history WHERE item_id=%s ORDER BY ts DESC LIMIT 1", (item_id,))
    latest = cur.fetchone()
    
    interval_str = get_setting('update_interval', '14400')
    interval_sec = int(interval_str)

    insert = True
    if latest:
        if latest["price_value"] == data["price_value"]:
            last = datetime.strptime(str(latest["ts"]), "%Y-%m-%d %H:%M:%S")
            if (datetime.utcnow() - last).total_seconds() < interval_sec:
                insert = False
                cur.execute("UPDATE price_history SET ts=%s, coupon_text=%s WHERE id=%s", (data["timestamp"], data["coupon_text"], latest["id"]))
                conn.commit()

    if insert:
        cur.execute("""
            INSERT INTO price_history(item_id, ts, item_name, price_text, price_value, coupon_text, discount_percent, error) 
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s)
        """, (item_id, data["timestamp"], data["item_name"], data["price_text"], data["price_value"], data["coupon_text"], data["discount_percent"], data["error"]))
        conn.commit()
    conn.close()

# ---------------- Auth Wrapper ----------------

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"): return redirect(url_for("login"))
        conn = db_conn(); cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id=%s", (session.get("user_id"),))
        user = cur.fetchone(); conn.close()
        if not user: session.clear(); return redirect(url_for("login"))
        if user["email"] == SUPER_ADMIN_EMAIL.lower(): return fn(*args, **kwargs)
        if user["is_paused"]: session.clear(); flash("Suspended", "error"); return redirect(url_for("login"))
        if not user["is_approved"] and request.endpoint != 'waitlist_page': return redirect(url_for("waitlist_page"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin": abort(403)
        return fn(*args, **kwargs)
    return wrapper

# ---------------- Utility ----------------
def clean(t): return re.sub(r"\s+", " ", t).strip() if t else None
def extract_asin(text):
    text = text.strip()
    if re.fullmatch(r"[A-Z0-9]{10}", text): return text
    m = re.search(r"/dp/([A-Z0-9]{10})", text)
    return m.group(1) if m else None
def canonical_url(asin): return f"https://www.amazon.sa/dp/{asin}"
def get_location_from_ip(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3); data = r.json()
        if data['status'] == 'success': return f"{data.get('city')}, {data.get('country')}"
    except: pass
    return "Unknown"

# ---------------- Routes ----------------

@app.route("/")
@login_required
def index():
    conn = db_conn(); cur = conn.cursor()
    uid = session.get("user_id")
    
    cur.execute("SELECT is_approved FROM users WHERE id=%s", (uid,))
    if not cur.fetchone()['is_approved']: return redirect(url_for("waitlist_page"))

    cur.execute("SELECT * FROM items WHERE user_id=%s ORDER BY created_at DESC", (uid,))
    items = cur.fetchall()
    
    announcement = get_setting('announcement')
    
    cur.execute("SELECT MAX(ts) as last_run FROM price_history")
    lr = cur.fetchone(); last_update = lr['last_run'] if lr and lr['last_run'] else "Pending..."

    enriched = []
    for it in items:
        cur.execute("""
            SELECT ph.* FROM price_history ph JOIN items i ON ph.item_id = i.id 
            WHERE i.asin = %s ORDER BY ph.ts DESC LIMIT 1
        """, (it["asin"],))
        latest = cur.fetchone()
        
        is_lowest = False
        if latest and latest['price_value']:
            cur.execute("""
                SELECT MIN(ph.price_value) as min_p 
                FROM price_history ph JOIN items i ON ph.item_id = i.id 
                WHERE i.asin = %s AND ph.price_value > 0
            """, (it["asin"],))
            min_row = cur.fetchone()
            if min_row and min_row['min_p'] and latest['price_value'] <= min_row['min_p']:
                is_lowest = True

        enriched.append({
            "id": it["id"], "asin": it["asin"], "url": it["url"], "target_price": it["target_price"],
            "latest_name": latest["item_name"] if latest else None,
            "latest_price_text": latest["price_text"] if latest else None,
            "latest_price_value": latest["price_value"] if latest else None,
            "latest_discount": latest["discount_percent"] if latest else None,
            "coupon_text": latest["coupon_text"] if latest else None,
            "latest_ts": latest["ts"] if latest else None,
            "is_lowest": is_lowest
        })
    conn.close()
    return render_template("index.html", user={"email": "User"}, items=enriched, 
                           announcement=announcement, is_admin=(session.get("role")=="admin"), last_global_update=last_update)

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM users"); total_users = cur.fetchone()['c']
    cur.execute("SELECT COUNT(*) as c FROM items"); total_items = cur.fetchone()['c']
    cur.execute("SELECT asin, COUNT(*) as c FROM items GROUP BY asin ORDER BY c DESC LIMIT 5")
    trending = cur.fetchall()
    announcement = get_setting('announcement')
    interval = get_setting('update_interval', '14400')
    conn.close()
    return render_template("admin_dashboard.html", total_users=total_users, total_items=total_items, trending=trending, announcement=announcement, interval=interval)

@app.route("/admin/set-announcement", methods=["POST"])
@admin_required
def set_announcement():
    txt = request.form.get("text")
    conn = db_conn(); cur = conn.cursor()
    cur.execute("INSERT INTO system_settings (key, value) VALUES ('announcement', %s) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", (txt,))
    conn.commit(); conn.close()
    flash("Announcement updated", "ok")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/settings/interval", methods=["POST"])
@admin_required
def set_update_interval():
    val = request.form.get("interval") 
    conn = db_conn(); cur = conn.cursor()
    cur.execute("INSERT INTO system_settings (key, value) VALUES ('update_interval', %s) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", (val,))
    conn.commit(); conn.close()
    flash(f"Update interval set to {int(val)//60} minutes.", "ok")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/force-update", methods=["POST"])
@admin_required
def force_update():
    # Only start if not already running
    if not SCRAPE_LOCK.locked():
        threading.Thread(target=run_global_scrape).start()
        flash("Forced Global Update Started...", "ok")
    else:
        flash("Update already running!", "error")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/cleanup-ghosts", methods=["POST"])
@admin_required
def cleanup_ghosts():
    conn = db_conn(); cur = conn.cursor()
    cutoff = (datetime.utcnow() - timedelta(days=90)).strftime("%Y-%m-%d")
    cur.execute("DELETE FROM items WHERE user_id IN (SELECT id FROM users WHERE last_login_at < %s)", (cutoff,))
    deleted = cur.rowcount
    conn.commit(); conn.close()
    flash(f"Cleaned {deleted} ghost items.", "ok")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/items", methods=["GET"])
@admin_required
def admin_items():
    conn = db_conn(); cur = conn.cursor()
    sort_by = request.args.get('sort', 'latest')
    user_filter = request.args.get('user_filter')
    base_query = """
        SELECT i.*, u.email AS user_email,
               (SELECT ph.item_name FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_name,
               (SELECT ph.price_text FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_price_text,
               (SELECT ph.ts FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_ts
        FROM items i JOIN users u ON u.id=i.user_id 
    """
    params = []
    if user_filter:
        base_query += " WHERE u.id = %s "
        params.append(user_filter)
    if sort_by == 'az_title': base_query += " ORDER BY latest_name ASC"
    elif sort_by == 'az_user': base_query += " ORDER BY u.email ASC"
    else: base_query += " ORDER BY i.created_at DESC"
    cur.execute(base_query, tuple(params))
    items = cur.fetchall()
    cur.execute("SELECT id, email FROM users ORDER BY email")
    users = cur.fetchall()
    conn.close()
    return render_template("admin_items.html", items=items, users=users, current_filter=user_filter)

@app.route("/add", methods=["POST"])
@login_required
def add():
    u_id = session.get("user_id")
    raw = request.form.get("item", "").strip()
    asin = extract_asin(raw)
    if not asin: flash("Invalid Link", "error"); return redirect(url_for("index"))
    conn = db_conn(); cur = conn.cursor()
    cur.execute("INSERT INTO items(user_id, asin, url, created_at) VALUES(%s, %s, %s, %s) ON CONFLICT DO NOTHING", 
               (u_id, asin, f"https://www.amazon.sa/dp/{asin}", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit(); conn.close()
    flash("Item Added", "ok"); return redirect(url_for("index"))

@app.route("/delete/<asin>", methods=["POST"])
@login_required
def delete(asin):
    u = session.get("user_id")
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM items WHERE user_id=%s AND asin=%s", (u, asin))
    item = cur.fetchone()
    if item:
        cur.execute("DELETE FROM price_history WHERE item_id=%s", (item["id"],))
        cur.execute("DELETE FROM items WHERE id=%s", (item["id"],))
    conn.commit(); conn.close()
    flash("Deleted.", "ok"); return redirect(url_for("index"))

@app.route("/set-target/<int:item_id>", methods=["POST"])
@login_required
def set_target_price(item_id):
    u = session.get("user_id")
    target_val = request.form.get("target_price")
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM items WHERE id=%s AND user_id=%s", (item_id, u))
    if cur.fetchone():
        try:
            new_target = float(target_val) if target_val else None
            cur.execute("UPDATE items SET target_price=%s WHERE id=%s", (new_target, item_id))
            conn.commit()
        except: pass
    conn.close()
    return redirect(url_for("index"))

@app.route("/update/<asin>", methods=["POST"])
@login_required
def update_one(asin):
    u = session.get("user_id")
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM items WHERE user_id=%s AND asin=%s", (u, asin))
    row = cur.fetchone(); conn.close()
    if row:
        results = run_async(scrape_many_sequential_with_delays, [asin])
        if results.get(asin): write_history(row["id"], results[asin])
        flash("Updated.", "ok")
    return redirect(url_for("index"))

@app.route("/history/<asin>.json", methods=["GET"])
@login_required
def history_json(asin):
    conn = db_conn(); cur = conn.cursor()
    cur.execute("""
        SELECT ph.ts, ph.item_name, ph.price_value, ph.price_text, ph.discount_percent
        FROM price_history ph JOIN items i ON ph.item_id = i.id
        WHERE i.asin = %s AND ph.price_value IS NOT NULL AND ph.price_value > 0
        ORDER BY ph.ts ASC LIMIT 200
    """, (asin,))
    rows = cur.fetchall(); conn.close()
    out = []
    for r in rows: out.append({"ts": r["ts"], "price_value": r["price_value"]})
    return jsonify(out)

# ... (Auth Routes) ...
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET": return render_template("register.html")
    email = request.form.get("email").strip().lower()
    password = request.form.get("password")
    role = "admin" if (email == SUPER_ADMIN_EMAIL.lower()) else "user"
    is_approved = True if role == "admin" else False
    conn = db_conn(); cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users(email, password_hash, role, created_at, is_approved) VALUES(%s, %s, %s, %s, %s)", 
                   (email, generate_password_hash(password), role, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), is_approved))
        conn.commit()
    except: flash("Email registered.", "error"); return redirect(url_for("login"))
    finally: conn.close()
    if not is_approved:
        send_new_user_alert(email)
        flash("Account created! You are on the waitlist.", "ok")
    else: flash("Account created.", "ok")
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET": return render_template("login.html")
    email = request.form.get("email").strip().lower()
    password = request.form.get("password")
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        conn.close(); flash("Invalid credentials.", "error"); return redirect(url_for("login"))
    if email == SUPER_ADMIN_EMAIL.lower():
        cur.execute("UPDATE users SET role='admin', is_approved=TRUE WHERE id=%s", (user["id"],))
        conn.commit()
        user = dict(user); user["role"]="admin"; user["is_approved"]=True
    session["user_id"] = user["id"]; session["role"] = user["role"]
    if not user.get("is_approved"): conn.close(); return redirect(url_for("waitlist_page"))
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    loc = get_location_from_ip(ip)
    cur.execute("UPDATE users SET last_login_at=%s, ip_address=%s, device_name=%s, location=%s WHERE id=%s", 
                (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), ip, request.user_agent.string, loc, user["id"]))
    conn.commit(); conn.close()
    if user["role"] == "admin": return redirect(url_for("admin_dashboard"))
    else: return redirect(url_for("index"))

@app.route("/logout", methods=["POST"])
def logout(): session.clear(); return redirect("/")
@app.route("/waitlist")
def waitlist_page(): return render_template("waitlist.html")
@app.route("/forgot", methods=["GET", "POST"])
def forgot(): return render_template("forgot.html")
@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token): return redirect(url_for("login"))

# ... (Admin Routes) ...
@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_users():
    conn = db_conn(); cur = conn.cursor()
    status = request.args.get('status', 'all')
    if status == 'pending': cur.execute("SELECT * FROM users WHERE is_approved = FALSE ORDER BY created_at DESC")
    else: cur.execute("SELECT * FROM users WHERE is_approved = TRUE ORDER BY created_at DESC")
    users = cur.fetchall()
    cur.execute("SELECT i.user_id, i.asin, (SELECT ph.item_name FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) as title FROM items i")
    all_items = cur.fetchall()
    user_items_map = {}
    for item in all_items:
        uid = item['user_id']
        if uid not in user_items_map: user_items_map[uid] = []
        user_items_map[uid].append(item)
    conn.close()
    return render_template("admin_users.html", users=users, user_items_map=user_items_map, current_status=status)

@app.route("/admin/user/<int:user_id>/approve", methods=["POST"])
@admin_required
def admin_user_approve(user_id):
    conn = db_conn(); cur = conn.cursor(); cur.execute("UPDATE users SET is_approved = TRUE WHERE id=%s", (user_id,)); conn.commit(); conn.close(); return redirect(url_for("admin_users", status="pending"))
@app.route("/admin/user/<int:user_id>/pause", methods=["POST"])
@admin_required
def admin_user_pause(user_id):
    conn = db_conn(); cur = conn.cursor(); cur.execute("UPDATE users SET is_paused = NOT is_paused WHERE id=%s", (user_id,)); conn.commit(); conn.close(); return redirect(url_for("admin_users"))
@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_user_delete(user_id):
    conn = db_conn(); cur = conn.cursor(); cur.execute("DELETE FROM users WHERE id=%s", (user_id,)); conn.commit(); conn.close(); return redirect(request.referrer)
@app.route("/admin/item/<int:item_id>/delete", methods=["POST"])
@admin_required
def admin_delete_item_by_id(item_id):
    conn = db_conn(); cur = conn.cursor(); cur.execute("DELETE FROM price_history WHERE item_id=%s", (item_id,)); cur.execute("DELETE FROM items WHERE id=%s", (item_id,)); conn.commit(); conn.close(); return redirect(url_for("admin_items"))

# --- CRON (With Lock & No Email) ---
def run_global_scrape():
    # Attempt to acquire lock. If locked, skip.
    if not SCRAPE_LOCK.acquire(blocking=False):
        print("Scrape already running. Skipping.")
        return

    try:
        conn = db_conn(); cur = conn.cursor()
        cur.execute("SELECT DISTINCT asin FROM items")
        rows = cur.fetchall()
        asins = [r['asin'] for r in rows]
        conn.close()

        if not asins: return

        results = run_async(scrape_many_sequential_with_delays, asins)

        conn = db_conn(); cur = conn.cursor()
        for asin, data in results.items():
            cur.execute("SELECT i.id, i.target_price, u.email FROM items i JOIN users u ON i.user_id=u.id WHERE i.asin=%s", (asin,))
            for item in cur.fetchall():
                write_history(item['id'], data)
                # EMAIL LOGIC DISABLED HERE
        conn.close()
        print(f"Scrape Finished: {len(asins)} items.")
    finally:
        SCRAPE_LOCK.release() # ALWAYS release lock

@app.route("/cron/update-all", methods=["GET", "POST", "HEAD"])
def cron():
    token = request.args.get("token")
    if token != CRON_TOKEN: return "401", 401
    
    # Start thread
    threading.Thread(target=run_global_scrape).start()
    return "OK", 200

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)