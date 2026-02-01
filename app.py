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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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

# DATABASE
DATABASE_URL = os.environ.get("DATABASE_URL")

# EMAIL CONFIG (Add these to Render Environment)
EMAIL_USER = os.environ.get("EMAIL_USER") # Your Gmail address
EMAIL_PASS = os.environ.get("EMAIL_PASS") # Your Gmail App Password

# SETTINGS
SUPER_ADMIN_EMAIL = "ashaari777@gmail.com"
ADMIN_EMAIL = (os.environ.get("ADMIN_EMAIL") or "").strip().lower()
RESET_MODE = os.environ.get("RESET_MODE", "manual").strip().lower()
CRON_TOKEN = os.environ.get("CRON_TOKEN", "")
PLAYWRIGHT_LOCALE = os.environ.get("PLAYWRIGHT_LOCALE", "en-US")
PLAYWRIGHT_TIMEOUT_MS = int(os.environ.get("PLAYWRIGHT_TIMEOUT_MS", "20000")) 
PLAYWRIGHT_NAV_TIMEOUT_MS = int(os.environ.get("PLAYWRIGHT_NAV_TIMEOUT_MS", "60000"))
BLOCK_HEAVY_RESOURCES = os.environ.get("BLOCK_HEAVY_RESOURCES", "1") == "1"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
]

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
            is_approved BOOLEAN DEFAULT FALSE
        );
    """)

    # Migration for users
    try:
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS ip_address TEXT;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS device_name TEXT;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS location TEXT;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_paused BOOLEAN DEFAULT FALSE;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_approved BOOLEAN DEFAULT FALSE;")
        cur.execute("UPDATE users SET is_approved = TRUE WHERE is_approved IS NULL")
    except: pass

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
    
    # Migration for items (Target Price)
    try:
        cur.execute("ALTER TABLE items ADD COLUMN IF NOT EXISTS target_price REAL;")
        cur.execute("ALTER TABLE items ADD COLUMN IF NOT EXISTS last_alert_sent TEXT;")
    except: pass

    cur.execute("""
        CREATE TABLE IF NOT EXISTS price_history (
            id SERIAL PRIMARY KEY,
            item_id INTEGER NOT NULL,
            ts TEXT NOT NULL,
            item_name TEXT,
            price_text TEXT,
            price_value REAL,
            rating REAL,
            reviews_count INTEGER,
            discount_percent INTEGER,
            error TEXT,
            FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE CASCADE
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)

    conn.commit()
    conn.close()

try: init_db()
except: pass

# ---------------- Email Helper ----------------

def send_alert_email(to_email, asin, item_name, price):
    if not EMAIL_USER or not EMAIL_PASS:
        print("Email credentials not set. Skipping alert.")
        return

    subject = f"Price Alert: {price} SAR for your item!"
    body = f"""
    <h3>Price Drop Alert!</h3>
    <p>Good news! The item you are tracking has dropped below your target price.</p>
    <p><strong>Item:</strong> {item_name}</p>
    <p><strong>Current Price:</strong> {price} SAR</p>
    <p><a href="https://www.amazon.sa/dp/{asin}">View on Amazon</a></p>
    <br>
    <p>Happy Shopping,<br>Zarss Tracker</p>
    """

    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, to_email, msg.as_string())
        server.quit()
        print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

# ---------------- Auth/Utils ----------------

def current_user():
    uid = session.get("user_id")
    if not uid: return None
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
    u = cur.fetchone()
    conn.close()
    return u

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        uid = session.get("user_id")
        if not uid: return redirect(url_for("login", next=request.path))
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT email, role, is_paused, is_approved FROM users WHERE id=%s", (uid,))
        status = cur.fetchone()
        conn.close()
        if not status: session.clear(); return redirect(url_for("login"))
        if status['email'] == SUPER_ADMIN_EMAIL.lower(): return fn(*args, **kwargs)
        if status['is_paused']: session.clear(); flash("Suspended.", "error"); return redirect(url_for("login"))
        if not status['is_approved']:
            if request.endpoint != 'waitlist_page': return redirect(url_for("waitlist_page"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"): return redirect(url_for("login"))
        if session.get("role") != "admin": abort(403)
        return fn(*args, **kwargs)
    return wrapper

def get_location_from_ip(ip):
    try:
        if ip and ip != '127.0.0.1':
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
            data = r.json()
            if data['status'] == 'success': return f"{data.get('city')}, {data.get('country')}"
    except: pass
    return "Unknown"

def clean(t): return re.sub(r"\s+", " ", t).strip() if t else None
def extract_asin(text):
    text = text.strip()
    if re.fullmatch(r"[A-Z0-9]{10}", text): return text
    m = re.search(r"/dp/([A-Z0-9]{10})", text)
    if m: return m.group(1)
    m = re.search(r"/gp/product/([A-Z0-9]{10})", text)
    if m: return m.group(1)
    return None
def canonical_url(asin): return f"https://www.amazon.sa/dp/{asin}"
def first_number(t):
    if not t: return None
    m = re.search(r"([\d.]+)", t)
    return float(m.group(1)) if m else None
def first_int_like(t):
    if not t: return None
    m = re.search(r"([\d,]+)", t)
    return int(m.group(1).replace(",", "")) if m else None
def parse_money_value(t):
    if not t: return None
    m = re.search(r"([\d,]+(?:\.\d+)?)", t)
    return float(m.group(1).replace(",", "")) if m else None

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
            try:
                if route.request.resource_type in ("image", "media", "font", "stylesheet"): await route.abort()
                else: await route.continue_()
            except: pass
        await context.route("**/*", route_handler)

    page = await context.new_page()
    await page.set_extra_http_headers({"Accept-Language": "en-US,en;q=0.9,ar;q=0.8"})
    page.set_default_timeout(PLAYWRIGHT_TIMEOUT_MS)
    
    url = canonical_url(asin)
    error_msg = None
    item_name = None
    price = None
    price_val = None
    rating = None
    reviews_count = None
    discount_percent = None

    try:
        await page.goto(url, wait_until="domcontentloaded")
        try: await wait_for_any_title_async(page, timeout_ms=PLAYWRIGHT_TIMEOUT_MS)
        except:
            await auto_nudge_async(page)
            await wait_for_any_title_async(page, timeout_ms=PLAYWRIGHT_TIMEOUT_MS)

        item_name = await pick_first_text_async(page, ["#productTitle", "h1 span", "h1", "[data-cy='title-recipe']"])
        price = await pick_first_text_async(page, [
            ".priceToPay .a-offscreen",
            ".apexPriceToPay .a-offscreen", 
            "#corePrice_feature_div .a-price .a-offscreen",
            "#corePriceDisplay_desktop_feature_div .a-price .a-offscreen"
        ])
        
        if not item_name: raise Exception("Amazon blocked request (No title)")

        try:
            rating_text = await page.locator("#acrPopover").first.get_attribute("title")
            rating = first_number(clean(rating_text))
        except: pass
        if not rating:
            rt = await pick_first_text_async(page, ["span[data-hook='rating-out-of-text']"])
            rating = first_number(rt)
        reviews_text = await pick_first_text_async(page, ["#acrCustomerReviewText", "span[data-hook='total-review-count']"])
        reviews_count = first_int_like(reviews_text)
        discount_text = await pick_first_text_async(page, [".savingsPercentage", "#corePriceDisplay_desktop_feature_div .savingsPercentage"])
        if discount_text:
            m = re.search(r"(\d{1,3})\s*%", discount_text)
            if m: discount_percent = int(m.group(1))
            
    except Exception as e: error_msg = str(e)
    finally:
        try: await page.close()
        except: pass
        try: await context.close()
        except: pass

    price_val = parse_money_value(price)
    if price_val and price_val < 1: 
        price_val = None; price = None
    if price_val and not price: price = f"SAR {price_val:.2f}"

    return {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "asin": asin, "url": url, 
        "item_name": item_name, "price_text": price, "price_value": price_val,
        "rating": rating, "reviews_count": reviews_count, "discount_percent": discount_percent,
        "error": error_msg
    }

async def scrape_many_sequential_with_delays(asins):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--disable-blink-features=AutomationControlled", "--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"])
        results = {}
        for i, asin in enumerate(asins):
            if i > 0: await asyncio.sleep(random.uniform(2.0, 5.0))
            results[asin] = await scrape_one_with_context(browser, asin)
        await browser.close()
        return results

def run_async(coro_func, *args, **kwargs):
    try: asyncio.get_running_loop(); running = True
    except RuntimeError: running = False
    if not running: return asyncio.run(coro_func(*args, **kwargs))
    def worker(out):
        try: out["result"] = asyncio.run(coro_func(*args, **kwargs))
        except Exception as e: out["error"] = e
    out = {"result": None, "error": None}
    t = threading.Thread(target=worker, args=(out,), daemon=True)
    t.start(); t.join()
    if out["error"]: raise out["error"]
    return out["result"]

# ---------------- DB Write ----------------

def write_history_for_item(item_id: int, data: dict):
    new_price = data.get("price_value")
    if not new_price or new_price <= 0: return

    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM price_history WHERE item_id=%s ORDER BY ts DESC LIMIT 1", (item_id,))
    latest = cur.fetchone()
    
    should_insert = True
    if latest:
        old_price = latest["price_value"]
        if old_price is not None and new_price == old_price:
             try:
                 last_ts_str = latest["ts"]
                 last_dt = datetime.strptime(str(last_ts_str), "%Y-%m-%d %H:%M:%S")
                 now_dt = datetime.utcnow()
                 diff = now_dt - last_dt
                 if diff.total_seconds() < 3600:
                     should_insert = False
                     cur.execute("UPDATE price_history SET ts=%s WHERE id=%s", (data.get("timestamp"), latest["id"]))
                     conn.commit()
             except: should_insert = True

    if should_insert:
        cur.execute("""
            INSERT INTO price_history(
                item_id, ts, item_name, price_text, price_value, rating, reviews_count, discount_percent, error
            ) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (item_id, data.get("timestamp"), data.get("item_name"), data.get("price_text"), data.get("price_value"), data.get("rating"), data.get("reviews_count"), data.get("discount_percent"), data.get("error")))
        conn.commit()
    conn.close()

def list_all_items_distinct_asins():
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT asin FROM items")
    rows = cur.fetchall()
    conn.close()
    return [r["asin"] for r in rows]

# ---------------- Cron ----------------

def run_global_scrape():
    conn = db_conn()
    cur = conn.cursor()
    
    # 1. Scrape all distinct ASINs
    cur.execute("SELECT DISTINCT asin FROM items")
    rows = cur.fetchall()
    asins = [r["asin"] for r in rows]
    
    if not asins: 
        conn.close()
        return

    results = run_async(scrape_many_sequential_with_delays, asins)
    
    # 2. Update DB and Check Alerts
    for asin, data in results.items():
        cur.execute("""
            SELECT i.id, i.target_price, i.last_alert_sent, u.email 
            FROM items i 
            JOIN users u ON i.user_id = u.id 
            WHERE i.asin = %s
        """, (asin,))
        item_rows = cur.fetchall()
        
        for r in item_rows:
            item_id = r["id"]
            user_email = r["email"]
            target_price = r["target_price"]
            last_alert = r["last_alert_sent"]
            current_price = data.get("price_value")
            
            # Write History
            write_history_for_item(item_id, data)
            
            # Check Alert Condition
            if current_price and target_price and current_price <= target_price:
                # Check frequency (prevent spam, e.g. once per 24h)
                should_alert = True
                if last_alert:
                    try:
                        last_alert_dt = datetime.strptime(last_alert, "%Y-%m-%d %H:%M:%S")
                        if (datetime.utcnow() - last_alert_dt).total_seconds() < 86400: # 24 hours
                            should_alert = False
                    except: pass
                
                if should_alert:
                    send_alert_email(user_email, asin, data.get("item_name"), current_price)
                    # Update alert timestamp
                    cur.execute("UPDATE items SET last_alert_sent=%s WHERE id=%s", (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), item_id))
                    conn.commit()
    conn.close()

@app.route("/cron/update-all", methods=["GET", "POST", "HEAD"]) 
def cron_update_all():
    token = request.args.get("token") or request.headers.get("X-CRON-TOKEN") or ""
    if not CRON_TOKEN or not hmac.compare_digest(token, CRON_TOKEN): return "Unauthorized", 401
    
    # Run in background to handle UptimeRobot timeout
    thread = threading.Thread(target=run_global_scrape)
    thread.start()
    return f"OK", 200

# ---------------- Main Routes ----------------

@app.route("/", methods=["GET"])
@login_required
def index():
    u = current_user()
    if not u: session.clear(); return redirect(url_for("login"))
    if not u.get('is_approved'): return redirect(url_for("waitlist_page"))

    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM items WHERE user_id=%s ORDER BY created_at DESC", (u["id"],))
    items = cur.fetchall()
    cur.execute("SELECT MAX(ts) as last_run FROM price_history")
    last_run = cur.fetchone()
    last_update = last_run['last_run'] if last_run and last_run['last_run'] else "Pending..."
    enriched = []
    for it in items:
        cur.execute("""
            SELECT ph.* FROM price_history ph JOIN items i ON ph.item_id = i.id 
            WHERE i.asin = %s ORDER BY ph.ts DESC LIMIT 1
        """, (it["asin"],))
        latest = cur.fetchone()
        display_price = None
        if latest:
            if latest.get("price_text"): display_price = latest["price_text"]
            elif latest.get("price_value"): display_price = f"SAR {latest['price_value']:.2f}"
        enriched.append({
            "id": it["id"], "asin": it["asin"], "url": it["url"],
            "target_price": it["target_price"], # Pass target price to UI
            "latest_name": latest["item_name"] if latest and latest["item_name"] else None,
            "latest_price_text": display_price,
            "latest_discount": latest["discount_percent"] if latest else None,
            "latest_ts": latest["ts"] if latest else None,
        })
    conn.close()
    return render_template("index.html", user=u, items=enriched, is_admin=(session.get("role") == "admin"), last_global_update=last_update)

@app.route("/add", methods=["POST"])
@login_required
def add():
    u = current_user()
    raw = request.form.get("item", "").strip()
    target = request.form.get("target_price", "").strip()
    
    asin = extract_asin(raw)
    if not asin: flash("Invalid ASIN.", "error"); return redirect(url_for("index"))
    
    target_price = None
    if target:
        try: target_price = float(target)
        except: pass

    conn = db_conn(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO items(user_id, asin, url, target_price, created_at) 
        VALUES(%s, %s, %s, %s, %s) 
        ON CONFLICT (user_id, asin) 
        DO UPDATE SET target_price = EXCLUDED.target_price
    """, (u["id"], asin, canonical_url(asin), target_price, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit(); conn.close()
    flash("Item added/updated.", "ok"); return redirect(url_for("index"))

# (Other routes: delete, update_one, history_json, admin routes, register, login, etc... kept same)
@app.route("/delete/<asin>", methods=["POST"])
@login_required
def delete(asin):
    u = current_user()
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM items WHERE user_id=%s AND asin=%s", (u["id"], asin))
    item = cur.fetchone()
    if item:
        cur.execute("DELETE FROM price_history WHERE item_id=%s", (item["id"],))
        cur.execute("DELETE FROM items WHERE id=%s", (item["id"],))
    conn.commit(); conn.close()
    flash("Deleted.", "ok"); return redirect(url_for("index"))

@app.route("/update/<asin>", methods=["POST"])
@login_required
def update_one(asin):
    u = current_user()
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM items WHERE user_id=%s AND asin=%s", (u["id"], asin))
    row = cur.fetchone()
    conn.close()
    if row:
        results = run_async(scrape_many_sequential_with_delays, [asin])
        if results.get(asin): write_history_for_item(row["id"], results[asin])
        flash("Updated.", "ok")
    return redirect(url_for("index"))

@app.route("/history/<asin>.json", methods=["GET"])
@login_required
def history_json(asin):
    conn = db_conn(); cur = conn.cursor()
    cur.execute("""
        SELECT ph.ts, ph.item_name, ph.price_value, ph.price_text, ph.discount_percent
        FROM price_history ph
        JOIN items i ON ph.item_id = i.id
        WHERE i.asin = %s AND ph.price_value IS NOT NULL AND ph.price_value > 0
        ORDER BY ph.ts ASC LIMIT 200
    """, (asin,))
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows: out.append({"ts": r["ts"], "price_value": r["price_value"]})
    return jsonify(out)

# Admin Routes (Users, Items, Pause, Delete, etc. - Keep as is from previous)
@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_users():
    conn = db_conn(); cur = conn.cursor()
    status = request.args.get('status', 'all')
    if status == 'pending': cur.execute("SELECT * FROM users WHERE is_approved = FALSE ORDER BY created_at DESC")
    else: cur.execute("SELECT * FROM users WHERE is_approved = TRUE ORDER BY created_at DESC")
    users = cur.fetchall()
    cur.execute("""
        SELECT i.user_id, i.asin, (SELECT ph.item_name FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) as title 
        FROM items i
    """)
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
    conn = db_conn(); cur = conn.cursor()
    cur.execute("UPDATE users SET is_approved = TRUE WHERE id=%s", (user_id,))
    conn.commit(); conn.close()
    return redirect(url_for("admin_users", status="pending"))

@app.route("/admin/user/<int:user_id>/pause", methods=["POST"])
@admin_required
def admin_user_pause(user_id):
    conn = db_conn(); cur = conn.cursor()
    cur.execute("UPDATE users SET is_paused = NOT is_paused WHERE id=%s", (user_id,))
    conn.commit(); conn.close()
    return redirect(url_for("admin_users"))

@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_user_delete(user_id):
    if user_id == session.get("user_id"): return redirect(url_for("admin_users"))
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM items WHERE user_id=%s", (user_id,))
    item_rows = cur.fetchall()
    item_ids = [r["id"] for r in item_rows]
    if item_ids:
        marks = ",".join(["%s"] * len(item_ids))
        cur.execute(f"DELETE FROM price_history WHERE item_id IN ({marks})", tuple(item_ids))
        cur.execute(f"DELETE FROM items WHERE id IN ({marks})", tuple(item_ids))
    cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
    conn.commit(); conn.close()
    return redirect(request.referrer or url_for("admin_users"))

@app.route("/admin/items", methods=["GET"])
@admin_required
def admin_items():
    conn = db_conn(); cur = conn.cursor()
    cur.execute("""
        SELECT i.*, u.email AS user_email,
               (SELECT ph.item_name FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_name,
               (SELECT ph.price_text FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_price_text,
               (SELECT ph.ts FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_ts
        FROM items i JOIN users u ON u.id=i.user_id ORDER BY i.created_at DESC
    """)
    rows = cur.fetchall()
    conn.close()
    return render_template("admin_items.html", items=rows)

@app.route("/admin/item/<int:item_id>/delete", methods=["POST"])
@admin_required
def admin_delete_item_by_id(item_id):
    conn = db_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM price_history WHERE item_id=%s", (item_id,))
    cur.execute("DELETE FROM items WHERE id=%s", (item_id,))
    conn.commit(); conn.close()
    return redirect(url_for("admin_items"))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
