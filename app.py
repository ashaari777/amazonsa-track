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

# DATABASE CONFIG
DATABASE_URL = os.environ.get("DATABASE_URL")

# Specific Admin Email
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
    
    # Create Tables
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
            is_paused BOOLEAN DEFAULT FALSE
        );
    """)

    # Migration for existing DBs (Add new columns if missing)
    try:
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS ip_address TEXT;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS device_name TEXT;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS location TEXT;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_paused BOOLEAN DEFAULT FALSE;")
    except Exception as e:
        print(f"Migration Note: {e}")
        conn.rollback()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            asin TEXT NOT NULL,
            url TEXT NOT NULL,
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

try:
    init_db()
except Exception as e:
    print(f"DB Init Error: {e}")

# ---------------- Auth helpers ----------------

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
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def get_location_from_ip(ip):
    try:
        # Simple free IP geolocation
        if ip and ip != '127.0.0.1':
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
            data = r.json()
            if data['status'] == 'success':
                return f"{data.get('city')}, {data.get('country')}"
    except:
        pass
    return "Unknown"

# ---------------- Utility helpers ----------------

def clean(t: str | None) -> str | None:
    if not t: return None
    return re.sub(r"\s+", " ", t).strip()

def extract_asin(text: str) -> str | None:
    text = text.strip()
    if re.fullmatch(r"[A-Z0-9]{10}", text): return text
    m = re.search(r"/dp/([A-Z0-9]{10})", text)
    if m: return m.group(1)
    m = re.search(r"/gp/product/([A-Z0-9]{10})", text)
    if m: return m.group(1)
    return None

def canonical_url(asin: str) -> str:
    return f"https://www.amazon.sa/dp/{asin}"

def first_number(t: str | None) -> float | None:
    if not t: return None
    m = re.search(r"([\d.]+)", t)
    return float(m.group(1)) if m else None

def first_int_like(t: str | None) -> int | None:
    if not t: return None
    m = re.search(r"([\d,]+)", t)
    if not m: return None
    return int(m.group(1).replace(",", ""))

def parse_money_value(t: str | None) -> float | None:
    if not t: return None
    m = re.search(r"([\d,]+(?:\.\d+)?)", t)
    if not m: return None
    return float(m.group(1).replace(",", ""))

# ---------------- Playwright scraping ----------------

async def pick_first_text_async(page, selectors) -> str | None:
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            txt = await loc.text_content()
            txt = clean(txt)
            if txt: return txt
        except Exception: pass
    return None

async def wait_for_any_title_async(page, timeout_ms=8000) -> None:
    selectors = ["#productTitle", "h1 span", "h1", "[data-cy='title-recipe']"]
    for sel in selectors:
        try:
            await page.wait_for_selector(sel, timeout=timeout_ms)
            return
        except Exception: pass
    raise TimeoutError("Title not found")

async def auto_nudge_async(page) -> None:
    try:
        await page.evaluate("window.scrollTo(0, 500)")
        await page.wait_for_timeout(200)
    except Exception: pass

async def scrape_one_with_context(browser, asin: str) -> dict:
    ua = random.choice(USER_AGENTS)
    context = await browser.new_context(locale=PLAYWRIGHT_LOCALE, user_agent=ua)
    
    if BLOCK_HEAVY_RESOURCES:
        async def route_handler(route):
            try:
                if route.request.resource_type in ("image", "media", "font", "stylesheet"):
                    await route.abort()
                else: 
                    await route.continue_()
            except Exception: pass
        await context.route("**/*", route_handler)

    page = await context.new_page()
    await page.set_extra_http_headers({"Accept-Language": "en-US,en;q=0.9,ar;q=0.8"})
    page.set_default_timeout(PLAYWRIGHT_TIMEOUT_MS)
    
    url = canonical_url(asin)
    error_msg = None
    item_name = None
    price = None
    rating = None
    reviews_count = None
    discount_percent = None

    try:
        await page.goto(url, wait_until="domcontentloaded")
        try: await wait_for_any_title_async(page, timeout_ms=PLAYWRIGHT_TIMEOUT_MS)
        except Exception:
            await auto_nudge_async(page)
            await wait_for_any_title_async(page, timeout_ms=PLAYWRIGHT_TIMEOUT_MS)

        item_name = await pick_first_text_async(page, ["#productTitle", "h1 span", "h1", "[data-cy='title-recipe']"])
        price = await pick_first_text_async(page, ["#corePriceDisplay_desktop_feature_div .a-price .a-offscreen", "#corePrice_feature_div .a-price .a-offscreen", "span.a-price > span.a-offscreen", ".a-price .a-offscreen"])
        
        if not item_name: raise Exception("Amazon blocked request (No title)")

        try:
            rating_text = await page.locator("#acrPopover").first.get_attribute("title")
            rating = first_number(clean(rating_text))
        except Exception: pass
        if not rating:
            rt = await pick_first_text_async(page, ["span[data-hook='rating-out-of-text']"])
            rating = first_number(rt)
        reviews_text = await pick_first_text_async(page, ["#acrCustomerReviewText", "span[data-hook='total-review-count']"])
        reviews_count = first_int_like(reviews_text)
        discount_text = await pick_first_text_async(page, [".savingsPercentage", "#corePriceDisplay_desktop_feature_div .savingsPercentage"])
        if discount_text:
            m = re.search(r"(\d{1,3})\s*%", discount_text)
            if m: discount_percent = int(m.group(1))
    except Exception as e:
        error_msg = str(e)
    finally:
        try: await page.close()
        except: pass
        try: await context.close()
        except: pass

    return {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "asin": asin, "url": url, 
        "item_name": item_name, "price_text": price, "price_value": parse_money_value(price),
        "rating": rating, "reviews_count": reviews_count, "discount_percent": discount_percent,
        "error": error_msg
    }

async def scrape_many_sequential_with_delays(asins: list[str]) -> dict[str, dict]:
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled", "--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
        )
        results = {}
        for i, asin in enumerate(asins):
            if i > 0:
                delay = random.uniform(2.0, 5.0)
                await asyncio.sleep(delay)
            data = await scrape_one_with_context(browser, asin)
            results[asin] = data
        await browser.close()
        return results

def run_async(coro_func, *args, **kwargs):
    try: asyncio.get_running_loop(); running = True
    except RuntimeError: running = False
    if not running: return asyncio.run(coro_func(*args, **kwargs))
    out = {"result": None, "error": None}
    def worker():
        try: out["result"] = asyncio.run(coro_func(*args, **kwargs))
        except Exception as e: out["error"] = e
    t = threading.Thread(target=worker, daemon=True)
    t.start(); t.join()
    if out["error"]: raise out["error"]
    return out["result"]

# ---------------- DB operations ----------------

def write_history_for_item(item_id: int, data: dict):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM price_history WHERE item_id=%s ORDER BY ts DESC LIMIT 1", (item_id,))
    latest = cur.fetchone()
    
    new_price = data.get("price_value")
    should_insert = True
    
    if latest:
        old_price = latest["price_value"]
        if new_price is not None and old_price is not None and new_price == old_price:
             try:
                 last_ts_str = latest["ts"]
                 last_dt = datetime.strptime(str(last_ts_str), "%Y-%m-%d %H:%M:%S")
                 now_dt = datetime.utcnow()
                 diff = now_dt - last_dt
                 if diff.total_seconds() < 3600:
                     should_insert = False
                     cur.execute("UPDATE price_history SET ts=%s WHERE id=%s", (data.get("timestamp"), latest["id"]))
                     conn.commit()
                     conn.close()
                     return
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

def list_all_item_ids_for_asin(asin: str):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM items WHERE asin=%s", (asin,))
    rows = cur.fetchall()
    conn.close()
    return [r["id"] for r in rows]

# ---------------- Auth routes ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET": return render_template("register.html")
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    password2 = request.form.get("password2") or ""
    if not email or not password:
        flash("Email and password are required.", "error"); return redirect(url_for("register"))
    if password != password2:
        flash("Passwords do not match.", "error"); return redirect(url_for("register"))
    
    # Auto-assign admin if matches SUPER_ADMIN_EMAIL
    role = "admin" if (email == SUPER_ADMIN_EMAIL.lower()) else "user"
    
    conn = db_conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users(email, password_hash, role, created_at) VALUES(%s, %s, %s, %s)", 
                   (email, generate_password_hash(password), role, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
    except psycopg2.IntegrityError:
        flash("This email is already registered. Please login.", "error"); return redirect(url_for("login"))
    finally: conn.close()
    flash("Account created. Please login.", "ok"); return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET": return render_template("login.html")
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    
    # Capture User Info
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    device_name = request.user_agent.string
    
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    
    if not user or not check_password_hash(user["password_hash"], password):
        conn.close()
        flash("Invalid email or password.", "error"); return redirect(url_for("login"))
        
    # Check if Paused
    if user.get("is_paused"):
        conn.close()
        flash("Your account has been suspended by the administrator.", "error"); return redirect(url_for("login"))

    # Force Admin Role if it matches the specific email
    if email == SUPER_ADMIN_EMAIL.lower() and user["role"] != "admin":
        cur.execute("UPDATE users SET role='admin' WHERE id=%s", (user["id"],))
        user = dict(user); user["role"] = "admin" # Update local dict
    
    # Update Tracking Info
    location = get_location_from_ip(ip_address)
    cur.execute("""
        UPDATE users 
        SET last_login_at=%s, ip_address=%s, device_name=%s, location=%s 
        WHERE id=%s
    """, (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), ip_address, device_name, location, user["id"]))
    conn.commit()
    conn.close()
    
    session["user_id"] = user["id"]
    session["role"] = user["role"]
    
    return redirect(url_for("index"))

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "GET": return render_template("forgot.html", reset_link=None)
    email = (request.form.get("email") or "").strip().lower()
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    conn.close()
    reset_link = None
    # Simple manual token generation for now
    if user:
        token = secrets.token_urlsafe(32) # In real app, save this token to DB
        reset_link = url_for("reset_password", token=token, _external=True)
    flash("If that email exists, a reset link is available.", "ok")
    return render_template("forgot.html", reset_link=reset_link)

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    # For this simplified version, we just show the form if token is present
    if request.method == "GET": return render_template("reset.html")
    # In real app, validate token here
    flash("Password reset functionality is simplified in this version.", "ok")
    return redirect(url_for("login"))

# ---------------- Main Routes ----------------

@app.route("/", methods=["GET"])
@login_required
def index():
    u = current_user()
    if not u: session.clear(); return redirect(url_for("login"))
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM items WHERE user_id=%s ORDER BY created_at DESC", (u["id"],))
    items = cur.fetchall()
    
    cur.execute("SELECT MAX(ts) as last_run FROM price_history")
    last_run_row = cur.fetchone()
    last_global_update = last_run_row['last_run'] if last_run_row and last_run_row['last_run'] else "Pending..."

    enriched = []
    for it in items:
        cur.execute("SELECT * FROM price_history WHERE item_id=%s ORDER BY ts DESC LIMIT 1", (it["id"],))
        latest = cur.fetchone()
        enriched.append({
            "id": it["id"], "asin": it["asin"], "url": it["url"], "created_at": it["created_at"],
            "latest_name": latest["item_name"] if latest and latest["item_name"] else None,
            "latest_price_text": latest["price_text"] if latest else None,
            "latest_discount": latest["discount_percent"] if latest else None,
            "latest_ts": latest["ts"] if latest else None,
        })
    conn.close()
    return render_template("index.html", user=u, items=enriched, is_admin=(session.get("role") == "admin"), last_global_update=last_global_update)

@app.route("/add", methods=["POST"])
@login_required
def add():
    u = current_user()
    raw = request.form.get("item", "").strip()
    asin = extract_asin(raw)
    if not asin: flash("Invalid ASIN/URL.", "error"); return redirect(url_for("index"))
    
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO items(user_id, asin, url, created_at) VALUES(%s, %s, %s, %s) ON CONFLICT (user_id, asin) DO NOTHING", 
               (u["id"], asin, canonical_url(asin), datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    
    flash("Item added.", "ok"); return redirect(url_for("index"))

@app.route("/delete/<asin>", methods=["POST"])
@login_required
def delete(asin):
    u = current_user()
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM items WHERE user_id=%s AND asin=%s", (u["id"], asin))
    item = cur.fetchone()
    if item:
        cur.execute("DELETE FROM price_history WHERE item_id=%s", (item["id"],))
        cur.execute("DELETE FROM items WHERE id=%s", (item["id"],))
    conn.commit()
    conn.close()
    flash("Item deleted.", "ok"); return redirect(url_for("index"))

@app.route("/update/<asin>", methods=["POST"])
@login_required
def update_one(asin):
    u = current_user()
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM items WHERE user_id=%s AND asin=%s", (u["id"], asin))
    row = cur.fetchone()
    conn.close()
    
    if row:
        results_by_asin = run_async(scrape_many_sequential_with_delays, [asin])
        data = results_by_asin.get(asin)
        if data: write_history_for_item(row["id"], data)
        flash("Item updated.", "ok")
    
    return redirect(url_for("index"))

@app.route("/history/<asin>.json", methods=["GET"])
@login_required
def history_json(asin):
    u = current_user()
    user_id = u["id"]
    if session.get("role") == "admin" and request.args.get("user_id"):
        try: user_id = int(request.args.get("user_id"))
        except: pass
        
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM items WHERE user_id=%s AND asin=%s", (user_id, asin))
    item = cur.fetchone()
    
    if not item: 
        conn.close()
        return jsonify([])
        
    cur.execute("SELECT ts, item_name, price_value, price_text, discount_percent FROM price_history WHERE item_id=%s ORDER BY ts ASC LIMIT 100", (item["id"],))
    rows = cur.fetchall()
    conn.close()
    
    out = []
    for r in rows:
        out.append({"ts": r["ts"], "item_name": r["item_name"], "price_value": r["price_value"], "price_text": r["price_text"], "discount_percent": r["discount_percent"]})
    return jsonify(out)

# ---------------- Admin Routes ----------------

@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_users():
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.*, (SELECT COUNT(*) FROM items i WHERE i.user_id=u.id) AS items_count 
        FROM users u 
        ORDER BY created_at DESC
    """)
    users = cur.fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)

@app.route("/admin/user/<int:user_id>/pause", methods=["POST"])
@admin_required
def admin_user_pause(user_id):
    conn = db_conn()
    cur = conn.cursor()
    # Toggle pause status
    cur.execute("UPDATE users SET is_paused = NOT is_paused WHERE id=%s", (user_id,))
    conn.commit()
    conn.close()
    flash("User status updated.", "ok")
    return redirect(url_for("admin_users"))

@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_user_delete(user_id):
    if user_id == session.get("user_id"):
        flash("You cannot delete yourself.", "error"); return redirect(url_for("admin_users"))
        
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM items WHERE user_id=%s", (user_id,))
    item_rows = cur.fetchall()
    item_ids = [r["id"] for r in item_rows]
    if item_ids:
        marks = ",".join(["%s"] * len(item_ids))
        cur.execute(f"DELETE FROM price_history WHERE item_id IN ({marks})", tuple(item_ids))
        cur.execute(f"DELETE FROM items WHERE id IN ({marks})", tuple(item_ids))
    cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
    conn.commit()
    conn.close()
    flash("User deleted.", "ok")
    return redirect(url_for("admin_users"))

@app.route("/admin/items", methods=["GET"])
@admin_required
def admin_items():
    conn = db_conn()
    cur = conn.cursor()
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

# ---------------- Cron ----------------

@app.route("/cron/update-all", methods=["GET", "POST", "HEAD"]) 
def cron_update_all():
    token = request.args.get("token") or request.headers.get("X-CRON-TOKEN") or ""
    if not CRON_TOKEN or not hmac.compare_digest(token, CRON_TOKEN):
        return "Unauthorized", 401

    if request.method == "HEAD":
        # UptimeRobot HEAD check - we still want to trigger the scrape?
        # User said "Update request happen from Uptimerobot". So we proceed.
        pass

    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT asin FROM items")
    rows = cur.fetchall()
    conn.close()
    asins = [r["asin"] for r in rows]
    
    if not asins: return "No items", 200
    
    results = run_async(scrape_many_sequential_with_delays, asins)
    
    for asin, data in results.items():
        # Get all item IDs for this ASIN (could be multiple users tracking same item)
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id FROM items WHERE asin=%s", (asin,))
        rows = cur.fetchall()
        conn.close()
        
        for r in rows:
            write_history_for_item(r["id"], data)
            
    return f"OK", 200

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
