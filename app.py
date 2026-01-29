import os
import re
import json
import time
import hmac
import base64
import sqlite3
import hashlib
import secrets
import asyncio
import threading
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, flash, abort, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from playwright.async_api import async_playwright

# ---------------- App config ----------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
DB_PATH = os.environ.get("DATABASE_PATH", "amazon_tracker.db")
ADMIN_EMAIL = (os.environ.get("ADMIN_EMAIL") or "").strip().lower()
RESET_MODE = os.environ.get("RESET_MODE", "manual").strip().lower()
CRON_TOKEN = os.environ.get("CRON_TOKEN", "")
PLAYWRIGHT_LOCALE = os.environ.get("PLAYWRIGHT_LOCALE", "en-US")
# Reduced timeouts for faster failure/retry
PLAYWRIGHT_TIMEOUT_MS = int(os.environ.get("PLAYWRIGHT_TIMEOUT_MS", "8000")) 
PLAYWRIGHT_NAV_TIMEOUT_MS = int(os.environ.get("PLAYWRIGHT_NAV_TIMEOUT_MS", "30000"))
BLOCK_HEAVY_RESOURCES = os.environ.get("BLOCK_HEAVY_RESOURCES", "1") == "1"
# Limit parallel tabs to prevent crashing Render free tier
MAX_CONCURRENT_SCRAPES = 3 

# ---------------- DB helpers ----------------

def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL,
            last_login_at TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            asin TEXT NOT NULL,
            url TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, asin),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS price_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------------- Auth helpers ----------------

def current_user():
    uid = session.get("user_id")
    if not uid: return None
    conn = db_conn()
    u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
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

def is_admin_email(email: str) -> bool:
    return bool(ADMIN_EMAIL) and email.strip().lower() == ADMIN_EMAIL

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

# ---------------- Playwright scraping (ASYNC & PARALLEL) ----------------

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

async def configure_page(context):
    page = await context.new_page()
    await page.set_extra_http_headers({"Accept-Language": "en-US,en;q=0.9,ar;q=0.8"})
    page.set_default_timeout(PLAYWRIGHT_TIMEOUT_MS)
    page.set_default_navigation_timeout(PLAYWRIGHT_NAV_TIMEOUT_MS)
    
    if BLOCK_HEAVY_RESOURCES:
        async def route_handler(route):
            try:
                if route.request.resource_type in ("image", "media", "font", "stylesheet"):
                    await route.abort()
                else: 
                    await route.continue_()
            except Exception: pass
        await context.route("**/*", route_handler)
    return page

async def scrape_one_task(context, asin: str) -> dict:
    """Scrapes a single ASIN using a fresh page from the shared context."""
    page = await configure_page(context)
    url = canonical_url(asin)
    
    error_msg = None
    item_name = None
    price = None
    rating = None
    reviews_count = None
    discount_percent = None

    try:
        await page.goto(url, wait_until="domcontentloaded")
        
        # Fast title check
        try: await wait_for_any_title_async(page, timeout_ms=PLAYWRIGHT_TIMEOUT_MS)
        except Exception:
            await auto_nudge_async(page)
            await wait_for_any_title_async(page, timeout_ms=PLAYWRIGHT_TIMEOUT_MS)

        item_name = await pick_first_text_async(page, ["#productTitle", "h1 span", "h1", "[data-cy='title-recipe']"])
        price = await pick_first_text_async(page, ["#corePriceDisplay_desktop_feature_div .a-price .a-offscreen", "#corePrice_feature_div .a-price .a-offscreen", "span.a-price > span.a-offscreen", ".a-price .a-offscreen"])
        
        # Ratings/Reviews (Optional, fail silently)
        try:
            rating_text = await page.locator("#acrPopover").first.get_attribute("title")
            rating = first_number(clean(rating_text))
        except Exception: pass
        
        if not rating:
            rt = await pick_first_text_async(page, ["span[data-hook='rating-out-of-text']"])
            rating = first_number(rt)
            
        reviews_text = await pick_first_text_async(page, ["#acrCustomerReviewText", "span[data-hook='total-review-count']"])
        reviews_count = first_int_like(reviews_text)
        
        # Discount
        discount_text = await pick_first_text_async(page, [".savingsPercentage", "#corePriceDisplay_desktop_feature_div .savingsPercentage"])
        if discount_text:
            m = re.search(r"(\d{1,3})\s*%", discount_text)
            if m: discount_percent = int(m.group(1))

    except Exception as e:
        error_msg = str(e)
    finally:
        await page.close()

    return {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "asin": asin, "url": url, 
        "item_name": item_name, "price_text": price, "price_value": parse_money_value(price),
        "rating": rating, "reviews_count": reviews_count, "discount_percent": discount_percent,
        "error": error_msg
    }

async def scrape_many_parallel(asins: list[str]) -> dict[str, dict]:
    """Scrapes multiple ASINs in parallel using a semaphore to limit concurrency."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled", "--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
        )
        context = await browser.new_context(locale=PLAYWRIGHT_LOCALE)
        
        # Semaphore to limit simultaneous tabs (prevent CPU overload)
        sem = asyncio.Semaphore(MAX_CONCURRENT_SCRAPES)
        
        async def sem_task(asin):
            async with sem:
                return await scrape_one_task(context, asin)

        tasks = [sem_task(asin) for asin in asins]
        results_list = await asyncio.gather(*tasks)
        
        await browser.close()
        
        # Convert list back to dict keyed by ASIN
        return {r["asin"]: r for r in results_list}

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

def get_user_items(user_id: int):
    conn = db_conn()
    items = conn.execute("SELECT * FROM items WHERE user_id=? ORDER BY created_at DESC", (user_id,)).fetchall()
    conn.close()
    return items

def get_latest_history_for_item(item_id: int):
    conn = db_conn()
    row = conn.execute("SELECT * FROM price_history WHERE item_id=? ORDER BY ts DESC LIMIT 1", (item_id,)).fetchone()
    conn.close()
    return row

def insert_item(user_id: int, asin: str):
    conn = db_conn()
    conn.execute("INSERT OR IGNORE INTO items(user_id, asin, url, created_at) VALUES(?,?,?,?)", (user_id, asin, canonical_url(asin), datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def delete_item(user_id: int, asin: str):
    conn = db_conn()
    cur = conn.cursor()
    item = cur.execute("SELECT id FROM items WHERE user_id=? AND asin=?", (user_id, asin)).fetchone()
    if item:
        cur.execute("DELETE FROM price_history WHERE item_id=?", (item["id"],))
        cur.execute("DELETE FROM items WHERE id=?", (item["id"],))
    conn.commit()
    conn.close()

def write_history_for_item(item_id: int, data: dict):
    # --- LOGIC TO SKIP DUPLICATES ---
    latest = get_latest_history_for_item(item_id)
    new_price = data.get("price_value")
    
    if latest:
        old_price = latest["price_value"]
        # If new price is None (error/out of stock), we might still want to record it to show error
        # But if both are valid numbers and equal, skip.
        if new_price is not None and old_price is not None and new_price == old_price:
             # Prices are exactly the same, do not record to DB
             return
             
    conn = db_conn()
    conn.execute("INSERT INTO price_history(item_id, ts, item_name, price_text, price_value, rating, reviews_count, discount_percent, error) VALUES(?,?,?,?,?,?,?,?,?)", 
                 (item_id, data.get("timestamp"), data.get("item_name"), data.get("price_text"), data.get("price_value"), data.get("rating"), data.get("reviews_count"), data.get("discount_percent"), data.get("error")))
    conn.commit()
    conn.close()

def get_item_id(user_id: int, asin: str):
    conn = db_conn()
    row = conn.execute("SELECT id FROM items WHERE user_id=? AND asin=?", (user_id, asin)).fetchone()
    conn.close()
    return row["id"] if row else None

def get_item_id_admin(user_id: int, asin: str):
    conn = db_conn()
    row = conn.execute("SELECT id FROM items WHERE user_id=? AND asin=?", (user_id, asin)).fetchone()
    conn.close()
    return row["id"] if row else None

def list_all_items_distinct_asins():
    conn = db_conn()
    rows = conn.execute("SELECT DISTINCT asin FROM items").fetchall()
    conn.close()
    return [r["asin"] for r in rows]

def list_all_item_ids_for_asin(asin: str):
    conn = db_conn()
    rows = conn.execute("SELECT id FROM items WHERE asin=?", (asin,)).fetchall()
    conn.close()
    return [r["id"] for r in rows]

# ---------------- Password reset ----------------

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def create_reset_token(user_id: int, minutes_valid: int = 30) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)
    expires_at = (datetime.utcnow() + timedelta(minutes=minutes_valid)).strftime("%Y-%m-%d %H:%M:%S")
    conn = db_conn()
    conn.execute("INSERT INTO password_resets(user_id, token_hash, expires_at, used_at) VALUES(?,?,?,NULL)", (user_id, token_hash, expires_at))
    conn.commit()
    conn.close()
    return token

def verify_reset_token(token: str):
    token_hash = _hash_token(token)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    conn = db_conn()
    row = conn.execute("SELECT * FROM password_resets WHERE token_hash=? AND used_at IS NULL AND expires_at > ? ORDER BY id DESC LIMIT 1", (token_hash, now)).fetchone()
    conn.close()
    return row

def consume_reset_token(reset_id: int):
    conn = db_conn()
    conn.execute("UPDATE password_resets SET used_at=? WHERE id=?", (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), reset_id))
    conn.commit()
    conn.close()

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
    role = "admin" if is_admin_email(email) else "user"
    conn = db_conn()
    try:
        conn.execute("INSERT INTO users(email, password_hash, role, created_at) VALUES(?,?,?,?)", (email, generate_password_hash(password), role, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
    except sqlite3.IntegrityError:
        flash("This email is already registered. Please login.", "error"); return redirect(url_for("login"))
    finally: conn.close()
    flash("Account created. Please login.", "ok"); return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET": return render_template("login.html")
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    conn = db_conn()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not user or not check_password_hash(user["password_hash"], password):
        flash("Invalid email or password.", "error"); return redirect(url_for("login"))
    if is_admin_email(email) and user["role"] != "admin":
        conn = db_conn()
        conn.execute("UPDATE users SET role='admin' WHERE id=?", (user["id"],))
        conn.commit()
        conn.close()
        user = dict(user); user["role"] = "admin"
    session["user_id"] = user["id"]; session["role"] = user["role"]
    conn = db_conn()
    conn.execute("UPDATE users SET last_login_at=? WHERE id=?", (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), user["id"]))
    conn.commit()
    conn.close()
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
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    reset_link = None
    if user and RESET_MODE == "manual":
        token = create_reset_token(user["id"], minutes_valid=30)
        reset_link = url_for("reset_password", token=token, _external=True)
    flash("If that email exists, a reset link is available.", "ok")
    return render_template("forgot.html", reset_link=reset_link)

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    row = verify_reset_token(token)
    if not row:
        flash("Reset link is invalid or expired.", "error"); return redirect(url_for("forgot"))
    if request.method == "GET": return render_template("reset.html")
    password = request.form.get("password") or ""
    password2 = request.form.get("password2") or ""
    if not password or password != password2:
        flash("Passwords do not match.", "error"); return redirect(url_for("reset_password", token=token))
    conn = db_conn()
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(password), row["user_id"]))
    conn.commit()
    conn.close()
    consume_reset_token(row["id"])
    flash("Password updated. Please login.", "ok")
    return redirect(url_for("login"))

# ---------------- Main Routes ----------------

@app.route("/", methods=["GET"])
@login_required
def index():
    u = current_user()
    if not u:
        session.clear()
        return redirect(url_for("login"))
        
    items = get_user_items(u["id"])
    enriched = []
    for it in items:
        latest = get_latest_history_for_item(it["id"])
        enriched.append({
            "id": it["id"], "asin": it["asin"], "url": it["url"], "created_at": it["created_at"],
            "latest_name": latest["item_name"] if latest and latest["item_name"] else None,
            "latest_price_text": latest["price_text"] if latest else None,
            "latest_discount": latest["discount_percent"] if latest else None,
            "latest_ts": latest["ts"] if latest else None,
        })
    return render_template("index.html", user=u, items=enriched, is_admin=(session.get("role") == "admin"))

@app.route("/add", methods=["POST"])
@login_required
def add():
    u = current_user()
    raw = request.form.get("item", "").strip()
    asin = extract_asin(raw)
    if not asin:
        flash("Invalid ASIN/URL.", "error"); return redirect(url_for("index"))
    insert_item(u["id"], asin)
    flash("Item added.", "ok"); return redirect(url_for("index"))

@app.route("/delete/<asin>", methods=["POST"])
@login_required
def delete(asin):
    u = current_user()
    delete_item(u["id"], asin)
    flash("Item deleted.", "ok"); return redirect(url_for("index"))

@app.route("/update", methods=["POST"])
@login_required
def update_all():
    u = current_user()
    items = get_user_items(u["id"])
    asins = [it["asin"] for it in items]
    if not asins:
        flash("No items to update.", "error"); return redirect(url_for("index"))
    
    # Use the PARALLEL scraper now
    results_by_asin = run_async(scrape_many_parallel, asins)
    
    for it in items:
        data = results_by_asin.get(it["asin"])
        if data: write_history_for_item(it["id"], data)
    
    flash("Updated all your items.", "ok"); return redirect(url_for("index"))

@app.route("/update/<asin>", methods=["POST"])
@login_required
def update_one(asin):
    u = current_user()
    item_id = get_item_id(u["id"], asin)
    if not item_id: abort(404)
    
    # Use parallel scraper even for one item (reuses code)
    results_by_asin = run_async(scrape_many_parallel, [asin])
    
    data = results_by_asin.get(asin)
    if data: write_history_for_item(item_id, data)
    flash("Item updated.", "ok"); return redirect(url_for("index"))

@app.route("/history/<asin>.json", methods=["GET"])
@login_required
def history_json(asin):
    u = current_user()
    user_id = u["id"]
    if session.get("role") == "admin" and request.args.get("user_id"):
        try: user_id = int(request.args.get("user_id"))
        except Exception: user_id = u["id"]
    item_id = get_item_id_admin(user_id, asin)
    if not item_id: return jsonify([])
    conn = db_conn()
    rows = conn.execute("SELECT ts, item_name, price_value, price_text, discount_percent FROM price_history WHERE item_id=? ORDER BY ts ASC LIMIT 80", (item_id,)).fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({"ts": r["ts"], "item_name": r["item_name"], "price_value": r["price_value"], "price_text": r["price_text"], "discount_percent": r["discount_percent"]})
    return jsonify(out)

# ---------------- Admin Routes ----------------

@app.route("/admin", methods=["GET"])
@admin_required
def admin_home(): return redirect(url_for("admin_users"))

@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_users():
    conn = db_conn()
    users = conn.execute("SELECT u.*, (SELECT COUNT(*) FROM items i WHERE i.user_id=u.id) AS items_count FROM users u ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)

@app.route("/admin/user/<int:user_id>", methods=["GET"])
@admin_required
def admin_user_detail(user_id):
    conn = db_conn()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user: conn.close(); abort(404)
    items = conn.execute("""
        SELECT i.*,
               (SELECT ph.item_name FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_name,
               (SELECT ph.price_text FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_price_text,
               (SELECT ph.ts FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_ts
        FROM items i WHERE i.user_id=? ORDER BY i.created_at DESC
    """, (user_id,)).fetchall()
    conn.close()
    return render_template("admin_user_detail.html", user=user, items=items)

@app.route("/admin/user/<int:user_id>/reset", methods=["POST"])
@admin_required
def admin_user_reset(user_id):
    conn = db_conn()
    user = conn.execute("SELECT id, email FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if not user: abort(404)
    token = create_reset_token(user_id, minutes_valid=30)
    reset_link = url_for("reset_password", token=token, _external=True)
    flash(f"Password reset link for {user['email']}: {reset_link}", "ok")
    return redirect(url_for("admin_users"))

@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_user_delete(user_id):
    me = current_user()
    if me and me["id"] == user_id:
        flash("You cannot delete your own admin account.", "error"); return redirect(url_for("admin_users"))
    conn = db_conn()
    item_ids = [r["id"] for r in conn.execute("SELECT id FROM items WHERE user_id=?", (user_id,))]
    if item_ids:
        marks = ",".join(["?"] * len(item_ids))
        conn.execute(f"DELETE FROM price_history WHERE item_id IN ({marks})", item_ids)
        conn.execute(f"DELETE FROM items WHERE id IN ({marks})", item_ids)
    conn.execute("DELETE FROM password_resets WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    flash("User deleted successfully.", "ok")
    return redirect(url_for("admin_users"))

@app.route("/admin/items", methods=["GET"])
@admin_required
def admin_items():
    conn = db_conn()
    rows = conn.execute("""
        SELECT i.*, u.email AS user_email,
               (SELECT ph.item_name FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_name,
               (SELECT ph.price_text FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_price_text,
               (SELECT ph.ts FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_ts
        FROM items i JOIN users u ON u.id=i.user_id ORDER BY i.created_at DESC
    """).fetchall()
    conn.close()
    return render_template("admin_items.html", items=rows)

@app.route("/cron/update-all", methods=["POST"])
def cron_update_all():
    if not CRON_TOKEN: return "CRON_TOKEN not set", 400
    token = request.headers.get("X-CRON-TOKEN") or request.args.get("token") or ""
    if not hmac.compare_digest(token, CRON_TOKEN): return "Unauthorized", 401
    asins = list_all_items_distinct_asins()
    if not asins: return "No items", 200
    
    # Parallel update for cron too
    results_by_asin = run_async(scrape_many_parallel, asins)
    
    wrote = 0
    for asin, data in results_by_asin.items():
        item_ids = list_all_item_ids_for_asin(asin)
        for item_id in item_ids:
            write_history_for_item(item_id, data)
            wrote += 1
    return f"OK checked items. Wrote {wrote} changes.", 200

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
