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
import os

def is_admin_user(user: dict) -> bool:
    admin_email = (os.getenv("ADMIN_EMAIL") or "").strip().lower()
    return bool(admin_email) and user["email"].strip().lower() == admin_email


from flask import (
    Flask, request, render_template, redirect, url_for,
    session, flash, abort, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from playwright.async_api import async_playwright


# ---------------- App config ----------------

app = Flask(__name__)

# REQUIRED on Render: set SECRET_KEY env var (long random string)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

DB_PATH = os.environ.get("DATABASE_PATH", "amazon_tracker.db")

# Admin is controlled by env var
ADMIN_EMAIL = (os.environ.get("ADMIN_EMAIL") or "").strip().lower()

# Forgot password mode:
# "manual" -> show reset link on screen (recommended for you now)
RESET_MODE = os.environ.get("RESET_MODE", "manual").strip().lower()

# Optional: Cron update protection token (recommended)
CRON_TOKEN = os.environ.get("CRON_TOKEN", "")

# Playwright tuning
PLAYWRIGHT_LOCALE = os.environ.get("PLAYWRIGHT_LOCALE", "en-US")
PLAYWRIGHT_TIMEOUT_MS = int(os.environ.get("PLAYWRIGHT_TIMEOUT_MS", "12000"))
PLAYWRIGHT_NAV_TIMEOUT_MS = int(os.environ.get("PLAYWRIGHT_NAV_TIMEOUT_MS", "45000"))

# If you want faster scraping:
# block images/fonts/media (True is recommended)
BLOCK_HEAVY_RESOURCES = os.environ.get("BLOCK_HEAVY_RESOURCES", "1") == "1"


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


# Run DB init at import time (works under gunicorn)
init_db()


# ---------------- Auth helpers ----------------

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
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
    if not t:
        return None
    return re.sub(r"\s+", " ", t).strip()


def extract_asin(text: str) -> str | None:
    text = text.strip()

    # If user pasted ASIN directly
    if re.fullmatch(r"[A-Z0-9]{10}", text):
        return text

    # From Amazon URL formats
    m = re.search(r"/dp/([A-Z0-9]{10})", text)
    if m:
        return m.group(1)

    m = re.search(r"/gp/product/([A-Z0-9]{10})", text)
    if m:
        return m.group(1)

    return None


def canonical_url(asin: str) -> str:
    return f"https://www.amazon.sa/dp/{asin}"


def first_number(t: str | None) -> float | None:
    if not t:
        return None
    m = re.search(r"([\d.]+)", t)
    return float(m.group(1)) if m else None


def first_int_like(t: str | None) -> int | None:
    if not t:
        return None
    m = re.search(r"([\d,]+)", t)
    if not m:
        return None
    return int(m.group(1).replace(",", ""))


def parse_money_value(t: str | None) -> float | None:
    if not t:
        return None
    m = re.search(r"([\d,]+(?:\.\d+)?)", t)
    if not m:
        return None
    return float(m.group(1).replace(",", ""))


# ---------------- Playwright scraping (ASYNC) ----------------

async def pick_first_text_async(page, selectors) -> str | None:
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            txt = await loc.text_content()
            txt = clean(txt)
            if txt:
                return txt
        except Exception:
            pass
    return None


async def wait_for_any_title_async(page, timeout_ms=12000) -> None:
    selectors = ["#productTitle", "h1 span", "h1", "[data-cy='title-recipe']"]
    last_exc = None
    for sel in selectors:
        try:
            await page.wait_for_selector(sel, timeout=timeout_ms)
            return
        except Exception as e:
            last_exc = e
    raise last_exc or TimeoutError("Title not found")


async def auto_nudge_async(page) -> None:
    try:
        await page.evaluate("window.scrollTo(0, 900)")
        await page.wait_for_timeout(250)
        await page.evaluate("window.scrollTo(0, 0)")
        await page.wait_for_timeout(150)
    except Exception:
        pass


async def make_browser_async():
    p = await async_playwright().start()

    browser = await p.chromium.launch(
        headless=True,
        args=[
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
        ],
    )
    context = await browser.new_context(locale=PLAYWRIGHT_LOCALE)
    page = await context.new_page()
    await page.set_extra_http_headers({"Accept-Language": "en-US,en;q=0.9,ar;q=0.8"})
    page.set_default_timeout(PLAYWRIGHT_TIMEOUT_MS)
    page.set_default_navigation_timeout(PLAYWRIGHT_NAV_TIMEOUT_MS)

    # Speed-up: block images/fonts/media
    if BLOCK_HEAVY_RESOURCES:
        async def route_handler(route):
            try:
                rtype = route.request.resource_type
                if rtype in ("image", "media", "font"):
                    await route.abort()
                else:
                    await route.continue_()
            except Exception:
                try:
                    await route.continue_()
                except Exception:
                    pass

        await context.route("**/*", route_handler)

    return p, browser, page


async def scrape_one_async(page, asin: str) -> dict:
    url = canonical_url(asin)

    await page.goto(url, wait_until="domcontentloaded")
    try:
        await wait_for_any_title_async(page, timeout_ms=PLAYWRIGHT_TIMEOUT_MS)
    except Exception:
        await auto_nudge_async(page)
        await wait_for_any_title_async(page, timeout_ms=PLAYWRIGHT_TIMEOUT_MS)

    await auto_nudge_async(page)

    item_name = await pick_first_text_async(page, ["#productTitle", "h1 span", "h1", "[data-cy='title-recipe']"])

    price = await pick_first_text_async(page, [
        "#corePriceDisplay_desktop_feature_div .a-price .a-offscreen",
        "#corePrice_feature_div .a-price .a-offscreen",
        "span.a-price > span.a-offscreen",
        ".a-price .a-offscreen",
    ])

    # Rating
    rating_text = None
    try:
        rating_text = await page.locator("#acrPopover").first.get_attribute("title")
        rating_text = clean(rating_text)
    except Exception:
        rating_text = None
    if not rating_text:
        rating_text = await pick_first_text_async(page, ["span[data-hook='rating-out-of-text']", "#acrPopover"])
    rating = first_number(rating_text)

    # Reviews count
    reviews_text = await pick_first_text_async(page, ["#acrCustomerReviewText", "span[data-hook='total-review-count']"])
    reviews_count = first_int_like(reviews_text)

    # Discount percent
    discount_percent = None
    discount_text = await pick_first_text_async(page, [
        ".savingsPercentage",
        "#corePriceDisplay_desktop_feature_div .savingsPercentage",
    ])
    if discount_text:
        m = re.search(r"(\d{1,3})\s*%", discount_text)
        if m:
            discount_percent = int(m.group(1))

    if discount_percent is None:
        list_price_text = await pick_first_text_async(page, [
            "#corePriceDisplay_desktop_feature_div span.a-price.a-text-price span.a-offscreen",
            "#corePrice_feature_div span.a-price.a-text-price span.a-offscreen",
            "span.a-price.a-text-price span.a-offscreen",
        ])
        cur = parse_money_value(price)
        old = parse_money_value(list_price_text)
        if cur and old and old > cur:
            discount_percent = int(round((old - cur) / old * 100))

    return {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "asin": asin,
        "url": url,
        "item_name": item_name,
        "price_text": price,
        "price_value": parse_money_value(price),
        "rating": rating,
        "reviews_count": reviews_count,
        "discount_percent": discount_percent,
    }


def run_async(coro_func, *args, **kwargs):
    """
    Safe runner for async code from sync Flask routes.
    If a loop is already running (some hosting environments), run in a new thread.
    """
    try:
        asyncio.get_running_loop()
        running = True
    except RuntimeError:
        running = False

    if not running:
        return asyncio.run(coro_func(*args, **kwargs))

    out = {"result": None, "error": None}

    def worker():
        try:
            out["result"] = asyncio.run(coro_func(*args, **kwargs))
        except Exception as e:
            out["error"] = e

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join()

    if out["error"]:
        raise out["error"]
    return out["result"]


async def scrape_many_asins_once_async(asins: list[str]) -> dict[str, dict]:
    """
    Scrape each ASIN once and return dict[asin] -> scraped data.
    Uses a single browser/page for speed (sequential, stable).
    """
    p, browser, page = await make_browser_async()
    results = {}
    try:
        for asin in asins:
            try:
                data = await scrape_one_async(page, asin)
                data["error"] = None
                results[asin] = data
            except Exception as e:
                results[asin] = {
                    "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                    "asin": asin,
                    "url": canonical_url(asin),
                    "item_name": None,
                    "price_text": None,
                    "price_value": None,
                    "rating": None,
                    "reviews_count": None,
                    "discount_percent": None,
                    "error": str(e),
                }
    finally:
        try:
            await browser.close()
        except Exception:
            pass
        try:
            await p.stop()
        except Exception:
            pass

    return results


# ---------------- DB operations for tracker ----------------

def get_user_items(user_id: int):
    conn = db_conn()
    items = conn.execute(
        "SELECT * FROM items WHERE user_id=? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    return items


def get_latest_history_for_item(item_id: int):
    conn = db_conn()
    row = conn.execute("""
        SELECT *
        FROM price_history
        WHERE item_id=?
        ORDER BY ts DESC
        LIMIT 1
    """, (item_id,)).fetchone()
    conn.close()
    return row


def insert_item(user_id: int, asin: str):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT OR IGNORE INTO items(user_id, asin, url, created_at) VALUES(?,?,?,?)",
        (user_id, asin, canonical_url(asin), datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
    )
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
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO price_history(
            item_id, ts, item_name, price_text, price_value, rating,
            reviews_count, discount_percent, error
        )
        VALUES(?,?,?,?,?,?,?,?,?)
    """, (
        item_id,
        data.get("timestamp"),
        data.get("item_name"),
        data.get("price_text"),
        data.get("price_value"),
        data.get("rating"),
        data.get("reviews_count"),
        data.get("discount_percent"),
        data.get("error"),
    ))
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


# ---------------- Password reset helpers ----------------

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_reset_token(user_id: int, minutes_valid: int = 30) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)
    expires_at = (datetime.utcnow() + timedelta(minutes=minutes_valid)).strftime("%Y-%m-%d %H:%M:%S")

    conn = db_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO password_resets(user_id, token_hash, expires_at, used_at)
        VALUES(?,?,?,NULL)
    """, (user_id, token_hash, expires_at))
    conn.commit()
    conn.close()
    return token


def verify_reset_token(token: str):
    token_hash = _hash_token(token)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    conn = db_conn()
    row = conn.execute("""
        SELECT * FROM password_resets
        WHERE token_hash=?
          AND used_at IS NULL
          AND expires_at > ?
        ORDER BY id DESC
        LIMIT 1
    """, (token_hash, now)).fetchone()
    conn.close()
    return row


def consume_reset_token(reset_id: int):
    conn = db_conn()
    conn.execute(
        "UPDATE password_resets SET used_at=? WHERE id=?",
        (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), reset_id)
    )
    conn.commit()
    conn.close()


# ---------------- Auth routes ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    password2 = request.form.get("password2") or ""

    if not email or not password:
        flash("Email and password are required.", "error")
        return redirect(url_for("register"))

    if password != password2:
        flash("Passwords do not match.", "error")
        return redirect(url_for("register"))

    role = "admin" if is_admin_email(email) else "user"

    conn = db_conn()
    try:
        conn.execute("""
            INSERT INTO users(email, password_hash, role, created_at)
            VALUES(?,?,?,?)
        """, (
            email,
            generate_password_hash(password),
            role,
            datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        ))
        conn.commit()
    except sqlite3.IntegrityError:
        flash("This email is already registered. Please login.", "error")
        return redirect(url_for("login"))
    finally:
        conn.close()

    flash("Account created. Please login.", "ok")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    conn = db_conn()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()

    # Generic error (do not reveal if email exists)
    if not user or not check_password_hash(user["password_hash"], password):
        flash("Invalid email or password.", "error")
        return redirect(url_for("login"))

    # Upgrade role if email matches ADMIN_EMAIL
    if is_admin_email(email) and user["role"] != "admin":
        conn = db_conn()
        conn.execute("UPDATE users SET role='admin' WHERE id=?", (user["id"],))
        conn.commit()
        conn.close()
        user = dict(user)
        user["role"] = "admin"

    # Session
    session["user_id"] = user["id"]
    session["role"] = user["role"]

    # last login
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
    if request.method == "GET":
        return render_template("forgot.html", reset_link=None)

    email = (request.form.get("email") or "").strip().lower()

    conn = db_conn()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()

    # Always show generic message, but in manual mode, show link if user exists
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
        flash("Reset link is invalid or expired.", "error")
        return redirect(url_for("forgot"))

    if request.method == "GET":
        return render_template("reset.html")

    password = request.form.get("password") or ""
    password2 = request.form.get("password2") or ""
    if not password or password != password2:
        flash("Passwords do not match.", "error")
        return redirect(url_for("reset_password", token=token))

    # Update password
    conn = db_conn()
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(password), row["user_id"]))
    conn.commit()
    conn.close()

    consume_reset_token(row["id"])
    flash("Password updated. Please login.", "ok")
    return redirect(url_for("login"))


# ---------------- Main tracker routes ----------------

@app.route("/", methods=["GET"])
@login_required
def index():
    u = current_user()
    items = get_user_items(u["id"])

    # Attach latest info for display titles
    enriched = []
    for it in items:
        latest = get_latest_history_for_item(it["id"])
        enriched.append({
            "id": it["id"],
            "asin": it["asin"],
            "url": it["url"],
            "created_at": it["created_at"],
            "latest_name": latest["item_name"] if latest and latest["item_name"] else None,
            "latest_price_text": latest["price_text"] if latest else None,
            "latest_discount": latest["discount_percent"] if latest else None,
            "latest_ts": latest["ts"] if latest else None,
        })

    return render_template(
        "index.html",
        user=u,
        items=enriched,
        is_admin=(session.get("role") == "admin"),
    )


@app.route("/add", methods=["POST"])
@login_required
def add():
    u = current_user()
    raw = request.form.get("item", "").strip()
    asin = extract_asin(raw)
    if not asin:
        flash("Invalid ASIN/URL.", "error")
        return redirect(url_for("index"))

    insert_item(u["id"], asin)
    flash("Item added.", "ok")
    return redirect(url_for("index"))


@app.route("/delete/<asin>", methods=["POST"])
@login_required
def delete(asin):
    u = current_user()
    delete_item(u["id"], asin)
    flash("Item deleted.", "ok")
    return redirect(url_for("index"))


@app.route("/update", methods=["POST"])
@login_required
def update_all():
    u = current_user()
    items = get_user_items(u["id"])
    asins = [it["asin"] for it in items]
    if not asins:
        flash("No items to update.", "error")
        return redirect(url_for("index"))

    # Scrape each ASIN once for this user
    results_by_asin = run_async(scrape_many_asins_once_async, asins)

    # Write history per item
    for it in items:
        data = results_by_asin.get(it["asin"])
        if data:
            write_history_for_item(it["id"], data)

    flash("Updated all your items.", "ok")
    return redirect(url_for("index"))


@app.route("/update/<asin>", methods=["POST"])
@login_required
def update_one(asin):
    u = current_user()
    item_id = get_item_id(u["id"], asin)
    if not item_id:
        abort(404)

    results_by_asin = run_async(scrape_many_asins_once_async, [asin])
    data = results_by_asin.get(asin)
    if data:
        write_history_for_item(item_id, data)

    flash("Item updated.", "ok")
    return redirect(url_for("index"))


@app.route("/history/<asin>.json", methods=["GET"])
@login_required
def history_json(asin):
    u = current_user()

    # Normal users: only their items
    # Admin: can pass ?user_id=123 to view that user
    user_id = u["id"]
    if session.get("role") == "admin" and request.args.get("user_id"):
        try:
            user_id = int(request.args.get("user_id"))
        except Exception:
            user_id = u["id"]

    item_id = get_item_id_admin(user_id, asin)
    if not item_id:
        return jsonify([])

    conn = db_conn()
    rows = conn.execute("""
        SELECT ts, item_name, price_value, price_text, discount_percent
        FROM price_history
        WHERE item_id=?
        ORDER BY ts ASC
        LIMIT 80
    """, (item_id,)).fetchall()
    conn.close()

    out = []
    for r in rows:
        out.append({
            "ts": r["ts"],
            "item_name": r["item_name"],
            "price_value": r["price_value"],
            "price_text": r["price_text"],
            "discount_percent": r["discount_percent"],
        })
    return jsonify(out)


# ---------------- Admin routes (view everything) ----------------

@app.route("/admin", methods=["GET"])
@admin_required
def admin_home():
    return redirect(url_for("admin_users"))


@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_users():
    conn = db_conn()
    users = conn.execute("""
        SELECT u.*,
               (SELECT COUNT(*) FROM items i WHERE i.user_id=u.id) AS items_count
        FROM users u
        ORDER BY created_at DESC
    """).fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)


@app.route("/admin/user/<int:user_id>", methods=["GET"])
@admin_required
def admin_user_detail(user_id):
    conn = db_conn()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        abort(404)

    items = conn.execute("""
        SELECT i.*,
               (SELECT ph.item_name FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_name,
               (SELECT ph.price_text FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_price_text,
               (SELECT ph.ts FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_ts
        FROM items i
        WHERE i.user_id=?
        ORDER BY i.created_at DESC
    """, (user_id,)).fetchall()
    conn.close()

    return render_template("admin_user_detail.html", user=user, items=items)

@app.route("/admin/user/<int:user_id>/reset", methods=["POST"])
@admin_required
def admin_user_reset(user_id):
    conn = db_conn()
    user = conn.execute(
        "SELECT id, email FROM users WHERE id=?",
        (user_id,)
    ).fetchone()
    conn.close()

    if not user:
        abort(404)

    # Create reset token (30 minutes)
    token = create_reset_token(user_id, minutes_valid=30)
    reset_link = url_for("reset_password", token=token, _external=True)

    flash(f"Password reset link for {user['email']}: {reset_link}", "ok")
    return redirect(url_for("admin_users"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_user_delete(user_id):
    me = current_user()

    # Safety: admin cannot delete himself
    if me and me["id"] == user_id:
        flash("You cannot delete your own admin account.", "error")
        return redirect(url_for("admin_users"))

    conn = db_conn()

    # Delete user items + history
    item_ids = [
        r["id"] for r in
        conn.execute("SELECT id FROM items WHERE user_id=?", (user_id,))
    ]

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


@app.route("/admin/user/<int:user_id>/reset", methods=["POST"])
@admin_required
def admin_user_reset(user_id):
    conn = db_conn()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if not user:
        abort(404)

    # Create a reset token (valid 30 minutes) and show link in a flash message
    token = create_reset_token(user_id, minutes_valid=30)
    reset_link = url_for("reset_password", token=token, _external=True)

    flash(f"Reset link for {user['email']}: {reset_link}", "ok")
    return redirect(url_for("admin_users"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_user_delete(user_id):
    # Safety: don't let admin delete themselves accidentally
    me = current_user()
    if me and me.get("id") == user_id:
        flash("You cannot delete your own admin account while logged in.", "error")
        return redirect(url_for("admin_users"))

    conn = db_conn()

    # Delete child records manually (works even if FK cascade isn't applied)
    item_ids = [r["id"] for r in conn.execute("SELECT id FROM items WHERE user_id=?", (user_id,)).fetchall()]
    if item_ids:
        q_marks = ",".join(["?"] * len(item_ids))
        conn.execute(f"DELETE FROM price_history WHERE item_id IN ({q_marks})", item_ids)
        conn.execute(f"DELETE FROM items WHERE id IN ({q_marks})", item_ids)

    conn.execute("DELETE FROM password_resets WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()

    flash("User deleted.", "ok")
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
        FROM items i
        JOIN users u ON u.id=i.user_id
        ORDER BY i.created_at DESC
    """).fetchall()
    conn.close()
    return render_template("admin_items.html", items=rows)


# ---------------- Cron endpoint (optional) ----------------

@app.route("/cron/update-all", methods=["POST"])
def cron_update_all():
    """
    Render Cron Job can call this endpoint every 6 hours.
    Protect it using CRON_TOKEN env var.
    """
    if not CRON_TOKEN:
        return "CRON_TOKEN not set", 400

    token = request.headers.get("X-CRON-TOKEN") or request.args.get("token") or ""
    if not hmac.compare_digest(token, CRON_TOKEN):
        return "Unauthorized", 401

    # Scrape each distinct ASIN once, then write history for all items that have that ASIN
    asins = list_all_items_distinct_asins()
    if not asins:
        return "No items", 200

    results_by_asin = run_async(scrape_many_asins_once_async, asins)

    wrote = 0
    for asin, data in results_by_asin.items():
        item_ids = list_all_item_ids_for_asin(asin)
        for item_id in item_ids:
            write_history_for_item(item_id, data)
            wrote += 1

    return f"OK wrote {wrote} history rows", 200


# ---------------- Local run ----------------

if __name__ == "__main__":
    # Local only. On Render use gunicorn.
    app.run(host="127.0.0.1", port=5000, debug=True)
