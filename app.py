import os
import re
import time
import hmac
import base64
import hashlib
import asyncio
import threading
from datetime import datetime, timedelta

import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from playwright.async_api import async_playwright
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, flash, abort, jsonify
)
from functools import wraps


# ---------------- Config ----------------

APP_SECRET = os.environ.get("APP_SECRET", "dev-secret-change-me")
DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL") or os.environ.get("DATABASE")
CRON_TOKEN = os.environ.get("CRON_TOKEN", "")
SUPER_ADMIN_EMAIL = os.environ.get("SUPER_ADMIN_EMAIL", "admin@zarss.local")

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36"
)

app = Flask(__name__)
app.secret_key = APP_SECRET


# ---------------- DB helpers ----------------

def db_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def ensure_schema():
    conn = db_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        is_approved BOOLEAN NOT NULL DEFAULT FALSE,
        is_paused BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TEXT NOT NULL DEFAULT (to_char(now() at time zone 'utc','YYYY-MM-DD HH24:MI:SS')),
        last_login_at TEXT,
        ip_address TEXT,
        device_name TEXT,
        location TEXT
    );
    """)

    # migrations (safe)
    try:
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS login_count INTEGER NOT NULL DEFAULT 0;")
    except Exception:
        conn.rollback()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS items (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        asin TEXT NOT NULL,
        url TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (to_char(now() at time zone 'utc','YYYY-MM-DD HH24:MI:SS')),
        target_price_value NUMERIC,
        UNIQUE(user_id, asin)
    );
    """)

    # migration for older builds that had target_price
    try:
        cur.execute("ALTER TABLE items ADD COLUMN IF NOT EXISTS target_price_value NUMERIC;")
    except Exception:
        conn.rollback()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS price_history (
        id SERIAL PRIMARY KEY,
        item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
        ts TEXT NOT NULL,
        item_name TEXT,
        price_text TEXT,
        price_value NUMERIC,
        coupon_text TEXT,
        discount_percent NUMERIC,
        error TEXT
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """)

    conn.commit()
    conn.close()


ensure_schema()


# ---------------- Settings helpers ----------------

def get_setting(key, default=None):
    try:
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT value FROM system_settings WHERE key=%s", (key,))
        row = cur.fetchone()
        conn.close()
        return row["value_toggle"] if False else (row["value"] if row else default)
    except Exception:
        return default


def set_setting(key, value):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO system_settings(key, value)
        VALUES(%s, %s)
        ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value
        """,
        (key, str(value)),
    )
    conn.commit()
    conn.close()


def get_system_announcement():
    return get_setting("announcement", None)


# ---------------- Utilities ----------------

ASIN_RE = re.compile(r"\b([A-Z0-9]{10})\b", re.IGNORECASE)


def extract_asin(text):
    if not text:
        return None
    t = text.strip()
    m = ASIN_RE.search(t)
    if m:
        return m.group(1).upper()
    patterns = [
        r"/dp/([A-Z0-9]{10})",
        r"/gp/product/([A-Z0-9]{10})",
        r"asin=([A-Z0-9]{10})",
    ]
    for p in patterns:
        m2 = re.search(p, t, re.IGNORECASE)
        if m2:
            return m2.group(1).upper()
    return None


def now_utc_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def hash_token(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def make_reset_token(user_id, email):
    ts = int(time.time())
    raw = f"{user_id}:{ts}:{APP_SECRET}:{email}"
    sig = hash_token(raw)[:24]
    token_raw = f"{user_id}:{ts}:{sig}"
    return base64.urlsafe_b64encode(token_raw.encode("utf-8")).decode("utf-8").strip("=")


def parse_reset_token(token):
    try:
        padded = token + "=" * (-len(token) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
        parts = decoded.split(":")
        if len(parts) != 3:
            return None
        return {"user_id": int(parts[0]), "ts": int(parts[1]), "sig": parts[2]}
    except Exception:
        return None


def verify_reset_token(token, email):
    data = parse_reset_token(token)
    if not data:
        return None
    if time.time() - data["ts"] > 2 * 60 * 60:
        return None
    raw = f'{data["user_id"]}:{data["ts"]}:{APP_SECRET}:{email}'
    expected = hash_token(raw)[:24]
    if not hmac.compare_digest(expected, data["sig"]):
        return None
    return data["user_id"]


def get_location_from_ip(ip):
    try:
        if not ip or ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
            return None
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=4)
        if r.status_code != 200:
            return None
        j = r.json()
        city = j.get("city")
        country = j.get("country_name")
        if city and country:
            return f"{city}, {country}"
        return country or city
    except Exception:
        return None


# ---------------- Scraper ----------------

async def scrape_one_amazon_sa(url_or_asin):
    asin = extract_asin(url_or_asin)
    url = url_or_asin
    if asin and ("http://" not in url_or_asin and "https://" not in url_or_asin):
        url = f"https://www.amazon.sa/dp/{asin}?language=en"

    out = {
        "timestamp": now_utc_str(),
        "item_name": None,
        "price_text": None,
        "price_value": None,
        "coupon_text": None,
        "discount_percent": None,
        "error": None
    }

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
            context = await browser.new_context(
                user_agent=USER_AGENT,
                viewport={"width": 1200, "height": 900},
                locale="en-US"
            )
            page = await context.new_page()
            await page.goto(url, wait_until="domcontentloaded", timeout=45000)
            await page.wait_for_timeout(650)

            title = None
            try:
                title = await page.locator("#productTitle").first.inner_text(timeout=2500)
                title = title.strip()
            except Exception:
                pass

            price_text = None
            price_value = None
            price_selectors = [
                "span.a-price span.a-offscreen",
                "#corePriceDisplay_desktop_feature_div span.a-price span.a-offscreen",
                "#corePrice_feature_div span.a-price span.a-offscreen",
                "#priceblock_ourprice",
                "#priceblock_dealprice",
                "#priceblock_saleprice",
            ]
            for sel in price_selectors:
                try:
                    price_text = await page.locator(sel).first.inner_text(timeout=2000)
                    price_text = price_text.strip()
                    break
                except Exception:
                    continue

            if price_text:
                nums = re.findall(r"[\d,.]+", price_text.replace("٫", "."))
                if nums:
                    try:
                        v = nums[0].replace(",", "")
                        price_value = float(v)
                    except Exception:
                        price_value = None

            coupon_text = None
            coupon_candidates = [
                "#promoPriceBlockMessage_feature_div span",
                "span.promoPriceBlockMessage",
                "span.a-size-base.a-color-success",
                "#vpcButton .a-color-success",
                "#couponBadge",
            ]
            for sel in coupon_candidates:
                try:
                    t = await page.locator(sel).first.inner_text(timeout=1500)
                    t = t.strip()
                    if t and ("%" in t or "coupon" in t.lower() or "save" in t.lower()):
                        coupon_text = t
                        break
                except Exception:
                    continue

            discount_percent = None
            if coupon_text:
                nums = (re.findall(r"\d{1,3}", coupon_text) or [])
                nums = [int(x) for x in nums if 1 <= int(x) <= 95]
                if nums:
                    discount_percent = max(nums)

            out.update({
                "item_name": title,
                "price_text": price_text,
                "price_value": price_value,
                "coupon_text": coupon_text,
                "discount_percent": discount_percent
            })

            await context.close()
            await browser.close()

    except Exception as e:
        out["error"] = str(e)

    return out


def run_async(coro_fn, *args, **kwargs):
    return asyncio.get_event_loop().run_until_complete(coro_fn(*args, **kwargs))


# ---------------- DB item/history logic ----------------

def write_history(item_id, data):
    # skip blocked / missing price rows
    if not data.get("price_value"):
        # if coupon exists, update last row coupon text (optional)
        if data.get("coupon_text"):
            try:
                conn = db_conn()
                cur = conn.cursor()
                cur.execute("""
                    SELECT id FROM price_history
                    WHERE item_id=%s
                    ORDER BY ts DESC
                    LIMIT 1
                """, (item_id,))
                r = cur.fetchone()
                if r:
                    cur.execute(
                        "UPDATE price_history SET coupon_text=%s, discount_percent=%s WHERE id=%s",
                        (data.get("coupon_text"), data.get("discount_percent"), r["id"])
                    )
                    conn.commit()
                conn.close()
            except Exception:
                pass
        return

    conn = db_conn()
    cur = conn.cursor()

    cur.execute("SELECT * FROM price_history WHERE item_id=%s ORDER BY ts DESC LIMIT 1", (item_id,))
    latest = cur.fetchone()

    interval_str = get_setting("update_interval", "1800")  # default 30 min
    try:
        interval_sec = int(interval_str)
    except Exception:
        interval_sec = 1800

    insert = True
    if latest and latest.get("price_value") == data.get("price_value"):
        try:
            last_ts = datetime.strptime(latest["ts"], "%Y-%m-%d %H:%M:%S")
            new_ts = datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S")
            if (new_ts - last_ts).total_seconds() < interval_sec:
                insert = False
        except Exception:
            insert = True

    if insert:
        cur.execute("""
            INSERT INTO price_history(item_id, ts, item_name, price_text, price_value, coupon_text, discount_percent, error)
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            item_id,
            data.get("timestamp"),
            data.get("item_name"),
            data.get("price_text"),
            data.get("price_value"),
            data.get("coupon_text"),
            data.get("discount_percent"),
            data.get("error")
        ))
        conn.commit()

    conn.close()


def run_global_scrape():
    interval_str = get_setting("update_interval", "1800")
    try:
        interval_sec = int(interval_str)
    except Exception:
        interval_sec = 1800

    last_run = get_setting("last_global_run", None)
    if last_run:
        try:
            last_dt = datetime.strptime(last_run, "%Y-%m-%d %H:%M:%S")
            if (datetime.utcnow() - last_dt).total_seconds() < interval_sec:
                return
        except Exception:
            pass

    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT asin FROM items")
    asins = [r["asin"] for r in cur.fetchall()]
    conn.close()

    for asin in asins:
        try:
            data = run_async(scrape_one_amazon_sa, asin)
        except Exception as e:
            data = {"timestamp": now_utc_str(), "error": str(e)}

        conn2 = db_conn()
        cur2 = conn2.cursor()
        cur2.execute("SELECT id, url FROM items WHERE asin=%s", (asin,))
        item_rows = cur2.fetchall()
        conn2.close()

        for it in item_rows:
            try:
                # use stored url if available
                if it.get("url"):
                    try:
                        data2 = run_async(scrape_one_amazon_sa, it["url"])
                        write_history(it["id"], data2)
                    except Exception:
                        write_history(it["id"], data)
                else:
                    write_history(it["id"], data)
            except Exception:
                pass

    set_setting("last_global_run", now_utc_str())


# ---------------- Auth Wrappers ----------------

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))

        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id=%s", (session.get("user_id"),))
        user = cur.fetchone()
        conn.close()

        if not user:
            session.clear()
            return redirect(url_for("login"))

        # super admin always allowed
        if (user.get("email") or "").lower() == SUPER_ADMIN_EMAIL.lower():
            session["role"] = "admin"
            return fn(*args, **kwargs)

        if user.get("is_paused"):
            session.clear()
            flash("Suspended", "error")
            return redirect(url_for("login"))

        if not user.get("is_approved") and request.endpoint != "waitlist_page":
            return redirect(url_for("waitlist_page"))

        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))

        if session.get("role") == "admin":
            return fn(*args, **kwargs)

        try:
            conn = db_conn()
            cur = conn.cursor()
            cur.execute("SELECT email, role FROM users WHERE id=%s", (session.get("user_id"),))
            row = cur.fetchone()
            conn.close()
            if row and (row.get("email") or "").lower() == SUPER_ADMIN_EMAIL.lower():
                session["role"] = "admin"
                return fn(*args, **kwargs)
        except Exception:
            pass

        abort(403)
    return wrapper


# ---------------- Marketing deals (Top deals) ----------------

def get_marketing_deals(user_asins, limit=5):
    """
    Returns list of dicts: {asin,title,price_text,discount_percent}
    Excludes ASINs already in user's list.
    Uses latest price_history rows across all items.
    """
    user_asins = set([a.upper() for a in (user_asins or [])])

    conn = db_conn()
    cur = conn.cursor()

    # latest history row per item
    cur.execute("""
        WITH latest AS (
            SELECT DISTINCT ON (ph.item_id)
                ph.item_id, ph.ts, ph.item_name, ph.price_text, ph.price_value, ph.discount_percent
            FROM price_history ph
            ORDER BY ph.item_id, ph.ts DESC
        )
        SELECT i.asin,
               MAX(latest.item_name) AS item_name,
               MAX(latest.price_text) AS price_text,
               MAX(latest.discount_percent) AS discount_percent,
               MAX(latest.ts) AS ts
        FROM items i
        JOIN latest ON latest.item_id = i.id
        GROUP BY i.asin
        ORDER BY MAX(latest.discount_percent) DESC NULLS LAST, MAX(latest.ts) DESC
        LIMIT 80
    """)

    rows = cur.fetchall()
    conn.close()

    deals = []
    for r in rows:
        asin = (r.get("asin") or "").upper()
        if not asin or asin in user_asins:
            continue
        pct = r.get("discount_percent")
        if pct is None:
            # allow no pct but rank later
            pct = 0
        deals.append({
            "asin": asin,
            "title": r.get("item_name") or asin,
            "price_text": r.get("price_text") or "SAR --",
            "discount_percent": int(pct) if isinstance(pct, (int, float)) else 0
        })
        if len(deals) >= limit:
            break

    return deals


# ---------------- Routes ----------------

@app.route("/")
@login_required
def index():
    uid = session.get("user_id")

    conn = db_conn()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
    user = cur.fetchone()
    if not user:
        conn.close()
        session.clear()
        return redirect(url_for("login"))

    if not user.get("is_approved") and (user.get("role") != "admin"):
        conn.close()
        return redirect(url_for("waitlist_page"))

    cur.execute("SELECT * FROM items WHERE user_id=%s ORDER BY created_at DESC", (uid,))
    items = cur.fetchall()

    announcement = get_system_announcement()

    cur.execute("SELECT MAX(ts) as last_run FROM price_history")
    lr = cur.fetchone()
    last_run = lr["last_run"] if lr and lr.get("last_run") else "Pending..."

    enriched = []
    user_asins = []
    for it in items:
        user_asins.append((it.get("asin") or "").upper())

        cur.execute("""
            SELECT * FROM price_history
            WHERE item_id=%s
            ORDER BY ts DESC
            LIMIT 1
        """, (it["id"],))
        latest = cur.fetchone()

        it = dict(it)

        # always supply target_price_value to template
        if "target_price_value" not in it:
            it["target_price_value"] = it.get("target_price")

        it["latest_name"] = latest["item_name"] if latest else None
        it["latest_price_text"] = latest["price_text"] if latest else None
        it["coupon_text"] = latest["coupon_text"] if latest else None
        enriched.append(it)

    conn.close()

    marketing_deals = get_marketing_deals(user_asins, limit=5)
    while len(marketing_deals) < 5:
        marketing_deals.append(None)

    return render_template(
        "index.html",
        user={"email": user.get("email") or ""},
        items=enriched,
        marketing_deals=marketing_deals,
        announcement=announcement,
        last_run=last_run,
        is_admin=(session.get("role") == "admin") or ((user.get("email") or "").lower() == SUPER_ADMIN_EMAIL.lower()),
    )


@app.route("/add", methods=["POST"])
@login_required
def add():
    raw = request.form.get("item", "").strip()
    asin = extract_asin(raw)
    if not asin:
        flash("Please paste a valid Amazon.sa link or ASIN.", "error")
        return redirect(url_for("index"))

    url = raw
    if "http://" not in raw and "https://" not in raw:
        url = f"https://www.amazon.sa/dp/{asin}?language=en"

    conn = db_conn()
    cur = conn.cursor()
    uid = session.get("user_id")

    try:
        cur.execute("INSERT INTO items(user_id, asin, url) VALUES(%s,%s,%s)", (uid, asin, url))
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        flash("This item is already in your list.", "error")
        return redirect(url_for("index"))

    cur.execute("SELECT id FROM items WHERE user_id=%s AND asin=%s", (uid, asin))
    row = cur.fetchone()
    conn.close()

    if row:
        try:
            data = run_async(scrape_one_amazon_sa, url)
            write_history(row["id"], data)
        except Exception:
            pass

    flash("Item added.", "ok")
    return redirect(url_for("index"))


@app.route("/delete/<asin>", methods=["POST"])
@login_required
def delete(asin):
    asin = (asin or "").upper()
    uid = session.get("user_id")

    conn = db_conn()
    cur = conn.cursor()

    cur.execute("SELECT id FROM items WHERE user_id=%s AND asin=%s", (uid, asin))
    item = cur.fetchone()
    if item:
        cur.execute("DELETE FROM price_history WHERE item_id=%s", (item["id"],))
        cur.execute("DELETE FROM items WHERE id=%s", (item["id"],))
        conn.commit()

    conn.close()
    flash("Deleted.", "ok")
    return redirect(url_for("index"))


@app.route("/set-target/<int:item_id>", methods=["POST"])
@login_required
def set_target(item_id):
    target = (
        (request.form.get("target") or request.form.get("target_price") or request.form.get("target_price_value") or "")
        .strip()
    )
    try:
        target_val = float(target) if target != "" else None
    except Exception:
        target_val = None

    uid = session.get("user_id")
    conn = db_conn()
    cur = conn.cursor()

    cur.execute("UPDATE items SET target_price_value=%s WHERE id=%s AND user_id=%s", (target_val, item_id, uid))
    conn.commit()
    conn.close()

    flash("Target updated.", "ok")
    return redirect(url_for("index"))


# Backward-compatible endpoint name (older templates)
@app.route("/set-target-price/<int:item_id>", methods=["POST"])
@login_required
def set_target_price(item_id):
    return set_target(item_id)


@app.route("/history/<asin>.json", methods=["GET"])
@login_required
def history_json(asin):
    asin = (asin or "").upper()
    uid = session.get("user_id")

    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM items WHERE user_id=%s AND asin=%s", (uid, asin))
    it = cur.fetchone()
    if not it:
        conn.close()
        return jsonify([])

    cur.execute("SELECT ts, price_value FROM price_history WHERE item_id=%s ORDER BY ts ASC", (it["id"],))
    rows = cur.fetchall()
    conn.close()

    out = [{"ts": r["ts"], "price_value": float(r["price_value"]) if r["price_value"] is not None else None} for r in rows]
    return jsonify(out)


# ---------------- Auth routes ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    if not email or not password:
        flash("Missing fields.", "error")
        return redirect(url_for("register"))

    is_approved = (email == SUPER_ADMIN_EMAIL.lower())
    role = "admin" if is_approved else "user"

    conn = db_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users(email,password_hash,role,is_approved) VALUES(%s,%s,%s,%s)",
            (email, generate_password_hash(password), role, is_approved)
        )
        conn.commit()
    except Exception:
        conn.close()
        flash("Email registered.", "error")
        return redirect(url_for("login"))

    conn.close()
    flash("Account created!", "ok")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        conn.close()
        flash("Invalid credentials.", "error")
        return redirect(url_for("login"))

    # ensure super admin is admin + approved
    if email == SUPER_ADMIN_EMAIL.lower():
        cur.execute("UPDATE users SET role='admin', is_approved=TRUE WHERE id=%s", (user["id"],))
        conn.commit()
        user = dict(user)
        user["role"] = "admin"
        user["is_approved"] = True

    session["user_id"] = user["id"]
    session["role"] = user.get("role") or "user"

    if not user.get("is_approved") and user.get("role") != "admin":
        conn.close()
        return redirect(url_for("waitlist_page"))

    ip = (request.headers.get("X-Forwarded-For", request.remote_addr) or "").split(",")[0].strip()
    loc = get_location_from_ip(ip)

    try:
        cur.execute("""
            UPDATE users
            SET last_login_at=%s,
                ip_address=%s,
                device_name=%s,
                location=%s,
                login_count=COALESCE(login_count,0)+1
            WHERE id=%s
        """, (
            now_utc_str(),
            ip,
            request.user_agent.string,
            loc,
            user["id"]
        ))
        conn.commit()
    except Exception:
        conn.rollback()

    conn.close()
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")


@app.route("/waitlist")
def waitlist_page():
    return render_template("waitlist.html")


@app.route("/cron/update-all", methods=["GET", "POST", "HEAD"])
def cron_update_all():
    if not CRON_TOKEN:
        return "CRON_TOKEN not set", 400

    token = request.headers.get("X-CRON-TOKEN") or request.args.get("token") or ""
    if not hmac.compare_digest(token, CRON_TOKEN):
        return "Unauthorized", 401

    threading.Thread(target=run_global_scrape, daemon=True).start()
    return "OK started", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
