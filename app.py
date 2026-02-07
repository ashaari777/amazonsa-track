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


# ---------------- Config ----------------

APP_SECRET = os.environ.get("APP_SECRET", "dev-secret-change-me")
DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL") or os.environ.get("DATABASE")
CRON_TOKEN = os.environ.get("CRON_TOKEN", "")
SUPER_ADMIN_EMAIL = os.environ.get("SUPER_ADMIN_EMAIL", "admin@zarss.local")

# If you use proxy (Render/Cloudflare), you may need this header:
# X-Forwarded-For is handled below.

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
        return row["value"] if row else default
    except Exception:
        return default


def set_setting(key, value):
    """Insert/update a system setting."""
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
    # No email involved; used by UI
    return get_setting("announcement", None)


# ---------------- Utilities ----------------

ASIN_RE = re.compile(r"\b([A-Z0-9]{10})\b")


def extract_asin(text):
    if not text:
        return None
    t = text.strip()
    m = ASIN_RE.search(t)
    if m:
        return m.group(1)
    # Try from URL patterns
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
    # token = base64(user_id:timestamp:secret-hash)
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
        user_id = int(parts[0])
        ts = int(parts[1])
        sig = parts[2]
        return {"user_id": user_id, "ts": ts, "sig": sig}
    except Exception:
        return None


def verify_reset_token(token, email):
    data = parse_reset_token(token)
    if not data:
        return None
    # Expire in 2 hours
    if time.time() - data["ts"] > 2 * 60 * 60:
        return None
    raw = f'{data["user_id"]}:{data["ts"]}:{APP_SECRET}:{email}'
    expected = hash_token(raw)[:24]
    if not hmac.compare_digest(expected, data["sig"]):
        return None
    return data["user_id"]


def get_location_from_ip(ip):
    # Best effort - do not crash if blocked.
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
    """
    Returns dict:
    {
      item_name, price_text, price_value, coupon_text, discount_percent, timestamp, error
    }
    """
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
                viewport={"width": 1200, "height": 800},
                locale="en-US"
            )
            page = await context.new_page()
            await page.goto(url, wait_until="domcontentloaded", timeout=45000)

            # Basic anti-bot wait
            await page.wait_for_timeout(600)

            title = None
            try:
                title = await page.locator("#productTitle").first.inner_text(timeout=3000)
                title = title.strip()
            except Exception:
                pass

            # Price - try several selectors
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
                # Extract numeric
                num = re.findall(r"[\d,.]+", price_text.replace("٫", "."))
                if num:
                    try:
                        v = num[0].replace(",", "")
                        price_value = float(v)
                    except Exception:
                        price_value = None

            # Coupon text - several patterns
            coupon_text = None
            coupon_candidates = [
                "#vpcButton .a-color-success",
                "#couponBadge",
                "span.promoPriceBlockMessage",
                "span.a-size-base.a-color-success",
                "span.a-size-base.a-color-secondary",
                "#promoPriceBlockMessage_feature_div span"
            ]
            for sel in coupon_candidates:
                try:
                    t = await page.locator(sel).first.inner_text(timeout=1500)
                    t = t.strip()
                    if t and ("coupon" in t.lower() or "%" in t or "SAR" in t):
                        coupon_text = t
                        break
                except Exception:
                    continue

            # Discount percent heuristic
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
    """Run an async coroutine from sync context."""
    return asyncio.get_event_loop().run_until_complete(coro_fn(*args, **kwargs))


# ---------------- DB item/history logic ----------------

def get_latest_row(item_id):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM price_history WHERE item_id=%s ORDER BY ts DESC LIMIT 1", (item_id,))
    row = cur.fetchone()
    conn.close()
    return row


def write_history(item_id, data):
    """Write one price history row for an item, with de-duplication by time interval.

    - If price_value is missing (blocked / not found), we normally do NOT insert a row.
    - But if coupon_text exists, we update the latest row coupon_text so it can appear in UI.
    """
    # Do not write empty/blocked rows
    if not data.get("price_value"):
        # Still update latest coupon text if we have it (even when price missing)
        if data.get("coupon_text"):
            conn = db_conn()
            cur = conn.cursor()
            cur.execute("""
                SELECT id FROM price_history
                WHERE item_id=%s
                ORDER BY ts DESC
                LIMIT 1
            """, (item_id,))
            latest_row = cur.fetchone()
            if latest_row:
                cur.execute(
                    "UPDATE price_history SET coupon_text=%s WHERE id=%s",
                    (data["coupon_text"], latest_row["id"])
                )
                conn.commit()
            conn.close()
        return

    conn = db_conn()
    cur = conn.cursor()

    cur.execute("SELECT * FROM price_history WHERE item_id=%s ORDER BY ts DESC LIMIT 1", (item_id,))
    latest = cur.fetchone()

    interval_str = get_setting("update_interval", "1800")  # default 30 minutes
    try:
        interval_sec = int(interval_str)
    except Exception:
        interval_sec = 1800

    insert = True
    if latest and latest.get("price_value") == data.get("price_value"):
        # Same price, consider de-dup by time window
        try:
            last_ts = datetime.strptime(latest["ts"], "%Y-%m-%d %H:%M:%S")
            new_ts = datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S")
            if (new_ts - last_ts).total_seconds() < interval_sec:
                insert = False
        except Exception:
            # if parsing fails, we insert
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
    """
    Global scrape: iterate all distinct ASINs and update each user's item history.
    De-dup window controlled by update_interval.
    """
    conn = db_conn()
    cur = conn.cursor()

    # global de-dup by interval: use last global run time stored in settings
    last_run = get_setting("last_global_run", None)
    try:
        if last_run:
            last_dt = datetime.strptime(last_run, "%Y-%m-%d %H:%M:%S")
        else:
            last_dt = None
    except Exception:
        last_dt = None

    try:
        interval_sec = int(get_setting("update_interval", "1800") or "1800")
    except Exception:
        interval_sec = 1800

    if last_dt:
        if (datetime.utcnow() - last_dt).total_seconds() < interval_sec:
            conn.close()
            return

    cur.execute("SELECT DISTINCT asin FROM items")
    asins = [r["asin"] for r in cur.fetchall()]
    conn.close()

    # scrape each asin once
    for asin in asins:
        try:
            data = run_async(scrape_one_amazon_sa, asin)
        except Exception as e:
            data = {"timestamp": now_utc_str(), "error": str(e)}

        conn2 = db_conn()
        cur2 = conn2.cursor()
        cur2.execute("SELECT id FROM items WHERE asin=%s", (asin,))
        item_rows = cur2.fetchall()
        conn2.close()

        for it in item_rows:
            try:
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

        # Super admin safety
        if (user.get("email") or "").lower() == SUPER_ADMIN_EMAIL.lower():
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

        # Fast path
        if session.get("role") == "admin":
            return fn(*args, **kwargs)

        # Super admin email bypass (in case role wasn't set)
        try:
            conn = db_conn()
            cur = conn.cursor()
            cur.execute("SELECT email FROM users WHERE id=%s", (session.get("user_id"),))
            row = cur.fetchone()
            conn.close()
            if row and (row.get("email") or "").lower() == SUPER_ADMIN_EMAIL.lower():
                session["role"] = "admin"
                return fn(*args, **kwargs)
        except Exception:
            pass

        abort(403)
    return wrapper


# ---------------- Routes ----------------

@app.route("/")
@login_required
def index():
    conn = db_conn()
    cur = conn.cursor()
    uid = session.get("user_id")

    cur.execute("SELECT is_approved FROM users WHERE id=%s", (uid,))
    row = cur.fetchone()
    if not row or not row.get("is_approved"):
        conn.close()
        return redirect(url_for("waitlist_page"))

    cur.execute("SELECT * FROM items WHERE user_id=%s ORDER BY created_at DESC", (uid,))
    items = cur.fetchall()

    announcement = get_system_announcement()

    cur.execute("SELECT MAX(ts) as last_run FROM price_history")
    lr = cur.fetchone()
    last_run = lr["last_run"] if lr and lr.get("last_run") else "Pending..."

    # Attach latest fields per item (for UI)
    enriched = []
    for it in items:
        cur.execute("""
            SELECT * FROM price_history
            WHERE item_id=%s
            ORDER BY ts DESC
            LIMIT 1
        """, (it["id"],))
        latest = cur.fetchone()
        it = dict(it)
        it["latest_name"] = latest["item_name"] if latest else None
        it["latest_price_text"] = latest["price_text"] if latest else None
        it["coupon_text"] = latest["coupon_text"] if latest else None
        enriched.append(it)

    conn.close()

    return render_template(
        "index.html",
        user={"email": session.get("email") or ""},
        items=enriched,
        announcement=announcement,
        last_run=last_run,
        is_admin=(session.get("role") == "admin"),
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
        cur.execute(
            "INSERT INTO items(user_id, asin, url) VALUES(%s,%s,%s)",
            (uid, asin, url)
        )
        conn.commit()
    except Exception:
        conn.rollback()
        flash("This item is already in your list.", "error")
        conn.close()
        return redirect(url_for("index"))

    # Immediately scrape once
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
    conn = db_conn()
    cur = conn.cursor()
    uid = session.get("user_id")

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
    target = request.form.get("target", "").strip()
    try:
        target_val = float(target)
    except Exception:
        target_val = None

    conn = db_conn()
    cur = conn.cursor()
    uid = session.get("user_id")

    cur.execute("UPDATE items SET target_price_value=%s WHERE id=%s AND user_id=%s", (target_val, item_id, uid))
    conn.commit()
    conn.close()

    flash("Target updated.", "ok")
    return redirect(url_for("index"))


@app.route("/update/<asin>", methods=["POST"])
@login_required
def update_one(asin):
    conn = db_conn()
    cur = conn.cursor()
    uid = session.get("user_id")

    cur.execute("SELECT * FROM items WHERE user_id=%s AND asin=%s", (uid, asin))
    item = cur.fetchone()
    conn.close()
    if not item:
        flash("Item not found.", "error")
        return redirect(url_for("index"))

    try:
        data = run_async(scrape_one_amazon_sa, item["url"])
        write_history(item["id"], data)
        flash("Updated.", "ok")
    except Exception as e:
        flash(f"Update failed: {e}", "error")

    return redirect(url_for("index"))


@app.route("/history/<asin>.json", methods=["GET"])
@login_required
def history_json(asin):
    conn = db_conn()
    cur = conn.cursor()
    uid = session.get("user_id")

    cur.execute("SELECT id FROM items WHERE user_id=%s AND asin=%s", (uid, asin))
    it = cur.fetchone()
    if not it:
        conn.close()
        return jsonify([])

    cur.execute("SELECT ts, price_value FROM price_history WHERE item_id=%s ORDER BY ts ASC", (it["id"],))
    rows = cur.fetchall()
    conn.close()

    out = [{"ts": r["ts"], "price_value": r["price_value"]} for r in rows]
    return jsonify(out)

# ---------------- Admin routes (single-page admin.html) ----------------

@app.route("/admin")
@admin_required
def admin_portal():
    tab = request.args.get("tab", "dashboard")

    conn = db_conn()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) as c FROM users WHERE is_approved=FALSE")
    pending_count = cur.fetchone()["c"]

    data = {}

    if tab == "dashboard":
        cur.execute("SELECT COUNT(*) as c FROM users")
        data["total_users"] = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) as c FROM items")
        data["total_items"] = cur.fetchone()["c"]

        cur.execute("SELECT MAX(ts) as last_run FROM price_history")
        lr = cur.fetchone()
        data["last_run"] = lr["last_run"] if lr and lr.get("last_run") else "Pending..."

        data["announcement"] = get_system_announcement()

        interval_sec = int(get_setting("update_interval", "1800") or "1800")
        data["update_interval_minutes"] = max(5, int(interval_sec // 60))

    elif tab in ("active_users", "pending_users"):
        if tab == "pending_users":
            cur.execute("SELECT * FROM users WHERE is_approved=FALSE ORDER BY created_at DESC")
        else:
            cur.execute("SELECT * FROM users WHERE is_approved=TRUE ORDER BY created_at DESC")
        data["users"] = cur.fetchall()

    elif tab == "items":
        user_filter = request.args.get("user_filter")

        base_query = """
            SELECT i.*, u.email AS user_email,
                   (SELECT ph.item_name FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_name,
                   (SELECT ph.price_text FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_price_text,
                   (SELECT ph.ts FROM price_history ph WHERE ph.item_id=i.id ORDER BY ph.ts DESC LIMIT 1) AS latest_ts
            FROM items i
            JOIN users u ON u.id=i.user_id
        """

        params = []
        if user_filter:
            base_query += " WHERE u.id = %s "
            params.append(user_filter)

        base_query += " ORDER BY i.created_at DESC"

        cur.execute(base_query, tuple(params))
        data["items"] = cur.fetchall()

        cur.execute("SELECT id, email FROM users ORDER BY email")
        data["all_users"] = cur.fetchall()
        data["current_filter"] = user_filter

    conn.close()
    return render_template("admin.html", tab=tab, data=data, pending_count=pending_count)


# Backward-compatible admin URLs (redirect to the unified page)
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    return redirect(url_for("admin_portal", tab="dashboard"))

@app.route("/admin/items", methods=["GET"])
@admin_required
def admin_items():
    # Preserve filter if present
    user_filter = request.args.get("user_filter")
    if user_filter:
        return redirect(url_for("admin_portal", tab="items", user_filter=user_filter))
    return redirect(url_for("admin_portal", tab="items"))

@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_users():
    status = request.args.get("status", "all")
    if status == "pending":
        return redirect(url_for("admin_portal", tab="pending_users"))
    return redirect(url_for("admin_portal", tab="active_users"))


@app.route("/admin/set-announcement", methods=["POST"])
@admin_required
def set_announcement():
    txt = request.form.get("text", "")
    set_setting("announcement", txt)
    flash("Announcement updated", "ok")
    return redirect(url_for("admin_portal", tab="dashboard"))


@app.route("/admin/set-interval", methods=["POST"])
@admin_required
def set_update_interval():
    minutes = (request.form.get("minutes") or "").strip()
    try:
        m = int(float(minutes))
        m = max(5, min(1440, m))
        set_setting("update_interval", str(m * 60))
        flash(f"Update interval set to {m} minutes.", "ok")
    except Exception:
        flash("Invalid interval.", "error")
    return redirect(url_for("admin_portal", tab="dashboard"))


@app.route("/admin/force-update", methods=["POST"])
@admin_required
def force_update():
    threading.Thread(target=run_global_scrape, daemon=True).start()
    flash("Forced Global Update Started...", "ok")
    return redirect(url_for("admin_portal", tab="dashboard"))


@app.route("/admin/cleanup-ghosts", methods=["POST"])
@admin_required
def cleanup_ghosts():
    conn = db_conn()
    cur = conn.cursor()
    cutoff = (datetime.utcnow() - timedelta(days=90)).strftime("%Y-%m-%d")
    cur.execute("DELETE FROM items WHERE user_id IN (SELECT id FROM users WHERE last_login_at < %s)", (cutoff,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    flash(f"Cleaned {deleted} ghost items.", "ok")
    return redirect(url_for("admin_portal", tab="dashboard"))


@app.route("/admin/user/<int:user_id>/approve", methods=["POST"])
@admin_required
def admin_user_approve(user_id):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_approved = TRUE WHERE id=%s", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_portal", tab="pending_users"))


@app.route("/admin/user/<int:user_id>/pause", methods=["POST"])
@admin_required
def admin_user_pause(user_id):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_paused = NOT is_paused WHERE id=%s", (user_id,))
    conn.commit()
    conn.close()
    return redirect(request.referrer or url_for("admin_portal", tab="active_users"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_user_delete(user_id):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
    conn.commit()
    conn.close()
    return redirect(request.referrer or url_for("admin_portal", tab="active_users"))


@app.route("/admin/item/<int:item_id>/delete", methods=["POST"])
@admin_required
def admin_delete_item_by_id(item_id):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM price_history WHERE item_id=%s", (item_id,))
    cur.execute("DELETE FROM items WHERE id=%s", (item_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_portal", tab="items"))

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

    # Auto-approve if it's super admin email
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

    if not is_approved:
        flash("Account created! You are on the waitlist.", "ok")
    else:
        flash("Account created.", "ok")
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

    # Ensure super admin is admin + approved
    if email == SUPER_ADMIN_EMAIL.lower():
        cur.execute("UPDATE users SET role='admin', is_approved=TRUE WHERE id=%s", (user["id"],))
        conn.commit()
        user = dict(user)
        user["role"] = "admin"
        user["is_approved"] = True

    session["user_id"] = user["id"]
    session["role"] = user["role"]

    # Waitlist redirect (admins bypass)
    if not user.get("is_approved") and user.get("role") != "admin":
        conn.close()
        return redirect(url_for("waitlist_page"))

    # If user is admin but not approved, auto-approve
    if user.get("role") == "admin" and not user.get("is_approved"):
        try:
            cur.execute("UPDATE users SET is_approved=TRUE WHERE id=%s", (user["id"],))
            conn.commit()
            user = dict(user)
            user["is_approved"] = True
        except Exception:
            pass

    # Log IP/device/location
    ip = (request.headers.get("X-Forwarded-For", request.remote_addr) or "").split(",")[0].strip()
    loc = get_location_from_ip(ip)

    cur.execute("""
        UPDATE users
        SET last_login_at=%s, ip_address=%s, device_name=%s, location=%s
        WHERE id=%s
    """, (
        datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        ip,
        request.user_agent.string,
        loc,
        user["id"]
    ))
    conn.commit()
    conn.close()

    if user["role"] == "admin":
        return redirect(url_for("admin_portal"))
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")


@app.route("/waitlist")
def waitlist_page():
    return render_template("waitlist.html")


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "GET":
        return render_template("forgot.html")

    email = (request.form.get("email") or "").strip().lower()
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    conn.close()

    if not user:
        flash("If that email exists, you will get a reset link.", "ok")
        return redirect(url_for("forgot"))

    token = make_reset_token(user["id"], email)

    # NOTE: Email send intentionally omitted in this version.
    # You can show the reset link for manual copy during testing:
    reset_link = url_for("reset", token=token, _external=True)
    flash(f"Reset link (copy/paste): {reset_link}", "ok")
    return redirect(url_for("forgot"))


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):
    if request.method == "GET":
        return render_template("reset.html", token=token)

    password = request.form.get("password") or ""
    if len(password) < 6:
        flash("Password too short.", "error")
        return redirect(url_for("reset", token=token))

    # Get email from token by looking up user_id
    parsed = parse_reset_token(token)
    if not parsed:
        flash("Invalid token.", "error")
        return redirect(url_for("login"))

    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE id=%s", (parsed["user_id"],))
    row = cur.fetchone()
    if not row:
        conn.close()
        flash("Invalid token.", "error")
        return redirect(url_for("login"))

    uid = verify_reset_token(token, row["email"])
    if not uid:
        conn.close()
        flash("Token expired/invalid.", "error")
        return redirect(url_for("login"))

    cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (generate_password_hash(password), uid))
    conn.commit()
    conn.close()

    flash("Password updated.", "ok")
    return redirect(url_for("login"))


@app.route("/cron/update-all", methods=["GET", "POST", "HEAD"])
def cron_update_all():
    if not CRON_TOKEN:
        return "CRON_TOKEN not set", 400

    token = request.headers.get("X-CRON-TOKEN") or request.args.get("token") or ""
    if not hmac.compare_digest(token, CRON_TOKEN):
        return "Unauthorized", 401

    # Run global scrape in background
    threading.Thread(target=run_global_scrape, daemon=True).start()
    return "OK started", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)