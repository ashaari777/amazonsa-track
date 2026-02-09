import os
import re
import time
import hmac
import base64
import hashlib
import asyncio
import threading
import random
import requests

from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    session,
    flash,
    abort,
    jsonify,
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

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/144.0.0.0 Safari/537.36"
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

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            is_approved BOOLEAN NOT NULL DEFAULT FALSE,
            is_paused BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TEXT NOT NULL DEFAULT (to_char(now() at time zone 'utc','YYYY-MM-DD HH24:MI:SS')),
            last_login_at TEXT,
            login_count INTEGER NOT NULL DEFAULT 0,
            ip_address TEXT,
            device_name TEXT,
            location TEXT
        );
        """
    )

    # Backward compatible migrations (in case the DB existed before these columns)
    try:
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS login_count INTEGER NOT NULL DEFAULT 0")
    except Exception:
        conn.rollback()

    try:
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_chat_id TEXT")
    except Exception:
        conn.rollback()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS items (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            asin TEXT NOT NULL,
            url TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (to_char(now() at time zone 'utc','YYYY-MM-DD HH24:MI:SS')),
            target_price_value NUMERIC,
            UNIQUE(user_id, asin)
        );
        """
    )

    # ---- Migration safety: older DBs might have UNIQUE(asin) or UNIQUE(url) constraints
    # which would prevent different users from adding the same ASIN.
    try:
        cur.execute(
            """
            SELECT conname, pg_get_constraintdef(oid) AS def
            FROM pg_constraint
            WHERE conrelid = 'items'::regclass AND contype = 'u';
            """
        )
        for row in cur.fetchall() or []:
            conname = row.get("conname")
            cdef = (row.get("def") or "").lower()
            # Drop unique constraints that are not the intended (user_id, asin)
            if "unique" in cdef and "(user_id, asin)" not in cdef:
                if "(asin)" in cdef or "(url)" in cdef or "(asin, url)" in cdef:
                    cur.execute(f'ALTER TABLE items DROP CONSTRAINT IF EXISTS "{conname}"')
    except Exception:
        conn.rollback()

    cur.execute(
        """
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
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS target_notifications (
            id SERIAL PRIMARY KEY,
            item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
            notified_at TEXT NOT NULL,
            price_at_notification NUMERIC
        );
        """
    )

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

    # Raw ASIN
    if re.fullmatch(r"[A-Z0-9]{10}", t, re.IGNORECASE):
        return t.upper()

    # URL patterns
    patterns = [
        r"/dp/([A-Z0-9]{10})",
        r"/gp/product/([A-Z0-9]{10})",
        r"asin=([A-Z0-9]{10})",
    ]
    for p in patterns:
        m = re.search(p, t, re.IGNORECASE)
        if m:
            return m.group(1).upper()

    # Last-resort token
    m2 = ASIN_RE.search(t)
    return m2.group(1).upper() if m2 else None


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


def parse_money_value(t):
    if not t:
        return None
    m = re.search(r"([\d,]+(?:\.[\d]+)?)", t.replace("٫", "."))
    if not m:
        return None
    try:
        return float(m.group(1).replace(",", ""))
    except Exception:
        return None


def max_percent_from_text(t):
    if not t:
        return None
    nums = []
    for m in re.findall(r"(\d{1,3})\s*%", t):
        try:
            n = int(m)
            if 1 <= n <= 95:
                nums.append(n)
        except Exception:
            pass
    return max(nums) if nums else None


# ---------------- Telegram Notifications ----------------

def send_telegram_alert(chat_id, item_data):
    """Send urgent price alert via Telegram"""
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not bot_token or not chat_id:
        return False
    
    item_name = item_data.get('item_name', 'Item')
    current_price = item_data.get('price_text', 'N/A')
    current_value = item_data.get('price_value', 0)
    target_price = item_data.get('target_price', 0)
    url = item_data.get('url', '')
    
    # Calculate savings
    savings = target_price - current_value if target_price and current_value else 0
    savings_percent = (savings / target_price * 100) if target_price and target_price > 0 else 0
    
    # Urgent notification message
    message = f"""🚨 *PRICE DROP ALERT!* 🚨

{item_name}
_Just hit your target price!_

💰 *NOW: {current_price}*
🎯 Target: SAR {target_price:.2f}
💵 *YOU SAVE: {savings:.2f} SAR ({savings_percent:.1f}%)*

⏰ _Prices may change anytime!_
🛒 Grab it NOW: {url}

🦅 *PriceHawk Alert*
"""
    
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown",
                "disable_web_page_preview": False
            },
            timeout=10
        )
        return response.status_code == 200
    except Exception as e:
        print(f"Telegram error: {e}")
        return False


def check_and_send_target_alert(item_id, new_price_data):
    """Check if target price reached and send Telegram alert"""
    conn = db_conn()
    cur = conn.cursor()
    
    # Get item details with user's Telegram chat ID
    cur.execute("""
        SELECT i.*, u.telegram_chat_id, u.email
        FROM items i
        JOIN users u ON u.id = i.user_id
        WHERE i.id = %s
    """, (item_id,))
    
    item = cur.fetchone()
    
    if not item:
        conn.close()
        return
    
    # Check if target price is set and user has Telegram
    if not item.get('target_price_value') or not item.get('telegram_chat_id'):
        conn.close()
        return
    
    target_price = float(item['target_price_value'])
    current_price = new_price_data.get('price_value')
    
    if not current_price or current_price <= 0:
        conn.close()
        return
    
    # Check if price dropped below target
    if current_price <= target_price:
        # Check if we already notified recently (avoid spam)
        cur.execute("""
            SELECT notified_at FROM target_notifications
            WHERE item_id = %s
            ORDER BY notified_at DESC
            LIMIT 1
        """, (item_id,))
        
        last_notification = cur.fetchone()
        
        # Only notify if never notified before or more than 24 hours passed
        should_notify = True
        
        if last_notification:
            from datetime import datetime, timedelta
            try:
                last_time = datetime.strptime(last_notification['notified_at'], '%Y-%m-%d %H:%M:%S')
                if (datetime.utcnow() - last_time) < timedelta(hours=24):
                    should_notify = False
            except:
                pass
        
        if should_notify:
            # Prepare data for Telegram
            telegram_data = {
                'item_name': new_price_data.get('item_name', item.get('asin', 'Item')),
                'price_text': new_price_data.get('price_text', f'SAR {current_price:.2f}'),
                'price_value': current_price,
                'target_price': target_price,
                'url': item['url']
            }
            
            # Send Telegram alert
            sent = send_telegram_alert(item['telegram_chat_id'], telegram_data)
            
            if sent:
                # Record notification
                cur.execute("""
                    INSERT INTO target_notifications (item_id, notified_at, price_at_notification)
                    VALUES (%s, %s, %s)
                """, (item_id, now_utc_str(), current_price))
                conn.commit()
    
    conn.close()


# ---------------- Marketing Deals ----------------

def get_marketing_deals(exclude_asins, limit=5):
    """Return 'top deals' from the global pool excluding the user's ASINs.

    We try to rank by the best % we can infer (coupon text % or discount_percent),
    but we still return items even if % is unknown so the marketing card never looks empty.
    """
    exclude_asins = exclude_asins or []

    conn = db_conn()
    cur = conn.cursor()

    if exclude_asins:
        cur.execute(
            """
            SELECT DISTINCT ON (i.asin)
                i.asin,
                ph.item_name,
                ph.price_text,
                ph.coupon_text,
                ph.discount_percent,
                ph.ts
            FROM items i
            JOIN price_history ph ON ph.item_id = i.id
            WHERE ph.price_value IS NOT NULL
              AND ph.price_value > 0
              AND NOT (i.asin = ANY(%s))
            ORDER BY i.asin, ph.ts DESC
            LIMIT 500
            """,
            (exclude_asins,),
        )
    else:
        cur.execute(
            """
            SELECT DISTINCT ON (i.asin)
                i.asin,
                ph.item_name,
                ph.price_text,
                ph.coupon_text,
                ph.discount_percent,
                ph.ts
            FROM items i
            JOIN price_history ph ON ph.item_id = i.id
            WHERE ph.price_value IS NOT NULL
              AND ph.price_value > 0
            ORDER BY i.asin, ph.ts DESC
            LIMIT 500
            """
        )

    rows = cur.fetchall()
    conn.close()

    deals = []
    for r in rows:
        pct_coupon = max_percent_from_text(r.get("coupon_text") or "")
        pct_disc = None
        try:
            pct_disc = int(float(r.get("discount_percent"))) if r.get("discount_percent") is not None else None
        except Exception:
            pct_disc = None

        best = max([p for p in [pct_coupon, pct_disc] if p is not None], default=None)

        deals.append(
            {
                "asin": r["asin"],
                "title": (r.get("item_name") or r["asin"]).strip() if r.get("item_name") else r["asin"],
                "price_text": (r.get("price_text") or "SAR --").strip(),
                "coupon_text": (r.get("coupon_text") or "").strip(),
                "best_percent": int(best) if best is not None else None,
                "url": f"https://www.amazon.sa/dp/{r['asin']}?language=en",
                "ts": r.get("ts") or "",
            }
        )

    # Sort: known % first, higher is better; then newest
    def _key(d):
        bp = d.get("best_percent")
        return (bp is not None, (bp or -1), d.get("ts") or "")
    deals.sort(key=_key, reverse=True)

    # Cap to requested limit
    return deals[: int(limit)][:limit]


# ---------------- Scraper ----------------

async def scrape_one_amazon_sa(url_or_asin):
    """Scrape a single item. Best-effort and tolerant of blocks."""
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
        "error": None,
    }

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = await browser.new_context(
                user_agent=USER_AGENT,
                viewport={"width": 1200, "height": 800},
                locale="en-US",
            )
            page = await context.new_page()
            await page.goto(url, wait_until="domcontentloaded", timeout=45000)
            await page.wait_for_timeout(650)

            # Title
            title = None
            try:
                title = await page.locator("#productTitle").first.inner_text(timeout=4000)
                title = title.strip()
            except Exception:
                title = None

            # Price
            price_text = None
            price_value = None
            price_selectors = [
                "#corePriceDisplay_desktop_feature_div span.a-price span.a-offscreen",
                "#corePrice_feature_div span.a-price span.a-offscreen",
                "span.a-price span.a-offscreen",
                "#priceblock_ourprice",
                "#priceblock_dealprice",
                "#priceblock_saleprice",
            ]
            for sel in price_selectors:
                try:
                    price_text = await page.locator(sel).first.inner_text(timeout=2500)
                    price_text = price_text.strip()
                    if price_text:
                        break
                except Exception:
                    continue

            if price_text:
                price_value = parse_money_value(price_text)

            # Coupon / promo text
            coupon_text = None
            coupon_candidates = [
                "label[id*='coupon']",
                "#couponBadge",
                "#vpcButton .a-color-success",
                "#promoPriceBlockMessage_feature_div",
                ".promoPriceBlockMessage",
                "#promotions_feature_div",
            ]
            for sel in coupon_candidates:
                try:
                    t = await page.locator(sel).first.inner_text(timeout=1500)
                    t = (t or "").strip()
                    if t and ("coupon" in t.lower() or "%" in t or "save" in t.lower() or "off" in t.lower()):
                        coupon_text = t
                        break
                except Exception:
                    continue

            discount_percent = None
            # Prefer percent from coupon_text
            if coupon_text:
                discount_percent = max_percent_from_text(coupon_text)

            out.update(
                {
                    "item_name": title,
                    "price_text": price_text,
                    "price_value": price_value,
                    "coupon_text": coupon_text,
                    "discount_percent": discount_percent,
                }
            )

            await context.close()
            await browser.close()

    except Exception as e:
        out["error"] = str(e)

    return out


def run_async(coro_fn, *args, **kwargs):
    """Run an async coroutine from sync context."""
    return asyncio.run(coro_fn(*args, **kwargs))


# ---------------- DB item/history logic ----------------

def write_history(item_id, data):
    """Write a history row with de-duplication by update_interval.

    - If price_value is missing, do not insert a new row.
    - If coupon_text exists, update latest row coupon_text.
    """

    if not data.get("price_value"):
        if data.get("coupon_text"):
            conn = db_conn()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id FROM price_history
                WHERE item_id=%s
                ORDER BY ts DESC
                LIMIT 1
                """,
                (item_id,),
            )
            latest_row = cur.fetchone()
            if latest_row:
                cur.execute(
                    "UPDATE price_history SET coupon_text=%s WHERE id=%s",
                    (data["coupon_text"], latest_row["id"]),
                )
                conn.commit()
            conn.close()
        return

    conn = db_conn()
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM price_history WHERE item_id=%s ORDER BY ts DESC LIMIT 1",
        (item_id,),
    )
    latest = cur.fetchone()

    interval_str = get_setting("update_interval", "1800")  # default: 30 minutes
    try:
        interval_sec = int(interval_str)
    except Exception:
        interval_sec = 1800

    insert = True
    if latest and latest.get("price_value") is not None:
        try:
            latest_val = float(latest["price_value"])
        except Exception:
            latest_val = None

        # If same price and within interval, skip insert
        if latest_val is not None and data.get("price_value") is not None:
            try:
                new_val = float(data["price_value"])
            except Exception:
                new_val = None

            if new_val is not None and latest_val == new_val:
                try:
                    last_ts = datetime.strptime(latest["ts"], "%Y-%m-%d %H:%M:%S")
                    new_ts = datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S")
                    if (new_ts - last_ts).total_seconds() < interval_sec:
                        insert = False
                except Exception:
                    insert = True

    if insert:
        cur.execute(
            """
            INSERT INTO price_history(item_id, ts, item_name, price_text, price_value, coupon_text, discount_percent, error)
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                item_id,
                data.get("timestamp"),
                data.get("item_name"),
                data.get("price_text"),
                data.get("price_value"),
                data.get("coupon_text"),
                data.get("discount_percent"),
                data.get("error"),
            ),
        )
        conn.commit()

    conn.close()
    
    # Check for target price alerts
    try:
        check_and_send_target_alert(item_id, data)
    except Exception as e:
        print(f"Alert check error: {e}")


def run_global_scrape():
    """Global scrape: scrape each distinct ASIN once then write to each user's item."""

    # Global interval gate
    last_run = get_setting("last_global_run", None)
    try:
        interval_sec = int(get_setting("update_interval", "1800") or "1800")
    except Exception:
        interval_sec = 1800

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

    if not asins:
        set_setting("global_update_running", "0")
        set_setting("global_update_total", "0")
        set_setting("global_update_done", "0")
        set_setting("global_update_current_asin", "")
        set_setting("last_global_run", now_utc_str())
        return

    # Progress tracking for Admin UI
    set_setting("global_update_running", "1")
    set_setting("global_update_total", str(len(asins)))
    set_setting("global_update_done", "0")
    set_setting("global_update_current_asin", "")

    done = 0
    total = len(asins)
    for asin in asins:
        set_setting("global_update_current_asin", asin)
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

        done += 1
        set_setting("global_update_done", str(done))

    set_setting("last_global_run", now_utc_str())
    set_setting("global_update_running", "0")
    set_setting("global_update_current_asin", "")


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

        # Super admin bypass
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

        if session.get("role") == "admin":
            return fn(*args, **kwargs)

        # Super admin email bypass
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
    uid = session.get("user_id")

    conn = db_conn()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
    user = cur.fetchone()
    if not user:
        conn.close()
        session.clear()
        return redirect(url_for("login"))

    if not user.get("is_approved"):
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
        user_asins.append(it["asin"])
        cur.execute(
            """
            SELECT * FROM price_history
            WHERE item_id=%s
            ORDER BY ts DESC
            LIMIT 1
            """,
            (it["id"],),
        )
        latest = cur.fetchone()
        it = dict(it)
        it["latest_name"] = latest["item_name"] if latest else None
        it["latest_price_text"] = latest["price_text"] if latest else None
        it["coupon_text"] = latest["coupon_text"] if latest else None
        it["discount_percent"] = latest["discount_percent"] if latest else None
        enriched.append(it)

    conn.close()

    marketing_deals = get_marketing_deals(user_asins, limit=5)

    telegram_link = build_telegram_deeplink(uid) if not user.get("telegram_chat_id") else None

    return render_template(
        "index.html",
        user={"email": user.get("email") or "", "telegram_chat_id": user.get("telegram_chat_id")},
        items=enriched,
        marketing_deals=marketing_deals,
        telegram_link=telegram_link,
        announcement=announcement,
        last_run=last_run,
        is_admin=(session.get("role") == "admin") or ((user.get("email") or "").lower() == SUPER_ADMIN_EMAIL.lower()),
    )


@app.route("/add", methods=["POST"])
@login_required
def add():
    raw = (request.form.get("item") or "").strip()
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

    # ✅ Explicit duplicate check (prevents false 'already in your list' on other DB errors)
    cur.execute("SELECT 1 FROM items WHERE user_id=%s AND asin=%s", (uid, asin))
    if cur.fetchone():
        conn.close()
        flash("This item is already in your list.", "error")
        return redirect(url_for("index"))

    try:
        cur.execute(
            "INSERT INTO items(user_id, asin, url, created_at) VALUES(%s,%s,%s,%s)",
            (uid, asin, url, now_utc_str()),
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        import traceback
        error_detail = str(e)
        traceback.print_exc()  # Log to console for debugging
        flash(f"Failed to add item: {error_detail}", "error")
        return redirect(url_for("index"))

    cur.execute("SELECT id FROM items WHERE user_id=%s AND asin=%s", (uid, asin))
    row = cur.fetchone()
    conn.close()

    # First scrape
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
    target = (request.form.get("target") or request.form.get("target_price") or request.form.get("target_price_value") or "").strip()
    try:
        target_val = float(target)
    except Exception:
        target_val = None

    conn = db_conn()
    cur = conn.cursor()
    uid = session.get("user_id")

    cur.execute(
        "UPDATE items SET target_price_value=%s WHERE id=%s AND user_id=%s",
        (target_val, item_id, uid),
    )
    conn.commit()
    conn.close()

    flash("Target updated.", "ok")
    return redirect(url_for("index"))



# Backward-compatible endpoint name used by older templates
@app.route("/set-target-price/<int:item_id>", methods=["POST"])
@login_required
def set_target_price(item_id):
    """Alias for set_target (older templates used endpoint name set_target_price)."""
    return set_target(item_id)

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

    cur.execute(
        "SELECT ts, price_value FROM price_history WHERE item_id=%s AND price_value IS NOT NULL AND price_value > 0 ORDER BY ts ASC",
        (it["id"],),
    )
    rows = cur.fetchall()
    conn.close()

    out = [{"ts": r["ts"], "price_value": float(r["price_value"]) if r["price_value"] is not None else None} for r in rows]
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

        # Global update progress (for Admin UI)
        try:
            data["global_update_running"] = (get_setting("global_update_running", "0") or "0")
            data["global_update_total"] = int(get_setting("global_update_total", "0") or "0")
            data["global_update_done"] = int(get_setting("global_update_done", "0") or "0")
            data["global_update_current_asin"] = get_setting("global_update_current_asin", "") or ""
        except Exception:
            data["global_update_running"] = "0"
            data["global_update_total"] = 0
            data["global_update_done"] = 0
            data["global_update_current_asin"] = ""

    elif tab in ("active_users", "pending_users"):
        if tab == "pending_users":
            cur.execute(
                """
                SELECT u.*,
                       (SELECT COUNT(*) FROM items i WHERE i.user_id=u.id) AS item_count
                FROM users u
                WHERE u.is_approved=FALSE
                ORDER BY u.created_at DESC
                """
            )
        else:
            cur.execute(
                """
                SELECT u.*,
                       (SELECT COUNT(*) FROM items i WHERE i.user_id=u.id) AS item_count
                FROM users u
                WHERE u.is_approved=TRUE
                ORDER BY u.created_at DESC
                """
            )
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

        base_query += " ORDER BY i.created_at DESC "

        cur.execute(base_query, tuple(params))
        data["items_list"] = cur.fetchall()

        cur.execute("SELECT id, email FROM users ORDER BY email")
        data["all_users"] = cur.fetchall()
        data["current_filter"] = user_filter

    conn.close()
    return render_template("admin.html", tab=tab, data=data, pending_count=pending_count)


# Backward-compatible admin URLs (redirect to unified page)
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    return redirect(url_for("admin_portal", tab="dashboard"))


@app.route("/admin/items", methods=["GET"])
@admin_required
def admin_items():
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
    cur.execute(
        "DELETE FROM items WHERE user_id IN (SELECT id FROM users WHERE last_login_at < %s)",
        (cutoff,),
    )
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


@app.route("/admin/item/<int:item_id>/update", methods=["POST"])
@admin_required
def admin_update_item_by_id(item_id):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM items WHERE id=%s", (item_id,))
    item = cur.fetchone()
    conn.close()

    if not item:
        flash("Item not found.", "error")
        return redirect(url_for("admin_portal", tab="items"))

    try:
        data = run_async(scrape_one_amazon_sa, item["url"])
        write_history(item["id"], data)
        flash("Item updated successfully.", "ok")
    except Exception as e:
        flash(f"Update failed: {e}", "error")

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

    is_approved = (email == SUPER_ADMIN_EMAIL.lower())
    role = "admin" if is_approved else "user"

    conn = db_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users(email,password_hash,role,is_approved) VALUES(%s,%s,%s,%s)",
            (email, generate_password_hash(password), role, is_approved),
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

    # If admin but not approved, auto-approve
    if user.get("role") == "admin" and not user.get("is_approved"):
        try:
            cur.execute("UPDATE users SET is_approved=TRUE WHERE id=%s", (user["id"],))
            conn.commit()
            user = dict(user)
            user["is_approved"] = True
        except Exception:
            pass

    # Waitlist redirect (admins bypass)
    if not user.get("is_approved") and user.get("role") != "admin":
        conn.close()
        return redirect(url_for("waitlist_page"))

    # Set session
    session["user_id"] = user["id"]
    session["role"] = user["role"]
    session["email"] = user.get("email") or ""

    # Log IP/device/location + login count
    ip = (request.headers.get("X-Forwarded-For", request.remote_addr) or "").split(",")[0].strip()
    loc = get_location_from_ip(ip)

    cur.execute(
        """
        UPDATE users
        SET last_login_at=%s,
            login_count = COALESCE(login_count, 0) + 1,
            ip_address=%s,
            device_name=%s,
            location=%s
        WHERE id=%s
        """,
        (
            now_utc_str(),
            ip,
            request.user_agent.string,
            loc,
            user["id"],
        ),
    )
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

    # Manual display for now (email sending not wired)
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

    threading.Thread(target=run_global_scrape, daemon=True).start()
    return "OK started", 200


# ---------------- Telegram Bot Routes ----------------


# ---------------- Telegram Bot Helpers ----------------

def get_or_create_telegram_link_token(user_id: int) -> str:
    """Return a stable per-user link token used with /start <token>.

    We persist it in system_settings so the user's Telegram link stays the same
    until you decide to reset it.
    """
    key = f"telegram_link_{user_id}"
    token = get_setting(key, None)
    if token:
        return token

    # Create a new token (short, URL-safe) and persist it
    raw = f"{user_id}:{APP_SECRET}:{time.time()}:{random.random()}"
    token = hashlib.sha256(raw.encode()).hexdigest()[:16]
    set_setting(key, token)
    return token


def build_telegram_deeplink(user_id: int) -> str:
    bot_username = os.environ.get("TELEGRAM_BOT_USERNAME", "PriceHawkSABot")
    link_token = get_or_create_telegram_link_token(user_id)
    return f"https://t.me/{bot_username}?start={link_token}"




@app.route("/telegram-setup", methods=["GET"])
@login_required
def telegram_setup():
    uid = session.get("user_id")
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
    user = cur.fetchone()
    conn.close()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    # If already connected, no need to setup again
    if user.get("telegram_chat_id"):
        return redirect(url_for("index"))

    bot_username = os.environ.get("TELEGRAM_BOT_USERNAME", "PriceHawkSABot")
    link_token = get_or_create_telegram_link_token(uid)
    telegram_link = build_telegram_deeplink(uid)

    return render_template(
        "telegram_setup.html",
        user={"email": user.get("email") or ""},
        bot_username=bot_username,
        link_token=link_token,
        telegram_link=telegram_link,
    )

@app.route("/telegram-disconnect", methods=["POST"])
@login_required
def telegram_disconnect():
    user_id = session.get("user_id")
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET telegram_chat_id = NULL WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    flash("Telegram disconnected", "ok")
    return redirect(url_for("index"))


@app.route("/telegram-webhook", methods=["POST"])
def telegram_webhook():
    """Handle incoming Telegram updates"""
    try:
        update = request.get_json()
        
        if "message" in update:
            message = update["message"]
            chat_id = message["chat"]["id"]
            text = message.get("text", "")
            
            # Handle /start command with link token
            if text.startswith("/start "):
                link_token = text.split(" ", 1)[1] if " " in text else ""
                
                # Find user with this link token
                conn = db_conn()
                cur = conn.cursor()
                
                # Check all users for matching token
                cur.execute("SELECT id FROM users")
                users = cur.fetchall()
                
                for user in users:
                    stored_token = get_setting(f"telegram_link_{user['id']}")
                    if stored_token == link_token:
                        # Link this chat_id to user
                        cur.execute(
                            "UPDATE users SET telegram_chat_id = %s WHERE id = %s",
                            (str(chat_id), user['id'])
                        )
                        conn.commit()
                        
                        # Send confirmation
                        bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
                        if bot_token:
                            requests.post(
                                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                                json={
                                    "chat_id": chat_id,
                                    "text": "🦅 *PriceHawk Connected!*\n\nYou'll now receive instant alerts when your tracked items hit target prices.\n\n_Go add items and set target prices on your dashboard_",
                                    "parse_mode": "Markdown"
                                }
                            )
                        
                        conn.close()
                        return "OK", 200
                
                conn.close()
        
        return "OK", 200
    except Exception as e:
        print(f"Webhook error: {e}")
        return "OK", 200



@app.route("/price-monitoring", methods=["GET"])
@login_required
def price_monitoring():
    uid = session.get("user_id")
    conn = db_conn()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
    user = cur.fetchone()
    if not user:
        conn.close()
        session.clear()
        return redirect(url_for("login"))

    if not user.get("is_approved"):
        conn.close()
        return redirect(url_for("waitlist_page"))

    # Only show items that have a target price set
    cur.execute(
        """
        SELECT * FROM items
        WHERE user_id=%s AND target_price_value IS NOT NULL
        ORDER BY created_at DESC
        """,
        (uid,),
    )
    items = cur.fetchall()

    rows = []
    for it in items:
        item_id = it["id"]
        asin = it["asin"]
        target = it.get("target_price_value")

        # Latest record (for title + current price)
        cur.execute(
            """
            SELECT item_name, price_value, price_text, ts
            FROM price_history
            WHERE item_id=%s
            ORDER BY ts DESC
            LIMIT 1
            """,
            (item_id,),
        )
        latest = cur.fetchone()

        title = (latest.get("item_name") if latest else None) or asin
        current_price_text = (latest.get("price_text") if latest else None) or "--"
        current_price_value = (latest.get("price_value") if latest else None)
        latest_ts = (latest.get("ts") if latest else None)

        status = "watching"
        reached_at = None

        # "Congrats" ONLY if the CURRENT price is <= target (not because it hit it in the past)
        try:
            if target is not None and current_price_value is not None and float(current_price_value) > 0:
                if float(current_price_value) <= float(target):
                    status = "congrats"

                    # Prefer the recorded notification time (when the target was actually hit and alerted)
                    cur.execute(
                        """
                        SELECT notified_at
                        FROM target_notifications
                        WHERE item_id=%s
                        ORDER BY notified_at DESC
                        LIMIT 1
                        """,
                        (item_id,),
                    )
                    nrow = cur.fetchone()
                    reached_at = (nrow.get("notified_at") if nrow else None) or latest_ts
        except Exception:
            status = "watching"
            reached_at = None

        rows.append(
            {
                "asin": asin,
                "title": title,
                "target": target,
                "current_price_text": current_price_text,
                "current_price_value": current_price_value,
                "status": status,
                "reached_at": reached_at,
            }
        )

    conn.close()

    return render_template(
        "price_monitoring.html",
        user={"email": user.get("email") or ""},
        rows=rows,
        is_admin=(session.get("role") == "admin")
        or ((user.get("email") or "").lower() == SUPER_ADMIN_EMAIL.lower()),
    )




if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
