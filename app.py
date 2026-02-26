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
import smtplib
import ssl

from datetime import datetime, timedelta
from functools import wraps
from email.message import EmailMessage
from email.utils import formataddr

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

APP_SECRET = os.environ.get("APP_SECRET") or os.environ.get("SECRET_KEY") or "dev-secret-change-me"
DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL") or os.environ.get("DATABASE")
CRON_TOKEN = os.environ.get("CRON_TOKEN", "")
SUPER_ADMIN_EMAIL = os.environ.get("SUPER_ADMIN_EMAIL", "admin@zarss.local")
BLOCK_HEAVY_RESOURCES = (os.environ.get("BLOCK_HEAVY_RESOURCES", "1") or "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
SMTP_HOST = (os.environ.get("SMTP_HOST") or os.environ.get("EMAIL_SMTP_HOST") or "smtp.gmail.com").strip()
try:
    SMTP_PORT = int((os.environ.get("SMTP_PORT") or os.environ.get("EMAIL_SMTP_PORT") or "587").strip())
except Exception:
    SMTP_PORT = 587
SMTP_USE_SSL = (os.environ.get("SMTP_USE_SSL") or os.environ.get("EMAIL_SMTP_SSL") or "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
SMTP_USE_STARTTLS = (os.environ.get("SMTP_USE_STARTTLS") or "").strip().lower() not in {"0", "false", "no", "off"}
EMAIL_USER = (os.environ.get("EMAIL_USER") or "").strip()
EMAIL_PASS = (os.environ.get("EMAIL_PASS") or "").strip()
EMAIL_FROM = (os.environ.get("EMAIL_FROM") or EMAIL_USER or "no-reply@pricehawk.local").strip()
EMAIL_FROM_NAME = (os.environ.get("EMAIL_FROM_NAME") or "PriceHawk").strip()
EMAIL_PROVIDER = (os.environ.get("EMAIL_PROVIDER") or "auto").strip().lower()
RESEND_API_KEY = (os.environ.get("RESEND_API_KEY") or "").strip()
RESEND_API_URL = (os.environ.get("RESEND_API_URL") or "https://api.resend.com/emails").strip()

try:
    PLAYWRIGHT_TIMEOUT_MS = int(os.environ.get("PLAYWRIGHT_TIMEOUT_MS", "45000") or "45000")
except Exception:
    PLAYWRIGHT_TIMEOUT_MS = 45000

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/144.0.0.0 Safari/537.36"
)

app = Flask(__name__)
app.secret_key = APP_SECRET

# Prevent overlapping global scrape runs (which can exhaust memory on small instances).
GLOBAL_SCRAPE_LOCK = threading.Lock()


# ---------------- DB helpers ----------------

def db_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def ensure_schema():
    """Create tables and run safe migrations (idempotent)."""
    conn = db_conn()
    cur = conn.cursor()

    # Core tables
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        );
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS system_settings (
            k TEXT PRIMARY KEY,
            value TEXT
        );
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS items (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            asin TEXT NOT NULL,
            url TEXT,
            target_price_value NUMERIC,
            created_at TEXT DEFAULT (to_char(now(), 'YYYY-MM-DD HH24:MI:SS'))
        );
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS price_history (
            id SERIAL PRIMARY KEY,
            asin TEXT NOT NULL,
            ts TEXT NOT NULL,
            price_value NUMERIC,
            price_text TEXT,
            title TEXT,
            coupon_text TEXT
        );
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS telegram_subscriptions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            chat_id TEXT,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT DEFAULT (to_char(now(), 'YYYY-MM-DD HH24:MI:SS'))
        );
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY,
            item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
            notified_at TEXT NOT NULL,
            price_at_notification NUMERIC
        );
        """
    )

    # ---- Safe migrations (run repeatedly) ----
    cur.execute("ALTER TABLE price_history ADD COLUMN IF NOT EXISTS seller_text TEXT")
    cur.execute("ALTER TABLE price_history ADD COLUMN IF NOT EXISTS seller_name TEXT")
    cur.execute("ALTER TABLE price_history ADD COLUMN IF NOT EXISTS availability_text TEXT")
    cur.execute("ALTER TABLE price_history ADD COLUMN IF NOT EXISTS source_hint TEXT")
    cur.execute("ALTER TABLE items ADD COLUMN IF NOT EXISTS url TEXT")

    # Helpful indexes
    cur.execute("CREATE INDEX IF NOT EXISTS idx_items_user ON items(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_items_asin ON items(asin)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_history_item_ts ON price_history(item_id, ts)")

    conn.commit()
    cur.close()
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
        r"/gp/aw/d/([A-Z0-9]{10})",
        r"/product/([A-Z0-9]{10})",
        r"[?&]pd_rd_i=([A-Z0-9]{10})",
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


def send_password_reset_email(to_email, reset_link):
    """
    Send password reset email.
    Priority:
    - Resend API (HTTPS) when configured
    - SMTP fallback when configured
    Returns (ok, error_message).
    """
    subject = "Reset your PriceHawk password"
    text_body = (
        "We received a request to reset your password.\n\n"
        f"Reset link: {reset_link}\n\n"
        "This link expires in 2 hours.\n"
        "If you did not request this, you can ignore this email."
    )
    html_body = (
        "<p>We received a request to reset your password.</p>"
        f"<p><a href=\"{reset_link}\">Reset your password</a></p>"
        "<p>This link expires in 2 hours.</p>"
        "<p>If you did not request this, you can ignore this email.</p>"
    )

    use_resend = EMAIL_PROVIDER in {"resend", "auto"} and bool(RESEND_API_KEY)
    if use_resend:
        try:
            payload = {
                "from": formataddr((EMAIL_FROM_NAME, EMAIL_FROM)),
                "to": [to_email],
                "subject": subject,
                "text": text_body,
                "html": html_body,
            }
            res = requests.post(
                RESEND_API_URL,
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=20,
            )
            if 200 <= res.status_code < 300:
                return True, None
            err_txt = (res.text or "").strip()
            if len(err_txt) > 300:
                err_txt = err_txt[:300] + "..."
            if EMAIL_PROVIDER == "resend":
                return False, f"Resend API error {res.status_code}: {err_txt}"
        except Exception as e:
            if EMAIL_PROVIDER == "resend":
                return False, f"Resend API error: {e}"

    if EMAIL_PROVIDER == "resend" and not RESEND_API_KEY:
        return False, "RESEND_API_KEY not configured"

    if not EMAIL_USER or not EMAIL_PASS:
        return False, "EMAIL_USER/EMAIL_PASS not configured"
    if not SMTP_HOST:
        return False, "SMTP_HOST not configured"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((EMAIL_FROM_NAME, EMAIL_FROM))
    msg["To"] = to_email
    msg.set_content(text_body)

    try:
        if SMTP_USE_SSL:
            with smtplib.SMTP_SSL(
                SMTP_HOST, SMTP_PORT, timeout=20, context=ssl.create_default_context()
            ) as smtp:
                smtp.login(EMAIL_USER, EMAIL_PASS)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
                smtp.ehlo()
                if SMTP_USE_STARTTLS:
                    smtp.starttls(context=ssl.create_default_context())
                    smtp.ehlo()
                smtp.login(EMAIL_USER, EMAIL_PASS)
                smtp.send_message(msg)
        return True, None
    except Exception as e:
        return False, str(e)


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
    m = re.search(r"([\d,]+(?:\.[\d]+)?)", t.replace("Ù«", "."))
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


def clean_text(t):
    return re.sub(r"\s+", " ", (t or "")).strip()


def format_bytes(n):
    try:
        size = float(int(n or 0))
    except Exception:
        size = 0.0
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    return f"{size:.2f} {units[idx]}"


def is_unavailable_text(t):
    low = clean_text(t).lower()
    return any(
        k in low
        for k in [
            "currently unavailable",
            "temporarily out of stock",
            "out of stock",
            "unavailable",
        ]
    )


def is_offers_only_text(t):
    low = clean_text(t).lower()
    return any(
        k in low
        for k in [
            "only available from",
            "see all offers",
            "see all buying options",
            "available from these sellers",
            "third-party sellers",
            "other sellers",
            "buying choices",
        ]
    )


def extract_seller_name_from_text(t):
    txt = clean_text(t)
    if not txt:
        return None

    # Canonical plain form.
    if re.fullmatch(r"(?i)amazon\.sa", txt):
        return "Amazon.sa"

    patterns = [
        r"(?i)shipper\s*/\s*seller\s*[:\-]?\s*(.+?)(?:[.;]|$)",
        r"(?i)ships\s+from\s+and\s+sold\s+by\s+(.+?)(?:[.;]|$)",
        r"(?i)dispatched\s+from\s+and\s+sold\s+by\s+(.+?)(?:[.;]|$)",
        r"(?i)seller\s*[:\-]\s*(.+?)(?:[.;]|$)",
        r"(?i)sold\s+by\s+(.+?)(?:[.;]|$)",
    ]
    for p in patterns:
        m = re.search(p, txt)
        if m:
            name = normalize_seller_name(m.group(1))
            return name or None
    return None


def is_seller_label_only_text(t):
    low = clean_text(t).lower()
    return low in {
        "shipper / seller",
        "ships from",
        "sold by",
        "seller",
        "shipper",
    }


def normalize_seller_name(t):
    name = clean_text(t)
    if not name:
        return None

    if is_offers_only_text(name) or is_unavailable_text(name):
        return None

    # Remove label-like prefixes.
    name = re.sub(r"(?i)^shipper\s*/\s*seller\s*[:\-]?\s*", "", name)
    name = re.sub(r"(?i)^sold\s+by\s*[:\-]?\s*", "", name)
    name = re.sub(r"(?i)^seller\s*[:\-]?\s*", "", name)
    name = clean_text(name)

    # Canonicalize Amazon seller name.
    if re.search(r"(?i)\bamazon\.sa\b", name):
        return "Amazon.sa"

    # Cut delivery text that may be concatenated in the same node.
    name = re.split(
        r"(?i)\b(?:free\s+delivery|or\s+fastest\s+delivery|order\s+within|ships?\s+from|dispatched\s+from|delivery)\b",
        name,
        maxsplit=1,
    )[0]
    name = clean_text(name.strip(" .,:;|-"))
    if not name:
        return None
    if is_seller_label_only_text(name):
        return None

    low = name.lower()
    if any(
        k in low
        for k in [
            "free delivery",
            "order within",
            "fastest delivery",
            "tomorrow",
            "today",
            "see all offers",
            "see all buying options",
            "available from these sellers",
            "only available from",
        ]
    ):
        return None

    return name


async def extract_primary_buying_option_offer(page):
    """
    Best-effort extraction from Amazon "See All Buying Options" panel.
    Returns dict with price/seller fields or None.
    """
    try:
        offer_rows = page.locator("#aod-offer, #aod-offer-list .aod-offer")
        rows_count = await offer_rows.count()

        if rows_count == 0:
            trigger_selectors = [
                "#buybox-see-all-buying-choices a",
                "#buybox-see-all-buying-choices-announce",
                "a[href*='/gp/offer-listing/']",
                "#newAccordionRow_1 a[href*='/gp/offer-listing/']",
            ]
            for sel in trigger_selectors:
                try:
                    loc = page.locator(sel).first
                    txt = clean_text(await loc.inner_text(timeout=700))
                    if txt and (is_offers_only_text(txt) or "offer" in txt.lower() or "buying" in txt.lower()):
                        await loc.click(timeout=1400)
                        break
                except Exception:
                    continue

            try:
                await page.wait_for_selector("#aod-offer, #aod-offer-list .aod-offer", timeout=3500)
            except Exception:
                pass
            rows_count = await offer_rows.count()

        if rows_count <= 0:
            return None

        offers = []
        for i in range(min(rows_count, 8)):
            row = offer_rows.nth(i)

            price_text = None
            price_value = None
            price_selectors = [
                ".a-price .a-offscreen",
                ".a-price.a-text-price .a-offscreen",
                "[data-a-color='price'] .a-offscreen",
            ]
            for psel in price_selectors:
                try:
                    cand = clean_text(await row.locator(psel).first.inner_text(timeout=800))
                    if not cand:
                        continue
                    pv = parse_money_value(cand)
                    if pv is None:
                        continue
                    price_text = cand
                    price_value = pv
                    break
                except Exception:
                    continue

            seller_text = None
            seller_name = None
            seller_selectors = [
                "[id*='aod-offer-soldBy'] a",
                "[id*='aod-offer-soldBy'] .a-size-small",
                "[id*='aod-offer-soldBy']",
            ]
            for ssel in seller_selectors:
                try:
                    sraw = clean_text(await row.locator(ssel).first.inner_text(timeout=700))
                    if not sraw or is_seller_label_only_text(sraw):
                        continue
                    seller_text = sraw
                    seller_name = extract_seller_name_from_text(sraw) or normalize_seller_name(sraw)
                    if seller_name:
                        break
                except Exception:
                    continue

            if price_value is None:
                continue

            offers.append(
                {
                    "price_text": price_text or (f"SAR {price_value:.2f}" if price_value is not None else None),
                    "price_value": price_value,
                    "seller_text": seller_text,
                    "seller_name": normalize_seller_name(seller_name),
                    "source_hint": "aod-offer",
                }
            )

        if not offers:
            return None

        # Prefer Amazon.sa offer when present, otherwise use the cheapest valid offer.
        amazon_sa_offers = [o for o in offers if (o.get("seller_name") or "").lower() == "amazon.sa"]
        pool = amazon_sa_offers or offers
        best = min(pool, key=lambda o: float(o.get("price_value") or 10**9))

        if amazon_sa_offers:
            best["source_hint"] = "aod-offer-amazon-sa"
        else:
            best["source_hint"] = "aod-offer-third-party"

        return best
    except Exception:
        return None


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
    message = f"""ð¨ *PRICE DROP ALERT!* ð¨

{item_name}
_Just hit your target price!_

ð° *NOW: {current_price}*
ð¯ Target: SAR {target_price:.2f}
ðµ *YOU SAVE: {savings:.2f} SAR ({savings_percent:.1f}%)*

â° _Prices may change anytime!_
ð Grab it NOW: {url}

ð¦ *PriceHawk Alert*
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
    """Return top deals from the global pool excluding the user's ASINs."""
    exclude_asins = exclude_asins or []

    conn = db_conn()
    cur = conn.cursor()

    if exclude_asins:
        cur.execute(
            """
            SELECT DISTINCT ON (i.asin)
                i.asin,
            COALESCE(
                (SELECT item_name FROM price_history WHERE item_id=i.id AND item_name IS NOT NULL AND item_name <> '' ORDER BY ts DESC LIMIT 1),
                ph.item_name
            ) AS item_name,
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
        if best is None:
            continue

        deals.append(
            {
                "asin": r["asin"],
                "title": (r.get("item_name") or r["asin"]).strip() if r.get("item_name") else r["asin"],
                "price_text": (r.get("price_text") or "SAR --").strip(),
                "coupon_text": (r.get("coupon_text") or "").strip(),
                "best_percent": int(best),
                "url": f"https://www.amazon.sa/dp/{r['asin']}?language=en",
                "ts": r.get("ts") or "",
            }
        )

    deals.sort(key=lambda d: (d["best_percent"], d["ts"]), reverse=True)
    return deals[:limit]


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
        "seller_text": None,
        "seller_name": None,
        "availability_text": None,
        "source_hint": None,
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

            if BLOCK_HEAVY_RESOURCES:
                async def route_handler(route):
                    if route.request.resource_type in {"image", "media", "font"}:
                        await route.abort()
                    else:
                        await route.continue_()

                await page.route("**/*", route_handler)

            await page.goto(url, wait_until="domcontentloaded", timeout=PLAYWRIGHT_TIMEOUT_MS)
            await page.wait_for_timeout(650)

            # Title
            title = None
            try:
                title = await page.locator("#productTitle").first.inner_text(timeout=4000)
                title = clean_text(title)
            except Exception:
                title = None
            if not title:
                title_selectors = [
                    "#title span#productTitle",
                    "#title span",
                    "h1#title span",
                    "meta[property='og:title']",
                ]
                for sel in title_selectors:
                    try:
                        if sel.startswith("meta"):
                            candidate = await page.locator(sel).first.get_attribute("content", timeout=1800)
                        else:
                            candidate = await page.locator(sel).first.inner_text(timeout=1800)
                        candidate = clean_text(candidate)
                        if candidate:
                            title = candidate
                            break
                    except Exception:
                        continue
            if not title:
                try:
                    page_title = clean_text(await page.title())
                    # Keep only the product part from Amazon title suffixes.
                    page_title = re.split(r"\s+:\s+Buy Online at Best Price", page_title, maxsplit=1)[0]
                    page_title = re.split(r"\s+:\s+Amazon\.sa", page_title, maxsplit=1)[0]
                    if page_title and page_title.lower() != "amazon.sa":
                        title = page_title
                except Exception:
                    pass
            if title and asin and clean_text(title).upper() == asin.upper():
                title = None

            # Availability / offers state
            availability_text = None
            availability_selectors = [
                "#availabilityInsideBuyBox_feature_div #availability span",
                "#availability_feature_div #availability span",
                "#availabilityInsideBuyBox_feature_div",
                "#availability_feature_div",
                "#availability span",
                "#availability",
                "#outOfStock",
                "#buybox-see-all-buying-choices",
                "#buybox-see-all-buying-choices-announce",
            ]
            for sel in availability_selectors:
                try:
                    raw = await page.locator(sel).first.inner_text(timeout=1400)
                    raw = clean_text(raw)
                    raw = clean_text(re.sub(r"\.[A-Za-z0-9_-]+\s*\{[^}]*\}", " ", raw))
                    if raw:
                        availability_text = raw
                        break
                except Exception:
                    continue

            offers_only = is_offers_only_text(availability_text)
            unavailable = is_unavailable_text(availability_text)

            # Seller
            seller_text = None
            seller_name = None
            seller_selectors = [
                "#merchantInfo #sellerProfileTriggerId",
                "#merchantInfo a",
                "#merchantInfo",
                "#merchantInfoFeature_feature_div",
                "#fulfillerInfoFeature_feature_div",
                "#deliveryBlockMessage span.a-size-base.a-color-secondary",
                "#deliveryBlockMessage",
                "#tabular-buybox .tabular-buybox-text[tabular-attribute-name='Sold by'] a",
                "#tabular-buybox .tabular-buybox-text[tabular-attribute-name='Sold by']",
                "#newAccordionRow_1 #sellerProfileTriggerId",
            ]
            for sel in seller_selectors:
                try:
                    raw = await page.locator(sel).first.inner_text(timeout=1400)
                    raw = clean_text(raw)
                    if not raw:
                        continue
                    if is_seller_label_only_text(raw):
                        continue
                    parsed = extract_seller_name_from_text(raw)
                    if parsed:
                        seller_text = raw
                        seller_name = parsed
                        break
                    if not seller_text:
                        seller_text = raw
                except Exception:
                    continue

            if seller_text and not seller_name:
                seller_name = extract_seller_name_from_text(seller_text)
                if not seller_name:
                    seller_name = normalize_seller_name(seller_text)

            if not seller_name:
                seller_context_selectors = [
                    "#deliveryBlockMessage",
                    "#merchantInfoFeature_feature_div",
                    "#fulfillerInfoFeature_feature_div",
                    "#merchantInfo",
                    "#tabular-buybox",
                ]
                for s2 in seller_context_selectors:
                    try:
                        raw2 = await page.locator(s2).first.inner_text(timeout=1200)
                        raw2 = clean_text(raw2)
                        if not raw2:
                            continue
                        parsed = extract_seller_name_from_text(raw2)
                        if parsed and not is_seller_label_only_text(parsed):
                            seller_text = seller_text or raw2
                            seller_name = parsed
                            break
                    except Exception:
                        continue

            if (not seller_name) and availability_text:
                seller_name = extract_seller_name_from_text(availability_text)
            seller_name = normalize_seller_name(seller_name)

            # Price (strict product-offer selectors only; no generic page-wide price selectors)
            price_text = None
            price_value = None
            source_hint = None
            price_selectors = [
                "#corePriceDisplay_desktop_feature_div span.a-price span.a-offscreen",
                "#corePrice_feature_div span.a-price span.a-offscreen",
                "#corePrice_desktop span.a-price span.a-offscreen",
                "#apex_desktop span.a-price span.a-offscreen",
                "#newAccordionRow_1 span.a-price span.a-offscreen",
                "#priceblock_ourprice",
                "#priceblock_dealprice",
                "#priceblock_saleprice",
            ]
            if not (unavailable or offers_only):
                for sel in price_selectors:
                    try:
                        candidate = await page.locator(sel).first.inner_text(timeout=2500)
                        candidate = clean_text(candidate)
                        if not candidate:
                            continue
                        candidate_value = parse_money_value(candidate)
                        if candidate_value is None:
                            continue
                        price_text = candidate
                        price_value = candidate_value
                        source_hint = sel
                        break
                    except Exception:
                        continue

            # Offers-only fallback: scrape real offer rows from the buying-options panel.
            if offers_only and not price_value:
                offer_pick = await extract_primary_buying_option_offer(page)
                if offer_pick and offer_pick.get("price_value") is not None:
                    price_text = offer_pick.get("price_text")
                    price_value = offer_pick.get("price_value")
                    source_hint = offer_pick.get("source_hint") or "aod-offer"
                    if offer_pick.get("seller_text"):
                        seller_text = offer_pick.get("seller_text")
                    if offer_pick.get("seller_name"):
                        seller_name = offer_pick.get("seller_name")

            if unavailable:
                price_text = "Currently unavailable"
                price_value = None
                source_hint = source_hint or "availability-unavailable"
            elif offers_only and not price_value:
                price_text = "Only available from third-party sellers (see all offers)"
                price_value = None
                source_hint = source_hint or "availability-offers-only"

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
                    t = clean_text(t)
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
                    "seller_text": seller_text,
                    "seller_name": seller_name,
                    "availability_text": availability_text,
                    "source_hint": source_hint,
                }
            )

            await page.close()
            await context.close()
            await browser.close()

    except Exception as e:
        out["error"] = str(e)

    return out


def run_async(coro_fn, *args, **kwargs):
    """Run an async coroutine from sync context."""
    return asyncio.run(coro_fn(*args, **kwargs))


# ---------------- DB item/history logic ----------------

def write_history(item_id, data, force=False):
    """Write a history row with de-duplication by update_interval."""
    data = dict(data or {})
    data["timestamp"] = data.get("timestamp") or now_utc_str()
    data["item_name"] = clean_text(data.get("item_name"))
    data["price_text"] = clean_text(data.get("price_text"))
    data["coupon_text"] = clean_text(data.get("coupon_text"))
    data["seller_text"] = clean_text(data.get("seller_text"))
    data["seller_name"] = clean_text(data.get("seller_name"))
    data["availability_text"] = clean_text(data.get("availability_text"))
    data["source_hint"] = clean_text(data.get("source_hint"))

    def as_float(v):
        try:
            if v is None:
                return None
            return float(v)
        except Exception:
            return None

    conn = db_conn()
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM price_history WHERE item_id=%s ORDER BY ts DESC LIMIT 1",
        (item_id,),
    )
    latest = cur.fetchone()

    # Keep the last known descriptive fields if scrape misses them.
    if (not data.get("item_name")) and latest and latest.get("item_name"):
        data["item_name"] = latest.get("item_name")
    interval_str = get_setting("update_interval", "1800")  # default: 30 minutes
    try:
        interval_sec = int(interval_str)
    except Exception:
        interval_sec = 1800

    meaningful = any(
        [
            data.get("item_name"),
            data.get("price_text"),
            data.get("price_value") is not None,
            data.get("coupon_text"),
            data.get("seller_name"),
            data.get("availability_text"),
            data.get("error"),
        ]
    )
    if not meaningful:
        conn.close()
        return

    insert = True
    if latest and (not force):
        try:
            last_ts = datetime.strptime(latest["ts"], "%Y-%m-%d %H:%M:%S")
            new_ts = datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S")
            within_interval = (new_ts - last_ts).total_seconds() < interval_sec
        except Exception:
            within_interval = False

        if within_interval:
            same_snapshot = (
                as_float(latest.get("price_value")) == as_float(data.get("price_value"))
                and clean_text(latest.get("price_text")) == data.get("price_text")
                and clean_text(latest.get("coupon_text")) == data.get("coupon_text")
                and clean_text(latest.get("seller_name")) == data.get("seller_name")
                and clean_text(latest.get("availability_text")) == data.get("availability_text")
            )
            if same_snapshot:
                insert = False

    if insert:
        cur.execute(
            """
            INSERT INTO price_history(
                item_id, ts, item_name, price_text, price_value, coupon_text,
                discount_percent, error, seller_text, seller_name, availability_text, source_hint
            )
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                data.get("seller_text"),
                data.get("seller_name"),
                data.get("availability_text"),
                data.get("source_hint"),
            ),
        )
        conn.commit()

    conn.close()
    
    # Check for target price alerts
    try:
        check_and_send_target_alert(item_id, data)
    except Exception as e:
        print(f"Alert check error: {e}")


def run_global_scrape(force_write=False):
    """Global scrape: scrape each distinct ASIN once then write to each user's item."""
    if not GLOBAL_SCRAPE_LOCK.acquire(blocking=False):
        return

    try:
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

        # Set start time immediately so concurrent triggers during a long run are skipped.
        set_setting("last_global_run", now_utc_str())

        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
                id,
                COALESCE(NULLIF(url, ''), CONCAT('https://www.amazon.sa/dp/', asin, '?language=en')) AS scrape_url
            FROM items
            """
        )
        rows = cur.fetchall()
        conn.close()

        url_to_item_ids = {}
        for r in rows or []:
            scrape_url = (r.get("scrape_url") or "").strip()
            if not scrape_url:
                continue
            url_to_item_ids.setdefault(scrape_url, []).append(r["id"])

        for scrape_url, item_ids in url_to_item_ids.items():
            try:
                data = run_async(scrape_one_amazon_sa, scrape_url)
            except Exception as e:
                data = {"timestamp": now_utc_str(), "error": str(e)}

            for item_id in item_ids:
                try:
                    write_history(item_id, data, force=force_write)
                except Exception:
                    pass

        set_setting("last_global_run", now_utc_str())
    finally:
        GLOBAL_SCRAPE_LOCK.release()


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
        title = None
        if latest and latest.get("item_name"):
            title = (latest.get("item_name") or "").strip() or None
        if not title:
            cur.execute(
                """
                SELECT item_name
                FROM price_history
                WHERE item_id=%s AND item_name IS NOT NULL AND item_name <> ''
                ORDER BY ts DESC
                LIMIT 1
                """,
                (it["id"],),
            )
            trow = cur.fetchone()
            if trow and trow.get("item_name"):
                title = (trow.get("item_name") or "").strip() or None
        it["latest_name"] = title
        it["latest_price_text"] = latest.get("price_text") if latest else None
        seller = (latest.get("seller_name") or latest.get("seller_text")) if latest else None
        it["latest_seller"] = normalize_seller_name(seller)
        it["latest_availability"] = latest.get("availability_text") if latest else None
        if (not it["latest_price_text"]) and it["latest_availability"]:
            it["latest_price_text"] = it["latest_availability"]
        it["coupon_text"] = latest.get("coupon_text") if latest else None
        enriched.append(it)

    conn.close()

    marketing_deals = get_marketing_deals(user_asins, limit=5)

    return render_template(
        "index.html",
        user={"email": user.get("email") or "", "telegram_chat_id": user.get("telegram_chat_id")},
        items=enriched,
        marketing_deals=marketing_deals,
        announcement=announcement,
        last_run=last_run,
        is_admin=(session.get("role") == "admin") or ((user.get("email") or "").lower() == SUPER_ADMIN_EMAIL.lower()),
    )


@app.route("/price-monitoring")
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

    # This page is meant for subscribed users (Telegram connected)
    if not user.get("telegram_chat_id"):
        conn.close()
        flash("Connect Telegram first to enable price monitoring.", "error")
        return redirect(url_for("telegram_setup"))

    cur.execute(
        """
        SELECT
            i.id,
            i.asin,
            i.url,
            i.created_at,
            i.target_price_value,
            ph.item_name,
            ph.price_text,
            ph.price_value,
            ph.seller_name,
            ph.seller_text,
            ph.effective_seller,
            ph.availability_text,
            ph.ts AS last_price_ts,
            tn.reached_at
        FROM items i
        LEFT JOIN LATERAL (
            SELECT
                item_name,
                price_text,
                price_value,
                seller_name,
                seller_text,
                availability_text,
                ts,
                COALESCE(
                    NULLIF(seller_name, ''),
                    NULLIF(seller_text, '')
                ) AS effective_seller
            FROM price_history
            WHERE item_id = i.id
            ORDER BY ts DESC
            LIMIT 1
        ) ph ON true
        LEFT JOIN (
            SELECT item_id, MIN(notified_at) AS reached_at
            FROM target_notifications
            GROUP BY item_id
        ) tn ON tn.item_id = i.id
        WHERE i.user_id = %s
          AND i.target_price_value IS NOT NULL
        ORDER BY i.created_at DESC
        """,
        (uid,),
    )

    rows = cur.fetchall()
    conn.close()

    items = []
    for r in rows or []:
        name = (r.get("item_name") or "").strip() or r.get("asin") or "Item"

        price_text = (r.get("price_text") or "").strip()
        if not price_text:
            availability = (r.get("availability_text") or "").strip()
            if availability:
                price_text = availability
        if not price_text:
            pv = r.get("price_value")
            try:
                price_text = f"SAR {float(pv):.2f}" if pv is not None else "SAR --"
            except Exception:
                price_text = "SAR --"

        reached_at = r.get("reached_at")
        status = "Still watching ð¦"
        if reached_at:
            status = "Congrats ð¯"

        try:
            target_val = float(r.get("target_price_value")) if r.get("target_price_value") is not None else None
        except Exception:
            target_val = None

        items.append(
            {
                "id": r.get("id"),
                "asin": r.get("asin"),
                "url": r.get("url"),
                "name": name,
                "current_price_text": price_text,
                "seller_name": normalize_seller_name(
                    (r.get("effective_seller") or r.get("seller_name") or r.get("seller_text") or "").strip() or None
                ),
                "availability_text": (r.get("availability_text") or "").strip() or None,
                "target_price_value": target_val,
                "reached_at": reached_at,
                "status": status,
            }
        )

    is_admin = (session.get("role") == "admin") or ((user.get("email") or "").lower() == SUPER_ADMIN_EMAIL.lower())

    return render_template(
        "price_monitoring.html",
        user={"email": user.get("email") or "", "telegram_chat_id": user.get("telegram_chat_id")},
        items=items,
        is_admin=is_admin,
    )



@app.route("/add", methods=["POST"])
@login_required
def add():
    raw = (request.form.get("item") or "").strip()
    asin = extract_asin(raw)
    # Resolve redirects for Amazon links (including short links like amzn.eu) and extract ASIN.
    if (not asin) and raw.lower().startswith(("http://", "https://")):
        try:
            if re.search(r"https?://([^/]+\.)?(amzn\.(eu|to)|amazon\.)", raw, re.IGNORECASE):
                r = requests.get(raw, allow_redirects=True, timeout=12, headers={"User-Agent": USER_AGENT})
                candidates = [raw, (r.url or "").strip()] + [(h.url or "").strip() for h in (r.history or [])]
                for u in candidates:
                    if not u:
                        continue
                    found = extract_asin(u)
                    if found:
                        asin = found
                        raw = (r.url or u).strip()
                        break
                if (not asin) and r.text:
                    m = re.search(r"/(?:dp|gp/product|gp/aw/d)/([A-Z0-9]{10})", r.text, re.IGNORECASE)
                    if m:
                        asin = m.group(1).upper()
                        raw = (r.url or raw).strip()
        except Exception:
            pass
    if not asin:
        flash("Please paste a valid Amazon.sa link or ASIN.", "error")
        return redirect(url_for("index"))

    url = raw
    if "http://" not in raw and "https://" not in raw:
        url = f"https://www.amazon.sa/dp/{asin}?language=en"

    conn = db_conn()
    cur = conn.cursor()
    uid = session.get("user_id")

    # â Explicit duplicate check (prevents false 'already in your list' on other DB errors)
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
            write_history(row["id"], data, force=True)
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
    next_ = request.args.get("next") or request.form.get("next") or ""
    if next_ == "monitoring":
        return redirect(url_for("price_monitoring"))
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
        scrape_target = (item.get("url") or "").strip() or f"https://www.amazon.sa/dp/{item['asin']}?language=en"
        data = run_async(scrape_one_amazon_sa, scrape_target)
        write_history(item["id"], data, force=True)
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
                   (SELECT ph.item_name FROM price_history ph WHERE ph.item_id=i.id AND ph.item_name IS NOT NULL AND ph.item_name <> '' ORDER BY ph.ts DESC LIMIT 1) AS latest_name,
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

    elif tab == "clear_data":
        cur.execute(
            """
            SELECT
                i.id,
                i.asin,
                i.created_at,
                u.email AS user_email,
                COALESCE(
                    (SELECT ph2.item_name
                     FROM price_history ph2
                     WHERE ph2.item_id = i.id
                       AND ph2.item_name IS NOT NULL
                       AND ph2.item_name <> ''
                     ORDER BY ph2.ts DESC
                     LIMIT 1),
                    i.asin
                ) AS latest_name,
                COUNT(ph.id) AS records_count,
                COALESCE(SUM(pg_column_size(ph)), 0) AS history_bytes
            FROM items i
            JOIN users u ON u.id = i.user_id
            LEFT JOIN price_history ph ON ph.item_id = i.id
            GROUP BY i.id, u.email
            ORDER BY history_bytes DESC, records_count DESC, i.created_at DESC
            """
        )
        rows = cur.fetchall() or []
        for r in rows:
            try:
                r["records_count"] = int(r.get("records_count") or 0)
            except Exception:
                r["records_count"] = 0
            try:
                r["history_bytes"] = int(r.get("history_bytes") or 0)
            except Exception:
                r["history_bytes"] = 0
            r["history_size"] = format_bytes(r.get("history_bytes"))
        data["clear_items"] = rows

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
    threading.Thread(target=run_global_scrape, kwargs={"force_write": True}, daemon=True).start()
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
        scrape_target = (item.get("url") or "").strip() or f"https://www.amazon.sa/dp/{item['asin']}?language=en"
        data = run_async(scrape_one_amazon_sa, scrape_target)
        write_history(item["id"], data, force=True)
        flash("Item updated successfully.", "ok")
    except Exception as e:
        flash(f"Update failed: {e}", "error")

    return redirect(url_for("admin_portal", tab="items"))


@app.route("/admin/item/<int:item_id>/clear-history", methods=["POST"])
@admin_required
def admin_clear_item_history(item_id):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM price_history WHERE item_id=%s", (item_id,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    flash(f"Cleared {deleted} history records.", "ok")
    return redirect(url_for("admin_portal", tab="clear_data"))


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
    reset_link = url_for("reset", token=token, _external=True)
    sent, err = send_password_reset_email(email, reset_link)
    if sent:
        flash("If that email exists, you will get a reset link.", "ok")
    else:
        # Fallback keeps password reset usable even if SMTP is not configured.
        flash(f"Email not sent ({err}). Reset link (copy/paste): {reset_link}", "error")
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
    # Keep plain uptime probes lightweight.
    if request.method == "HEAD" and not (request.headers.get("X-CRON-TOKEN") or request.args.get("token")):
        return "", 200

    if not CRON_TOKEN:
        return "CRON_TOKEN not set", 400

    token = request.headers.get("X-CRON-TOKEN") or request.args.get("token") or ""
    if not hmac.compare_digest(token, CRON_TOKEN):
        return "Unauthorized", 401

    if request.method == "GET":
        return jsonify(
            {
                "ok": True,
                "running": GLOBAL_SCRAPE_LOCK.locked(),
                "last_run": get_setting("last_global_run", None),
            }
        ), 200

    if GLOBAL_SCRAPE_LOCK.locked():
        return "Already running", 202

    force_write = (request.args.get("force") or "").strip().lower() in {"1", "true", "yes", "on"}
    threading.Thread(target=run_global_scrape, kwargs={"force_write": force_write}, daemon=True).start()
    return "OK started", 202


# ---------------- Telegram Bot Routes ----------------

@app.route("/telegram-setup")
@login_required
def telegram_setup():
    bot_username = os.environ.get("TELEGRAM_BOT_USERNAME", "PriceHawkSABot")
    user_id = session.get("user_id")
    
    # Generate a unique link token
    link_token = hashlib.sha256(f"{user_id}:{APP_SECRET}:{time.time()}".encode()).hexdigest()[:16]
    set_setting(f"telegram_link_{user_id}", link_token)
    
    telegram_link = f"https://t.me/{bot_username}?start={link_token}"
    
    return render_template(
        "telegram_setup.html",
        bot_username=bot_username,
        link_token=link_token,
        telegram_link=telegram_link
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
                                    "text": "ð¦ *PriceHawk Connected!*\n\nYou'll now receive instant alerts when your tracked items hit target prices.\n\n_Go add items and set target prices on your dashboard_",
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
