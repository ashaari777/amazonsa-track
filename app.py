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
from email.utils import formataddr
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
PLAYWRIGHT_TIMEOUT_MS = int(os.environ.get("PLAYWRIGHT_TIMEOUT_MS", "30000")) 
BLOCK_HEAVY_RESOURCES = os.environ.get("BLOCK_HEAVY_RESOURCES", "1") == "1"

ENABLE_EMAIL = False # Disabled for stability on free tier

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
        exit(1)
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

def init_db():
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT, role TEXT DEFAULT 'user', created_at TEXT, last_login_at TEXT, ip_address TEXT, device_name TEXT, location TEXT, is_paused BOOLEAN DEFAULT FALSE, is_approved BOOLEAN DEFAULT FALSE, item_limit INTEGER DEFAULT 20);")
    cur.execute("CREATE TABLE IF NOT EXISTS items (id SERIAL PRIMARY KEY, user_id INTEGER, asin TEXT, url TEXT, target_price REAL, last_alert_sent TEXT, created_at TEXT, UNIQUE(user_id, asin), FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);")
    cur.execute("CREATE TABLE IF NOT EXISTS price_history (id SERIAL PRIMARY KEY, item_id INTEGER, ts TEXT, item_name TEXT, price_text TEXT, price_value REAL, coupon_text TEXT, rating REAL, reviews_count INTEGER, discount_percent INTEGER, error TEXT, FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE CASCADE);")
    cur.execute("CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT);")
    conn.commit(); conn.close()

try: init_db()
except: pass

# ---------------- Helpers ----------------

def get_setting(key, default=None):
    try:
        conn = db_conn(); cur = conn.cursor()
        cur.execute("SELECT value FROM system_settings WHERE key=%s", (key,))
        row = cur.fetchone(); conn.close()
        return row['value'] if row else default
    except: return default

def send_alert_email(to_email, asin, item_name, price, is_coupon=False):
    if not ENABLE_EMAIL: return
    pass

def send_new_user_alert(new_user_email):
    if not ENABLE_EMAIL: return
    pass

def get_location_from_ip(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3); data = r.json()
        if data['status'] == 'success': return f"{data.get('city')}, {data.get('country')}"
    except: pass
    return "Unknown"

def clean(t): return re.sub(r"\s+", " ", t).strip() if t else None
def extract_asin(text):
    text = text.strip()
    if re.fullmatch(r"[A-Z0-9]{10}", text): return text
    m = re.search(r"/dp/([A-Z0-9]{10})", text)
    return m.group(1) if m else None
def canonical_url(asin): return f"https://www.amazon.sa/dp/{asin}"
def parse_money_value(t):
    if not t: return None
    m = re.search(r"([\d,]+(?:\.\d+)?)", t)
    return float(m.group(1).replace(",", "")) if m else None
def first_number(t):
    if not t: return None
    m = re.search(r"([\d.]+)", t)
    return float(m.group(1)) if m else None
def first_int_like(t):
    if not t: return None
    m = re.search(r"([\d,]+)", t)
    return int(m.group(1).replace(",", "")) if m else None

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
    page.set_default_timeout(30000)
    
    data = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "asin": asin, "error": None, "item_name": None, "price_text": None, "price_value": None,
        "coupon_text": None, "discount_percent": None
    }

    try:
        url = f"https://www.amazon.sa/dp/{asin}"
        await page.goto(url, wait_until="domcontentloaded")
        
        # Title
        try:
            await page.wait_for_selector("#productTitle", timeout=5000)
            data["item_name"] = (await page.locator("#productTitle").first.text_content()).strip()
        except:
            try: data["item_name"] = (await page.locator("h1").first.text_content()).strip()
            except: pass

        if not data["item_name"]: 
            print(f"[{asin}] BLOCKED: No Title")
            raise Exception("Blocked")

        # Price (Aggressive Search)
        for sel in [
            ".priceToPay .a-offscreen", 
            ".apexPriceToPay .a-offscreen", 
            "#corePrice_feature_div .a-price .a-offscreen", 
            "#corePriceDisplay_desktop_feature_div .a-price .a-offscreen",
            ".a-price .a-offscreen",
            "span.a-price:not(.a-text-price) > span.a-offscreen"
        ]:
            try:
                txt = await page.locator(sel).first.text_content()
                if txt:
                    data["price_text"] = txt.strip()
                    m = re.search(r"([\d,]+(?:\.\d+)?)", txt)
                    if m: 
                        data["price_value"] = float(m.group(1).replace(",", ""))
                        break
            except: pass

        # Coupons (Enhanced)
        coupons_found = []
        try:
            coupon_els = page.locator("label[id*='coupon']").all_inner_texts()
            for c in await coupon_els:
                c = clean(c)
                if c: coupons_found.append(c)
        except: pass
        
        # Text-based Offers
        try:
            promo_texts = await page.locator(".promoPriceBlockMessage, #instant-order-update, .a-section.a-spacing-small span").all_inner_texts()
            for txt in promo_texts:
                txt = clean(txt)
                if txt and any(k in txt for k in ["Savings", "promo code", "Credit Cards", "Bank", "Save %", "off"]):
                    if len(txt) < 150: coupons_found.append(txt)
        except: pass

        # Extract only the important part (percentage) for the UI
        coupon_display = []
        for c in coupons_found:
             m = re.search(r"(\d+%)|(SAR\s?\d+)", c)
             if m: coupon_display.append(m.group(0))
        
        if coupon_display:
            data["coupon_text"] = " | ".join(list(set(coupon_display)))
        elif coupons_found:
            # Fallback to full text if no % found
            data["coupon_text"] = "Coupon Available"

        # Discount Badge
        try:
            txt = await page.locator(".savingsPercentage").first.text_content()
            if txt:
                m = re.search(r"(\d{1,3})\s*%", txt)
                if m: data["discount_percent"] = int(m.group(1))
        except: pass

    except Exception as e: 
        data["error"] = str(e)
    finally:
        try: await page.close(); await context.close()
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
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-blink-features=AutomationControlled"]
                )
                for asin in batch:
                    print(f"Scraping {asin}...") 
                    await asyncio.sleep(random.uniform(3.0, 6.0))
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
    
    interval_str = get_setting('update_interval', '3600') # Default 1 Hour
    interval_sec = int(interval_str)

    insert = True
    if latest:
        if latest["price_value"] == data["price_value"]:
            last = datetime.strptime(str(latest["ts"]), "%Y-%m-%d %H:%M:%S")
            diff = (datetime.utcnow() - last).total_seconds()
            
            # If less than interval, just update timestamp (don't add new row)
            if diff < interval_sec:
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

# ---------------- Routes & Cron ----------------

# (Auth and Admin routes omitted for brevity - Keep them as they were in previous version)
# Ensure you copy register, login, logout, admin_users, admin_items, etc.

# --- CRON (Fixed Logic: Check time FIRST) ---
def run_global_scrape():
    if not SCRAPE_LOCK.acquire(blocking=False): return
    try:
        # Check Last Run Time First!
        conn = db_conn(); cur = conn.cursor()
        cur.execute("SELECT MAX(ts) as last_run FROM price_history")
        row = cur.fetchone()
        
        interval_str = get_setting('update_interval', '3600')
        interval_sec = int(interval_str)

        if row and row['last_run']:
            last_run = datetime.strptime(str(row['last_run']), "%Y-%m-%d %H:%M:%S")
            diff = (datetime.utcnow() - last_run).total_seconds()
            if diff < interval_sec:
                print(f"Skipping Scrape: Last run was {int(diff/60)} mins ago (Limit: {int(interval_sec/60)} mins)")
                conn.close()
                return

        # Proceed with scraping
        cur.execute("SELECT DISTINCT asin FROM items")
        rows = cur.fetchall()
        asins = [r['asin'] for r in rows]
        conn.close()

        results = run_async(scrape_many_sequential_with_delays, asins)

        conn = db_conn(); cur = conn.cursor()
        for asin, data in results.items():
            cur.execute("SELECT i.id, i.target_price, u.email FROM items i JOIN users u ON i.user_id=u.id WHERE i.asin=%s", (asin,))
            for item in cur.fetchall():
                write_history(item['id'], data)
                # Emails disabled
        conn.close()
        print(f"Scrape Finished: {len(asins)} items.")
    finally:
        SCRAPE_LOCK.release()

@app.route("/cron/update-all", methods=["GET", "POST", "HEAD"])
def cron():
    token = request.args.get("token")
    if token != CRON_TOKEN: return "401", 401
    # Trigger background thread
    threading.Thread(target=run_global_scrape).start()
    return "OK", 200

# (Include all other routes: index, add, delete, admin_*, etc.)

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
