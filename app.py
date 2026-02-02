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
PLAYWRIGHT_TIMEOUT_MS = int(os.environ.get("PLAYWRIGHT_TIMEOUT_MS", "20000")) 
BLOCK_HEAVY_RESOURCES = os.environ.get("BLOCK_HEAVY_RESOURCES", "1") == "1"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
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
    # (Table creation scripts kept same as before for brevity)
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
    if not EMAIL_USER or not EMAIL_PASS: return
    
    if is_coupon:
        subject = f"Coupon Alert: {item_name[:30]}..."
        body_content = f"<p>A new <strong>Coupon</strong> is available for <strong>{item_name}</strong>!</p>"
    else:
        subject = f"Price Drop: {item_name[:30]}..."
        body_content = f"<p><strong>{item_name}</strong> has dropped to <strong>{price} SAR</strong>.</p>"

    body = f"""
    <div style="font-family:sans-serif; color:#333;">
        <h2 style="color:#d53369;">Zarss Alert</h2>
        {body_content}
        <p><a href="https://www.amazon.sa/dp/{asin}" style="background:#d53369; color:white; padding:10px 20px; text-decoration:none; border-radius:5px;">Buy Now</a></p>
    </div>
    """
    msg = MIMEMultipart()
    msg['From'] = formataddr(("Zarss Tracker", EMAIL_USER))
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.add_header('Reply-To', 'no-reply@gmail.com')
    msg.attach(MIMEText(body, 'html'))
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, to_email, msg.as_string())
        server.quit()
    except Exception as e: print(f"Email error: {e}")

def send_new_user_alert(new_user_email):
    # Only notify if NOTIFICATION_EMAIL is set
    if NOTIFICATION_EMAIL:
        body = f"<h3>New User</h3><p>{new_user_email} is waiting for approval.</p>"
        msg = MIMEMultipart()
        msg['From'] = formataddr(("Zarss Admin", EMAIL_USER))
        msg['To'] = NOTIFICATION_EMAIL
        msg['Subject'] = "New User Registration"
        msg.attach(MIMEText(body, 'html'))
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587); server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, NOTIFICATION_EMAIL, msg.as_string()); server.quit()
        except: pass

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
    page.set_default_timeout(20000)
    
    data = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "asin": asin, "error": None, "item_name": None, "price_text": None, "price_value": None,
        "coupon_text": None, "discount_percent": None
    }

    try:
        await page.goto(f"https://www.amazon.sa/dp/{asin}", wait_until="domcontentloaded")
        try: 
            await page.wait_for_selector("#productTitle", timeout=10000)
            data["item_name"] = (await page.locator("#productTitle").first.text_content()).strip()
        except: pass

        if not data["item_name"]: raise Exception("Blocked")

        # Price
        for sel in [".priceToPay .a-offscreen", ".apexPriceToPay .a-offscreen", "#corePrice_feature_div .a-price .a-offscreen"]:
            try:
                txt = await page.locator(sel).first.text_content()
                if txt:
                    data["price_text"] = txt.strip()
                    m = re.search(r"([\d,]+(?:\.\d+)?)", txt)
                    if m: data["price_value"] = float(m.group(1).replace(",", ""))
                    break
            except: pass

        # Coupon
        coupons = []
        try:
            els = page.locator("label[id*='coupon']").all_inner_texts()
            for c in await els:
                m = re.search(r"(\d+%)|(SAR\s?\d+)", c)
                if m: coupons.append(m.group(0))
        except: pass
        
        try:
            promos = page.locator("span:has-text('promo code'), span:has-text('Save %'), span:has-text('Savings')")
            count = await promos.count()
            for i in range(count):
                txt = await promos.nth(i).text_content()
                m = re.search(r"(\d+%)|(SAR\s?\d+)", txt)
                if m: coupons.append(m.group(0))
        except: pass
        if coupons: data["coupon_text"] = " | ".join(list(set(coupons)))

        # Discount
        try:
            txt = await page.locator(".savingsPercentage").first.text_content()
            if txt:
                m = re.search(r"(\d{1,3})\s*%", txt)
                if m: data["discount_percent"] = int(m.group(1))
        except: pass

    except Exception as e: data["error"] = str(e)
    finally:
        try: await page.close(); await context.close()
        except: pass

    if data["price_value"] and data["price_value"] < 1: data["price_value"] = None
    if data["price_value"] and not data["price_text"]: data["price_text"] = f"SAR {data['price_value']:.2f}"

    return data

async def scrape_many_sequential_with_delays(asins):
    results = {}
    def chunked(l, n):
        for i in range(0, len(l), n): yield l[i:i + n]
    for batch in chunked(asins, 4):
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
                for asin in batch:
                    await asyncio.sleep(random.uniform(2.0, 5.0))
                    results[asin] = await scrape_one_with_context(browser, asin)
                await browser.close()
        except: pass
    return results

def run_async(coro, *args):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro(*args))

# ---------------- DB Write Logic (Dynamic Interval) ----------------

def write_history(item_id, data):
    if not data["price_value"]: return
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM price_history WHERE item_id=%s ORDER BY ts DESC LIMIT 1", (item_id,))
    latest = cur.fetchone()
    
    # FETCH INTERVAL SETTING (Default 4 hours = 14400s)
    interval_str = get_setting('update_interval', '14400')
    interval_sec = int(interval_str)

    insert = True
    if latest:
        if latest["price_value"] == data["price_value"]:
            last = datetime.strptime(str(latest["ts"]), "%Y-%m-%d %H:%M:%S")
            diff = (datetime.utcnow() - last).total_seconds()
            
            # If time passed is LESS than interval, just update timestamp (don't create new row)
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

# ---------------- Routes ----------------

# (Standard Auth Routes & Helpers Omitted for Brevity - They remain exactly as previous version)
# Assume clean, extract_asin, canonical_url, get_location_from_ip, login_required, admin_required exist here.
# COPY THEM FROM PREVIOUS IF NEEDED, OR I CAN PROVIDE FULL FILE AGAIN.
# ... [Insert Auth Helpers & Routes Here] ...

# ... (Insert Register/Login/Logout/Add/Delete/Update/HistoryJSON Routes Here) ...
# Assuming standard CRUD routes from previous logic are here.

# --- ADMIN ROUTES ---

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM users"); total_users = cur.fetchone()['c']
    cur.execute("SELECT COUNT(*) as c FROM items"); total_items = cur.fetchone()['c']
    cur.execute("SELECT asin, COUNT(*) as c FROM items GROUP BY asin ORDER BY c DESC LIMIT 5")
    trending = cur.fetchall()
    announcement = get_setting('announcement')
    interval = get_setting('update_interval', '14400') # Get current interval
    conn.close()
    return render_template("admin_dashboard.html", total_users=total_users, total_items=total_items, trending=trending, announcement=announcement, interval=interval)

@app.route("/admin/settings/interval", methods=["POST"])
@admin_required
def set_update_interval():
    val = request.form.get("interval") # 14400 or 600
    conn = db_conn(); cur = conn.cursor()
    cur.execute("INSERT INTO system_settings (key, value) VALUES ('update_interval', %s) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", (val,))
    conn.commit(); conn.close()
    flash(f"Update interval set to {int(val)//60} minutes.", "ok")
    return redirect(url_for("admin_dashboard"))

# --- CRON ---
def run_global_scrape():
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT DISTINCT asin FROM items"); rows = cur.fetchall(); conn.close()
    asins = [r['asin'] for r in rows]
    if not asins: return
    results = run_async(scrape_many_sequential_with_delays, asins)
    
    conn = db_conn(); cur = conn.cursor()
    for asin, data in results.items():
        cur.execute("SELECT i.id, i.target_price, u.email FROM items i JOIN users u ON i.user_id=u.id WHERE i.asin=%s", (asin,))
        rows = cur.fetchall()
        
        # Check if this item HAD a coupon before this scrape
        cur.execute("SELECT coupon_text FROM price_history ph JOIN items i ON ph.item_id=i.id WHERE i.asin=%s ORDER BY ph.ts DESC LIMIT 1", (asin,))
        prev_row = cur.fetchone()
        prev_coupon = prev_row['coupon_text'] if prev_row else None
        
        new_coupon = data.get('coupon_text')
        
        for r in rows:
            write_history(r['id'], data)
            
            # PRICE Alert
            if data['price_value'] and r['target_price'] and data['price_value'] <= r['target_price']:
                send_alert_email(r['email'], asin, data['item_name'], data['price_value'])
            
            # COUPON Alert (Only if new coupon appeared)
            if new_coupon and new_coupon != prev_coupon:
                send_alert_email(r['email'], asin, data['item_name'], data['price_value'], is_coupon=True)

    conn.close()

@app.route("/cron/update-all", methods=["GET", "POST", "HEAD"])
def cron():
    token = request.args.get("token")
    if token != CRON_TOKEN: return "401", 401
    threading.Thread(target=run_global_scrape).start()
    return "OK", 200

# (For testing, include main execution)
if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)