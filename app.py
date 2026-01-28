import os
import re
import sqlite3
import asyncio
import threading
from datetime import datetime
from typing import Optional

from flask import Flask, request, render_template, redirect, url_for, jsonify
from playwright.async_api import async_playwright

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "amazon_tracker.db")

# ----------------- DB -----------------

def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS items (
        asin TEXT PRIMARY KEY,
        url TEXT,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS price_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asin TEXT NOT NULL,
        ts TEXT NOT NULL,
        item_name TEXT,
        price_text TEXT,
        price_value REAL,
        rating REAL,
        reviews_count INTEGER,
        discount_percent INTEGER,
        seller_name TEXT,
        error TEXT,
        FOREIGN KEY (asin) REFERENCES items(asin)
    )
    """)

    conn.commit()
    conn.close()


# IMPORTANT: run at import time for gunicorn
init_db()

# ----------------- Helpers -----------------

ASIN_RE = re.compile(r"/dp/([A-Z0-9]{10})|/gp/product/([A-Z0-9]{10})|(?:^|[^A-Z0-9])([A-Z0-9]{10})(?:[^A-Z0-9]|$)")

def extract_asin(text: str) -> Optional[str]:
    if not text:
        return None
    m = ASIN_RE.search(text.upper())
    if not m:
        return None
    for g in m.groups():
        if g:
            return g
    return None


def clean(t: Optional[str]) -> Optional[str]:
    if not t:
        return None
    return re.sub(r"\s+", " ", t).strip()


def first_number(t: Optional[str]) -> Optional[float]:
    if not t:
        return None
    m = re.search(r"([\d.]+)", t)
    return float(m.group(1)) if m else None


def first_int_like(t: Optional[str]) -> Optional[int]:
    if not t:
        return None
    m = re.search(r"([\d,]+)", t)
    return int(m.group(1).replace(",", "")) if m else None


def parse_money(t: Optional[str]) -> Optional[float]:
    if not t:
        return None
    # Amazon sometimes shows "SAR 1,234.00" or "1,234.00"
    m = re.search(r"([\d,]+(?:\.\d+)?)", t.replace("\u00a0", " "))
    if not m:
        return None
    return float(m.group(1).replace(",", ""))


async def pick_first_text(page, selectors) -> Optional[str]:
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            txt = clean(await loc.text_content())
            if txt:
                return txt
        except Exception:
            pass
    return None


async def auto_nudge(page) -> None:
    try:
        await page.evaluate("window.scrollTo(0, 650)")
        await page.wait_for_timeout(120)
        await page.evaluate("window.scrollTo(0, 0)")
        await page.wait_for_timeout(80)
    except Exception:
        pass


async def wait_for_any_title(page, timeout_ms=9000) -> None:
    for sel in ["#productTitle", "h1 span", "h1", "[data-cy='title-recipe']"]:
        try:
            await page.wait_for_selector(sel, timeout=timeout_ms)
            return
        except Exception:
            continue
    raise TimeoutError("Title not found")


def run_async(coro_fn, *args, **kwargs):
    """
    Safely run async Playwright code from Flask (sync request handlers)
    by executing asyncio.run() inside a separate thread.
    """
    out = {"result": None, "error": None}

    def _t():
        try:
            out["result"] = asyncio.run(coro_fn(*args, **kwargs))
        except Exception as e:
            out["error"] = e

    t = threading.Thread(target=_t, daemon=True)
    t.start()
    t.join()

    if out["error"]:
        raise out["error"]
    return out["result"]

# ----------------- Playwright -----------------

async def make_page():
    """
    One browser/page with speed + memory optimizations (Render-friendly)
    """
    p = await async_playwright().start()

    browser = await p.chromium.launch(
        headless=True,
        args=[
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
        ],
    )

    context = await browser.new_context(
        locale="en-US",
        viewport={"width": 1280, "height": 720},
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/121.0.0.0 Safari/537.36"
        ),
    )

    page = await context.new_page()

    # Block heavy resources to reduce memory
    async def route_handler(route, req):
        if req.resource_type in ("image", "media", "font"):
            await route.abort()
        else:
            await route.continue_()

    await page.route("**/*", route_handler)

    await page.set_extra_http_headers({
        "Accept-Language": "en-US,en;q=0.9,ar;q=0.8"
    })

    page.set_default_timeout(15000)
    return p, browser, page


async def scrape_one(page, asin: str) -> dict:
    canonical = f"https://www.amazon.sa/dp/{asin}"

    # default result shape
    base = {
        "asin": asin,
        "url": canonical,
        "item_name": None,
        "price_text": None,
        "price_value": None,
        "rating": None,
        "reviews_count": None,
        "discount_percent": None,
        "error": None,
    }

    try:
        await page.goto(canonical, wait_until="domcontentloaded", timeout=25000)
        await auto_nudge(page)

        # Detect captcha / robot check
        title = clean(await page.title())
        cur_url = page.url or ""
        if title and ("robot check" in title.lower() or "captcha" in title.lower()):
            base["error"] = f"Blocked by Amazon (captcha): {title}"
            return base
        if "validatecaptcha" in cur_url.lower() or "captcha" in cur_url.lower():
            base["error"] = f"Blocked by Amazon (captcha) url: {cur_url}"
            return base

        # Wait for title area to exist
        try:
            await wait_for_any_title(page, timeout_ms=9000)
        except Exception:
            # one more nudge + retry
            await auto_nudge(page)
            await wait_for_any_title(page, timeout_ms=9000)

        await auto_nudge(page)

    except Exception as e:
        base["error"] = f"Page load failed: {str(e)}"
        return base

    item_name = await pick_first_text(page, ["#productTitle", "h1 span", "h1", "[data-cy='title-recipe']"])

    price_text = await pick_first_text(page, [
        "#corePriceDisplay_desktop_feature_div .a-price .a-offscreen",
        "#corePrice_feature_div .a-price .a-offscreen",
        "span[data-a-color='price'] span.a-offscreen",
        "#priceblock_ourprice",
        "#priceblock_dealprice",
        "span.a-price > span.a-offscreen",
        ".a-price .a-offscreen",
    ])
    price_value = parse_money(price_text)

    rating_text = None
    try:
        rating_text = clean(await page.locator("#acrPopover").first.get_attribute("title"))
    except Exception:
        pass
    if not rating_text:
        rating_text = await pick_first_text(page, ["span[data-hook='rating-out-of-text']", "#acrPopover"])
    rating = first_number(rating_text)

    reviews_text = await pick_first_text(page, [
        "#acrCustomerReviewText",
        "span[data-hook='total-review-count']",
        "#acrCustomerReviewText span",
    ])
    reviews_count = first_int_like(reviews_text)

    discount_percent = None
    discount_text = await pick_first_text(page, [
        ".savingsPercentage",
        "#corePriceDisplay_desktop_feature_div .savingsPercentage",
        "span.savingsPercentage",
    ])
    if discount_text:
        m = re.search(r"(\d{1,3})\s*%", discount_text)
        if m:
            discount_percent = int(m.group(1))

    # compute discount if possible
    if discount_percent is None:
        list_price_text = await pick_first_text(page, [
            "#corePriceDisplay_desktop_feature_div span.a-price.a-text-price span.a-offscreen",
            "#corePrice_feature_div span.a-price.a-text-price span.a-offscreen",
            "span.a-price.a-text-price span.a-offscreen",
        ])
        old = parse_money(list_price_text)
        cur = price_value
        if cur and old and old > cur:
            discount_percent = int(round((old - cur) / old * 100))

    # If everything is None, likely blocked or different DOM -> store a meaningful error
    if not item_name and not price_text:
        base["error"] = base["error"] or "No title/price found (blocked or DOM changed)"
        return base

    return {
        "asin": asin,
        "url": canonical,
        "item_name": item_name,
        "price_text": price_text,
        "price_value": price_value,
        "rating": rating,
        "reviews_count": reviews_count,
        "discount_percent": discount_percent,
        "error": None,
    }


async def scrape_many(asins: list[str]) -> list[dict]:
    if not asins:
        return []
    p, browser, page = await make_page()
    results: list[dict] = []
    try:
        for i, asin in enumerate(asins):
            try:
                # per-item timeout
                r = await asyncio.wait_for(scrape_one(page, asin), timeout=30.0)
                results.append(r)
            except asyncio.TimeoutError:
                results.append({
                    "asin": asin,
                    "url": f"https://www.amazon.sa/dp/{asin}",
                    "item_name": None,
                    "price_text": None,
                    "price_value": None,
                    "rating": None,
                    "reviews_count": None,
                    "discount_percent": None,
                    "error": "Scraping timeout",
                })
            except Exception as e:
                results.append({
                    "asin": asin,
                    "url": f"https://www.amazon.sa/dp/{asin}",
                    "item_name": None,
                    "price_text": None,
                    "price_value": None,
                    "rating": None,
                    "reviews_count": None,
                    "discount_percent": None,
                    "error": str(e),
                })

            if i < len(asins) - 1:
                await asyncio.sleep(1)

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

# ----------------- History insert -----------------

def insert_history(ts: str, r: dict):
    conn = db_conn()
    conn.execute("""
        INSERT INTO price_history
        (asin, ts, item_name, price_text, price_value, rating, reviews_count, discount_percent, seller_name, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        r["asin"], ts, r.get("item_name"), r.get("price_text"), r.get("price_value"),
        r.get("rating"), r.get("reviews_count"), r.get("discount_percent"),
        None,
        r.get("error")
    ))
    conn.commit()
    conn.close()

# ----------------- Routes -----------------

@app.route("/", methods=["GET"])
def index():
    conn = db_conn()
    items = conn.execute("SELECT asin, url, created_at FROM items ORDER BY created_at DESC").fetchall()

    latest = conn.execute("""
        SELECT h.*
        FROM price_history h
        JOIN (
            SELECT asin, MAX(ts) AS max_ts
            FROM price_history
            GROUP BY asin
        ) x ON x.asin = h.asin AND x.max_ts = h.ts
        ORDER BY h.ts DESC
    """).fetchall()

    latest_by_asin = {r["asin"]: r for r in latest}
    conn.close()

    return render_template("index.html", items=items, latest_by_asin=latest_by_asin)


@app.route("/add", methods=["POST"])
def add_item():
    raw = request.form.get("item", "").strip()
    asin = extract_asin(raw)
    if not asin:
        return redirect(url_for("index"))

    url = f"https://www.amazon.sa/dp/{asin}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    conn = db_conn()
    conn.execute("INSERT OR IGNORE INTO items (asin, url, created_at) VALUES (?, ?, ?)", (asin, url, now))
    conn.commit()
    conn.close()

    return redirect(url_for("index"))


@app.route("/delete/<asin>", methods=["POST"])
def delete_item(asin):
    conn = db_conn()
    conn.execute("DELETE FROM price_history WHERE asin = ?", (asin,))
    conn.execute("DELETE FROM items WHERE asin = ?", (asin,))
    conn.commit()
    conn.close()
    return redirect(url_for("index"))


@app.route("/update", methods=["POST"])
def update_all():
    conn = db_conn()
    rows = conn.execute("SELECT asin FROM items ORDER BY created_at DESC").fetchall()
    conn.close()

    asins = [r["asin"] for r in rows]
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")

    results = run_async(scrape_many, asins)
    for r in results:
        insert_history(ts, r)

    return redirect(url_for("index"))


@app.route("/update/<asin>", methods=["POST"])
def update_one(asin):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")

    results = run_async(scrape_many, [asin])
    r = results[0] if results else {
        "asin": asin,
        "url": f"https://www.amazon.sa/dp/{asin}",
        "item_name": None,
        "price_text": None,
        "price_value": None,
        "rating": None,
        "reviews_count": None,
        "discount_percent": None,
        "error": "No result",
    }

    insert_history(ts, r)
    return redirect(url_for("index"))


@app.route("/history/<asin>.json", methods=["GET"])
def history_json(asin):
    conn = db_conn()
    rows = conn.execute("""
        SELECT ts, price_value, discount_percent
        FROM price_history
        WHERE asin = ?
        ORDER BY ts ASC
    """, (asin,)).fetchall()
    conn.close()

    return jsonify({
        "asin": asin,
        "labels": [r["ts"] for r in rows],
        "prices": [r["price_value"] for r in rows],
        "discounts": [r["discount_percent"] for r in rows],
    })


if __name__ == "__main__":
    print("Starting server...")
    app.run(host="127.0.0.1", port=5000, debug=True)
