import re
import sqlite3
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, jsonify
from playwright.sync_api import sync_playwright

app = Flask(__name__)
DB_PATH = "amazon_tracker.db"


# ----------------- DB -----------------

def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db_conn()
    cur = conn.cursor()

    # Saved items (persistent watchlist/cart)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS items (
        asin TEXT PRIMARY KEY,
        url TEXT,
        created_at TEXT
    )
    """)

    # History table (keep seller_name column if it exists in your DB; we will not use it)
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

# IMPORTANT: ensure DB tables exist when app is imported by gunicorn
init_db()


# ----------------- Scraper helpers -----------------

def extract_asin(text: str) -> str | None:
    text = (text or "").strip()
    if re.fullmatch(r"[A-Z0-9]{10}", text):
        return text

    m = re.search(r"/dp/([A-Z0-9]{10})", text)
    if m:
        return m.group(1)
    m = re.search(r"/gp/product/([A-Z0-9]{10})", text)
    if m:
        return m.group(1)
    return None


def clean(t: str | None) -> str | None:
    if not t:
        return None
    return re.sub(r"\s+", " ", t).strip()


def first_number(t: str | None) -> float | None:
    if not t:
        return None
    m = re.search(r"([\d.]+)", t)
    return float(m.group(1)) if m else None


def first_int_like(t: str | None) -> int | None:
    if not t:
        return None
    m = re.search(r"([\d,]+)", t)
    return int(m.group(1).replace(",", "")) if m else None


def parse_money(t: str | None) -> float | None:
    if not t:
        return None
    m = re.search(r"([\d,]+(?:\.\d+)?)", t)
    if not m:
        return None
    return float(m.group(1).replace(",", ""))


def pick_first_text(page, selectors) -> str | None:
    for sel in selectors:
        try:
            txt = clean(page.locator(sel).first.text_content())
            if txt:
                return txt
        except Exception:
            pass
    return None


def auto_nudge(page) -> None:
    # minimal nudge to trigger hydration quickly
    page.evaluate("window.scrollTo(0, 600)")
    page.wait_for_timeout(120)
    page.evaluate("window.scrollTo(0, 0)")
    page.wait_for_timeout(80)


def wait_for_any_title(page, timeout_ms=8000) -> None:
    for sel in ["#productTitle", "h1 span", "h1", "[data-cy='title-recipe']"]:
        try:
            page.wait_for_selector(sel, timeout=timeout_ms)
            return
        except Exception:
            continue
    raise TimeoutError("Title not found")


def scrape_one(page, asin: str) -> dict:
    canonical = f"https://www.amazon.sa/dp/{asin}"

    page.goto(canonical, wait_until="commit", timeout=45000)

    try:
        wait_for_any_title(page, timeout_ms=8000)
    except Exception:
        auto_nudge(page)
        wait_for_any_title(page, timeout_ms=8000)

    auto_nudge(page)

    item_name = pick_first_text(page, ["#productTitle", "h1 span", "h1", "[data-cy='title-recipe']"])

    price_text = pick_first_text(page, [
        "#corePriceDisplay_desktop_feature_div .a-price .a-offscreen",
        "#corePrice_feature_div .a-price .a-offscreen",
        "span.a-price > span.a-offscreen",
        ".a-price .a-offscreen",
    ])
    price_value = parse_money(price_text)

    rating_text = clean(page.locator("#acrPopover").first.get_attribute("title"))
    if not rating_text:
        rating_text = pick_first_text(page, ["span[data-hook='rating-out-of-text']", "#acrPopover"])
    rating = first_number(rating_text)

    reviews_text = pick_first_text(page, ["#acrCustomerReviewText", "span[data-hook='total-review-count']"])
    reviews_count = first_int_like(reviews_text)

    discount_percent = None
    discount_text = pick_first_text(page, [
        ".savingsPercentage",
        "#corePriceDisplay_desktop_feature_div .savingsPercentage",
    ])
    if discount_text:
        m = re.search(r"(\d{1,3})\s*%", discount_text)
        if m:
            discount_percent = int(m.group(1))

    if discount_percent is None:
        list_price_text = pick_first_text(page, [
            "#corePriceDisplay_desktop_feature_div span.a-price.a-text-price span.a-offscreen",
            "#corePrice_feature_div span.a-price.a-text-price span.a-offscreen",
            "span.a-price.a-text-price span.a-offscreen",
        ])
        old = parse_money(list_price_text)
        cur = price_value
        if cur and old and old > cur:
            discount_percent = int(round((old - cur) / old * 100))

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


def make_browser():
    """
    Create one browser/page with speed optimizations:
    - block images/fonts/media
    - shorter timeouts
    """
    p = sync_playwright().start()
    bbrowser = p.chromium.launch(
    headless=True,
    args=[
        "--disable-blink-features=AutomationControlled",
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
    ],
)
    context = browser.new_context(locale="en-US")
    page = context.new_page()
    page.set_extra_http_headers({"Accept-Language": "en-US,en;q=0.9,ar;q=0.8"})
    page.set_default_timeout(11000)

    # Block heavy assets for speed
    page.route(
        "**/*",
        lambda route, request: route.abort()
        if request.resource_type in ("image", "media", "font")
        else route.continue_()
    )

    return p, browser, page


def scrape_all_saved_items() -> list[dict]:
    conn = db_conn()
    rows = conn.execute("SELECT asin FROM items ORDER BY created_at DESC").fetchall()
    conn.close()
    asins = [r["asin"] for r in rows]
    if not asins:
        return []

    results = []
    p, browser, page = make_browser()
    try:
        for asin in asins:
            try:
                results.append(scrape_one(page, asin))
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
    finally:
        browser.close()
        p.stop()

    return results


def scrape_single_item(asin: str) -> dict:
    p, browser, page = make_browser()
    try:
        return scrape_one(page, asin)
    finally:
        browser.close()
        p.stop()


def insert_history(ts: str, r: dict):
    conn = db_conn()
    # Keep seller_name column in DB but store NULL; we don't use it anymore
    conn.execute("""
        INSERT INTO price_history
        (asin, ts, item_name, price_text, price_value, rating, reviews_count, discount_percent, seller_name, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        r["asin"], ts, r.get("item_name"), r.get("price_text"), r.get("price_value"),
        r.get("rating"), r.get("reviews_count"), r.get("discount_percent"),
        None,  # seller_name removed
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
    conn.execute(
        "INSERT OR IGNORE INTO items (asin, url, created_at) VALUES (?, ?, ?)",
        (asin, url, now)
    )
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
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    results = scrape_all_saved_items()
    for r in results:
        insert_history(ts, r)
    return redirect(url_for("index"))


@app.route("/update/<asin>", methods=["POST"])
def update_one(asin):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    try:
        r = scrape_single_item(asin)
    except Exception as e:
        r = {
            "asin": asin,
            "url": f"https://www.amazon.sa/dp/{asin}",
            "item_name": None,
            "price_text": None,
            "price_value": None,
            "rating": None,
            "reviews_count": None,
            "discount_percent": None,
            "error": str(e),
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
    init_db()
    print("Starting server...")
    app.run(host="127.0.0.1", port=5000, debug=True)

