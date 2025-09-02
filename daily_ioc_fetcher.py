#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Daily IoC Fetcher & Grepper
- Fetch from multiple OSINT feeds
- Extract IP/Domain/URL/Hashes via regex
- Deduplicate in SQLite with first_seen/last_seen
- Output today's new IoCs to CSV

Python 3.10+
pip install requests feedparser python-dateutil
"""

import os
import re
import csv
import ssl
import json
import time
import sqlite3
import hashlib
import logging
import datetime as dt
from typing import List, Dict, Tuple, Iterable, Optional
import requests
import feedparser
from dateutil import tz

# ---------- Config ----------
DB_PATH = os.path.join(os.path.dirname(__file__), "ioc_store.sqlite")
OUT_DIR = os.path.join(os.path.dirname(__file__), "out")
os.makedirs(OUT_DIR, exist_ok=True)

# 預設來源（可按需要增刪改）
FEEDS = [
    # abuse.ch URLHaus (plaintext; 每行可能包含URL)
    {"name": "urlhaus_recent", "url": "https://urlhaus.abuse.ch/downloads/text_recent/", "type": "text"},
    # abuse.ch SSLBL（可能包含惡意IP/域名）
    {"name": "sslbl_ips", "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv", "type": "csv"},
    # PhishFeed RSS（示例）
    {"name": "phishfeed_rss", "url": "https://phishfeed.com/feeds/rss", "type": "rss"},
    # Bambenek C2 IP feed（示例，若失效可替換）
    {"name": "bambenek_c2", "url": "https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt", "type": "text"},
    # OpenPhish（JSON 示例，若需 API Key 可換其他公共源）
    {"name": "openphish", "url": "https://openphish.com/feed.json", "type": "json"},
]

HTTP_TIMEOUT = 30
USER_AGENT = "DailyIoCFetcher/1.0 (+https://security.local)"
TZ = tz.gettz("Europe/London")

# ---------- Regex（可自行增強） ----------
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?!$)|$)){4}\b")
RE_DOMAIN = re.compile(r"\b(?!(?:\d+\.){3}\d+\b)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
RE_URL = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ---------- DB ----------
def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            indicator TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_type ON iocs(type)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_last_seen ON iocs(last_seen)")
    con.commit()
    con.close()

def upsert_ioc(indicator: str, ioc_type: str, source: str, seen_ts: str):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT indicator, first_seen FROM iocs WHERE indicator=?", (indicator,))
    row = cur.fetchone()
    if row is None:
        cur.execute(
            "INSERT INTO iocs(indicator, type, source, first_seen, last_seen) VALUES(?,?,?,?,?)",
            (indicator, ioc_type, source, seen_ts, seen_ts)
        )
    else:
        cur.execute(
            "UPDATE iocs SET last_seen=? WHERE indicator=?",
            (seen_ts, indicator)
        )
    con.commit()
    con.close()

def get_new_iocs_for_date(date_str: str) -> List[Tuple[str, str, str, str, str]]:
    """
    取當日新增（first_seen == date_str 的）IoC
    """
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        SELECT indicator, type, source, first_seen, last_seen
        FROM iocs
        WHERE substr(first_seen, 1, 10) = ?
        ORDER BY type, indicator
    """, (date_str,))
    rows = cur.fetchall()
    con.close()
    return rows

# ---------- Fetch ----------
def fetch_url(url: str) -> Optional[bytes]:
    try:
        resp = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
        if resp.status_code == 200:
            return resp.content
        logging.warning(f"HTTP {resp.status_code} for {url}")
    except Exception as e:
        logging.warning(f"Fetch error for {url}: {e}")
    return None

def parse_feed(feed: Dict) -> str:
    content = fetch_url(feed["url"])
    if not content:
        return ""
    t = feed["type"]
    if t == "rss":
        d = feedparser.parse(content)
        texts = []
        for e in d.entries:
            if "title" in e: texts.append(str(e.title))
            if "summary" in e: texts.append(str(e.summary))
            if "link" in e: texts.append(str(e.link))
        return "\n".join(texts)
    elif t == "json":
        try:
            j = json.loads(content.decode("utf-8", errors="ignore"))
            # 將 JSON 扁平化為字串
            return json.dumps(j, ensure_ascii=False)
        except Exception:
            return content.decode("utf-8", errors="ignore")
    elif t == "csv":
        return content.decode("utf-8", errors="ignore")
    else:  # text / unknown
        return content.decode("utf-8", errors="ignore")

# ---------- Extract ----------
def normalize_domain(d: str) -> str:
    d = d.strip().strip(".").lower()
    # 去除明顯雜質
    return d

def classify_and_yield(text: str) -> Iterable[Tuple[str, str]]:
    # URL
    for u in set(RE_URL.findall(text)):
        yield (u.strip(), "url")
    # IP
    for ip in set(RE_IPV4.findall(text)):
        yield (ip.strip(), "ip")
    # Hashes
    for h in set(RE_SHA256.findall(text)):
        yield (h.lower(), "sha256")
    for h in set(RE_SHA1.findall(text)):
        yield (h.lower(), "sha1")
    for h in set(RE_MD5.findall(text)):
        yield (h.lower(), "md5")
    # Domain（避免把 URL 已抓到的 Host 再重複，這裡仍保留域名直抽，方便某些列表）
    for d in set(RE_DOMAIN.findall(text)):
        dn = normalize_domain(d)
        if dn:
            yield (dn, "domain")

# ---------- Main ----------
def main():
    init_db()
    now = dt.datetime.now(TZ)
    seen_ts = now.isoformat(timespec="seconds")
    today = now.strftime("%Y-%m-%d")
    total_new = 0
    total_seen = 0

    for f in FEEDS:
        logging.info(f"Fetching {f['name']} -> {f['url']}")
        raw = parse_feed(f)
        if not raw:
            logging.info(f"Skip {f['name']} (no content)")
            continue

        count_src = 0
        # 用 set 做來源內去重
        local_set = set()
        for indicator, ioc_type in classify_and_yield(raw):
            key = (indicator, ioc_type)
            if key in local_set:
                continue
            local_set.add(key)
            count_src += 1
            upsert_ioc(indicator, ioc_type, f["name"], seen_ts)

        total_seen += count_src
        logging.info(f"Parsed {f['name']}: {count_src} items (pre-dedup per source)")

    # 當日新 IoC
    rows = get_new_iocs_for_date(today)
    total_new = len(rows)
    out_path = os.path.join(OUT_DIR, f"new_iocs_{today.replace('-','')}.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as fp:
        writer = csv.writer(fp)
        writer.writerow(["indicator", "type", "source", "first_seen", "last_seen"])
        writer.writerows(rows)

    logging.info(f"Done. Today new IoCs: {total_new}. CSV: {out_path}")
    # 簡報輸出（方便 pipeline）
    print(json.dumps({
        "date": today,
        "new_iocs": total_new,
        "total_seen_insert_or_update": total_seen,
        "csv": out_path
    }, ensure_ascii=False))

if __name__ == "__main__":
    main()
