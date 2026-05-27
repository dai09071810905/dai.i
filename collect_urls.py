import requests
import json
import time
import re
from bs4 import BeautifulSoup
from urllib.parse import quote, urljoin, urlparse

CACHE_FILE = "urls.json"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; DaiBot/1.0)"
}

def load_cache():
    try:
        return json.load(open(CACHE_FILE, encoding="utf-8"))
    except:
        return {}

def save_cache(cache):
    json.dump(cache, open(CACHE_FILE, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

def get_members():
    url = "https://ja.wikipedia.org/wiki/衆議院議員一覧"
    html = requests.get(url, headers=HEADERS, timeout=15).text
    soup = BeautifulSoup(html, "lxml")

    members = []
    seen = set()

    for a in soup.select("a[href^='/wiki/']"):
        href = a.get("href")
        name = a.get_text(strip=True)

        if not name:
            continue

        if any(x in href for x in [
            "Wikipedia:", "Help:", "File:", "Category:", "Template:",
            "Special:", "Portal:"
        ]):
            continue

        name = re.sub(r"[（(].*?[）)]", "", name).strip()

        if not re.match(r"^[一-龥ぁ-んァ-ンー]+$", name):
            continue

        if len(name) < 2 or len(name) > 8:
            continue

        if name in seen:
            continue

        seen.add(name)
        members.append(name)

    print(f"議員候補数: {len(members)}")
    return members

def get_wiki_page(name):
    url = f"https://ja.wikipedia.org/wiki/{quote(name)}"

    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            return r.text
    except:
        pass

    return None

def normalize_url(href):
    if not href:
        return None

    if href.startswith("//"):
        href = "https:" + href

    if href.startswith("http://") or href.startswith("https://"):
        return href

    return None

def is_good_official_url(url):
    if not url:
        return False

    bad_domains = [
        "wikipedia.org",
        "wikimedia.org",
        "twitter.com",
        "x.com",
        "facebook.com",
        "instagram.com",
        "youtube.com",
        "ameblo.jp",
        "blog",
    ]

    host = urlparse(url).hostname or ""

    if any(bad in host for bad in bad_domains):
        return False

    return True

def extract_official_url(html):
    soup = BeautifulSoup(html, "lxml")

    candidates = []

    # infobox優先
    for a in soup.select("table.infobox a[href]"):
        text = a.get_text(strip=True)
        href = normalize_url(a.get("href"))

        if href and is_good_official_url(href):
            if "公式" in text or "サイト" in text or "ホームページ" in text:
                return href
            candidates.append(href)

    # 外部リンク
    ext = soup.find(id="外部リンク")
    if ext:
        parent = ext.find_parent()
        for a in parent.select("a[href]"):
            text = a.get_text(strip=True)
            href = normalize_url(a.get("href"))

            if href and is_good_official_url(href):
                if "公式" in text or "ホームページ" in text or "サイト" in text:
                    return href
                candidates.append(href)

    return candidates[0] if candidates else None

def main():
    cache = load_cache()
    members = get_members()

    for name in members:
        if name in cache:
            continue

        print("▶", name)

        html = get_wiki_page(name)

        if not html:
            print("  ❌ Wikipedia取得失敗")
            cache[name] = None
            continue

        url = extract_official_url(html)

        if url:
            print("  ✔", url)
            cache[name] = url
        else:
            print("  ❌ 見つからず")
            cache[name] = None

        save_cache(cache)
        time.sleep(0.3)

if __name__ == "__main__":
    main()
