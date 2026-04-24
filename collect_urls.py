import requests
import json
import time
import re
from bs4 import BeautifulSoup
from urllib.parse import quote

CACHE_FILE = "urls.json"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; DaiBot/1.0)"
}

# ------------------------
# キャッシュ
# ------------------------
def load_cache():
    try:
        return json.load(open(CACHE_FILE, encoding="utf-8"))
    except:
        return {}

def save_cache(cache):
    json.dump(cache, open(CACHE_FILE, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

# ------------------------
# Wikipedia検索（fallback）
# ------------------------
def search_wikipedia(name):
    try:
        url = f"https://ja.wikipedia.org/w/index.php?search={quote(name)}"
        html = requests.get(url, headers=HEADERS, timeout=5).text
        soup = BeautifulSoup(html, "lxml")

        result = soup.select_one(".mw-search-result-heading a")
        if result:
            return "https://ja.wikipedia.org" + result.get("href")
    except:
        pass
    return None

# ------------------------
# Wikipediaページ取得
# ------------------------
def get_wiki_page(name):
    url = f"https://ja.wikipedia.org/wiki/{quote(name)}"

    try:
        r = requests.get(url, headers=HEADERS, timeout=5)
        if r.status_code == 200:
            return url, r.text
    except:
        pass

    # fallback（検索）
    url = search_wikipedia(name)
    if url:
        try:
            r = requests.get(url, headers=HEADERS, timeout=5)
            if r.status_code == 200:
                return url, r.text
        except:
            pass

    return None, None

# ------------------------
# Wikipediaから公式URL取得
# ------------------------
def extract_official_url(html):
    soup = BeautifulSoup(html, "lxml")

    # ① infobox
    for a in soup.select("table.infobox a[href]"):
        href = a.get("href")
        if href and href.startswith("http"):
            return href

    # ② 外部リンク（重要）
    for a in soup.select("#外部リンク a[href]"):
        href = a.get("href")
        if href and href.startswith("http"):
            return href

    return None

# ------------------------
# 自民党ページ補完（簡易）
# ------------------------
def try_jimin(name):
    try:
        url = f"https://www.jimin.jp/member/?name={quote(name)}"
        html = requests.get(url, headers=HEADERS, timeout=5).text
        soup = BeautifulSoup(html, "lxml")

        for a in soup.select("a[href]"):
            href = a.get("href")
            if href and href.startswith("http") and ".jp" in href:
                return href
    except:
        pass

    return None

# ------------------------
# 議員一覧（修正版）
# ------------------------
def get_members():
    url = "https://ja.wikipedia.org/wiki/衆議院議員一覧"
    html = requests.get(url, headers=HEADERS).text
    soup = BeautifulSoup(html, "lxml")

    members = []

    def get_members():
    import re

    url = "https://ja.wikipedia.org/wiki/衆議院議員一覧"
    html = requests.get(url, headers=HEADERS).text
    soup = BeautifulSoup(html, "lxml")

    members = []

    for a in soup.select("a[href^='/wiki/']"):
        href = a.get("href")
        name = a.text.strip()

        # Wikipedia記事リンクだけ
        if not href.startswith("/wiki/"):
            continue

        # 除外（これ重要）
        if any(x in href for x in [
            "Wikipedia:", "Help:", "File:", "Category:", "Template:"
        ]):
            continue

        # 日本人名っぽい
        if not re.match(r'^[一-龥ぁ-んァ-ンー]+$', name):
            continue

        # 長さチェック
        if len(name) < 2 or len(name) > 6:
            continue

        members.append(name)

    members = list(set(members))

    print(f"議員候補数: {len(members)}")

    return members
# ------------------------
# メイン
# ------------------------
def main():
    cache = load_cache()
    members = get_members()

    for name in members:
        if name in cache:
            continue

        print("▶", name)

        wiki_url, html = get_wiki_page(name)

        if not html:
            print("  ❌ Wikipedia取得失敗")
            cache[name] = None
            continue

        url = extract_official_url(html)

        # fallback：自民党
        if not url:
            url = try_jimin(name)

        if url:
            print("  ✔", url)
            cache[name] = url
        else:
            print("  ❌ 見つからず")
            cache[name] = None

        time.sleep(0.2)

    save_cache(cache)

if __name__ == "__main__":
    main()
