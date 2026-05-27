import re
import time
import urllib.parse
import requests
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; research bot)"}

# ------------------------
# Wikipedia 検索
# ------------------------
def search_wikipedia(name):
    url = "https://ja.wikipedia.org/w/api.php"
    params = {
        "action": "query",
        "list": "search",
        "srsearch": name,
        "format": "json",
        "srlimit": 1,
    }
    try:
        res = requests.get(url, params=params, headers=HEADERS, timeout=10)
        data = res.json()
        hits = data.get("query", {}).get("search", [])
        if hits:
            title = hits[0]["title"]
            return f"https://ja.wikipedia.org/wiki/{urllib.parse.quote(title)}"
    except Exception:
        pass
    return None


# ------------------------
# Wikipedia ページ取得
# ------------------------
def get_wiki_page(name):
    # まず直接アクセス
    direct_url = f"https://ja.wikipedia.org/wiki/{urllib.parse.quote(name)}"
    try:
        res = requests.get(direct_url, headers=HEADERS, timeout=10)
        if res.status_code == 200 and "曖昧さ回避" not in res.text[:2000]:
            return direct_url, res.text
    except Exception:
        pass

    # fallback（検索）
    url = search_wikipedia(name)
    if url:
        try:
            res = requests.get(url, headers=HEADERS, timeout=10)
            if res.status_code == 200:
                return url, res.text
        except Exception:
            pass

    return None, None


# ------------------------
# 公式URL抽出
# ------------------------
def extract_official_url(html):
    soup = BeautifulSoup(html, "lxml")

    # infobox
    for a in soup.select("table.infobox a[href]"):
        href = a.get("href")
        if href and href.startswith("http"):
            return href

    # 外部リンク
    for a in soup.select("#外部リンク a[href]"):
        href = a.get("href")
        if href and href.startswith("http"):
            return href

    # 外部リンク（英語ページ混在対策）
    for a in soup.select("#External_links a[href]"):
        href = a.get("href")
        if href and href.startswith("http"):
            return href

    return None


# ------------------------
# 自民党公式ページ fallback
# ------------------------
def try_jimin(name):
    url = f"https://www.jimin.jp/member/search/?keyword={urllib.parse.quote(name)}"
    try:
        res = requests.get(url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(res.text, "lxml")
        link = soup.select_one("a.member-link")
        if link:
            return "https://www.jimin.jp" + link.get("href", "")
    except Exception:
        pass
    return None


# ------------------------
# 議員一覧（修正版・重要）
# ------------------------
def get_members():
    url = "https://ja.wikipedia.org/wiki/衆議院議員一覧"
    html = requests.get(url, headers=HEADERS).text
    soup = BeautifulSoup(html, "html.parser")

    members = []
    seen = set()

    # 人名パターン: 漢字3〜6文字（日本人議員の姓名は通常3〜6文字）
    name_pat = re.compile(r'^[一-龥]{3,6}$')

    # 名前空間・不要パス除外パターン
    skip_namespace = re.compile(
        r'(Wikipedia:|Help:|File:|Category:|Template:|'
        r'特別:|ノート:|ファイル:|Portal:|'
        r'第\d+回|選挙区|比例|ブロック)'
    )

    # 人名として不適切なワード
    skip_words = re.compile(
        r'(日本|中国|韓国|選挙|議員|委員|大臣|議院|議会|国会|政党|政府|'
        r'憲法|条約|内閣|府県|都道|市区|町村|北海道|東京|大阪|裁判|法律|'
        r'制度|天皇|国家|自治|最高裁|地方|会派|議長|副議長|野党|与党|'
        r'公明|共産|社会|維新|民主|自由|国民|参政|保守|れいわ|無所属|'
        r'会計|監査|司法|立法|行政|主権|両院|単一|基本|憲章|規定|規則|'
        r'総合区|中核市|特別区|広域|連合|事務組合|改革|都市|指定)'
    )

    for a in soup.find_all("a"):
        href = a.get("href", "")

        # ★修正点: /wiki/ 形式と //ja.wikipedia.org/wiki/ 形式の両方に対応
        if href.startswith("/wiki/"):
            raw_path = href[len("/wiki/"):]
            wiki_url = "https://ja.wikipedia.org" + href
        elif "ja.wikipedia.org/wiki/" in href:
            raw_path = href.split("ja.wikipedia.org/wiki/")[-1]
            wiki_url = ("https:" if href.startswith("//") else "") + href
        else:
            continue

        # URLデコードして名前取得（括弧付き曖昧さ回避を除去）
        name = urllib.parse.unquote(raw_path).split("_(")[0].strip()

        # 名前空間・除外パス
        if skip_namespace.search(name):
            continue

        # 人名パターンマッチ
        if not name_pat.match(name):
            continue

        # 不要ワード除外
        if skip_words.search(name):
            continue

        # 重複除去
        if name in seen:
            continue
        seen.add(name)
        members.append({"name": name, "wiki": wiki_url})

    print(f"議員候補数: {len(members)}")
    return members


# ------------------------
# メイン
# ------------------------
def main():
    import json

    members = get_members()
    results = []

    for i, member in enumerate(members):
        name = member["name"]
        print(f"[{i+1}/{len(members)}] {name} を処理中...")

        wiki_url, html = get_wiki_page(name)
        if not html:
            print(f"  → Wikipediaページ取得失敗")
            continue

        url = extract_official_url(html)

        if not url:
            url = try_jimin(name)

        if url:
            print(f"  → {url}")
            results.append({"name": name, "wiki": wiki_url, "official": url})
        else:
            print(f"  → 公式URL見つからず")

        time.sleep(0.5)  # rate limit

    with open("urls.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"\n完了: {len(results)} 件の公式URLを収集しました")


if __name__ == "__main__":
    main()
