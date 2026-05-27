import requests
import json
import time
import re
from bs4 import BeautifulSoup
from urllib.parse import quote, urljoin, urlparse

URLS_FILE = "urls.json"
MEMBERS_FILE = "members.json"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; DaiBot/1.0)"
}

SANGIIN_URL = "https://www.sangiin.go.jp/japanese/joho1/kousei/giin/221/giin.htm"
SHUGIIN_WIKI_URL = "https://ja.wikipedia.org/wiki/衆議院議員一覧"

PARTIES = [
    "自由民主党",
    "立憲民主党",
    "日本維新の会",
    "公明党",
    "国民民主党",
    "日本共産党",
    "れいわ新選組",
    "参政党",
    "社会民主党",
    "中道改革連合",
    "チームみらい",
    "減税日本・ゆうこく連合",
    "日本保守党",
    "無所属",
]

SANGIIN_PARTY_MAP = {
    "自民": "自由民主党",
    "立憲": "立憲民主党",
    "維新": "日本維新の会",
    "公明": "公明党",
    "民主": "国民民主党",
    "共産": "日本共産党",
    "れ新": "れいわ新選組",
    "参政": "参政党",
    "社民": "社会民主党",
    "みら": "チームみらい",
    "保守": "日本保守党",
    "無所属": "無所属",
}

EXCLUDE_NAMES = set([
    "北海道", "東北", "北関東", "南関東", "東京", "北陸信越", "東海",
    "近畿", "中国", "四国", "九州",
    "青森", "岩手", "宮城", "秋田", "山形", "福島",
    "茨城", "栃木", "群馬", "埼玉", "千葉", "神奈川", "山梨",
    "新潟", "富山", "石川", "福井", "長野",
    "岐阜", "静岡", "愛知", "三重",
    "滋賀", "京都", "大阪", "兵庫", "奈良", "和歌山",
    "鳥取", "島根", "岡山", "広島", "山口",
    "徳島", "香川", "愛媛", "高知",
    "福岡", "佐賀", "長崎", "熊本", "大分", "宮崎", "鹿児島", "沖縄",
    "比例", "選挙区", "小選挙区", "参議院", "衆議院",
    "議長", "副議長", "一覧", "脚注", "出典", "外部リンク",
    "免責事項", "お知らせ", "最近の更新", "ノート",
    *PARTIES
])


def fetch(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        if r.status_code == 200:
            return r.text
        print("HTTPエラー:", r.status_code, url)
    except Exception as e:
        print("取得失敗:", url, e)
    return None


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def clean_name(name):
    if not name:
        return ""

    name = re.sub(r"\[.*?\]", "", name)
    name = re.sub(r"[（(].*?[）)]", "", name)
    name = name.replace("　", " ").strip()
    name = re.sub(r"\s+", "", name)
    return name


def is_person_name(name):
    if not name:
        return False

    if name in EXCLUDE_NAMES:
        return False

    # 日本人名っぽいものだけ
    if not re.match(r"^[一-龥ぁ-んァ-ンー]+$", name):
        return False

    if len(name) < 2 or len(name) > 10:
        return False

    return True


def normalize_party(party):
    if not party:
        return ""

    p = str(party).strip()
    p = p.replace("　", "").replace(" ", "")
    p = p.replace("（", "").replace("）", "").replace("(", "").replace(")", "")

    if p in SANGIIN_PARTY_MAP:
        return SANGIIN_PARTY_MAP[p]

    for full in PARTIES:
        if full in p:
            return full

    return p


def detect_party_from_text(text):
    if not text:
        return ""

    text = text.replace("　", " ")

    # 衆議院Wikipedia用：名前の近くの（自由民主党）などを拾う
    for p in PARTIES:
        if p in text:
            return p

    # 参議院略称用
    for abbr, full in SANGIIN_PARTY_MAP.items():
        if re.search(rf"(^|\s){re.escape(abbr)}($|\s)", text):
            return full

    return ""


def normalize_url(href):
    if not href:
        return None

    href = str(href).strip()

    if href.startswith("//"):
        href = "https:" + href

    if href.startswith("http://") or href.startswith("https://"):
        return href

    return None


def is_good_official_url(url):
    if not url:
        return False

    host = urlparse(url).hostname or ""
    host = host.lower()

    bad_domains = [
        "wikipedia.org",
        "wikimedia.org",
        "twitter.com",
        "x.com",
        "facebook.com",
        "instagram.com",
        "youtube.com",
        "youtu.be",
        "ameblo.jp",
        "note.com",
        "line.me",
        "tiktok.com",
        "threads.net",
    ]

    if any(bad in host for bad in bad_domains):
        return False

    return True


# ------------------------
# 参議院：公式サイトから議員一覧を取得
# ------------------------
def get_sangiin_members():
    html = fetch(SANGIIN_URL)
    if not html:
        return []

    soup = BeautifulSoup(html, "lxml")

    members = []
    seen = set()

    for tr in soup.select("tr"):
        tds = tr.select("td")
        if len(tds) < 3:
            continue

        a = tds[0].select_one("a[href]")
        if not a:
            continue

        name = clean_name(a.get_text(" ", strip=True))

        if not is_person_name(name):
            continue

        party_raw = tds[2].get_text(" ", strip=True)
        party = normalize_party(party_raw)

        profile_url = urljoin(SANGIIN_URL, a.get("href"))

        key = f"参議院:{name}"
        if key in seen:
            continue

        seen.add(key)

        members.append({
            "name": name,
            "chamber": "参議院",
            "party": party,
            "party_raw": party_raw,
            "wiki_url": None,
            "official_url": None,
            "url": None,
            "official_url_source": None,
            "party_profile_url": profile_url
        })

    print(f"参議院: {len(members)}件")
    return members


# ------------------------
# 衆議院：Wikipediaの議員一覧セクションから取得
# ------------------------
def get_wiki_member_area(soup):
    start = soup.find(id="議員一覧")
    if not start:
        return soup.select_one("#mw-content-text") or soup

    heading = start.find_parent(["h2", "h3"])
    if not heading:
        return soup.select_one("#mw-content-text") or soup

    html_parts = []

    for tag in heading.find_all_next():
        if tag.name == "h2":
            break
        html_parts.append(str(tag))

    return BeautifulSoup("<div>" + "\n".join(html_parts) + "</div>", "lxml")


def get_shugiin_members():
    html = fetch(SHUGIIN_WIKI_URL)
    if not html:
        return []

    soup = BeautifulSoup(html, "lxml")
    area = get_wiki_member_area(soup)

    members = []
    seen = set()

    for a in area.select("a[href^='/wiki/']"):
        href = a.get("href")
        name = clean_name(a.get_text(" ", strip=True))

        if not href or ":" in href:
            continue

        if not is_person_name(name):
            continue

        parent = a.find_parent(["td", "li", "p", "tr"])
        context = parent.get_text(" ", strip=True) if parent else ""
        party = detect_party_from_text(context)

        # 政党が全く拾えないものは、選挙区リンク等の誤検出の可能性が高い
        if not party:
            continue

        key = f"衆議院:{name}"
        if key in seen:
            continue

        seen.add(key)

        members.append({
            "name": name,
            "chamber": "衆議院",
            "party": party,
            "party_raw": party,
            "wiki_url": "https://ja.wikipedia.org" + href,
            "official_url": None,
            "url": None,
            "official_url_source": None,
            "party_profile_url": ""
        })

    print(f"衆議院: {len(members)}件")
    return members


# ------------------------
# Wikipediaページ検索
# ------------------------
def search_wikipedia(name, chamber=""):
    # 1. 直接URL
    direct_url = f"https://ja.wikipedia.org/wiki/{quote(name)}"
    html = fetch(direct_url)
    if html and "ウィキペディアには現在この名前の項目はありません" not in html:
        return direct_url, html

    # 2. Wikipedia検索
    queries = [
        f"{name} {chamber}議員",
        f"{name} 国会議員",
        name
    ]

    for q in queries:
        try:
            search_url = f"https://ja.wikipedia.org/w/index.php?search={quote(q)}"
            html = fetch(search_url)
            if not html:
                continue

            soup = BeautifulSoup(html, "lxml")

            # 直接ページに飛んだ場合
            canonical = soup.select_one("link[rel='canonical']")
            if canonical and canonical.get("href") and "/wiki/" in canonical.get("href"):
                page_url = canonical.get("href")
                page_html = fetch(page_url)
                if page_html:
                    return page_url, page_html

            result = soup.select_one(".mw-search-result-heading a[href^='/wiki/']")
            if result:
                page_url = "https://ja.wikipedia.org" + result.get("href")
                page_html = fetch(page_url)
                if page_html:
                    return page_url, page_html
        except:
            pass

    return None, None


def get_section_after_id(soup, section_id):
    start = soup.find(id=section_id)
    if not start:
        return []

    heading = start.find_parent(["h2", "h3", "h4"])
    if not heading:
        return []

    tags = []

    for tag in heading.find_all_next():
        if tag.name in ["h2", "h3"]:
            break
        tags.append(tag)

    return tags


# ------------------------
# 各議員Wikipediaページから公式URL取得
# ------------------------
def extract_official_url_from_wiki(html):
    if not html:
        return None

    soup = BeautifulSoup(html, "lxml")
    candidates = []

    # 1. infoboxの「公式サイト」「ウェブサイト」行を最優先
    for table in soup.select("table.infobox"):
        for tr in table.select("tr"):
            tr_text = tr.get_text(" ", strip=True)

            if not any(k in tr_text for k in ["公式", "ホームページ", "ウェブサイト", "サイト"]):
                continue

            for a in tr.select("a[href]"):
                href = normalize_url(a.get("href"))

                if href and is_good_official_url(href):
                    return href

    # 2. infobox内の外部URL
    for a in soup.select("table.infobox a[href]"):
        href = normalize_url(a.get("href"))

        if href and is_good_official_url(href):
            candidates.append(href)

    # 3. 外部リンクセクション
    for tag in get_section_after_id(soup, "外部リンク"):
        for a in tag.select("a[href]"):
            text = a.get_text(" ", strip=True)
            href = normalize_url(a.get("href"))

            if not href or not is_good_official_url(href):
                continue

            if any(k in text for k in ["公式", "ホームページ", "ウェブサイト", "サイト", "オフィシャル"]):
                return href

            candidates.append(href)

    # 4. それでもなければ候補の先頭
    return candidates[0] if candidates else None


def main():
    all_members = []

    # 参議院は公式ページから取得
    all_members.extend(get_sangiin_members())
    time.sleep(0.5)

    # 衆議院はWikipedia一覧から取得
    all_members.extend(get_shugiin_members())
    time.sleep(0.5)

    print(f"合計議員候補数: {len(all_members)}")

    urls_legacy = {}
    enriched_members = []

    seen = set()

    for i, member in enumerate(all_members, start=1):
        name = member["name"]
        chamber = member["chamber"]

        key = f"{chamber}:{name}"
        if key in seen:
            continue
        seen.add(key)

        print(f"[{i}/{len(all_members)}] ▶ {chamber} {member.get('party','')} {name}")

        wiki_url = member.get("wiki_url")
        html = None

        # 衆議院は一覧からWikipedia URL取得済み
        if wiki_url:
            html = fetch(wiki_url)

        # 参議院は名前からWikipedia検索
        if not html:
            wiki_url, html = search_wikipedia(name, chamber)

        member["wiki_url"] = wiki_url

        official_url = None

        if html:
            official_url = extract_official_url_from_wiki(html)

        member["official_url"] = official_url
        member["url"] = official_url
        member["official_url_source"] = "Wikipedia" if official_url else None

        if official_url:
            print("  ✔", official_url)
            urls_legacy[name] = official_url
        else:
            print("  ❌ 公式URL見つからず")
            urls_legacy[name] = None

        enriched_members.append(member)

        # 途中保存
        save_json(URLS_FILE, urls_legacy)
        save_json(MEMBERS_FILE, enriched_members)

        time.sleep(0.3)

    save_json(URLS_FILE, urls_legacy)
    save_json(MEMBERS_FILE, enriched_members)

    print("完了")
    print(f"- {URLS_FILE} 作成")
    print(f"- {MEMBERS_FILE} 作成")


if __name__ == "__main__":
    main()
