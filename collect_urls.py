import requests
import json
import time
import re
from bs4 import BeautifulSoup
from urllib.parse import quote, urlparse

URLS_FILE = "urls.json"
MEMBERS_FILE = "members.json"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; DaiBot/1.0)"
}

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
    "無所属",
]

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
    "自由民主党", "立憲民主党", "日本維新の会", "公明党", "国民民主党",
    "日本共産党", "れいわ新選組", "参政党", "社会民主党",
    "中道改革連合", "チームみらい", "減税日本・ゆうこく連合", "無所属",
])

TARGET_PAGES = [
    {
        "chamber": "衆議院",
        "url": "https://ja.wikipedia.org/wiki/衆議院議員一覧"
    },
    {
        "chamber": "参議院",
        "url": "https://ja.wikipedia.org/wiki/参議院議員一覧"
    }
]


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def fetch(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        if r.status_code == 200:
            return r.text
    except Exception as e:
        print("取得失敗:", url, e)
    return None


def clean_name(name):
    name = re.sub(r"\[.*?\]", "", name)
    name = re.sub(r"[（(].*?[）)]", "", name)
    name = name.strip()
    return name


def is_person_name(name):
    if not name:
        return False

    if name in EXCLUDE_NAMES:
        return False

    if name in PARTIES:
        return False

    if not re.match(r"^[一-龥ぁ-んァ-ンー]+$", name):
        return False

    if len(name) < 2 or len(name) > 8:
        return False

    return True


def detect_party(text):
    if not text:
        return ""

    for party in PARTIES:
        if party in text:
            return party

    return ""


def find_member_area(soup):
    """
    Wikipedia本文のうち「議員一覧」から「脚注」手前までを対象にする
    """
    start = soup.find(id="議員一覧")
    if not start:
        return soup.select_one("#mw-content-text") or soup

    heading = start.find_parent(["h2", "h3"])
    if not heading:
        return soup.select_one("#mw-content-text") or soup

    blocks = []
    for tag in heading.find_all_next():
        if tag.name == "h2":
            span = tag.find("span", id=True)
            if span and span.get("id") in ["脚注", "関連項目", "外部リンク"]:
                break
        blocks.append(tag)

    wrapper = BeautifulSoup("<div></div>", "lxml")
    div = wrapper.div
    for b in blocks:
        div.append(BeautifulSoup(str(b), "lxml"))

    return div


def get_members_from_page(page_url, chamber):
    html = fetch(page_url)
    if not html:
        return []

    soup = BeautifulSoup(html, "lxml")
    area = find_member_area(soup)

    members = []
    seen = set()

    for a in area.select("a[href^='/wiki/']"):
        href = a.get("href")
        name = clean_name(a.get_text(strip=True))

        if not href or ":" in href:
            continue

        if not is_person_name(name):
            continue

        parent_text = ""
        parent = a.find_parent(["td", "li", "tr", "p"])
        if parent:
            parent_text = parent.get_text(" ", strip=True)

        party = detect_party(parent_text)

        key = f"{chamber}:{name}"
        if key in seen:
            continue

        seen.add(key)

        members.append({
            "name": name,
            "chamber": chamber,
            "party": party,
            "wiki_url": "https://ja.wikipedia.org" + href,
            "official_url": None,
            "official_url_source": None
        })

    print(f"{chamber}: {len(members)}件")
    return members


def normalize_url(href):
    if not href:
        return None

    href = href.strip()

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
    ]

    if any(bad in host for bad in bad_domains):
        return False

    return True


def get_wiki_page_html(wiki_url):
    return fetch(wiki_url)


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


def extract_official_url_from_wiki(html):
    soup = BeautifulSoup(html, "lxml")
    candidates = []

    # 1. infobox内の「公式サイト」「ホームページ」っぽいリンクを優先
    for table in soup.select("table.infobox"):
        for tr in table.select("tr"):
            tr_text = tr.get_text(" ", strip=True)
            if not any(k in tr_text for k in ["公式", "ホームページ", "ウェブサイト", "サイト"]):
                continue

            for a in tr.select("a[href]"):
                href = normalize_url(a.get("href"))
                if href and is_good_official_url(href):
                    return href

    # 2. infobox内の外部URLを候補に入れる
    for a in soup.select("table.infobox a[href]"):
        href = normalize_url(a.get("href"))
        if href and is_good_official_url(href):
            candidates.append(href)

    # 3. 外部リンクセクションを見る
    ext_tags = get_section_after_id(soup, "外部リンク")
    for tag in ext_tags:
        for a in tag.select("a[href]"):
            text = a.get_text(" ", strip=True)
            href = normalize_url(a.get("href"))

            if not href or not is_good_official_url(href):
                continue

            if any(k in text for k in ["公式", "ホームページ", "ウェブサイト", "サイト"]):
                return href

            candidates.append(href)

    # 4. 候補のうち最初のものを返す
    return candidates[0] if candidates else None


def search_wikipedia(name):
    try:
        url = f"https://ja.wikipedia.org/w/index.php?search={quote(name)}"
        html = fetch(url)
        if not html:
            return None

        soup = BeautifulSoup(html, "lxml")
        result = soup.select_one(".mw-search-result-heading a")

        if result:
            return "https://ja.wikipedia.org" + result.get("href")
    except:
        pass

    return None


def main():
    all_members = []

    for page in TARGET_PAGES:
        members = get_members_from_page(page["url"], page["chamber"])
        all_members.extend(members)
        time.sleep(0.5)

    print(f"合計議員候補数: {len(all_members)}")

    urls_legacy = {}
    enriched_members = []

    for i, member in enumerate(all_members, start=1):
        name = member["name"]
        wiki_url = member["wiki_url"]

        print(f"[{i}/{len(all_members)}] ▶ {member['chamber']} {name}")

        html = get_wiki_page_html(wiki_url)

        if not html:
            # 念のため検索fallback
            fallback_url = search_wikipedia(name)
            if fallback_url:
                html = get_wiki_page_html(fallback_url)
                member["wiki_url"] = fallback_url

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
            print("  ❌ 見つからず")
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
