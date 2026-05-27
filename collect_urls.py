from __future__ import annotations

import json
import re
import time
import urllib.parse
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; diet-member-ssl-checker/1.0)"
}

LIST_PAGES = [
    ("衆議院", "https://ja.wikipedia.org/wiki/衆議院議員一覧"),
    ("参議院", "https://ja.wikipedia.org/wiki/参議院議員一覧"),
]

OUT_FILE = Path("urls.json")

SKIP_DOMAINS = (
    "wikipedia.org",
    "wikimedia.org",
    "twitter.com",
    "x.com",
    "facebook.com",
    "instagram.com",
    "youtube.com",
    "youtu.be",
    "linkedin.com",
    "line.me",
    "tiktok.com",
)

SKIP_WORDS = re.compile(
    r"委員|議会|政党|選挙|制度|内閣|大臣|政府|国会|衆議院|参議院|議長|副議長"
    r"|裁判|司法|立法|行政|都道府県|市町村|自治|条例|憲法|法律|法案"
    r"|予算|税|補助|公共|政策|改革|連合|同盟|協会|連盟|組合|財団"
    r"|大学|学校|研究|機関|センター|庁|省|局|部|課"
    r"|北海道|青森|岩手|宮城|秋田|山形|福島|茨城|栃木|群馬|埼玉|千葉"
    r"|東京|神奈川|新潟|富山|石川|福井|山梨|長野|岐阜|静岡|愛知|三重"
    r"|滋賀|京都|大阪|兵庫|奈良|和歌山|鳥取|島根|岡山|広島|山口"
    r"|徳島|香川|愛媛|高知|福岡|佐賀|長崎|熊本|大分|宮崎|鹿児島|沖縄"
    r"|比例|小選挙区|名簿|選挙区|ブロック|ファイル|カテゴリ"
    r"|自由民主党|立憲民主党|日本維新の会|公明党|国民民主党|日本共産党"
    r"|れいわ新選組|参政党|社会民主党|無所属|会派"
)

NAME_RE = re.compile(r"^[一-龥々ぁ-んァ-ヶーA-Za-z・]{2,14}$")


def fetch(url: str) -> str | None:
    try:
        res = requests.get(url, headers=HEADERS, timeout=20)
        res.raise_for_status()
        return res.text
    except Exception as e:
        print(f"[fetch error] {url}: {e}")
        return None


def save_json(path: Path, data: list[dict]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def normalize_wiki_url(href: str) -> str | None:
    if not href:
        return None

    if href.startswith("//"):
        href = "https:" + href
    elif href.startswith("/wiki/"):
        href = "https://ja.wikipedia.org" + href
    elif href.startswith("./"):
        href = urljoin("https://ja.wikipedia.org/wiki/", href)

    parsed = urlparse(href)

    if parsed.netloc != "ja.wikipedia.org":
        return None
    if not parsed.path.startswith("/wiki/"):
        return None

    page_name = urllib.parse.unquote(parsed.path.split("/wiki/", 1)[1])
    if ":" in page_name:
        return None

    return href.split("#", 1)[0]


def clean_name(value: str) -> str:
    value = value.strip()
    value = re.sub(r"\s*[（(].*$", "", value)
    value = value.replace(" ", "").replace("　", "")
    return value


def is_probable_person_name(name: str) -> bool:
    if not NAME_RE.match(name):
        return False
    if SKIP_WORDS.search(name):
        return False
    return True


def collect_members_from_list_page(house: str, list_url: str) -> list[dict]:
    html = fetch(list_url)
    if not html:
        return []

    soup = BeautifulSoup(html, "lxml")
    members: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for table in soup.select("table.wikitable"):
        for a in table.select("a[href]"):
            wiki_url = normalize_wiki_url(a.get("href", ""))
            if not wiki_url:
                continue

            title = a.get("title") or a.get_text(" ", strip=True)
            name = clean_name(title)

            if not is_probable_person_name(name):
                continue

            key = (house, name)
            if key in seen:
                continue

            seen.add(key)

            members.append(
                {
                    "house": house,
                    "name": name,
                    "wiki": wiki_url,
                    "official": None,
                }
            )

    print(f"{house}: 議員候補 {len(members)} 件")
    return members


def normalize_external_url(href: str, base_url: str) -> str | None:
    if not href:
        return None

    href = urljoin(base_url, href)

    parsed = urlparse(href)

    if parsed.scheme not in ("http", "https"):
        return None

    host = (parsed.netloc or "").lower()

    if any(skip in host for skip in SKIP_DOMAINS):
        return None

    if parsed.path.lower().endswith((".pdf", ".jpg", ".jpeg", ".png", ".gif")):
        return None

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            "",
            parsed.query,
            "",
        )
    )


def extract_official_url(wiki_html: str, wiki_url: str) -> str | None:
    soup = BeautifulSoup(wiki_html, "lxml")

    def valid_links(parent) -> list[str]:
        urls: list[str] = []

        if not parent:
            return urls

        for a in parent.find_all("a", href=True):
            url = normalize_external_url(a["href"], wiki_url)
            if url:
                urls.append(url)

        return urls

    # 1. infobox内の「公式」「ウェブサイト」「ホームページ」行を優先
    for row in soup.select("table.infobox tr, table.infobox_v2 tr"):
        label_cell = row.find(["th", "td"])
        if not label_cell:
            continue

        label = label_cell.get_text(" ", strip=True).lower()

        if any(
            k in label
            for k in ["公式", "ウェブサイト", "ホームページ", "website", "web site", "hp"]
        ):
            links = valid_links(row)
            if links:
                return links[0]

    # 2. 外部リンクセクションを見る
    for section_id in ["外部リンク", "External_links", "外部リンク_1"]:
        target = soup.find(id=section_id)
        if not target:
            continue

        heading = (
            target
            if target.name in ["h2", "h3", "h4"]
            else target.find_parent(["h2", "h3", "h4"])
        )

        if not heading:
            continue

        # 「公式」と書かれたリンクを優先
        for sibling in heading.find_next_siblings():
            if sibling.name in ["h2", "h3"]:
                break

            if sibling.name not in ["ul", "ol", "div", "p"]:
                continue

            for a in sibling.find_all("a", href=True):
                text = a.get_text(" ", strip=True)
                href = a.get("href", "")

                if any(
                    k in text.lower()
                    for k in ["公式", "ホームページ", "ウェブサイト", "website", "hp"]
                ):
                    url = normalize_external_url(href, wiki_url)
                    if url:
                        return url

        # 公式表記がない場合、外部リンクセクションの最初の有効URL
        for sibling in heading.find_next_siblings():
            if sibling.name in ["h2", "h3"]:
                break

            links = valid_links(sibling)
            if links:
                return links[0]

    # 3. 最後の保険：infobox内の最初の外部URL
    for table in soup.select("table.infobox, table.infobox_v2"):
        links = valid_links(table)
        if links:
            return links[0]

    return None


def add_official_urls(members: list[dict]) -> list[dict]:
    results: list[dict] = []

    for i, member in enumerate(members, 1):
        name = member["name"]
        wiki_url = member["wiki"]

        print(f"[{i}/{len(members)}] {name}")

        html = fetch(wiki_url)
        if not html:
            member["error"] = "Wikipediaページ取得失敗"
            results.append(member)
            continue

        official = extract_official_url(html, wiki_url)
        member["official"] = official

        if official:
            print(f"  -> {official}")
        else:
            print("  -> 公式URLなし")

        results.append(member)

        if i % 20 == 0:
            save_json(OUT_FILE, results)
            print(f"  checkpoint: {len(results)} 件保存")

        time.sleep(0.25)

    return results


def main() -> None:
    members: list[dict] = []
    seen_wiki: set[str] = set()

    for house, url in LIST_PAGES:
        for member in collect_members_from_list_page(house, url):
            if member["wiki"] in seen_wiki:
                continue

            seen_wiki.add(member["wiki"])
            members.append(member)

    print(f"合計候補: {len(members)} 件")

    results = add_official_urls(members)
    save_json(OUT_FILE, results)

    print(f"完了: {OUT_FILE} に {len(results)} 件保存しました")


if __name__ == "__main__":
    main()
