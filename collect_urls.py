from __future__ import annotations

import json
import re
import time
import urllib.parse

from pathlib import Path

from urllib.parse import (
    urljoin,
    urlparse,
    urlunparse,
    quote_plus,
    parse_qs,
    urlsplit,
    unquote,
)

import requests

from bs4 import BeautifulSoup


HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    )
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


NAME_RE = re.compile(
    r"^[一-龥々ぁ-んァ-ヶーA-Za-z・\s]{2,20}$"
)


PARTY_RULES = [
    ("自由民主党", "自民"),
    ("自民党", "自民"),
    ("立憲民主党", "立憲"),
    ("日本維新の会", "維新"),
    ("維新", "維新"),
    ("公明党", "公明"),
    ("国民民主党", "国民"),
    ("日本共産党", "共産"),
    ("共産党", "共産"),
    ("れいわ新選組", "れ新"),
    ("れいわ", "れ新"),
    ("参政党", "参政"),
    ("社会民主党", "社民"),
    ("社民党", "社民"),
    ("日本保守党", "保守"),
    ("チームみらい", "みらい"),
    ("無所属", "無所属"),
]


def fetch(url: str) -> str | None:

    for attempt in range(1, 4):

        try:

            res = requests.get(
                url,
                headers=HEADERS,
                timeout=10,
            )

            res.raise_for_status()

            res.encoding = res.apparent_encoding

            return res.text

        except Exception as e:

            print(
                f"[fetch error {attempt}/3] {url}: {e}"
            )

            time.sleep(1)

    return None


def save_json(
    path: Path,
    data: list[dict]
) -> None:

    tmp = path.with_suffix(
        path.suffix + ".tmp"
    )

    tmp.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )

    tmp.replace(path)


def normalize_wiki_url(
    href: str
) -> str | None:

    if not href:
        return None

    if href.startswith("//"):
        href = "https:" + href

    elif href.startswith("/wiki/"):
        href = "https://ja.wikipedia.org" + href

    elif href.startswith("./"):
        href = urljoin(
            "https://ja.wikipedia.org/wiki/",
            href
        )

    parsed = urlparse(href)

    if parsed.netloc != "ja.wikipedia.org":
        return None

    if not parsed.path.startswith("/wiki/"):
        return None

    page_name = urllib.parse.unquote(
        parsed.path.split("/wiki/", 1)[1]
    )

    if ":" in page_name:
        return None

    return href.split("#", 1)[0]


def clean_name(value: str) -> str:

    value = value.strip()

    value = re.sub(
        r"\s*[（(].*$",
        "",
        value
    )

    value = (
        value
        .replace(" ", "")
        .replace("　", "")
    )

    return value


def normalize_party(text: str) -> str:

    text = text or ""

    for keyword, party in PARTY_RULES:

        if keyword in text:
            return party

    return "不明"


def is_probable_person_name(
    name: str
) -> bool:

    if not name:
        return False

    name = name.strip()

    if len(name) < 2 or len(name) > 12:
        return False

    ng_words = [
        "党",
        "会",
        "委員",
        "議会",
        "制度",
        "政府",
        "国会",
        "法律",
        "法案",
        "選挙",
        "比例",
        "ブロック",
        "一覧",
        "カテゴリ",
        "日本",
        "政治",
        "民主制",
        "主権",
        "内閣",
        "行政",
        "立法",
        "司法",
        "天皇",
        "憲法",
        "自治",
        "省",
        "庁",
        "局",
        "県",
        "都",
        "府",
        "道",
        "市",
        "区",
        "町",
        "村",
        "免責",
        "特権",
        "新緑風会",

        # 除外
        "沖縄の風",
        "無所属クラブ",
        "参議院議長",
        "衆議院副議長",
        "議長",
        "副議長",
    ]

    for ng in ng_words:

        if ng in name:
            return False

    if "/" in name or ":" in name:
        return False

    if re.fullmatch(
        r"[A-Za-z0-9]+",
        name
    ):
        return False

    if not NAME_RE.match(name):
        return False

    return True


def collect_members_from_list_page(
    house: str,
    list_url: str
) -> list[dict]:

    html = fetch(list_url)

    if not html:

        print(f"{house}: HTML取得失敗")

        return []

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    members: list[dict] = []

    seen: set[tuple[str, str]] = set()

    tables = soup.select(
        "table.wikitable"
    )

    for table in tables:

        for tr in table.select("tr"):

            cells = tr.find_all(
                ["td", "th"]
            )

            if not cells:
                continue

            row_text = tr.get_text(
                " ",
                strip=True
            )

            party = normalize_party(
                row_text
            )

            for a in tr.select("a[href]"):

                href = a.get("href", "")

                if any(
                    x in href
                    for x in [
                        "カテゴリ",
                        "Category",
                        "一覧",
                        "Template",
                        "Help:",
                        "Portal:",
                        "File:",
                    ]
                ):
                    continue

                wiki_url = normalize_wiki_url(
                    href
                )

                if not wiki_url:
                    continue

                title = (
                    a.get("title")
                    or a.get_text(
                        " ",
                        strip=True
                    )
                )

                name = clean_name(title)

                if not is_probable_person_name(
                    name
                ):
                    continue

                key = (house, name)

                if key in seen:
                    continue

                seen.add(key)

                members.append(
                    {
                        "house": house,
                        "party": party,
                        "name": name,
                        "wiki": wiki_url,
                        "official": None,
                    }
                )

                break

    print(
        f"{house}: 有効議員数 {len(members)} 件"
    )

    return members


def normalize_external_url(
    href: str,
    base_url: str
) -> str | None:

    if not href:
        return None

    href = urljoin(base_url, href)

    parsed = urlparse(href)

    if parsed.scheme not in (
        "http",
        "https"
    ):
        return None

    host = (
        parsed.netloc or ""
    ).lower()

    if any(
        skip in host
        for skip in SKIP_DOMAINS
    ):
        return None

    if parsed.path.lower().endswith(
        (
            ".pdf",
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".svg",
            ".webp",
        )
    ):
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


def find_section_heading(
    soup: BeautifulSoup,
    keywords: list[str]
):

    for tag in soup.find_all(
        ["h2", "h3", "h4"]
    ):

        text = tag.get_text(
            strip=True
        )

        if any(
            kw in text
            for kw in keywords
        ):
            return tag

    return None


def extract_official_url(
    wiki_html: str,
    wiki_url: str
) -> str | None:

    soup = BeautifulSoup(
        wiki_html,
        "html.parser"
    )

    def valid_links(parent):

        if not parent:
            return []

        links = []

        for a in parent.find_all(
            "a",
            href=True
        ):

            url = normalize_external_url(
                a["href"],
                wiki_url
            )

            if url:
                links.append(url)

        return links

    official_keywords = [
        "公式",
        "ウェブサイト",
        "ホームページ",
        "website",
        "web site",
        "hp",
    ]

    for table in soup.select(
        "table[class*='infobox']"
    ):

        for row in table.find_all("tr"):

            label_cell = row.find(
                ["th", "td"]
            )

            if not label_cell:
                continue

            label = label_cell.get_text(
                " ",
                strip=True
            ).lower()

            if any(
                k in label
                for k in official_keywords
            ):

                links = valid_links(row)

                if links:
                    return links[0]

    heading = find_section_heading(
        soup,
        [
            "外部リンク",
            "External links",
            "外部リンク一覧",
        ],
    )

    if heading:

        for sibling in heading.find_next_siblings():

            if sibling.name in [
                "h2",
                "h3",
                "h4",
            ]:
                break

            links = valid_links(sibling)

            if links:
                return links[0]

    for table in soup.select(
        "table[class*='infobox']"
    ):

        links = valid_links(table)

        if links:
            return links[0]

    return None


def normalize_search_url(
    href: str
) -> str | None:

    if not href:
        return None

    if href.startswith("//duckduckgo.com/l/?uddg="):

        qs = parse_qs(
            urlsplit(
                "https:" + href
            ).query
        )

        if "uddg" in qs:
            return unquote(
                qs["uddg"][0]
            )

    if href.startswith("/l/?uddg="):

        qs = parse_qs(
            urlsplit(
                "https://duckduckgo.com" + href
            ).query
        )

        if "uddg" in qs:
            return unquote(
                qs["uddg"][0]
            )

    if href.startswith("http"):
        return href

    return None


def find_from_search(
    name: str
) -> str | None:

    print(f"  -> 検索 fallback: {name}")

    queries = [
        f"{name} 公式サイト",
    ]

    for q in queries:

        url = (
            "https://html.duckduckgo.com/html/?q="
            + quote_plus(q)
        )

        html = fetch(url)

        if not html:
            continue

        soup = BeautifulSoup(
            html,
            "html.parser"
        )

        for a in soup.select(
            "a.result__a[href]"
        ):

            href = a.get(
                "href",
                ""
            )

            candidate = normalize_search_url(
                href
            )

            if not candidate:
                continue

            parsed = urlparse(candidate)

            host = (
                parsed.netloc or ""
            ).lower()

            if any(
                skip in host
                for skip in SKIP_DOMAINS
            ):
                continue

            if not host.endswith(
                (
                    ".jp",
                    ".com",
                    ".net",
                    ".org",
                    ".tokyo",
                )
            ):
                continue

            return urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path or "/",
                    "",
                    "",
                    "",
                )
            )

        time.sleep(0.5)

    return None


def add_official_urls(
    members: list[dict]
) -> list[dict]:

    results: list[dict] = []

    for i, member in enumerate(
        members,
        1
    ):

        name = member["name"]

        wiki_url = member["wiki"]

        print(
            f"[{i}/{len(members)}] {name}"
        )

        html = fetch(wiki_url)

        if not html:

            member["error"] = (
                "Wikipediaページ取得失敗"
            )

            results.append(member)

            continue

        official = extract_official_url(
            html,
            wiki_url
        )

        if not official:

            official = find_from_search(
                name
            )

        member["official"] = official

        print(
            f"  -> {official or '公式URLなし'}"
        )

        results.append(member)

        if i % 20 == 0:

            save_json(
                OUT_FILE,
                results
            )

            print(
                f"  checkpoint: {len(results)} 件保存"
            )

        time.sleep(0.1)

    return results


def main() -> None:

    members: list[dict] = []

    seen_wiki: set[str] = set()

    for house, url in LIST_PAGES:

        collected = collect_members_from_list_page(
            house,
            url
        )

        for member in collected:

            if member["wiki"] in seen_wiki:
                continue

            seen_wiki.add(
                member["wiki"]
            )

            members.append(member)

    print(
        f"合計候補: {len(members)} 件"
    )

    if not members:

        raise SystemExit(
            "ERROR: 議員一覧を取得できませんでした。"
        )

    results = add_official_urls(
        members
    )

    save_json(
        OUT_FILE,
        results
    )

    print(
        f"完了: {OUT_FILE} に "
        f"{len(results)} 件保存しました"
    )


if __name__ == "__main__":
    main()
