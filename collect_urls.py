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

import pandas as pd
import requests
from bs4 import BeautifulSoup


HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    )
}

MEMBER_FILE = Path("members.xlsx")
OUT_FILE = Path("urls.json")

USE_SEARCH_FALLBACK = False

PARTY_MAP = {
    "みら": "みらい",
    "みらい": "みらい",
    "民主": "国民",
    "無": "無所属",
    "沖縄": "無所属",
}

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

MANUAL_OFFICIAL_URLS = {
    "ラサール石井": "https://lishii.jp/",
}


def fetch(url: str, timeout: int = 15) -> str | None:

    for attempt in range(1, 4):

        try:

            res = requests.get(
                url,
                headers=HEADERS,
                timeout=timeout,
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


def save_json(path: Path, data: list[dict]) -> None:

    tmp = path.with_suffix(
        path.suffix + ".tmp"
    )

    tmp.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    tmp.replace(path)


def clean_text(value) -> str:

    if value is None:
        return ""

    if pd.isna(value):
        return ""

    return (
        str(value)
        .strip()
        .replace("\n", "")
        .replace("\r", "")
    )


def clean_name(value) -> str:

    value = clean_text(value)

    value = re.sub(
        r"\s*[（(].*$",
        "",
        value
    )

    value = re.sub(
        r"\s*\[.*?\]\s*",
        "",
        value
    )

    value = (
        value
        .replace(" ", "")
        .replace("　", "")
    )

    return value


def normalize_party(value) -> str:

    party = clean_text(value)

    party = (
        party
        .replace(" ", "")
        .replace("　", "")
    )

    return PARTY_MAP.get(
        party,
        party
    )


def normalize_manual_url(url: str) -> str | None:

    url = clean_text(url)

    if not url:
        return None

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.netloc:
        return None

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


def load_members() -> list[dict]:

    if not MEMBER_FILE.exists():

        raise SystemExit(
            f"ERROR: {MEMBER_FILE} が見つかりません。"
        )

    df = pd.read_excel(
        MEMBER_FILE,
        header=None
    )

    print(
        f"Excel raw rows: {len(df)}"
    )

    members: list[dict] = []

    seen: set[tuple[str, str]] = set()

    for _, row in df.iterrows():

        house = clean_text(
            row.iloc[0]
            if len(row) > 0 else ""
        )

        name = clean_name(
            row.iloc[1]
            if len(row) > 1 else ""
        )

        party = normalize_party(
            row.iloc[2]
            if len(row) > 2 else ""
        )

        manual_url = normalize_manual_url(
            row.iloc[3]
            if len(row) > 3 else ""
        )

        if not house or not name:
            continue

        if not party:
            party = "不明"

        key = (house, name)

        if key in seen:
            continue

        seen.add(key)

        members.append(
            {
                "house": house,
                "party": party,
                "name": name,
                "manual_url": manual_url,
                "wiki": None,
                "official": None,
            }
        )

    print(
        f"Excel議員数: {len(members)} 件"
    )

    return members


def normalize_external_url(
    href: str,
    base_url: str
) -> str | None:

    if not href:
        return None

    href = urljoin(
        base_url,
        href
    )

    parsed = urlparse(href)

    if parsed.scheme not in (
        "http",
        "https",
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


def find_wikipedia_page(
    name: str
) -> str | None:

    search_url = (
        "https://ja.wikipedia.org/w/index.php?search="
        + quote_plus(name)
    )

    html = fetch(
        search_url,
        timeout=12
    )

    if not html:
        return None

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    first = soup.select_one(
        ".mw-search-result-heading a[href]"
    )

    if first:

        return normalize_wiki_url(
            first.get("href", "")
        )

    heading = soup.select_one(
        "#firstHeading"
    )

    if heading:

        title = clean_name(
            heading.get_text(
                " ",
                strip=True
            )
        )

        if name in title or title in name:

            return (
                "https://ja.wikipedia.org/wiki/"
                + urllib.parse.quote(name)
            )

    return None


def extract_official_url(
    wiki_html: str,
    wiki_url: str
) -> str | None:

    soup = BeautifulSoup(
        wiki_html,
        "html.parser"
    )

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

            text = row.get_text(
                " ",
                strip=True
            ).lower()

            if any(
                k in text
                for k in official_keywords
            ):

                for a in row.find_all(
                    "a",
                    href=True
                ):

                    url = normalize_external_url(
                        a["href"],
                        wiki_url
                    )

                    if url:
                        return url

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

    if not USE_SEARCH_FALLBACK:
        return None

    print(
        f"  -> 検索 fallback: {name}"
    )

    url = (
        "https://html.duckduckgo.com/html/?q="
        + quote_plus(f"{name} 公式サイト")
    )

    html = fetch(
        url,
        timeout=8
    )

    if not html:
        return None

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    for a in soup.select(
        "a.result__a[href]"
    ):

        candidate = normalize_search_url(
            a.get("href", "")
        )

        if not candidate:
            continue

        return candidate

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

        print(
            f"[{i}/{len(members)}] {name}"
        )

        official = None

        # 1. Excel D列優先
        if member.get("manual_url"):

            official = member["manual_url"]

            print(
                "  -> Excel D列URL使用"
            )

        # 2. 手動定義
        elif name in MANUAL_OFFICIAL_URLS:

            official = MANUAL_OFFICIAL_URLS[name]

            print(
                "  -> MANUAL_OFFICIAL_URLS使用"
            )

        # 3. Wikipedia
        else:

            wiki_url = find_wikipedia_page(name)

            member["wiki"] = wiki_url

            if wiki_url:

                wiki_html = fetch(
                    wiki_url,
                    timeout=12
                )

                if wiki_html:

                    official = extract_official_url(
                        wiki_html,
                        wiki_url
                    )

        # 4. 検索 fallback
        if not official:

            official = find_from_search(name)

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
                f"checkpoint: {len(results)} 件保存"
            )

        time.sleep(0.1)

    return results


def main() -> None:

    members = load_members()

    if not members:

        raise SystemExit(
            "ERROR: members.xlsx から議員一覧を取得できませんでした。"
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
