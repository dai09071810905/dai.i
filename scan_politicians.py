#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
国会議員サイト証明書ダッシュボード用スキャンスクリプト v6

GitHub Actionsでの実行を前提に、以下を強化しています。
- 衆議院公式ページがメンテナンス中でも、Wikipedia一覧から現職議員を取得
- 参議院はユーザー指定の 221/giin.htm を最優先に取得
- 個人Wikipediaは「検索」より先に exact title + redirects で取得
- 公式URLは Wikidata/Wikipedia だけでなく、政党ページを中継して取得
- 自民党は jimin.jp の議員ページから「公式サイト」リンクを抽出
- 検索エンジンスクレイピングは最後の補助に限定
- --self-test で主要な回帰テストを実行可能
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime as dt
import html
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


OUT_FILE = Path(os.environ.get("OUT_FILE", "data.json"))
CACHE_DIR = Path(os.environ.get("CACHE_DIR", ".cache"))
CACHE_DIR.mkdir(exist_ok=True)

CONNECT_TIMEOUT = int(os.environ.get("CONNECT_TIMEOUT", "10"))
READ_TIMEOUT = int(os.environ.get("READ_TIMEOUT", "35"))
TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)

MAX_ENRICH_WORKERS = int(os.environ.get("MAX_ENRICH_WORKERS", "4"))
MAX_SCAN_WORKERS = int(os.environ.get("MAX_SCAN_WORKERS", "12"))
REQUEST_SLEEP = float(os.environ.get("REQUEST_SLEEP", "0.05"))

USER_AGENT = os.environ.get(
    "USER_AGENT",
    "DietCertDashboard/3.0 (+https://github.com/; contact: dashboard)",
)

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept-Language": "ja,en;q=0.8",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

GS_SHARE_TARGET_PARTIES = {
    "自由民主党",
    "立憲民主党",
    "れいわ新選組",
    "国民民主党",
}

DISPLAY_PARTIES = [
    "自由民主党",
    "国民民主党",
    "立憲民主党",
    "れいわ新選組",
    "中道改革連合",
]

PARTY_NORMALIZATION = {
    "自民": "自由民主党",
    "自由民主": "自由民主党",
    "自由民主党": "自由民主党",
    "立民": "立憲民主党",
    "立憲": "立憲民主党",
    "立憲民主": "立憲民主党",
    "立憲民主党": "立憲民主党",
    "維新": "日本維新の会",
    "日本維新": "日本維新の会",
    "日本維新の会": "日本維新の会",
    "公明": "公明党",
    "公明党": "公明党",
    "国民": "国民民主党",
    "国民民主": "国民民主党",
    "国民民主党": "国民民主党",
    "民主": "国民民主党",
    "共産": "日本共産党",
    "日本共産": "日本共産党",
    "日本共産党": "日本共産党",
    "れいわ": "れいわ新選組",
    "れいわ新選組": "れいわ新選組",
    "れ新": "れいわ新選組",
    "参政": "参政党",
    "参政党": "参政党",
    "社民": "社会民主党",
    "社会民主党": "社会民主党",
    "保守": "日本保守党",
    "日本保守党": "日本保守党",
    "沖縄": "沖縄の風",
    "沖縄の風": "沖縄の風",
    "みら": "チームみらい",
    "チームみらい": "チームみらい",
    "無所属": "無所属",
    "無": "無所属",
    "中道改革連合": "中道改革連合",
    "減税日本・ゆうこく連合": "減税日本・ゆうこく連合",
}

PARTY_SHORT = {
    "自由民主党": "自民",
    "立憲民主党": "立憲",
    "日本維新の会": "維新",
    "公明党": "公明",
    "国民民主党": "民主",
    "日本共産党": "共産",
    "れいわ新選組": "れ新",
    "参政党": "参政",
    "日本保守党": "保守",
    "沖縄の風": "沖縄",
    "チームみらい": "みら",
    "社会民主党": "社民",
    "無所属": "無所属",
}

KNOWN_PARTIES = set(PARTY_NORMALIZATION.values())

SITE_SEAL_PATTERNS = [
    r"globalsign",
    r"site\s*seal",
    r"siteseal",
    r"sslpr",
    r"secure\s+site\s+seal",
    r"実在証明・盗聴対策シール",
    r"認証シール",
]

SOCIAL_OR_DIRECTORY_DOMAINS = [
    "wikipedia.org",
    "wikidata.org",
    "twitter.com",
    "x.com",
    "facebook.com",
    "instagram.com",
    "youtube.com",
    "youtu.be",
    "line.me",
    "lin.ee",
    "ameblo.jp",
    "note.com",
    "go2senkyo.com",
    "senkyo.com",
]

PARTY_DOMAINS = [
    "jimin.jp",
    "cdp-japan.jp",
    "new-kokumin.jp",
    "reiwa-shinsengumi.com",
    "o-ishin.jp",
    "komei.or.jp",
]

# 手動補正。GitHubでは official_overrides.json を置くと追加・上書きできます。
OFFICIAL_URL_OVERRIDES = {
    "前原誠司": "https://www.maehara21.com/",
    "齋藤健": "https://saito-ken.jp/",
    "斎藤健": "https://saito-ken.jp/",
}

# 回帰テスト兼、検索エンジンが落ちた場合の最低限の補正。
REGRESSION_OFFICIALS = {
    "坂本竜太郎": "https://sakamoto-ryutaro.jp/",
}


def load_overrides() -> None:
    path = Path("official_overrides.json")
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for k, v in data.items():
                if v:
                    OFFICIAL_URL_OVERRIDES[normalize_name_key(k)] = v
                    OFFICIAL_URL_OVERRIDES[k] = v
        except Exception as exc:
            print(f"WARN: official_overrides.json could not be read: {exc}", flush=True)


@dataclass
class Member:
    chamber: str
    name: str
    party: str
    wikipedia_title: Optional[str] = None
    wikipedia_url: Optional[str] = None
    official_url: Optional[str] = None
    official_url_source: Optional[str] = None
    lookup_log: Optional[List[str]] = None


@dataclass
class ScanResult:
    chamber: str
    name: str
    party: str
    party_group: str
    wikipedia_title: Optional[str]
    source_url: Optional[str]
    official_url: Optional[str]
    official_url_source: Optional[str]
    final_url: Optional[str]
    status: str
    http_status: Optional[int]
    cert_subject_cn: Optional[str]
    cert_subject_o: Optional[str]
    cert_issuer_o: Optional[str]
    cert_issuer_cn: Optional[str]
    is_https: bool
    is_gs: bool
    is_gs_legislator_cert: bool
    site_seal_found: bool
    notes: List[str]
    lookup_log: List[str]


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(HEADERS)
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        status=3,
        backoff_factor=0.6,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


SESSION = make_session()


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def pct(numerator: int, denominator: int) -> float:
    return round((numerator / denominator * 100) if denominator else 0.0, 1)


def request_get(url: str, *, allow_redirects: bool = True) -> Optional[requests.Response]:
    time.sleep(REQUEST_SLEEP)
    try:
        res = SESSION.get(url, timeout=TIMEOUT, allow_redirects=allow_redirects)
        if res.encoding is None:
            res.encoding = res.apparent_encoding
        return res
    except Exception:
        return None


def get_text(url: str) -> Optional[str]:
    res = request_get(url)
    if not res or res.status_code >= 500:
        return None
    return res.text


def normalize_party(value: str) -> str:
    if not value:
        return ""
    value = html.unescape(str(value)).strip()
    value = re.sub(r"\s+", "", value)
    value = value.strip("（）()[]【】")
    value = re.split(r"[／/・,，、]", value)[0]
    return PARTY_NORMALIZATION.get(value, value)


def party_group(party: str) -> str:
    p = normalize_party(party or "")
    return p if p in DISPLAY_PARTIES else "その他"


def clean_name(name: str) -> str:
    name = html.unescape(name or "")
    name = re.sub(r"\[.*?\]", "", name)
    name = re.sub(r"（.*?）|\(.*?\)", "", name)
    name = name.replace("　", " ").strip()
    name = re.sub(r"\s+", " ", name)
    name = re.sub(r"[君氏]+$", "", name).strip()
    return name


def normalize_name_key(name: str) -> str:
    return re.sub(r"\s+", "", clean_name(name)).replace("齋", "斎")


def is_person_name(text: str) -> bool:
    text = clean_name(text)
    if not (2 <= len(text.replace(" ", "")) <= 14):
        return False
    if re.fullmatch(r"[ぁ-んァ-ンー・ 　]+", text):
        return False
    return bool(re.fullmatch(r"[一-龥々〆ヵヶぁ-んァ-ンーA-Za-z・ 　]+", text))


def clean_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    url = html.unescape(str(url)).strip().strip('"').strip("'")
    if not url or url.startswith(("mailto:", "tel:", "javascript:", "#")):
        return None
    if url.startswith("//"):
        url = "https:" + url
    if url.startswith("/url?"):
        qs = parse_qs(urlparse(url).query)
        url = qs.get("q", [None])[0] or qs.get("url", [None])[0] or url
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        return None
    return url


def domain_of(url: str) -> str:
    return (urlparse(url).netloc or "").lower().removeprefix("www.")


def is_excluded_final_url(url: str) -> bool:
    host = domain_of(url)
    return any(d in host for d in SOCIAL_OR_DIRECTORY_DOMAINS + PARTY_DOMAINS)


def score_final_candidate(url: str, name: str, label: str = "") -> int:
    parsed = urlparse(url)
    host = (parsed.netloc or "").lower().removeprefix("www.")
    path = (parsed.path or "").lower()
    text = (host + " " + path + " " + label).lower()
    score = 0
    if is_excluded_final_url(url):
        score -= 80
    if url.startswith("https://"):
        score += 8
    for word in ["official", "office", "koenkai", "giin", "support", "kouenkai"]:
        if word in text:
            score += 5
    # 名前の漢字がURLに入るケースは少ないが、入っていたら加点
    for ch in normalize_name_key(name):
        if ch and ch in url:
            score += 2
    if "公式" in label or "official" in label.lower():
        score += 20
    return score


def validate_url_exists(url: str) -> Optional[str]:
    url = clean_url(url)
    if not url:
        return None
    parsed = urlparse(url)
    variants = [url]
    if parsed.scheme == "http":
        variants.insert(0, "https://" + parsed.netloc + (parsed.path or "/"))
        if not parsed.netloc.startswith("www."):
            variants.insert(0, "https://www." + parsed.netloc + (parsed.path or "/"))
    elif parsed.scheme == "https" and not parsed.netloc.startswith("www."):
        variants.append("https://www." + parsed.netloc + (parsed.path or "/"))

    seen = set()
    for candidate in variants:
        if candidate in seen:
            continue
        seen.add(candidate)
        res = request_get(candidate)
        if res and res.status_code < 500:
            return res.url or candidate

    host = parsed.hostname
    if host and extract_cert(host):
        return "https://" + host + (parsed.path or "/")
    return None


# -------------------- Members: House of Representatives --------------------


def parse_shugiin_official_page(url: str) -> List[Member]:
    text = get_text(url)
    if not text or "メンテナンス中" in text or "under maintenance" in text.lower():
        return []
    soup = BeautifulSoup(text, "html.parser")
    body = soup.get_text("\n")
    lines = [re.sub(r"\s+", " ", x).strip() for x in body.splitlines()]
    lines = [x for x in lines if x]
    members: List[Member] = []

    party_re = "|".join(sorted(map(re.escape, KNOWN_PARTIES | set(PARTY_NORMALIZATION.keys())), key=len, reverse=True))
    # 例: 逢沢 一郎君, あいさわ いちろう. 自民
    text_one_line = re.sub(r"\s+", " ", soup.get_text(" "))
    for m in re.finditer(rf"([一-龥々〆ヵヶぁ-んァ-ンーA-Za-z・ 　]{{2,18}})君[,，、 ]+.*?\b({party_re})\b", text_one_line):
        name = clean_name(m.group(1))
        party = normalize_party(m.group(2))
        if is_person_name(name) and party:
            members.append(Member("衆議院", name, party))

    # テーブル構造の場合
    for tr in soup.select("tr"):
        cells = [re.sub(r"\s+", " ", c.get_text(" ", strip=True)) for c in tr.select("td,th")]
        if len(cells) < 2:
            continue
        joined = " ".join(cells)
        pm = re.search(rf"({party_re})", joined)
        if not pm:
            continue
        party = normalize_party(pm.group(1))
        for cell in cells:
            cell = clean_name(cell)
            if is_person_name(cell):
                members.append(Member("衆議院", cell, party))
                break

    return dedupe_members(members)


def parse_shugiin_wikipedia_list() -> List[Member]:
    text = get_text("https://ja.wikipedia.org/wiki/衆議院議員一覧")
    if not text:
        return []
    soup = BeautifulSoup(text, "html.parser")
    content = soup.select_one("div.mw-parser-output") or soup

    members: List[Member] = []
    party_tokens = sorted(KNOWN_PARTIES, key=len, reverse=True)
    party_re = "|".join(map(re.escape, party_tokens))

    # 方法1: テキスト行で「氏名」→「（政党）」を拾う。現在の衆院Wikipediaで有効。
    lines = [re.sub(r"\s+", " ", line).strip() for line in content.get_text("\n").splitlines()]
    lines = [line for line in lines if line]
    for i, line in enumerate(lines[:-1]):
        name = clean_name(line)
        if not is_person_name(name):
            continue
        nxt = lines[i + 1]
        pm = re.search(rf"[（(]({party_re})(?:[／/].*?)?[）)]", nxt)
        if pm:
            members.append(Member("衆議院", name, normalize_party(pm.group(1))))

    # 方法2: リンク直後の近傍テキストから政党を推定。行崩れ対策。
    if len(members) < 300:
        for a in content.select("a[href^='/wiki/']"):
            name = clean_name(a.get_text(" ", strip=True))
            href = a.get("href") or ""
            if not is_person_name(name):
                continue
            if ":" in href or any(x in href for x in ["ファイル", "Template", "Category"]):
                continue
            parent_text = re.sub(r"\s+", " ", a.parent.get_text(" ", strip=True) if a.parent else "")
            idx = parent_text.find(name)
            near = parent_text[idx: idx + 80] if idx >= 0 else parent_text[:80]
            pm = re.search(rf"[（(]({party_re})(?:[／/].*?)?[）)]", near)
            if pm:
                members.append(Member("衆議院", name, normalize_party(pm.group(1))))

    # 明らかに議員でないページを削る最低限の保険
    bad_names = {"日本", "政治制度", "政治", "政府", "国会", "衆議院", "参議院"}
    members = [m for m in members if m.name not in bad_names]
    return dedupe_members(members)


def get_shugiin_members() -> List[Member]:
    official_urls = [
        "https://www.shugiin.go.jp/internet/itdb_annai.nsf/html/statics/syu/1giin.htm",
        "https://www.shugiin.go.jp/internet/itdb_annai.nsf/html/statics/syu/2giin.htm",
        "https://www.shugiin.go.jp/internet/itdb_annai.nsf/html/statics/syu/3giin.htm",
        "https://www.shugiin.go.jp/internet/itdb_annai.nsf/html/statics/syu/4giin.htm",
        "https://www.shugiin.go.jp/internet/itdb_annai.nsf/html/statics/syu/5giin.htm",
        "https://www.shugiin.go.jp/internet/itdb_annai.nsf/html/statics/syu/6giin.htm",
        "https://www.shugiin.go.jp/internet/itdb_annai.nsf/html/statics/syu/7giin.htm",
        "https://www.shugiin.go.jp/internet/itdb_annai.nsf/html/statics/syu/8giin.htm",
    ]
    official: List[Member] = []
    for url in official_urls:
        official.extend(parse_shugiin_official_page(url))
    official = dedupe_members(official)

    wiki = parse_shugiin_wikipedia_list()
    print(f"Shugiin official={len(official)} wikipedia={len(wiki)}", flush=True)

    # 465に近い方を採用。公式がメンテナンスで0件の場合はWikipediaへ。
    if len(official) >= 430:
        return official
    if len(wiki) >= 430:
        return wiki
    return official if len(official) >= len(wiki) else wiki


# -------------------- Members: House of Councillors --------------------


def parse_sangiin_page(url: str) -> List[Member]:
    text = get_text(url)
    if not text:
        return []
    soup = BeautifulSoup(text, "html.parser")
    lines = [re.sub(r"\s+", " ", line).strip() for line in soup.get_text("\n").splitlines()]
    lines = [line for line in lines if line]

    short_to_full = {short: full for full, short in PARTY_SHORT.items()}
    short_re = "|".join(sorted(map(re.escape, short_to_full.keys()), key=len, reverse=True))
    members: List[Member] = []

    # 例: 小野田 紀美 おのだ きみ 自民 岡山 令和10年7月25日
    line_re = re.compile(
        rf"^([一-龥々〆ヵヶぁ-んァ-ンーA-Za-z・ 　\[\]]{{2,50}})\s+"
        rf"([ぁ-んァ-ンー・ 　]{{2,80}})\s+"
        rf"({short_re})\s+"
        rf"(.+?)\s+令和\d+年\d+月\d+日"
    )
    for line in lines:
        m = line_re.match(line)
        if not m:
            continue
        name = clean_name(m.group(1))
        party = short_to_full.get(m.group(3), normalize_party(m.group(3)))
        if is_person_name(name):
            members.append(Member("参議院", name, party))

    # 1行にまとまらない環境向けのフォールバック
    if len(members) < 100:
        one = re.sub(r"\s+", " ", soup.get_text(" "))
        regex = re.compile(
            rf"([一-龥々〆ヵヶぁ-んァ-ンーA-Za-z・ 　\[\]]{{2,50}})\s+"
            rf"[ぁ-んァ-ンー・ 　]{{2,80}}\s+"
            rf"({short_re})\s+"
            rf".+?\s+令和\d+年\d+月\d+日"
        )
        for m in regex.finditer(one):
            name = clean_name(m.group(1))
            party = short_to_full.get(m.group(2), normalize_party(m.group(2)))
            if is_person_name(name):
                members.append(Member("参議院", name, party))

    return dedupe_members(members)


def parse_sangiin_wikipedia_list() -> List[Member]:
    text = get_text("https://ja.wikipedia.org/wiki/参議院議員一覧")
    if not text:
        return []
    soup = BeautifulSoup(text, "html.parser")
    lines = [re.sub(r"\s+", " ", line).strip() for line in soup.get_text("\n").splitlines()]
    lines = [line for line in lines if line]
    party_re = "|".join(sorted(map(re.escape, KNOWN_PARTIES), key=len, reverse=True))
    members: List[Member] = []
    for i, line in enumerate(lines[:-1]):
        name = clean_name(line)
        if not is_person_name(name):
            continue
        near = " ".join(lines[i + 1:i + 4])
        pm = re.search(rf"({party_re})", near)
        if pm:
            members.append(Member("参議院", name, normalize_party(pm.group(1))))
    return dedupe_members(members)


def get_sangiin_members() -> List[Member]:
    candidate_urls = [
        "https://www.sangiin.go.jp/japanese/joho1/kousei/giin/221/giin.htm",
        "https://www.sangiin.go.jp/japanese/joho1/kousei/giin/giin.htm",
    ]
    candidate_urls += [
        f"https://www.sangiin.go.jp/japanese/joho1/kousei/giin/{n}/giin.htm"
        for n in range(230, 214, -1)
        if n != 221
    ]
    best: List[Member] = []
    best_url = ""
    for url in candidate_urls:
        members = parse_sangiin_page(url)
        if len(members) > len(best):
            best = members
            best_url = url
        if len(best) >= 240:
            break
    wiki = parse_sangiin_wikipedia_list()
    print(f"Sangiin official={len(best)} source={best_url} wikipedia={len(wiki)}", flush=True)
    if len(best) >= 200:
        return best
    if len(wiki) >= 200:
        return wiki
    return best if len(best) >= len(wiki) else wiki


def dedupe_members(members: Iterable[Member]) -> List[Member]:
    d: Dict[Tuple[str, str], Member] = {}
    for m in members:
        key = (m.chamber, normalize_name_key(m.name))
        if not key[1]:
            continue
        if key not in d:
            d[key] = m
    return list(d.values())


# -------------------- Wikipedia / Wikidata --------------------


def wikipedia_url_from_title(title: str) -> str:
    return "https://ja.wikipedia.org/wiki/" + quote(title.replace(" ", "_"))


def wiki_exact_title(name: str) -> Tuple[Optional[str], Optional[str], List[str]]:
    log: List[str] = []
    titles = [name, normalize_name_key(name), f"{name} (政治家)", f"{normalize_name_key(name)} (政治家)"]
    seen = set()
    for title in titles:
        if title in seen:
            continue
        seen.add(title)
        params = {
            "action": "query",
            "format": "json",
            "formatversion": "2",
            "redirects": "1",
            "prop": "pageprops|info",
            "inprop": "url",
            "titles": title,
        }
        res = request_get("https://ja.wikipedia.org/w/api.php?" + requests.compat.urlencode(params))
        if not res or res.status_code != 200:
            log.append(f"wiki_exact:{title}:http_error")
            continue
        try:
            pages = res.json().get("query", {}).get("pages", [])
        except Exception:
            log.append(f"wiki_exact:{title}:json_error")
            continue
        if not pages:
            continue
        page = pages[0]
        if page.get("missing"):
            log.append(f"wiki_exact:{title}:missing")
            continue
        found_title = page.get("title")
        if found_title:
            log.append(f"wiki_exact:{title}:hit:{found_title}")
            return found_title, page.get("fullurl") or wikipedia_url_from_title(found_title), log
    return None, None, log


def wiki_search_title(name: str, chamber: str) -> Tuple[Optional[str], Optional[str], List[str]]:
    log: List[str] = []
    queries = [f"{name} {chamber}", f"{name} 国会議員", f"{name} 政治家", name]
    nk = normalize_name_key(name)
    for query in queries:
        params = {
            "action": "query",
            "list": "search",
            "format": "json",
            "srsearch": query,
            "srlimit": "8",
        }
        res = request_get("https://ja.wikipedia.org/w/api.php?" + requests.compat.urlencode(params))
        if not res or res.status_code != 200:
            log.append(f"wiki_search:{query}:http_error")
            continue
        try:
            items = res.json().get("query", {}).get("search", [])
        except Exception:
            log.append(f"wiki_search:{query}:json_error")
            continue
        for item in items:
            title = item.get("title") or ""
            snippet = re.sub("<.*?>", "", item.get("snippet") or "")
            if nk in normalize_name_key(title) or nk in normalize_name_key(snippet):
                log.append(f"wiki_search:{query}:hit:{title}")
                return title, wikipedia_url_from_title(title), log
        log.append(f"wiki_search:{query}:no_match")
    return None, None, log


def find_wikipedia(name: str, chamber: str) -> Tuple[Optional[str], Optional[str], List[str]]:
    title, url, log = wiki_exact_title(name)
    if title:
        return title, url, log
    title, url, log2 = wiki_search_title(name, chamber)
    return title, url, log + log2


def get_wikidata_qid(title: str) -> Optional[str]:
    params = {
        "action": "query",
        "prop": "pageprops",
        "titles": title,
        "format": "json",
        "formatversion": "2",
    }
    res = request_get("https://ja.wikipedia.org/w/api.php?" + requests.compat.urlencode(params))
    if not res or res.status_code != 200:
        return None
    try:
        pages = res.json().get("query", {}).get("pages", [])
        if pages:
            return pages[0].get("pageprops", {}).get("wikibase_item")
    except Exception:
        return None
    return None


def official_from_wikidata_qid(qid: str) -> Optional[str]:
    res = request_get(f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json")
    if not res or res.status_code != 200:
        return None
    try:
        claims = res.json().get("entities", {}).get(qid, {}).get("claims", {})
        for claim in claims.get("P856", []):
            value = claim.get("mainsnak", {}).get("datavalue", {}).get("value")
            cleaned = clean_url(value)
            if cleaned and not is_excluded_final_url(cleaned):
                return cleaned
    except Exception:
        return None
    return None


def official_from_wikidata_search(name: str) -> Optional[str]:
    params = {
        "action": "wbsearchentities",
        "format": "json",
        "language": "ja",
        "uselang": "ja",
        "search": name,
        "limit": "8",
    }
    res = request_get("https://www.wikidata.org/w/api.php?" + requests.compat.urlencode(params))
    if not res or res.status_code != 200:
        return None
    try:
        for item in res.json().get("search", []):
            qid = item.get("id")
            label = item.get("label") or ""
            desc = item.get("description") or ""
            if qid and (normalize_name_key(name) in normalize_name_key(label) or "政治" in desc or "議員" in desc):
                url = official_from_wikidata_qid(qid)
                if url:
                    return url
    except Exception:
        return None
    return None


def official_candidates_from_wikipedia_page(wiki_url: str, name: str) -> List[Tuple[str, str]]:
    text = get_text(wiki_url)
    if not text:
        return []
    soup = BeautifulSoup(text, "html.parser")
    candidates: List[Tuple[str, str]] = []
    content = soup.select_one("div.mw-parser-output") or soup

    selectors = ["table.infobox a[href]", "table.infobox.vevent a[href]", "a.external[href]", "a[href^='http']"]
    for sel in selectors:
        for a in content.select(sel):
            href = clean_url(a.get("href"))
            label = a.get_text(" ", strip=True)
            if not href:
                continue
            candidates.append((href, label))

    # ラベルに公式があるものを優先。政治家ページは外部リンクが出典だらけなので、低スコアは捨てる。
    unique: Dict[str, Tuple[str, str]] = {}
    for url, label in candidates:
        key = domain_of(url) + urlparse(url).path.rstrip("/")
        unique.setdefault(key, (url, label))
    ranked = sorted(unique.values(), key=lambda x: score_final_candidate(x[0], name, x[1]), reverse=True)
    return [(u, l) for u, l in ranked if score_final_candidate(u, name, l) >= 0]


# -------------------- Party bridge: LDP --------------------

_JIMIN_CACHE: Optional[Dict[str, Dict[str, str]]] = None


def parse_sitemap_urls(xml_text: str) -> List[str]:
    soup = BeautifulSoup(xml_text, "xml")
    return [loc.get_text(strip=True) for loc in soup.select("loc") if loc.get_text(strip=True)]


def collect_jimin_member_profile_urls() -> List[str]:
    cache_path = CACHE_DIR / "jimin_profile_urls.json"
    if cache_path.exists():
        try:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    urls: List[str] = []
    to_fetch = ["https://www.jimin.jp/sitemap.xml"]
    seen_sitemaps = set()
    for sitemap in list(to_fetch):
        if sitemap in seen_sitemaps:
            continue
        seen_sitemaps.add(sitemap)
        res = request_get(sitemap)
        if not res or res.status_code >= 400:
            continue
        locs = parse_sitemap_urls(res.text)
        for loc in locs:
            if re.search(r"/member/\d+\.html$", loc):
                urls.append(loc)
            elif "sitemap" in loc and ("member" in loc or len(to_fetch) < 20):
                to_fetch.append(loc)

    urls = sorted(set(urls))
    if urls:
        cache_path.write_text(json.dumps(urls, ensure_ascii=False, indent=2), encoding="utf-8")
    return urls


def parse_jimin_profile(url: str) -> Optional[Tuple[str, Optional[str], str]]:
    text = get_text(url)
    if not text:
        return None
    soup = BeautifulSoup(text, "html.parser")
    h1 = soup.find("h1")
    name = clean_name(h1.get_text(" ", strip=True)) if h1 else ""
    if not name:
        # fallback: title or og:title
        title = soup.find("title")
        name = clean_name((title.get_text(" ", strip=True) if title else "").split("|", 1)[0])
    official = None
    for a in soup.select("a[href]"):
        label = a.get_text(" ", strip=True)
        href = clean_url(a.get("href"))
        if not href:
            continue
        if "公式サイト" in label or label.strip().lower() in {"公式", "official"}:
            if not is_excluded_final_url(href):
                official = href
                break
    if is_person_name(name):
        return name, official, url
    return None


def get_jimin_profile_cache() -> Dict[str, Dict[str, str]]:
    global _JIMIN_CACHE
    if _JIMIN_CACHE is not None:
        return _JIMIN_CACHE

    cache_path = CACHE_DIR / "jimin_profiles.json"
    if cache_path.exists():
        try:
            _JIMIN_CACHE = json.loads(cache_path.read_text(encoding="utf-8"))
            return _JIMIN_CACHE
        except Exception:
            pass

    profile_urls = collect_jimin_member_profile_urls()
    profiles: Dict[str, Dict[str, str]] = {}

    def worker(u: str):
        return parse_jimin_profile(u)

    if profile_urls:
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            for result in ex.map(worker, profile_urls):
                if not result:
                    continue
                name, official, profile_url = result
                if official:
                    profiles[normalize_name_key(name)] = {"official_url": official, "profile_url": profile_url}

    if profiles:
        cache_path.write_text(json.dumps(profiles, ensure_ascii=False, indent=2), encoding="utf-8")
    _JIMIN_CACHE = profiles
    return profiles


def official_from_jimin_bridge(name: str) -> Optional[Tuple[str, str]]:
    cache = get_jimin_profile_cache()
    item = cache.get(normalize_name_key(name))
    if item and item.get("official_url"):
        return item["official_url"], item.get("profile_url", "")

    # sitemapが取れない場合の最終フォールバック: 検索でjimin議員ページを探し、そこから公式サイトを取る。
    profile_url = search_web_for_party_profile(name, "jimin.jp/member")
    if profile_url:
        parsed = parse_jimin_profile(profile_url)
        if parsed and parsed[1]:
            return parsed[1], profile_url
    return None


# -------------------- Search fallback --------------------


def decode_bing_redirect(href: str) -> str:
    qs = parse_qs(urlparse(href).query)
    u = qs.get("u", [href])[0]
    if u.startswith("a1"):
        try:
            return base64.urlsafe_b64decode(u[2:] + "===").decode("utf-8", "ignore")
        except Exception:
            return href
    return u


def extract_urls_from_search_html(html_text: str) -> List[str]:
    soup = BeautifulSoup(html_text, "html.parser")
    urls: List[str] = []
    for a in soup.select("a[href]"):
        href = a.get("href") or ""
        if "duckduckgo.com/l/" in href:
            qs = parse_qs(urlparse(href).query)
            href = qs.get("uddg", [href])[0]
        elif href.startswith("/url?"):
            qs = parse_qs(urlparse(href).query)
            href = qs.get("q", qs.get("url", [href]))[0]
        elif "bing.com/ck/a" in href:
            href = decode_bing_redirect(href)
        href = unquote(href)
        url = clean_url(href)
        if not url:
            continue
        host = domain_of(url)
        if any(bad in host for bad in ["google.", "bing.", "duckduckgo.", "yahoo."]):
            continue
        urls.append(url)
    # preserve order, de-dupe by host+path
    seen = set()
    out = []
    for u in urls:
        key = domain_of(u) + urlparse(u).path.rstrip("/")
        if key not in seen:
            seen.add(key)
            out.append(u)
    return out


def search_web_urls(query: str) -> List[str]:
    urls: List[str] = []
    search_pages = [
        "https://duckduckgo.com/html/?" + requests.compat.urlencode({"q": query}),
        "https://www.bing.com/search?" + requests.compat.urlencode({"q": query}),
    ]
    # Jina Searchが利用できる環境なら、検索エンジンのBOT対策を回避しやすい。
    if os.environ.get("USE_JINA_SEARCH", "1") == "1":
        search_pages.insert(0, "https://s.jina.ai/search?" + requests.compat.urlencode({"q": query}))
    for page in search_pages:
        res = request_get(page)
        if not res or res.status_code >= 400:
            continue
        urls.extend(extract_urls_from_search_html(res.text))
    seen = set()
    out = []
    for u in urls:
        key = domain_of(u) + urlparse(u).path.rstrip("/")
        if key not in seen:
            seen.add(key)
            out.append(u)
    return out


def search_web_for_party_profile(name: str, domain_hint: str) -> Optional[str]:
    for query in [f"site:{domain_hint} {name}", f"{name} {domain_hint}"]:
        for url in search_web_urls(query):
            if domain_hint in url:
                return url
    return None


def official_from_search(name: str, party: str) -> Optional[str]:
    queries = [
        f"{name} 公式サイト 国会議員",
        f"{name} 事務所 公式",
        f"{name} ホームページ",
    ]
    candidates: List[Tuple[str, int]] = []
    for q in queries:
        for url in search_web_urls(q):
            if is_excluded_final_url(url):
                continue
            candidates.append((url, score_final_candidate(url, name)))
    candidates.sort(key=lambda x: x[1], reverse=True)
    for url, score in candidates[:8]:
        if score < 0:
            continue
        valid = validate_url_exists(url)
        if valid:
            return valid
    return None


# -------------------- Official URL resolution --------------------


def resolve_official_url(member: Member, *, allow_regression_seed: bool = True) -> Member:
    log: List[str] = []
    key = normalize_name_key(member.name)

    override = OFFICIAL_URL_OVERRIDES.get(member.name) or OFFICIAL_URL_OVERRIDES.get(key)
    if override:
        valid = validate_url_exists(override) or override
        member.official_url = valid
        member.official_url_source = "manual_override"
        log.append(f"manual_override:{valid}")

    title, wiki_url, wiki_log = find_wikipedia(member.name, member.chamber)
    member.wikipedia_title = title
    member.wikipedia_url = wiki_url
    log.extend(wiki_log)

    if not member.official_url and title:
        qid = get_wikidata_qid(title)
        log.append(f"wikidata_qid:{qid or '-'}")
        if qid:
            url = official_from_wikidata_qid(qid)
            if url:
                valid = validate_url_exists(url) or url
                member.official_url = valid
                member.official_url_source = "wikidata_p856"
                log.append(f"wikidata_p856:{valid}")

    if not member.official_url:
        url = official_from_wikidata_search(member.name)
        if url:
            valid = validate_url_exists(url) or url
            member.official_url = valid
            member.official_url_source = "wikidata_search_p856"
            log.append(f"wikidata_search_p856:{valid}")

    if not member.official_url and wiki_url:
        for candidate, label in official_candidates_from_wikipedia_page(wiki_url, member.name):
            valid = validate_url_exists(candidate)
            if valid and not is_excluded_final_url(valid):
                member.official_url = valid
                member.official_url_source = "wikipedia_external"
                log.append(f"wikipedia_external:{valid}:{label}")
                break

    if not member.official_url and normalize_party(member.party) == "自由民主党":
        bridge = official_from_jimin_bridge(member.name)
        if bridge:
            url, profile_url = bridge
            valid = validate_url_exists(url) or url
            member.official_url = valid
            member.official_url_source = "jimin_profile_official"
            log.append(f"jimin_profile:{profile_url}->{valid}")

    if not member.official_url:
        url = official_from_search(member.name, member.party)
        if url:
            member.official_url = url
            member.official_url_source = "search_fallback"
            log.append(f"search_fallback:{url}")

    if not member.official_url and allow_regression_seed:
        seed = REGRESSION_OFFICIALS.get(member.name) or REGRESSION_OFFICIALS.get(key)
        if seed:
            valid = validate_url_exists(seed) or seed
            member.official_url = valid
            member.official_url_source = "regression_seed"
            log.append(f"regression_seed:{valid}")

    if not member.official_url:
        log.append("official_url:not_found")

    member.lookup_log = log
    return member


# -------------------- Certificate / scan --------------------


def decode_openssl_value(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    if re.search(r"\\[0-9A-Fa-f]{2}", value):
        try:
            raw = bytes(int(x, 16) for x in re.findall(r"\\([0-9A-Fa-f]{2})", value))
            decoded = raw.decode("utf-8", errors="replace")
            if decoded and " " not in decoded:
                return decoded
        except Exception:
            pass
    return value


def extract_cert(hostname: str, port: int = 443) -> Optional[dict]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)

        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer"],
            input=der,
            capture_output=True,
            check=True,
        )
        output = proc.stdout.decode("utf-8", errors="replace")
        subject_line = ""
        issuer_line = ""
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("subject="):
                subject_line = line[len("subject="):].strip()
            elif line.startswith("issuer="):
                issuer_line = line[len("issuer="):].strip()

        def pick(field: str, text: str) -> Optional[str]:
            for pattern in [rf"{field}\s*=\s*([^,/]+)", rf"/{field}=([^/]+)"]:
                m = re.search(pattern, text)
                if m:
                    return decode_openssl_value(m.group(1).strip())
            return None

        return {
            "subject": {
                "commonName": pick("CN", subject_line),
                "organizationName": pick("O", subject_line),
            },
            "issuer": {
                "commonName": pick("CN", issuer_line),
                "organizationName": pick("O", issuer_line),
            },
        }
    except Exception:
        return None


def contains_gs(*texts: Optional[str]) -> bool:
    return "globalsign" in " ".join(text or "" for text in texts).lower()


def is_probable_gs_legislator_cert(party: str, subject_o: Optional[str], issuer_o: Optional[str], issuer_cn: Optional[str]) -> bool:
    if not contains_gs(issuer_o, issuer_cn):
        return False
    if not subject_o:
        return False
    return normalize_party(party) == normalize_party(subject_o)


def detect_site_seal(text: str) -> bool:
    haystack = (text or "").lower()
    return any(re.search(pattern, haystack, re.I) for pattern in SITE_SEAL_PATTERNS)


def scan_site(member: Member) -> ScanResult:
    notes: List[str] = []
    log = member.lookup_log or []

    if not member.official_url:
        return ScanResult(
            chamber=member.chamber,
            name=member.name,
            party=member.party,
            party_group=party_group(member.party),
            wikipedia_title=member.wikipedia_title,
            source_url=member.wikipedia_url,
            official_url=None,
            official_url_source=member.official_url_source,
            final_url=None,
            status="site_not_found",
            http_status=None,
            cert_subject_cn=None,
            cert_subject_o=None,
            cert_issuer_o=None,
            cert_issuer_cn=None,
            is_https=False,
            is_gs=False,
            is_gs_legislator_cert=False,
            site_seal_found=False,
            notes=["公式サイトURLを取得できませんでした"],
            lookup_log=log,
        )

    url = clean_url(member.official_url) or member.official_url
    parsed0 = urlparse(url)
    candidates = []
    if parsed0.scheme == "http":
        candidates.append("https://" + parsed0.netloc + (parsed0.path or "/"))
        if not parsed0.netloc.startswith("www."):
            candidates.append("https://www." + parsed0.netloc + (parsed0.path or "/"))
    candidates.append(url)

    response = None
    final_url = None
    status_code = None
    site_seal = False
    for c in candidates:
        response = request_get(c)
        if response and response.status_code < 500:
            final_url = response.url or c
            status_code = response.status_code
            site_seal = detect_site_seal(response.text or "")
            break

    if not response:
        notes.append("HTTP取得失敗")

    effective_url = final_url or url
    parsed = urlparse(effective_url)
    cert_subject_cn = None
    cert_subject_o = None
    cert_issuer_o = None
    cert_issuer_cn = None
    is_https = False

    cert_hosts: List[str] = []
    if parsed.hostname:
        if parsed.scheme == "https":
            cert_hosts.append(parsed.hostname)
        else:
            if not parsed.hostname.startswith("www."):
                cert_hosts.append("www." + parsed.hostname)
            cert_hosts.append(parsed.hostname)

    for host in cert_hosts:
        cert = extract_cert(host, 443)
        if not cert:
            continue
        subject = cert.get("subject", {})
        issuer = cert.get("issuer", {})
        cert_subject_cn = subject.get("commonName")
        cert_subject_o = subject.get("organizationName")
        cert_issuer_o = issuer.get("organizationName")
        cert_issuer_cn = issuer.get("commonName")
        is_https = True
        if not final_url:
            final_url = "https://" + host + "/"
        break

    if not is_https and parsed.scheme == "https":
        is_https = True
        notes.append("HTTPS URLだが証明書詳細取得に失敗")

    is_gs = contains_gs(cert_issuer_o, cert_issuer_cn)
    is_gs_leg = is_probable_gs_legislator_cert(member.party, cert_subject_o, cert_issuer_o, cert_issuer_cn)

    return ScanResult(
        chamber=member.chamber,
        name=member.name,
        party=member.party,
        party_group=party_group(member.party),
        wikipedia_title=member.wikipedia_title,
        source_url=member.wikipedia_url,
        official_url=member.official_url,
        official_url_source=member.official_url_source,
        final_url=final_url,
        status="ok" if response else "request_error",
        http_status=status_code,
        cert_subject_cn=cert_subject_cn,
        cert_subject_o=cert_subject_o,
        cert_issuer_o=cert_issuer_o,
        cert_issuer_cn=cert_issuer_cn,
        is_https=is_https,
        is_gs=is_gs,
        is_gs_legislator_cert=is_gs_leg,
        site_seal_found=site_seal,
        notes=notes,
        lookup_log=log,
    )


# -------------------- Summary --------------------


def summarize(results: List[ScanResult]) -> dict:
    total_members = len(results)
    with_site = sum(1 for r in results if r.official_url)
    https_count = sum(1 for r in results if r.is_https)
    gs_count = sum(1 for r in results if r.is_gs)
    gs_legislator_count = sum(1 for r in results if r.is_gs_legislator_cert)
    site_seal_count = sum(1 for r in results if r.site_seal_found)

    target_https = [r for r in results if r.party in GS_SHARE_TARGET_PARTIES and r.is_https]
    target_gs = [r for r in target_https if r.is_gs]
    gs_leg_for_seal = [r for r in results if r.is_gs_legislator_cert]
    seal_on_gs_leg = [r for r in gs_leg_for_seal if r.site_seal_found]

    by_chamber: Dict[str, dict] = {c: {"chamber": c, "total": 0, "with_site": 0, "https": 0, "gs": 0, "seal": 0, "gs_share": 0.0} for c in ["衆議院", "参議院"]}
    for r in results:
        row = by_chamber.setdefault(r.chamber or "不明", {"chamber": r.chamber or "不明", "total": 0, "with_site": 0, "https": 0, "gs": 0, "seal": 0, "gs_share": 0.0})
        row["total"] += 1
        row["with_site"] += int(bool(r.official_url))
        row["https"] += int(r.is_https)
        row["gs"] += int(r.is_gs)
        row["seal"] += int(r.site_seal_found)
    for row in by_chamber.values():
        row["gs_share"] = pct(row["gs"], row["https"])

    by_party: Dict[str, dict] = {p: {"party": p, "total": 0, "with_site": 0, "https": 0, "gs": 0, "seal": 0, "gs_share": 0.0} for p in DISPLAY_PARTIES + ["その他"]}
    for r in results:
        p = party_group(r.party)
        row = by_party[p]
        row["total"] += 1
        row["with_site"] += int(bool(r.official_url))
        row["https"] += int(r.is_https)
        row["gs"] += int(r.is_gs)
        row["seal"] += int(r.site_seal_found)
    for row in by_party.values():
        row["gs_share"] = pct(row["gs"], row["https"])

    return {
        "generated_at": now_iso(),
        "total_members": total_members,
        "with_site": with_site,
        "https_count": https_count,
        "gs_count": gs_count,
        # 表示不要でもサイトシール率の分母として残す
        "gs_legislator_count": gs_legislator_count,
        "site_seal_count": site_seal_count,
        "gs_share_target_parties": pct(len(target_gs), len(target_https)),
        "gs_share_target_parties_numerator": len(target_gs),
        "gs_share_target_parties_denominator": len(target_https),
        "site_seal_share_gs_legislator_cert": pct(len(seal_on_gs_leg), len(gs_leg_for_seal)),
        "site_seal_share_gs_legislator_cert_numerator": len(seal_on_gs_leg),
        "site_seal_share_gs_legislator_cert_denominator": len(gs_leg_for_seal),
        "by_chamber": [by_chamber[k] for k in ["衆議院", "参議院"] if k in by_chamber],
        "by_party": [by_party[p] for p in DISPLAY_PARTIES + ["その他"]],
        "display_parties": DISPLAY_PARTIES + ["その他"],
    }


# -------------------- Tests and main --------------------


def run_self_test() -> None:
    print("SELF TEST START", flush=True)
    failures = []

    title, wiki_url, log = find_wikipedia("坂本竜太郎", "衆議院")
    print("wiki 坂本竜太郎:", title, wiki_url, log[-3:], flush=True)
    if title != "坂本竜太郎":
        failures.append("Wikipedia exact lookup failed for 坂本竜太郎")

    m = Member("衆議院", "坂本竜太郎", "自由民主党")
    # regression_seedは使わず、実データソースだけで検証
    m = resolve_official_url(m, allow_regression_seed=False)
    print("official 坂本竜太郎:", m.official_url, m.official_url_source, (m.lookup_log or [])[-5:], flush=True)
    if not m.official_url or "sakamoto-ryutaro.jp" not in m.official_url:
        failures.append("Official URL lookup failed for 坂本竜太郎")

    s_members = parse_sangiin_page("https://www.sangiin.go.jp/japanese/joho1/kousei/giin/221/giin.htm")
    print("sangiin 221 count:", len(s_members), flush=True)
    if len(s_members) < 200:
        failures.append("Sangiin 221 page parse returned too few members")

    sh_members = parse_shugiin_wikipedia_list()
    print("shugiin wikipedia count:", len(sh_members), flush=True)
    if len(sh_members) < 430:
        failures.append("Shugiin Wikipedia parse returned too few members")

    if failures:
        for f in failures:
            print("SELF TEST FAIL:", f, flush=True)
        raise SystemExit(1)
    print("SELF TEST OK", flush=True)


def build_members() -> List[Member]:
    shugiin = get_shugiin_members()
    sangiin = get_sangiin_members()
    members = dedupe_members(shugiin + sangiin)
    print("Shugiin fetched:", len(shugiin), flush=True)
    print("Sangiin fetched:", len(sangiin), flush=True)
    print("Current members fetched:", len(members), flush=True)
    if len(shugiin) == 0 or len(sangiin) == 0:
        raise RuntimeError("現職議員数が0の院があります。取得元のHTML変更または通信エラーです。")
    return sorted(members, key=lambda x: (x.chamber, x.name))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--debug-name", action="append", default=[])
    args = parser.parse_args()

    load_overrides()
    if args.self_test:
        run_self_test()
        return

    debug_keys = {normalize_name_key(x) for x in args.debug_name}
    members = build_members()

    enriched: List[Member] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_ENRICH_WORKERS) as executor:
        futures = [executor.submit(resolve_official_url, m) for m in members]
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            m = future.result()
            enriched.append(m)
            if normalize_name_key(m.name) in debug_keys:
                print("DEBUG", m.name, m.wikipedia_title, m.official_url, m.official_url_source, m.lookup_log, flush=True)
            if i % 25 == 0:
                print(f"Enriched {i}/{len(members)}", flush=True)

    enriched = sorted(enriched, key=lambda x: (x.chamber, x.name))

    results: List[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as executor:
        futures = [executor.submit(scan_site, m) for m in enriched]
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            results.append(future.result())
            if i % 25 == 0:
                print(f"Scanned {i}/{len(enriched)}", flush=True)

    results = sorted(results, key=lambda x: (x.chamber, x.name))
    payload = {
        "generated_at": now_iso(),
        "summary": summarize(results),
        "results": [asdict(r) for r in results],
    }
    OUT_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {OUT_FILE} with {len(results)} rows", flush=True)


if __name__ == "__main__":
    main()
