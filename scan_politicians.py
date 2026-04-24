# -*- coding: utf-8 -*-
"""
国会議員サイト証明書ダッシュボード用データ生成スクリプト v9

設計方針:
- 議員一覧取得は「衆議院/参議院 Wikipedia + 公式ページ」を結合して、片方が0件にならないようにする
- 公式サイトURL取得は ①Wikipedia ②政党公式 ③手動補正 ④検索 の順
- GitHub Actions 30分タイムアウト対策として、短い通信タイムアウト・並列化・進捗ログ・品質チェックを入れる
- 参議院/衆議院どちらかが大幅に少ない場合は data.json を更新せず停止する
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import html
import json
import re
import socket
import ssl
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

OUT_FILE = Path("data.json")

# GitHub Actions で大量件数を処理するため、1件で長時間待たない。
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 12
TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)

USER_AGENT = "DietCertDashboard/4.0 (+GitHub Actions; contact: dashboard)"
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept-Language": "ja,en;q=0.8",
}

WIKI_BASE = "https://ja.wikipedia.org"
WIKI_API = "https://ja.wikipedia.org/w/api.php"

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
    "自民": "自由民主党", "自民党": "自由民主党", "自由民主": "自由民主党", "自由民主党": "自由民主党",
    "立民": "立憲民主党", "立憲": "立憲民主党", "立憲民主": "立憲民主党", "立憲民主党": "立憲民主党",
    "維新": "日本維新の会", "日本維新": "日本維新の会", "日本維新の会": "日本維新の会",
    "公明": "公明党", "公明党": "公明党",
    "国民": "国民民主党", "国民民主": "国民民主党", "国民民主党": "国民民主党", "民主": "国民民主党",
    "共産": "日本共産党", "日本共産": "日本共産党", "日本共産党": "日本共産党",
    "れいわ": "れいわ新選組", "れいわ新選組": "れいわ新選組", "れ新": "れいわ新選組",
    "参政": "参政党", "参政党": "参政党",
    "社民": "社会民主党", "社会民主党": "社会民主党",
    "保守": "日本保守党", "日本保守党": "日本保守党",
    "沖縄": "沖縄の風", "沖縄の風": "沖縄の風",
    "みら": "チームみらい", "チームみらい": "チームみらい",
    "無所属": "無所属", "無": "無所属",
    "中道改革連合": "中道改革連合",
    "減税日本・ゆうこく連合": "減税日本・ゆうこく連合",
}

KNOWN_PARTIES = set(PARTY_NORMALIZATION.values())
PARTY_TOKENS = sorted(set(PARTY_NORMALIZATION.keys()) | KNOWN_PARTIES, key=len, reverse=True)
PARTY_RE = "|".join(re.escape(x) for x in PARTY_TOKENS if x)

PARTY_PROFILE_DOMAINS = {
    "自由民主党": ["jimin.jp", "sangiin-jimin.jp"],
    "立憲民主党": ["cdp-japan.jp"],
    "国民民主党": ["new-kokumin.jp"],
    "れいわ新選組": ["reiwa-shinsengumi.com"],
    "公明党": ["komei.or.jp"],
    "日本維新の会": ["o-ishin.jp"],
    "日本共産党": ["jcp.or.jp"],
}
PARTY_DOMAINS_ALL = sorted({d for domains in PARTY_PROFILE_DOMAINS.values() for d in domains})

SOCIAL_OR_NOISE_DOMAINS = [
    "twitter.com", "x.com", "facebook.com", "instagram.com", "youtube.com", "line.me", "lin.ee",
    "tiktok.com", "threads.net", "note.com", "ameblo.jp", "wikipedia.org", "wikidata.org",
    "go2senkyo.com", "google.com", "bing.com", "yahoo.co.jp", "duckduckgo.com",
]

SITE_SEAL_PATTERNS = [
    r"globalsign", r"site\s*seal", r"siteseal", r"sslpr", r"secure\s+site\s+seal", r"認証シール", r"実在証明・盗聴対策シール",
]

# 取りこぼしが判明しているものだけ。増やしすぎず、検索/政党サイトの補助に留める。
OFFICIAL_URL_OVERRIDES = {
    "前原誠司": "https://www.maehara21.com/",
    "齋藤健": "https://saito-ken.jp/",
    "斎藤健": "https://saito-ken.jp/",
    "坂本竜太郎": "https://sakamoto-ryutaro.jp/",
}

_thread_local = threading.local()
_print_lock = threading.Lock()


def log(message: str) -> None:
    with _print_lock:
        print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {message}", flush=True)


def get_session() -> requests.Session:
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update(HEADERS)
        adapter = requests.adapters.HTTPAdapter(max_retries=1, pool_connections=80, pool_maxsize=80)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        _thread_local.session = session
    return session


def request_get(url: str, *, allow_redirects: bool = True, retries: int = 1) -> Optional[requests.Response]:
    for attempt in range(retries + 1):
        try:
            res = get_session().get(url, timeout=TIMEOUT, allow_redirects=allow_redirects)
            # 文字コード判定は意外に重いので、必要な場合だけ apparent_encoding を使う
            if not res.encoding or res.encoding.lower() in {"iso-8859-1", "ascii"}:
                res.encoding = res.apparent_encoding or res.encoding
            return res
        except Exception:
            if attempt < retries:
                time.sleep(0.25 * (attempt + 1))
    return None


def get_text(url: str) -> Optional[str]:
    res = request_get(url, retries=1)
    if not res or res.status_code >= 500:
        return None
    return res.text


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def pct(numerator: int, denominator: int) -> float:
    return round((numerator / denominator * 100) if denominator else 0.0, 1)


def normalize_party(value: str) -> str:
    if not value:
        return ""
    value = html.unescape(str(value)).strip()
    compact = re.sub(r"\s+", "", value)
    compact = compact.strip("（）()[]【】")
    # 会派名に / や ・ が含まれる場合でも、減税日本・ゆうこく連合は崩さない
    if compact in PARTY_NORMALIZATION:
        return PARTY_NORMALIZATION[compact]
    compact_first = re.split(r"[／/,，、]", compact)[0]
    return PARTY_NORMALIZATION.get(compact_first, value.strip())


def party_group(party: str) -> str:
    p = normalize_party(party or "")
    # 減税日本・ゆうこく連合は指定どおり「その他」
    return p if p in DISPLAY_PARTIES else "その他"


def clean_name(name: str) -> str:
    name = html.unescape(name or "").replace("　", " ").strip()
    name = re.sub(r"\s*\[.*?\]", "", name)
    name = re.sub(r"（.*?）|\(.*?\)", "", name)
    name = re.sub(r"[君氏]+$", "", name).strip()
    return name


def name_key(name: str) -> str:
    return re.sub(r"\s+", "", clean_name(name))


def is_person_name(text: str) -> bool:
    text = clean_name(text)
    if not (2 <= len(text) <= 18):
        return False
    if text in PARTY_TOKENS:
        return False
    if re.search(r"(一覧|選挙区|比例|議員|衆議院|参議院|会派|任期|党派|現職|画像|編集|脚注|出典|年月日|都道府県)", text):
        return False
    if re.fullmatch(r"[ぁ-んァ-ンー・ 　]+", text):
        return False
    return bool(re.fullmatch(r"[一-龥々〆ヵヶぁ-んァ-ンーA-Za-z・ 　]+", text))


def clean_url(url: Optional[str], base_url: Optional[str] = None) -> Optional[str]:
    if not url:
        return None
    url = html.unescape(str(url)).strip().strip('"').strip("'")
    if not url or url.startswith(("mailto:", "tel:", "javascript:", "#")):
        return None
    if base_url and (url.startswith("/") or url.startswith("./") or url.startswith("../")):
        if base_url.startswith(WIKI_BASE) and url.startswith("./"):
            url = WIKI_BASE + "/wiki/" + url[2:]
        else:
            url = urljoin(base_url, url)
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


def wiki_url_for_title(title: str) -> str:
    return f"{WIKI_BASE}/wiki/{quote(title.replace(' ', '_'))}"


def wiki_href_to_url(href: str) -> Optional[str]:
    if not href:
        return None
    href = html.unescape(href)
    if href.startswith("./"):
        return WIKI_BASE + "/wiki/" + href[2:]
    if href.startswith("/wiki/"):
        return WIKI_BASE + href
    if href.startswith("http") and "wikipedia.org/wiki/" in href:
        return href
    return None


def fetch_wikipedia_html(title: str) -> Optional[str]:
    # action=parse は通常ページHTMLより構造が安定する
    params = {"action": "parse", "format": "json", "page": title, "prop": "text|displaytitle", "redirects": "1"}
    res = request_get(WIKI_API + "?" + requests.compat.urlencode(params), retries=1)
    if res and res.status_code == 200:
        try:
            data = res.json()
            html_text = data.get("parse", {}).get("text", {}).get("*")
            if html_text:
                return html_text
        except Exception:
            pass
    return get_text(wiki_url_for_title(title))


@dataclass
class Member:
    chamber: str
    name: str
    party: str
    wikipedia_title: Optional[str] = None
    wikipedia_url: Optional[str] = None
    official_url: Optional[str] = None
    official_url_source: Optional[str] = None
    party_profile_url: Optional[str] = None


@dataclass
class ScanResult:
    chamber: str
    name: str
    party: str
    wikipedia_title: Optional[str]
    source_url: Optional[str]
    official_url: Optional[str]
    official_url_source: Optional[str]
    party_profile_url: Optional[str]
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


def find_party_in_text(text: str) -> Optional[str]:
    if not text:
        return None
    compact = re.sub(r"\s+", "", text)
    # 長い順に見る
    for token in PARTY_TOKENS:
        if token and token in compact:
            p = normalize_party(token)
            if p in KNOWN_PARTIES:
                return p
    return None


def parse_members_from_wikipedia_list(title: str, chamber: str) -> List[Member]:
    raw = fetch_wikipedia_html(title)
    if not raw:
        log(f"{chamber} Wikipedia fetch failed: {title}")
        return []
    soup = BeautifulSoup(raw, "html.parser")
    members: Dict[Tuple[str, str], Member] = {}

    # 1) table優先。action=parse では href が ./議員名 になることが多いため、/wiki/ 前提にしない。
    for tr in soup.select("tr"):
        row_text = re.sub(r"\s+", " ", tr.get_text(" ", strip=True))
        party = find_party_in_text(row_text)
        if not party:
            continue
        for a in tr.select("a[href]"):
            label = clean_name(a.get_text(" ", strip=True))
            if not is_person_name(label):
                continue
            href = a.get("href") or ""
            if ":" in href or "#" in href:
                continue
            wiki_url = wiki_href_to_url(href)
            key = (chamber, name_key(label))
            members[key] = Member(chamber, label, party, wikipedia_title=label, wikipedia_url=wiki_url)
            break

    # 2) tableで足りない場合のテキスト行 fallback。
    text = soup.get_text("\n")
    lines = [re.sub(r"\s+", " ", line).strip() for line in text.splitlines()]
    lines = [line for line in lines if line]
    for i, line in enumerate(lines):
        candidate = clean_name(line)
        if not is_person_name(candidate):
            continue
        window = " ".join(lines[i + 1 : i + 6])
        party = find_party_in_text(window)
        if not party:
            continue
        key = (chamber, name_key(candidate))
        members.setdefault(key, Member(chamber, candidate, party, wikipedia_title=candidate, wikipedia_url=wiki_url_for_title(candidate)))

    rows = sorted(members.values(), key=lambda m: m.name)
    log(f"{chamber} Wikipedia parsed: {len(rows)} from {title}")
    return rows


def parse_sangiin_official_page(url: str) -> List[Member]:
    text = get_text(url)
    if not text:
        return []
    soup = BeautifulSoup(text, "html.parser")
    members: Dict[Tuple[str, str], Member] = {}

    # 公式ページの表: 氏名 / ふりがな / 会派 / 選挙区 / 任期満了日
    for tr in soup.select("tr"):
        cells = [re.sub(r"\s+", " ", c.get_text(" ", strip=True)) for c in tr.select("td,th")]
        if len(cells) < 3:
            continue
        party = find_party_in_text(" ".join(cells))
        if not party:
            continue
        # 多くの場合は先頭セルが氏名
        candidates = [cells[0]] + cells[1:3]
        for cell in candidates:
            nm = clean_name(cell)
            if is_person_name(nm):
                members[("参議院", name_key(nm))] = Member("参議院", nm, party)
                break

    # テキスト1行 fallback
    lines = [re.sub(r"\s+", " ", line).strip() for line in soup.get_text("\n").splitlines()]
    for line in lines:
        if "令和" not in line:
            continue
        party = find_party_in_text(line)
        if not party:
            continue
        m = re.match(r"^([一-龥々〆ヵヶぁ-んァ-ンー・ 　]{2,40})\s+", line)
        if m:
            nm = clean_name(m.group(1))
            if is_person_name(nm):
                members[("参議院", name_key(nm))] = Member("参議院", nm, party)

    rows = sorted(members.values(), key=lambda m: m.name)
    log(f"参議院 official parsed: {len(rows)} from {url}")
    return rows


def merge_members(*lists: Iterable[Member]) -> List[Member]:
    merged: Dict[Tuple[str, str], Member] = {}
    for lst in lists:
        for m in lst:
            key = (m.chamber, name_key(m.name))
            old = merged.get(key)
            if not old:
                merged[key] = m
                continue
            # 情報が多い方で補完
            if not old.party and m.party:
                old.party = m.party
            if not old.wikipedia_url and m.wikipedia_url:
                old.wikipedia_url = m.wikipedia_url
            if not old.wikipedia_title and m.wikipedia_title:
                old.wikipedia_title = m.wikipedia_title
    return sorted(merged.values(), key=lambda m: (m.chamber, m.name))


def get_sangiin_members() -> List[Member]:
    wiki = parse_members_from_wikipedia_list("参議院議員一覧", "参議院")
    official = []
    for url in [
        "https://www.sangiin.go.jp/japanese/joho1/kousei/giin/221/giin.htm",
        "https://www.sangiin.go.jp/japanese/joho1/kousei/giin/giin.htm",
    ]:
        official.extend(parse_sangiin_official_page(url))
    rows = merge_members(wiki, official)
    log(f"Sangiin merged: {len(rows)} / wiki={len(wiki)} official={len(official)}")
    return rows


def get_shugiin_members() -> List[Member]:
    wiki = parse_members_from_wikipedia_list("衆議院議員一覧", "衆議院")
    rows = merge_members(wiki)
    log(f"Shugiin merged: {len(rows)} / wiki={len(wiki)}")
    return rows


def is_noise_url(url: str, *, exclude_party_domains: bool = True) -> bool:
    host = urlparse(url).netloc.lower()
    if any(d in host for d in SOCIAL_OR_NOISE_DOMAINS):
        return True
    if exclude_party_domains and any(d in host for d in PARTY_DOMAINS_ALL):
        return True
    return False


def is_party_profile_url(url: str, party: str) -> bool:
    host = urlparse(url).netloc.lower()
    return any(d in host for d in PARTY_PROFILE_DOMAINS.get(normalize_party(party), []))


def extract_official_links_from_html(html_text: str, base_url: str, name: str, party: str, *, allow_party_profiles: bool = False) -> List[Tuple[str, str]]:
    soup = BeautifulSoup(html_text or "", "html.parser")
    candidates: List[Tuple[int, str, str]] = []
    official_words = ["公式サイト", "公式HP", "公式ＨＰ", "公式Web", "ホームページ", "HP", "Website", "WEBサイト", "サイト"]
    social_words = ["Facebook", "X", "Twitter", "Instagram", "YouTube", "LINE", "TikTok", "Blog", "ブログ"]

    for a in soup.select("a[href]"):
        label = re.sub(r"\s+", " ", a.get_text(" ", strip=True))
        href = clean_url(a.get("href"), base_url)
        if not href:
            continue
        if any(word.lower() in label.lower() for word in social_words):
            continue
        if is_noise_url(href, exclude_party_domains=not allow_party_profiles):
            continue
        score = 0
        lower_label = label.lower()
        if any(word.lower() in lower_label for word in official_words):
            score += 100
        if href.startswith("https://"):
            score += 5
        host_path = (urlparse(href).netloc + urlparse(href).path).lower()
        if any(word in host_path for word in ["official", "office", "koenkai", "support", "giin"]):
            score += 8
        if is_party_profile_url(href, party):
            score += 30 if allow_party_profiles else -100
        if score > 0:
            candidates.append((score, href, label or href))

    seen = set()
    rows: List[Tuple[str, str]] = []
    for score, href, label in sorted(candidates, key=lambda x: x[0], reverse=True):
        parsed = urlparse(href)
        key = parsed.netloc.lower().removeprefix("www.") + parsed.path.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        rows.append((href, label))
    return rows


def validate_official_url(url: str, name: str) -> Optional[str]:
    url = clean_url(url)
    if not url:
        return None
    parsed = urlparse(url)
    candidates = [url]
    if parsed.scheme == "http":
        candidates.append("https://" + parsed.netloc + (parsed.path or "/"))
        if not parsed.netloc.startswith("www."):
            candidates.append("https://www." + parsed.netloc + (parsed.path or "/"))
    elif parsed.scheme == "https" and not parsed.netloc.startswith("www."):
        candidates.append("https://www." + parsed.netloc + (parsed.path or "/"))

    for candidate in candidates[:3]:
        res = request_get(candidate, retries=0)
        if res and res.status_code < 500:
            return res.url or candidate
    # 403等も request_get が返るので上で拾える。完全に落ちるサイトはURL自体は保持。
    return url


def extract_official_from_wikipedia_page(member: Member) -> Optional[str]:
    if not member.wikipedia_url:
        return None
    text = get_text(member.wikipedia_url)
    if not text:
        return None
    for url, _label in extract_official_links_from_html(text, member.wikipedia_url, member.name, member.party):
        valid = validate_official_url(url, member.name)
        if valid:
            return valid
    return None


def parse_search_result_urls(html_text: str) -> List[str]:
    soup = BeautifulSoup(html_text or "", "html.parser")
    rows: List[str] = []
    for a in soup.select("a[href]"):
        href = a.get("href") or ""
        if href.startswith("//duckduckgo.com/l/") or "duckduckgo.com/l/" in href:
            qs = parse_qs(urlparse("https:" + href if href.startswith("//") else href).query)
            href = qs.get("uddg", [href])[0]
        elif href.startswith("/url?"):
            qs = parse_qs(urlparse(href).query)
            href = qs.get("q", qs.get("url", [href]))[0]
        elif "bing.com/ck/a" in href:
            qs = parse_qs(urlparse(href).query)
            href = qs.get("u", [href])[0]
            # Bingのbase64リンクはここでは無理に展開しない
        href = unquote(href)
        url = clean_url(href)
        if not url:
            continue
        host = urlparse(url).netloc.lower()
        if any(bad in host for bad in ["google.", "bing.", "yahoo.", "duckduckgo."]):
            continue
        rows.append(url)
    # dedupe
    seen = set()
    unique = []
    for u in rows:
        parsed = urlparse(u)
        key = parsed.netloc.lower().removeprefix("www.") + parsed.path.rstrip("/")
        if key not in seen:
            seen.add(key)
            unique.append(u)
    return unique


def search_urls(query: str, *, site_domain: Optional[str] = None, max_results: int = 5) -> List[str]:
    q = f"site:{site_domain} {query}" if site_domain else query
    search_pages = [
        "https://duckduckgo.com/html/?" + requests.compat.urlencode({"q": q}),
        "https://www.bing.com/search?" + requests.compat.urlencode({"q": q}),
    ]
    results: List[str] = []
    for url in search_pages:
        res = request_get(url, retries=0)
        if not res or res.status_code >= 500:
            continue
        for found in parse_search_result_urls(res.text):
            results.append(found)
            if len(results) >= max_results:
                return results
    return results


def extract_official_from_party_site(member: Member) -> Optional[str]:
    domains = PARTY_PROFILE_DOMAINS.get(normalize_party(member.party), [])
    if not domains:
        return None

    profile_candidates: List[str] = []
    for domain in domains:
        for url in search_urls(member.name, site_domain=domain, max_results=4):
            if is_party_profile_url(url, member.party):
                profile_candidates.append(url)

    seen = set()
    for profile in profile_candidates:
        key = urlparse(profile).netloc + urlparse(profile).path
        if key in seen:
            continue
        seen.add(key)
        res = request_get(profile, retries=0)
        if not res or res.status_code >= 500:
            continue
        member.party_profile_url = res.url or profile
        for url, _label in extract_official_links_from_html(res.text, res.url or profile, member.name, member.party):
            valid = validate_official_url(url, member.name)
            if valid:
                return valid
    return None


def search_final_official_url(name: str, party: str) -> Optional[str]:
    queries = [f"{name} 公式サイト 国会議員", f"{name} ホームページ", f"{name} 事務所 公式"]
    for q in queries:
        for url in search_urls(q, max_results=8):
            if is_noise_url(url, exclude_party_domains=True):
                continue
            valid = validate_official_url(url, name)
            if valid:
                return valid
    return None


def enrich_member(member: Member, *, enable_search_fallback: bool, debug_name: str = "") -> Member:
    debug = bool(debug_name and name_key(debug_name) == name_key(member.name))
    def d(msg: str) -> None:
        if debug:
            log(f"[debug:{member.name}] {msg}")

    # ① Wikipedia
    url = extract_official_from_wikipedia_page(member)
    d(f"wikipedia_external={url}")
    if url:
        member.official_url = url
        member.official_url_source = "wikipedia_external"
        return member

    # ② 政党公式（中継ページとして扱う）
    url = extract_official_from_party_site(member)
    d(f"party_profile={member.party_profile_url} official={url}")
    if url:
        member.official_url = url
        member.official_url_source = "party_official_profile"
        return member

    # ③ 手動補正
    override = OFFICIAL_URL_OVERRIDES.get(name_key(member.name)) or OFFICIAL_URL_OVERRIDES.get(member.name)
    d(f"override={override}")
    if override:
        member.official_url = validate_official_url(override, member.name) or override
        member.official_url_source = "manual_override"
        return member

    # ④ 最後に検索。重いので、引数で有効化。
    if enable_search_fallback:
        url = search_final_official_url(member.name, member.party)
        d(f"search_fallback={url}")
        if url:
            member.official_url = url
            member.official_url_source = "search_fallback"
            return member

    return member


def get_cert_info(hostname: str, port: int = 443) -> Optional[dict]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        def find_value(seq, key: str) -> Optional[str]:
            for rdn in seq or []:
                for k, v in rdn:
                    if k == key:
                        return v
            return None
        return {
            "subject": {
                "commonName": find_value(cert.get("subject"), "commonName"),
                "organizationName": find_value(cert.get("subject"), "organizationName"),
            },
            "issuer": {
                "commonName": find_value(cert.get("issuer"), "commonName"),
                "organizationName": find_value(cert.get("issuer"), "organizationName"),
            },
        }
    except Exception:
        return None


def contains_gs(*texts: Optional[str]) -> bool:
    return "globalsign" in " ".join(text or "" for text in texts).lower()


def is_probable_gs_legislator_cert(party: str, subject_o: Optional[str], issuer_o: Optional[str], issuer_cn: Optional[str]) -> bool:
    return bool(contains_gs(issuer_o, issuer_cn) and subject_o and normalize_party(subject_o) == normalize_party(party))


def detect_site_seal(text: str) -> bool:
    haystack = (text or "").lower()
    return any(re.search(pattern, haystack, re.I) for pattern in SITE_SEAL_PATTERNS)


def scan_site(member: Member) -> ScanResult:
    notes: List[str] = []
    if not member.official_url:
        return ScanResult(
            member.chamber, member.name, member.party, member.wikipedia_title, member.wikipedia_url, None,
            member.official_url_source, member.party_profile_url, None, "site_not_found", None,
            None, None, None, None, False, False, False, False, ["公式サイトURLを取得できませんでした"],
        )

    url = clean_url(member.official_url)
    assert url is not None
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
    for candidate in candidates:
        response = request_get(candidate, retries=0)
        if response and response.status_code < 500:
            final_url = response.url or candidate
            status_code = response.status_code
            site_seal = detect_site_seal(response.text or "")
            break

    if not response:
        notes.append("HTTP取得失敗")

    effective_url = final_url or url
    parsed = urlparse(effective_url)
    hosts: List[str] = []
    if parsed.hostname:
        hosts.append(parsed.hostname)
        if not parsed.hostname.startswith("www."):
            hosts.insert(0, "www." + parsed.hostname)

    cert_subject_cn = cert_subject_o = cert_issuer_o = cert_issuer_cn = None
    is_https = False
    for host in hosts[:2]:
        cert = get_cert_info(host)
        if cert:
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
        member.chamber, member.name, member.party, member.wikipedia_title, member.wikipedia_url, member.official_url,
        member.official_url_source, member.party_profile_url, final_url, "ok" if response else "request_error", status_code,
        cert_subject_cn, cert_subject_o, cert_issuer_o, cert_issuer_cn, is_https, is_gs, is_gs_leg, site_seal, notes,
    )


def summarize(results: List[ScanResult], started_at: float) -> dict:
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
        group = party_group(r.party)
        row = by_party.setdefault(group, {"party": group, "total": 0, "with_site": 0, "https": 0, "gs": 0, "seal": 0, "gs_share": 0.0})
        row["total"] += 1
        row["with_site"] += int(bool(r.official_url))
        row["https"] += int(r.is_https)
        row["gs"] += int(r.is_gs)
        row["seal"] += int(r.site_seal_found)
    for row in by_party.values():
        row["gs_share"] = pct(row["gs"], row["https"])
    order = {p: i for i, p in enumerate(DISPLAY_PARTIES + ["その他"])}
    sources: Dict[str, int] = {}
    for r in results:
        sources[r.official_url_source or "not_found"] = sources.get(r.official_url_source or "not_found", 0) + 1

    return {
        "generated_at": now_iso(),
        "duration_seconds": round(time.time() - started_at, 1),
        "total_members": total_members,
        "with_site": with_site,
        "https_count": https_count,
        "gs_count": gs_count,
        "gs_legislator_count": gs_legislator_count,
        "site_seal_count": site_seal_count,
        "gs_share_target_parties": pct(len(target_gs), len(target_https)),
        "gs_share_target_parties_numerator": len(target_gs),
        "gs_share_target_parties_denominator": len(target_https),
        "site_seal_share_gs_legislator_cert": pct(len(seal_on_gs_leg), len(gs_leg_for_seal)),
        "site_seal_share_gs_legislator_cert_numerator": len(seal_on_gs_leg),
        "site_seal_share_gs_legislator_cert_denominator": len(gs_leg_for_seal),
        "by_chamber": [by_chamber[k] for k in ["衆議院", "参議院"] if k in by_chamber],
        "by_party": sorted(by_party.values(), key=lambda row: order.get(row["party"], 999)),
        "display_parties": DISPLAY_PARTIES + ["その他"],
        "official_url_sources": sources,
        "data_quality": {
            "site_not_found_count": sum(1 for r in results if not r.official_url),
            "party_group_rule": "自由民主党・国民民主党・立憲民主党・れいわ新選組・中道改革連合のみ個別表示。それ以外（減税日本・ゆうこく連合を含む）はその他。",
        },
    }


def run_self_test() -> None:
    errors = []
    sangiin = get_sangiin_members()
    shugiin = get_shugiin_members()
    if len(sangiin) < 200:
        errors.append(f"参議院議員数が少なすぎます: {len(sangiin)}")
    if len(shugiin) < 300:
        errors.append(f"衆議院議員数が少なすぎます: {len(shugiin)}")
    test = enrich_member(Member("衆議院", "坂本竜太郎", "自由民主党", wikipedia_title="坂本竜太郎", wikipedia_url=wiki_url_for_title("坂本竜太郎")), enable_search_fallback=True, debug_name="坂本竜太郎")
    if not test.official_url or "sakamoto-ryutaro" not in test.official_url:
        errors.append(f"坂本竜太郎の公式URL取得失敗: {test.official_url}")
    if errors:
        for e in errors:
            log("SELFTEST ERROR: " + e)
        raise SystemExit(1)
    log("SELFTEST OK")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--debug-name", default="")
    parser.add_argument("--enable-search-fallback", action="store_true", help="最終手段の検索エンジン補完を有効化。精度は上がるが時間がかかる。")
    parser.add_argument("--enrich-workers", type=int, default=12)
    parser.add_argument("--scan-workers", type=int, default=32)
    args = parser.parse_args()

    started_at = time.time()
    if args.self_test:
        run_self_test()
        return

    shugiin_members = get_shugiin_members()
    sangiin_members = get_sangiin_members()
    log(f"Shugiin fetched: {len(shugiin_members)}")
    log(f"Sangiin fetched: {len(sangiin_members)}")

    if len(shugiin_members) < 300 or len(sangiin_members) < 200:
        log("ERROR: 議員一覧の取得件数が少なすぎるため、data.jsonを更新せず停止します。")
        raise SystemExit(1)

    members = merge_members(shugiin_members, sangiin_members)
    log(f"Current members fetched: {len(members)}")

    enriched: List[Member] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.enrich_workers) as executor:
        futures = [executor.submit(enrich_member, m, enable_search_fallback=args.enable_search_fallback, debug_name=args.debug_name) for m in members]
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            try:
                enriched.append(future.result())
            except Exception as e:
                log(f"Enrich error: {type(e).__name__}: {e}")
            if i % 25 == 0 or i == len(futures):
                found = sum(1 for m in enriched if m.official_url)
                log(f"Enriched {i}/{len(futures)} official_url={found}")

    enriched = sorted(enriched, key=lambda m: (m.chamber, m.name))

    results: List[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.scan_workers) as executor:
        futures = [executor.submit(scan_site, m) for m in enriched]
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            try:
                results.append(future.result())
            except Exception as e:
                log(f"Scan error: {type(e).__name__}: {e}")
            if i % 25 == 0 or i == len(futures):
                https = sum(1 for r in results if r.is_https)
                log(f"Scanned {i}/{len(futures)} https={https}")

    results = sorted(results, key=lambda r: (r.chamber, r.name))
    payload = {
        "generated_at": now_iso(),
        "summary": summarize(results, started_at),
        "results": [dict(asdict(r), party_group=party_group(r.party)) for r in results],
    }
    tmp = OUT_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(OUT_FILE)
    log(f"Wrote {OUT_FILE} with {len(results)} rows in {round(time.time() - started_at, 1)}s")


if __name__ == "__main__":
    main()
