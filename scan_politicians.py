#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime as dt
import html
import json
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

OUT_FILE = Path("data.json")
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 35
TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)
MAX_ENRICH_WORKERS = 5
MAX_SCAN_WORKERS = 16

USER_AGENT = "DietCertDashboard/3.0 (+GitHub Actions; contact: dashboard)"
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept-Language": "ja,en;q=0.8",
}

WIKI_BASE = "https://ja.wikipedia.org"
WIKI_API = "https://ja.wikipedia.org/w/api.php"
WIKIDATA_API = "https://www.wikidata.org/w/api.php"

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
    "自民党": "自由民主党",
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

KNOWN_PARTIES = set(PARTY_NORMALIZATION.values())

PARTY_PROFILE_DOMAINS = {
    "自由民主党": ["jimin.jp", "sangiin-jimin.jp"],
    "立憲民主党": ["cdp-japan.jp"],
    "国民民主党": ["new-kokumin.jp"],
    "れいわ新選組": ["reiwa-shinsengumi.com"],
    "公明党": ["komei.or.jp"],
    "日本維新の会": ["o-ishin.jp"],
    "日本共産党": ["jcp.or.jp"],
}

SOCIAL_OR_NOISE_DOMAINS = [
    "twitter.com", "x.com", "facebook.com", "instagram.com", "youtube.com",
    "line.me", "lin.ee", "tiktok.com", "threads.net", "note.com", "ameblo.jp",
    "wikipedia.org", "wikidata.org", "go2senkyo.com", "google.com", "bing.com",
    "yahoo.co.jp", "duckduckgo.com",
]

# Party sites are not final official sites, but they are important relay pages.
PARTY_DOMAINS_ALL = sorted({d for domains in PARTY_PROFILE_DOMAINS.values() for d in domains})

SITE_SEAL_PATTERNS = [
    r"globalsign",
    r"site\s*seal",
    r"siteseal",
    r"sslpr",
    r"secure\s+site\s+seal",
    r"実在証明・盗聴対策シール",
    r"認証シール",
]

OFFICIAL_URL_OVERRIDES = {
    "前原誠司": "https://www.maehara21.com/",
    "齋藤健": "https://saito-ken.jp/",
    "斎藤健": "https://saito-ken.jp/",
}

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


def log(msg: str) -> None:
    print(msg, flush=True)


def new_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS)
    adapter = requests.adapters.HTTPAdapter(max_retries=1, pool_connections=30, pool_maxsize=30)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def request_get(url: str, *, allow_redirects: bool = True, retries: int = 2) -> Optional[requests.Response]:
    for attempt in range(retries + 1):
        try:
            s = new_session()
            res = s.get(url, timeout=TIMEOUT, allow_redirects=allow_redirects)
            res.encoding = res.apparent_encoding or res.encoding
            return res
        except Exception as e:
            if attempt == retries:
                return None
            time.sleep(0.5 * (attempt + 1))
    return None


def get_text(url: str) -> Optional[str]:
    res = request_get(url, retries=2)
    if not res or res.status_code >= 500:
        return None
    return res.text


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def pct(num: int, den: int) -> float:
    return round((num / den * 100) if den else 0.0, 1)


def normalize_party(value: str) -> str:
    if not value:
        return ""
    value = html.unescape(str(value)).strip()
    value = re.sub(r"\[[^\]]+\]", "", value)
    value = value.strip("（）()[]【】")
    value = re.split(r"[／/、,，]", value)[0]
    compact = re.sub(r"\s+", "", value)
    return PARTY_NORMALIZATION.get(compact, value.strip())


def party_group(party: str) -> str:
    p = normalize_party(party or "")
    return p if p in DISPLAY_PARTIES else "その他"


def clean_name(name: str) -> str:
    name = html.unescape(name or "")
    name = name.replace("\u3000", " ").strip()
    name = re.sub(r"\[[^\]]+\]", "", name)
    name = re.sub(r"（.*?）|\(.*?\)", "", name)
    name = re.sub(r"[君氏]+$", "", name).strip()
    name = re.sub(r"\s+", " ", name)
    return name


def name_key(name: str) -> str:
    return re.sub(r"\s+", "", clean_name(name))


def clean_url(url: Optional[str], base: Optional[str] = None) -> Optional[str]:
    if not url:
        return None
    url = html.unescape(str(url)).strip().strip('"').strip("'")
    if not url or url.startswith(("mailto:", "tel:", "javascript:", "#")):
        return None
    if base:
        url = urljoin(base, url)
    if url.startswith("//"):
        url = "https:" + url
    parsed = urlparse(url)
    if parsed.path == "/url" or url.startswith("/url?"):
        qs = parse_qs(parsed.query)
        url = qs.get("q", [None])[0] or qs.get("url", [None])[0] or url
    if "bing.com/ck/a" in url:
        qs = parse_qs(urlparse(url).query)
        u = qs.get("u", [None])[0]
        if u:
            if u.startswith("a1"):
                try:
                    u = base64.urlsafe_b64decode(u[2:] + "===").decode("utf-8", "ignore")
                except Exception:
                    pass
            url = u
    url = unquote(url)
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        return None
    return url


def is_person_name(text: str) -> bool:
    text = clean_name(text)
    if not (2 <= len(name_key(text)) <= 14):
        return False
    if re.search(r"(一覧|選挙区|比例|議員|衆議院|参議院|会派|任期|党派|現職|画像|編集|脚注|出典)", text):
        return False
    if re.fullmatch(r"[ぁ-んァ-ンー・ 　]+", text):
        return False
    return bool(re.fullmatch(r"[一-龥々〆ヵヶぁ-んァ-ンーA-Za-z・ 　]+", text))


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


def wiki_url_for_title(title: str) -> str:
    return f"{WIKI_BASE}/wiki/{quote(title.replace(' ', '_'))}"


def fetch_wikipedia_html(title: str) -> Optional[str]:
    # action=parse is more stable than scraping the desktop page directly.
    params = {
        "action": "parse",
        "format": "json",
        "page": title,
        "prop": "text|displaytitle",
        "redirects": "1",
    }
    res = request_get(WIKI_API + "?" + requests.compat.urlencode(params), retries=2)
    if res and res.status_code == 200:
        try:
            data = res.json()
            return data.get("parse", {}).get("text", {}).get("*")
        except Exception:
            pass
    return get_text(wiki_url_for_title(title))


def parse_members_from_wikipedia_list(title: str, chamber: str) -> List[Member]:
    raw = fetch_wikipedia_html(title)
    if not raw:
        return []
    soup = BeautifulSoup(raw, "html.parser")
    text = soup.get_text("\n")
    lines = [re.sub(r"\s+", " ", line).strip() for line in text.splitlines()]
    lines = [line for line in lines if line]

    members: List[Member] = []
    party_re = "|".join(re.escape(p) for p in sorted(KNOWN_PARTIES, key=len, reverse=True))

    # Main pattern on Wikipedia pages: Name line followed by （Party） within a few lines.
    for i, line in enumerate(lines):
        candidate = clean_name(line)
        if not is_person_name(candidate):
            continue
        window = " ".join(lines[i + 1 : i + 5])
        m = re.search(rf"[（(]([^）)]*?(?:{party_re})[^）)]*)[）)]", window)
        if not m:
            continue
        party = normalize_party(m.group(1))
        if party not in KNOWN_PARTIES:
            continue
        members.append(Member(chamber=chamber, name=candidate, party=party))

    # Table fallback.
    for tr in soup.select("tr"):
        row_text = re.sub(r"\s+", " ", tr.get_text(" ", strip=True))
        pm = re.search(rf"({party_re})", row_text)
        if not pm:
            continue
        party = normalize_party(pm.group(1))
        if party not in KNOWN_PARTIES:
            continue
        for a in tr.select('a[href^="/wiki/"]'):
            label = clean_name(a.get_text(" ", strip=True))
            href = a.get("href") or ""
            if is_person_name(label) and not any(x in href for x in [":", "#"]):
                members.append(Member(chamber=chamber, name=label, party=party))
                break

    unique = {(m.chamber, name_key(m.name)): m for m in members if m.name and m.party}
    return sorted(unique.values(), key=lambda m: m.name)


def parse_sangiin_official_page(url: str) -> List[Member]:
    text = get_text(url)
    if not text:
        return []
    soup = BeautifulSoup(text, "html.parser")
    lines = [re.sub(r"\s+", " ", line).strip() for line in soup.get_text("\n").splitlines()]
    lines = [line for line in lines if line]
    members: List[Member] = []
    short = {
        "自民": "自由民主党", "立憲": "立憲民主党", "維新": "日本維新の会", "公明": "公明党",
        "民主": "国民民主党", "参政": "参政党", "共産": "日本共産党", "れ新": "れいわ新選組",
        "保守": "日本保守党", "沖縄": "沖縄の風", "みら": "チームみらい", "社民": "社会民主党", "無所属": "無所属",
    }
    short_re = "|".join(map(re.escape, sorted(short.keys(), key=len, reverse=True)))
    line_re = re.compile(
        rf"^([一-龥々〆ヵヶぁ-んァ-ンー・ 　]{{2,40}})\s+"
        rf"([ぁ-んァ-ンー・ 　]{{2,80}})\s+({short_re})\s+.*?令和\d+年\d+月\d+日"
    )
    for line in lines:
        m = line_re.match(line)
        if m:
            members.append(Member("参議院", clean_name(m.group(1)), short.get(m.group(3), normalize_party(m.group(3)))))
    return sorted({(m.chamber, name_key(m.name)): m for m in members}.values(), key=lambda m: m.name)


def get_sangiin_members() -> List[Member]:
    # User requested Wikipedia as a source too. Prefer Wikipedia if it returns enough rows.
    wiki = parse_members_from_wikipedia_list("参議院議員一覧", "参議院")
    official_candidates = [
        "https://www.sangiin.go.jp/japanese/joho1/kousei/giin/221/giin.htm",
        "https://www.sangiin.go.jp/japanese/joho1/kousei/giin/giin.htm",
    ]
    official: List[Member] = []
    for url in official_candidates:
        rows = parse_sangiin_official_page(url)
        if len(rows) > len(official):
            official = rows

    best = wiki if len(wiki) >= len(official) else official
    source = "Wikipedia" if best is wiki else "Sangiin official"
    log(f"Sangiin source: {source} ({len(best)} members) / wiki={len(wiki)} official={len(official)}")
    return best


def get_shugiin_members() -> List[Member]:
    wiki = parse_members_from_wikipedia_list("衆議院議員一覧", "衆議院")
    # Keep old official source as fallback only; it is often maintenance.
    official = parse_shugiin_official_fallback()
    best = wiki if len(wiki) >= len(official) else official
    source = "Wikipedia" if best is wiki else "Shugiin official"
    log(f"Shugiin source: {source} ({len(best)} members) / wiki={len(wiki)} official={len(official)}")
    return best


def parse_shugiin_official_fallback() -> List[Member]:
    urls = [
        "https://www.shugiin.go.jp/internet/itdb_annai.nsf/html/statics/syu/1giin.htm",
        "https://www.shugiin.go.jp/internet/itdb_annai.nsf/html/statics/syu/giin.htm",
    ]
    members: List[Member] = []
    for url in urls:
        text = get_text(url)
        if not text or "メンテナンス中" in text or "under maintenance" in text.lower():
            continue
        soup = BeautifulSoup(text, "html.parser")
        pattern = re.compile(r"([^\s,、。<>]+(?:\s+[^\s,、。<>]+)*)君[,，、]\s*([^\s<.。]+)")
        for match in pattern.finditer(soup.get_text(" ")):
            name = clean_name(match.group(1))
            party = normalize_party(match.group(2))
            if is_person_name(name) and party:
                members.append(Member("衆議院", name, party))
    return sorted({(m.chamber, name_key(m.name)): m for m in members}.values(), key=lambda m: m.name)


def search_wikipedia_exact(name: str, chamber: str) -> Tuple[Optional[str], Optional[str]]:
    candidates = [name, f"{name} (政治家)", f"{name}_{chamber}"]
    for title in candidates:
        params = {"action": "query", "format": "json", "titles": title, "redirects": "1"}
        res = request_get(WIKI_API + "?" + requests.compat.urlencode(params), retries=2)
        if not res or res.status_code != 200:
            continue
        try:
            pages = res.json().get("query", {}).get("pages", {})
        except Exception:
            continue
        for page in pages.values():
            if page.get("missing") is None and page.get("pageid"):
                actual_title = page.get("title") or title
                return actual_title, wiki_url_for_title(actual_title)

    queries = [f'intitle:"{name}" 国会議員', f"{name} {chamber}", f"{name} 政治家", name]
    nk = name_key(name)
    for q in queries:
        params = {"action": "query", "list": "search", "format": "json", "srsearch": q, "srlimit": 10}
        res = request_get(WIKI_API + "?" + requests.compat.urlencode(params), retries=2)
        if not res or res.status_code != 200:
            continue
        try:
            items = res.json().get("query", {}).get("search", [])
        except Exception:
            continue
        exact = []
        loose = []
        for item in items:
            title = item.get("title") or ""
            snippet = re.sub("<.*?>", "", item.get("snippet") or "")
            tk = name_key(title)
            if tk == nk or tk.startswith(nk):
                exact.append(title)
            elif nk in tk or nk in name_key(snippet):
                loose.append(title)
        for title in exact + loose:
            return title, wiki_url_for_title(title)
    return None, None


def get_wikidata_qid(title: str) -> Optional[str]:
    params = {"action": "query", "prop": "pageprops", "titles": title, "format": "json", "redirects": "1"}
    res = request_get(WIKI_API + "?" + requests.compat.urlencode(params), retries=2)
    if not res or res.status_code != 200:
        return None
    try:
        pages = res.json().get("query", {}).get("pages", {})
        for page in pages.values():
            qid = page.get("pageprops", {}).get("wikibase_item")
            if qid:
                return qid
    except Exception:
        return None
    return None


def get_official_website_from_wikidata(qid: str) -> Optional[str]:
    res = request_get(f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json", retries=2)
    if not res or res.status_code != 200:
        return None
    try:
        claims = res.json().get("entities", {}).get(qid, {}).get("claims", {})
        for claim in claims.get("P856", []):
            value = claim.get("mainsnak", {}).get("datavalue", {}).get("value")
            url = clean_url(value)
            if url and not is_noise_url(url, exclude_party_domains=True):
                return url
    except Exception:
        return None
    return None


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
        host = urlparse(href).netloc.lower()
        if any(word.lower() in label.lower() for word in social_words):
            continue
        if is_noise_url(href, exclude_party_domains=not allow_party_profiles):
            continue
        score = 0
        if any(word.lower() in label.lower() for word in official_words):
            score += 100
        if href.startswith("https://"):
            score += 5
        if any(part in host for part in ["official", "office", "koenkai", "support", "giin"]):
            score += 8
        nk = name_key(name)
        for ch in nk:
            if ch and ch in href:
                score += 1
        if is_party_profile_url(href, party):
            score += 30 if allow_party_profiles else -100
        if score > 0:
            candidates.append((score, href, label or href))

    # Deduplicate by host+path
    seen = set()
    rows = []
    for score, href, label in sorted(candidates, key=lambda x: x[0], reverse=True):
        parsed = urlparse(href)
        key = parsed.netloc.lower().removeprefix("www.") + parsed.path.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        rows.append((href, label))
    return rows


def extract_official_from_wikipedia_page(page_url: str, name: str, party: str) -> Optional[str]:
    text = get_text(page_url)
    if not text:
        return None
    # Wikipedia pages sometimes include official links in infobox/external links.
    links = extract_official_links_from_html(text, page_url, name, party)
    for url, _label in links:
        valid = validate_official_url(url, name)
        if valid:
            return valid
    return None


def search_urls(query: str, *, site_domain: Optional[str] = None) -> List[str]:
    q = f"site:{site_domain} {query}" if site_domain else query
    urls_to_fetch = [
        "https://duckduckgo.com/html/?" + requests.compat.urlencode({"q": q}),
        "https://www.bing.com/search?" + requests.compat.urlencode({"q": q}),
    ]
    candidates: List[str] = []
    for search_url in urls_to_fetch:
        res = request_get(search_url, retries=1)
        if not res or res.status_code >= 500:
            continue
        soup = BeautifulSoup(res.text, "html.parser")
        for a in soup.select("a[href]"):
            href = a.get("href") or ""
            cleaned = clean_url(href, search_url)
            if not cleaned:
                continue
            if site_domain and site_domain not in urlparse(cleaned).netloc.lower():
                # DuckDuckGo redirect may still hide target in query.
                parsed = urlparse(href)
                qs = parse_qs(parsed.query)
                target = qs.get("uddg", [None])[0] or qs.get("q", [None])[0] or qs.get("u", [None])[0]
                cleaned = clean_url(target) if target else cleaned
            if cleaned and (not site_domain or site_domain in urlparse(cleaned).netloc.lower()):
                candidates.append(cleaned)
    seen = set()
    out = []
    for u in candidates:
        parsed = urlparse(u)
        key = parsed.netloc.lower() + parsed.path.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
    return out[:20]


def get_party_profile_candidates(name: str, party: str) -> List[str]:
    domains = PARTY_PROFILE_DOMAINS.get(normalize_party(party), [])
    queries = [f'"{name}"', f'{name} 議員', f'{name} 公式サイト']
    out: List[str] = []
    for domain in domains:
        for q in queries:
            out.extend(search_urls(q, site_domain=domain))
    # Keep only party profile-looking pages.
    cleaned = []
    seen = set()
    for url in out:
        if not is_party_profile_url(url, party):
            continue
        if any(x in url for x in ["/news/", "/activity/", "/statement/", "#"]):
            continue
        key = urlparse(url).netloc.lower() + urlparse(url).path.rstrip("/")
        if key not in seen:
            seen.add(key)
            cleaned.append(url)
    return cleaned[:8]


def extract_official_from_party_site(member: Member) -> Optional[str]:
    for profile_url in get_party_profile_candidates(member.name, member.party):
        text = get_text(profile_url)
        if not text:
            continue
        # Confirm the page mentions the member name.
        if name_key(member.name) not in name_key(BeautifulSoup(text, "html.parser").get_text(" ")):
            continue
        member.party_profile_url = profile_url
        links = extract_official_links_from_html(text, profile_url, member.name, member.party, allow_party_profiles=False)
        for url, label in links:
            if is_party_profile_url(url, member.party):
                continue
            valid = validate_official_url(url, member.name)
            if valid:
                return valid
    return None


def search_final_official_url(name: str, party: str) -> Optional[str]:
    queries = [
        f'"{name}" 公式サイト 国会議員',
        f'"{name}" ホームページ 議員',
        f'"{name}" 事務所 公式',
    ]
    candidates: List[str] = []
    for q in queries:
        candidates.extend(search_urls(q))
    scored: List[Tuple[int, str]] = []
    for url in candidates:
        if is_noise_url(url, exclude_party_domains=True):
            continue
        host_path = (urlparse(url).netloc + urlparse(url).path).lower()
        score = 0
        if url.startswith("https://"):
            score += 5
        for word in ["official", "office", "koenkai", "support", "giin"]:
            if word in host_path:
                score += 5
        # Japanese names rarely appear in romanized URLs, so use the destination page text check.
        text = get_text(url)
        if text and name_key(name) in name_key(BeautifulSoup(text, "html.parser").get_text(" ")):
            score += 40
        if score >= 10:
            valid = validate_official_url(url, name)
            if valid:
                scored.append((score, valid))
    if not scored:
        return None
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored[0][1]


def validate_official_url(url: str, name: str) -> Optional[str]:
    url = clean_url(url)
    if not url:
        return None
    candidates = [url]
    p = urlparse(url)
    if p.scheme == "http":
        candidates.insert(0, "https://" + p.netloc + (p.path or "/"))
        if not p.netloc.startswith("www."):
            candidates.insert(0, "https://www." + p.netloc + (p.path or "/"))
    elif p.scheme == "https" and not p.netloc.startswith("www."):
        candidates.append("https://www." + p.netloc + (p.path or "/"))

    for c in candidates:
        res = request_get(c, retries=1)
        if res and res.status_code < 500:
            return res.url or c
    host = p.hostname
    if host and extract_cert(host):
        return "https://" + host + (p.path if p.path else "/")
    # Keep the URL if it is at least structurally valid. The scan step can mark request_error.
    return url


def enrich_member(member: Member, debug: bool = False) -> Member:
    def d(msg: str) -> None:
        if debug:
            log(f"[debug:{member.name}] {msg}")

    # ① Wikipedia first
    title, wiki_url = search_wikipedia_exact(member.name, member.chamber)
    member.wikipedia_title = title
    member.wikipedia_url = wiki_url
    d(f"wikipedia={title} {wiki_url}")

    if title:
        qid = get_wikidata_qid(title)
        d(f"wikidata_qid={qid}")
        if qid:
            url = get_official_website_from_wikidata(qid)
            d(f"wikidata_p856={url}")
            if url:
                member.official_url = validate_official_url(url, member.name)
                member.official_url_source = "wikipedia_wikidata_p856"
                return member
        if wiki_url:
            url = extract_official_from_wikipedia_page(wiki_url, member.name, member.party)
            d(f"wikipedia_external={url}")
            if url:
                member.official_url = url
                member.official_url_source = "wikipedia_external"
                return member

    # ② Party official site as the most important relay.
    url = extract_official_from_party_site(member)
    d(f"party_profile={member.party_profile_url} official={url}")
    if url:
        member.official_url = url
        member.official_url_source = "party_official_profile"
        return member

    # ③ Known direct official URLs / overrides.
    override = OFFICIAL_URL_OVERRIDES.get(name_key(member.name)) or OFFICIAL_URL_OVERRIDES.get(member.name)
    d(f"override={override}")
    if override:
        member.official_url = validate_official_url(override, member.name) or override
        member.official_url_source = "manual_override"
        return member

    # ④ Final search fallback.
    url = search_final_official_url(member.name, member.party)
    d(f"search_fallback={url}")
    if url:
        member.official_url = url
        member.official_url_source = "search_engine_fallback"

    return member


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
                subject_line = line[len("subject=") :].strip()
            elif line.startswith("issuer="):
                issuer_line = line[len("issuer=") :].strip()

        def pick(field: str, text: str) -> Optional[str]:
            for pattern in [rf"{field}\s*=\s*([^,/]+)", rf"/{field}=([^/]+)"]:
                m = re.search(pattern, text)
                if m:
                    return decode_openssl_value(m.group(1).strip())
            return None

        return {
            "subject": {"commonName": pick("CN", subject_line), "organizationName": pick("O", subject_line)},
            "issuer": {"commonName": pick("CN", issuer_line), "organizationName": pick("O", issuer_line)},
        }
    except Exception:
        return None


def contains_gs(*texts: Optional[str]) -> bool:
    return "globalsign" in " ".join(t or "" for t in texts).lower()


def is_probable_gs_legislator_cert(party: str, subject_o: Optional[str], issuer_o: Optional[str], issuer_cn: Optional[str]) -> bool:
    if not contains_gs(issuer_o, issuer_cn) or not subject_o:
        return False
    return normalize_party(party) == normalize_party(subject_o)


def detect_site_seal(text: str) -> bool:
    haystack = (text or "").lower()
    return any(re.search(pattern, haystack, re.I) for pattern in SITE_SEAL_PATTERNS)


def scan_site(member: Member) -> ScanResult:
    notes: List[str] = []
    if not member.official_url:
        return ScanResult(
            member.chamber, member.name, member.party, member.wikipedia_title, member.wikipedia_url,
            None, member.official_url_source, member.party_profile_url, None, "site_not_found", None,
            None, None, None, None, False, False, False, False, ["公式サイトURLを取得できませんでした"],
        )

    url = clean_url(member.official_url)
    assert url
    parsed0 = urlparse(url)
    scan_candidates = []
    if parsed0.scheme == "http":
        scan_candidates.append("https://" + parsed0.netloc + (parsed0.path or "/"))
        if not parsed0.netloc.startswith("www."):
            scan_candidates.append("https://www." + parsed0.netloc + (parsed0.path or "/"))
    scan_candidates.append(url)

    response = None
    final_url = None
    status_code = None
    site_seal = False
    for candidate in scan_candidates:
        response = request_get(candidate, retries=1)
        if response and response.status_code < 500:
            final_url = response.url
            status_code = response.status_code
            site_seal = detect_site_seal(response.text or "")
            break
    if not response:
        notes.append("HTTP取得失敗")

    effective = final_url or url
    parsed = urlparse(effective)
    cert_hosts = []
    if parsed.hostname:
        if parsed.scheme == "https":
            cert_hosts.append(parsed.hostname)
        else:
            if not parsed.hostname.startswith("www."):
                cert_hosts.append("www." + parsed.hostname)
            cert_hosts.append(parsed.hostname)

    cert_subject_cn = cert_subject_o = cert_issuer_o = cert_issuer_cn = None
    is_https = False
    for host in cert_hosts:
        cert = extract_cert(host, 443)
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
        chamber=member.chamber,
        name=member.name,
        party=member.party,
        wikipedia_title=member.wikipedia_title,
        source_url=member.wikipedia_url,
        official_url=member.official_url,
        official_url_source=member.official_url_source,
        party_profile_url=member.party_profile_url,
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
    )


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
        party = party_group(r.party)
        row = by_party.setdefault(party, {"party": party, "total": 0, "with_site": 0, "https": 0, "gs": 0, "seal": 0, "gs_share": 0.0})
        row["total"] += 1
        row["with_site"] += int(bool(r.official_url))
        row["https"] += int(r.is_https)
        row["gs"] += int(r.is_gs)
        row["seal"] += int(r.site_seal_found)
    for row in by_party.values():
        row["gs_share"] = pct(row["gs"], row["https"])

    party_order = {p: i for i, p in enumerate(DISPLAY_PARTIES + ["その他"])}
    return {
        "generated_at": now_iso(),
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
        "by_party": sorted(by_party.values(), key=lambda row: party_order.get(row["party"], 999)),
        "display_parties": DISPLAY_PARTIES + ["その他"],
        "data_quality": {
            "unknown_chamber_count": sum(1 for r in results if r.chamber not in {"衆議院", "参議院"}),
            "site_not_found_count": sum(1 for r in results if not r.official_url),
            "expected_chambers": ["衆議院", "参議院"],
            "party_group_rule": "自由民主党・国民民主党・立憲民主党・れいわ新選組・中道改革連合のみ個別表示。それ以外（減税日本・ゆうこく連合を含む）はその他。",
        },
    }


def run_self_test() -> None:
    errors = []
    title, wiki_url = search_wikipedia_exact("坂本竜太郎", "衆議院")
    if not title or not wiki_url:
        errors.append("坂本竜太郎のWikipediaページを取得できません")
    member = enrich_member(Member("衆議院", "坂本竜太郎", "自由民主党"), debug=True)
    if not member.official_url or "sakamoto-ryutaro" not in member.official_url:
        errors.append(f"坂本竜太郎の公式サイト取得失敗: {member.official_url}")
    sangiin = get_sangiin_members()
    if len(sangiin) < 200:
        errors.append(f"参議院議員数が少なすぎます: {len(sangiin)}")
    shugiin = get_shugiin_members()
    if len(shugiin) < 300:
        errors.append(f"衆議院議員数が少なすぎます: {len(shugiin)}")
    if errors:
        for e in errors:
            log("SELFTEST ERROR: " + e)
        raise SystemExit(1)
    log("SELFTEST OK")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--debug-name", default="")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    # Fail fast: 現職国会議員は必ず衆議院または参議院に所属するため、
    # どちらかが極端に少ない、または0件の場合は data.json を更新しない。
    # GitHub Actions上で一時的にWikipedia/参議院ページ取得に失敗した場合、
    # 0件データで上書きされることを防ぐ。
    shugiin_members = get_shugiin_members()
    sangiin_members = get_sangiin_members()

    log(f"Shugiin fetched: {len(shugiin_members)}")
    log(f"Sangiin fetched: {len(sangiin_members)}")

    min_shugiin = 300
    min_sangiin = 200
    if len(shugiin_members) < min_shugiin or len(sangiin_members) < min_sangiin:
        log("ERROR: 議員一覧の取得件数が少なすぎるため、data.json を更新せず停止します。")
        log(f"ERROR: 衆議院={len(shugiin_members)}件 / 参議院={len(sangiin_members)}件")
        log("ERROR: 取得元ページの構造変更、通信失敗、GitHub Actions上の一時的な接続失敗を確認してください。")
        raise SystemExit(1)

    members = shugiin_members + sangiin_members
    members = sorted({(m.chamber, name_key(m.name)): m for m in members}.values(), key=lambda m: (m.chamber, m.name))
    log(f"Current members fetched: {len(members)}")

    enriched: List[Member] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_ENRICH_WORKERS) as executor:
        futures = [executor.submit(enrich_member, m, name_key(m.name) == name_key(args.debug_name)) for m in members]
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            try:
                enriched.append(future.result())
            except Exception as e:
                log(f"Enrich error: {type(e).__name__}: {e}")
            if i % 25 == 0:
                log(f"Enriched {i}/{len(members)}")

    results: List[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as executor:
        futures = [executor.submit(scan_site, m) for m in enriched]
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            try:
                results.append(future.result())
            except Exception as e:
                log(f"Scan error: {type(e).__name__}: {e}")
            if i % 25 == 0:
                log(f"Scanned {i}/{len(enriched)}")

    results = sorted(results, key=lambda r: (r.chamber, r.name))
    payload = {
        "generated_at": now_iso(),
        "summary": summarize(results),
        "results": [dict(asdict(r), party_group=party_group(r.party)) for r in results],
    }
    OUT_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    log(f"Wrote {OUT_FILE} with {len(results)} rows")


if __name__ == "__main__":
    main()
