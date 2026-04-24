#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import concurrent.futures
import datetime as dt
import html
import json
import re
import socket
import ssl
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests
from bs4 import BeautifulSoup


OUT_FILE = Path("data.json")

# 公式サイト取得が落ちて件数が減らないよう、短すぎるタイムアウトをやめます。
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 35
TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)

# Wikipedia/Wikidataは同時接続を絞った方が安定します。
MAX_ENRICH_WORKERS = 6
MAX_SCAN_WORKERS = 16

USER_AGENT = "DietCertDashboard/2.1 (+GitHub Actions; contact: dashboard)"
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept-Language": "ja,en;q=0.8",
}

GS_SHARE_TARGET_PARTIES = {
    "自由民主党",
    "立憲民主党",
    "れいわ新選組",
    "国民民主党",
}

SITE_SEAL_PATTERNS = [
    r"globalsign",
    r"site\s*seal",
    r"siteseal",
    r"sslpr",
    r"secure\s+site\s+seal",
    r"実在証明・盗聴対策シール",
    r"認証シール",
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
}

SHUGIIN_PARTIES = set(PARTY_NORMALIZATION.values()) | {
    "中道改革連合",
    "減税日本・ゆうこく連合",
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

# 個別に取りこぼしやすい議員はここで補正します。
# 必要に応じて追加してください。
OFFICIAL_URL_OVERRIDES = {
    "前原誠司": "https://www.maehara21.com/",
}

DISPLAY_PARTIES = [
    "自由民主党",
    "国民民主党",
    "立憲民主党",
    "れいわ新選組",
    "中道改革連合",
]

def party_group(party: str) -> str:
    p = normalize_party(party or "")
    return p if p in DISPLAY_PARTIES else "その他"


@dataclass
class Member:
    chamber: str
    name: str
    party: str
    wikipedia_title: Optional[str] = None
    wikipedia_url: Optional[str] = None
    official_url: Optional[str] = None
    official_url_source: Optional[str] = None


@dataclass
class ScanResult:
    chamber: str
    name: str
    party: str
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


def new_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS)
    adapter = requests.adapters.HTTPAdapter(max_retries=1, pool_connections=20, pool_maxsize=20)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def pct(numerator: int, denominator: int) -> float:
    return round((numerator / denominator * 100) if denominator else 0.0, 1)


def request_get(url: str, *, allow_redirects: bool = True, retries: int = 2) -> Optional[requests.Response]:
    last_error = None
    for attempt in range(retries + 1):
        try:
            s = new_session()
            res = s.get(url, timeout=TIMEOUT, allow_redirects=allow_redirects)
            res.encoding = res.apparent_encoding or res.encoding
            return res
        except Exception as e:
            last_error = e
            time.sleep(0.4 * (attempt + 1))
    return None


def get_text(url: str) -> Optional[str]:
    res = request_get(url, retries=2)
    if not res or res.status_code >= 500:
        return None
    return res.text


def normalize_party(value: str) -> str:
    if not value:
        return ""
    value = html.unescape(str(value)).strip()
    compact = re.sub(r"\s+", "", value)
    compact = compact.strip("（）()[]【】")
    compact = re.split(r"[／/・,，、]", compact)[0]
    return PARTY_NORMALIZATION.get(compact, value.strip())


def clean_name(name: str) -> str:
    name = html.unescape(name or "")
    name = name.replace("　", " ").strip()
    name = re.sub(r"\s*\[.*?\]", "", name)
    name = re.sub(r"[君氏]+$", "", name).strip()
    return name


def name_key(name: str) -> str:
    return re.sub(r"\s+", "", clean_name(name))


def clean_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    url = html.unescape(str(url)).strip().strip('"').strip("'")
    if not url or url.startswith(("mailto:", "tel:", "javascript:")):
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


def is_person_name(text: str) -> bool:
    return bool(re.fullmatch(r"[一-龥々〆ヵヶぁ-んァ-ンーA-Za-z・ 　]{2,40}", text or ""))


def get_shugiin_members_from_official() -> List[Member]:
    urls = [
        "https://www.shugiin.go.jp/internet/itdb_annai.nsf/html/statics/syu/1giin.htm",
        "https://www.shugiin.go.jp/internet/itdb_annai.nsf/html/statics/syu/giin.htm",
        "https://www.shugiin.go.jp/internet/itdb_annai.nsf/html/statics/syu/meibo.htm",
    ]
    best: List[Member] = []
    party_tokens = sorted(set(list(PARTY_NORMALIZATION.keys()) + list(SHUGIIN_PARTIES)), key=len, reverse=True)
    party_re = "|".join(re.escape(x) for x in party_tokens if x)
    for url in urls:
        text = get_text(url)
        if not text:
            continue
        if "under maintenance" in text.lower() or "メンテナンス中" in text:
            continue
        soup = BeautifulSoup(text, "html.parser")
        members: List[Member] = []
        pattern = re.compile(r"([^\s,、。<>]+(?:\s+[^\s,、。<>]+)*)君[,，、]\s*([^\s<.。]+)")
        for match in pattern.finditer(soup.get_text(" ")):
            name = clean_name(match.group(1))
            party = normalize_party(match.group(2))
            if name and party:
                members.append(Member(chamber="衆議院", name=name, party=party))
        for tr in soup.select("tr"):
            cells = [re.sub(r"\s+", " ", c.get_text(" ", strip=True)) for c in tr.select("td,th")]
            if len(cells) < 2:
                continue
            joined = " ".join(cells)
            pm = re.search(rf"({party_re})", joined) if party_re else None
            if not pm:
                continue
            party = normalize_party(pm.group(1))
            if party not in SHUGIIN_PARTIES:
                continue
            for cell in cells:
                c = clean_name(cell)
                if is_person_name(c) and not re.fullmatch(r"[ぁ-んァ-ンー・ 　]+", c) and len(c) <= 12:
                    members.append(Member(chamber="衆議院", name=c, party=party))
                    break
        uniq = list({(m.chamber, name_key(m.name)): m for m in members if m.name}.values())
        if len(uniq) > len(best):
            best = uniq
    return best

def get_shugiin_members_from_wikipedia() -> List[Member]:
    text = get_text("https://ja.wikipedia.org/wiki/衆議院議員一覧")
    if not text:
        return []
    soup = BeautifulSoup(text, "html.parser")
    members: List[Member] = []
    for tr in soup.select("tr"):
        cells = [re.sub(r"\s+", " ", c.get_text(" ", strip=True)) for c in tr.select("td,th")]
        if len(cells) < 2:
            continue
        found_party = None
        for cell in cells:
            p = normalize_party(cell)
            if p in SHUGIIN_PARTIES:
                found_party = p
                break
            for token in SHUGIIN_PARTIES:
                if token and token in cell:
                    found_party = token
                    break
            if found_party:
                break
        if not found_party:
            continue
        for cell in cells:
            c = clean_name(re.sub(r"（.*?）|\(.*?\)", "", cell))
            if is_person_name(c) and not re.fullmatch(r"[ぁ-んァ-ンー・ 　]+", c) and len(c) <= 12:
                members.append(Member(chamber="衆議院", name=c, party=found_party))
                break
    if len(members) < 100:
        lines = [re.sub(r"\s+", " ", line).strip() for line in soup.get_text("\n").splitlines()]
        lines = [line for line in lines if line]
        for i in range(len(lines) - 1):
            name = lines[i]
            party_line = lines[i + 1]
            if not is_person_name(name):
                continue
            party = normalize_party(party_line.strip("（）").strip())
            if party in SHUGIIN_PARTIES:
                members.append(Member(chamber="衆議院", name=clean_name(name), party=party))
    return list({(m.chamber, name_key(m.name)): m for m in members}.values())

def get_shugiin_members() -> List[Member]:
    official = get_shugiin_members_from_official()
    wiki = get_shugiin_members_from_wikipedia()
    return official if len(official) >= len(wiki) else wiki


def parse_sangiin_page(url: str) -> List[Member]:
    text = get_text(url)
    if not text:
        return []

    soup = BeautifulSoup(text, "html.parser")
    page_text = soup.get_text("\n")
    lines = [re.sub(r"\s+", " ", line).strip() for line in page_text.splitlines()]
    lines = [line for line in lines if line]

    members: List[Member] = []

    # 現行ページのテキスト行: 氏名 ふりがな 会派 選挙区 任期満了日
    party_pattern = "|".join(sorted(map(re.escape, PARTY_SHORT.values()), key=len, reverse=True))
    line_re = re.compile(
        rf"^([一-龥々〆ヵヶぁ-んァ-ンー・ 　]{{2,40}})\s+"
        rf"([ぁ-んァ-ンー・ 　]{{2,80}})\s+"
        rf"({party_pattern})\s+"
        rf"(\S+)\s+"
        rf"(令和\d+年\d+月\d+日)"
    )

    reverse_party = {v: k for k, v in PARTY_SHORT.items()}

    for line in lines:
        m = line_re.match(line)
        if m:
            members.append(
                Member(
                    chamber="参議院",
                    name=clean_name(m.group(1)),
                    party=reverse_party.get(m.group(3), normalize_party(m.group(3))),
                )
            )

    # HTMLテーブルからも拾う
    if len(members) < 50:
        for tr in soup.select("tr"):
            cells = [re.sub(r"\s+", " ", c.get_text(" ", strip=True)) for c in tr.select("td,th")]
            if len(cells) < 3:
                continue
            joined = " ".join(cells)
            found_party = None
            for short, full in reverse_party.items():
                if re.search(rf"(^|\s){re.escape(short)}($|\s)", joined):
                    found_party = full
                    break
            if not found_party:
                continue
            for cell in cells:
                if is_person_name(cell) and not re.fullmatch(r"[ぁ-んァ-ンー・ 　]+", cell):
                    members.append(Member("参議院", clean_name(cell), found_party))
                    break

    return list({(m.chamber, name_key(m.name)): m for m in members if m.name}.values())


def get_sangiin_members() -> List[Member]:
    # 回次番号を固定すると0件になりやすいので、複数候補から最大件数のページを採用します。
    candidate_urls = [
        "https://www.sangiin.go.jp/japanese/joho1/kousei/giin/giin.htm",
        "https://www.sangiin.go.jp/japanese/joho1/kousei/giin/joho1/kousei/giin/giin.htm",
    ]
    candidate_urls += [
        f"https://www.sangiin.go.jp/japanese/joho1/kousei/giin/{n}/giin.htm"
        for n in range(230, 215, -1)
    ]

    best: List[Member] = []
    best_url = None
    for url in candidate_urls:
        members = parse_sangiin_page(url)
        if len(members) > len(best):
            best = members
            best_url = url
        if len(best) >= 230:
            break

    if best:
        print(f"Sangiin source: {best_url} ({len(best)} members)", flush=True)
        return best

    # 最終フォールバック
    return get_sangiin_members_from_wikipedia()


def get_sangiin_members_from_wikipedia() -> List[Member]:
    text = get_text("https://ja.wikipedia.org/wiki/参議院議員一覧")
    if not text:
        return []
    soup = BeautifulSoup(text, "html.parser")
    members: List[Member] = []

    for tr in soup.select("tr"):
        cells = [re.sub(r"\s+", " ", c.get_text(" ", strip=True)) for c in tr.select("td,th")]
        if len(cells) < 2:
            continue
        found_party = None
        for cell in cells:
            party = normalize_party(cell)
            if party in SHUGIIN_PARTIES:
                found_party = party
                break
        if not found_party:
            continue
        for cell in cells:
            if is_person_name(cell):
                members.append(Member("参議院", clean_name(cell), found_party))
                break

    return list({(m.chamber, name_key(m.name)): m for m in members}.values())


def search_wikipedia(name: str, chamber: str) -> Tuple[Optional[str], Optional[str]]:
    api = "https://ja.wikipedia.org/w/api.php"
    queries = [f'intitle:"{name}" 政治家', f"{name} {chamber}", f"{name} 国会議員", name]

    for query in queries:
        try:
            res = request_get(
                api
                + "?"
                + requests.compat.urlencode(
                    {
                        "action": "query",
                        "list": "search",
                        "format": "json",
                        "srsearch": query,
                        "srlimit": 8,
                    }
                ),
                retries=2,
            )
            if not res or res.status_code != 200:
                continue
            items = res.json().get("query", {}).get("search", [])
        except Exception:
            continue

        nk = name_key(name)
        for item in items:
            title = item.get("title") or ""
            snippet = re.sub("<.*?>", "", item.get("snippet") or "")
            title_key = name_key(title)
            if nk in title_key or title_key.startswith(nk) or nk in name_key(snippet):
                wiki_url = f"https://ja.wikipedia.org/wiki/{quote(title.replace(' ', '_'))}"
                return title, wiki_url

    # API検索で落ちる場合の直接ページ候補
    for title in [name, f"{name}_(政治家)"]:
        url = f"https://ja.wikipedia.org/wiki/{quote(title)}"
        res = request_get(url, retries=1)
        if res and res.status_code == 200 and "Wikipedia" in res.text:
            return title.replace("_", " "), url

    return None, None


def get_wikidata_qid(title: str) -> Optional[str]:
    try:
        res = request_get(
            "https://ja.wikipedia.org/w/api.php"
            + "?"
            + requests.compat.urlencode(
                {
                    "action": "query",
                    "prop": "pageprops",
                    "titles": title,
                    "format": "json",
                }
            ),
            retries=2,
        )
        if not res or res.status_code != 200:
            return None
        for page in res.json().get("query", {}).get("pages", {}).values():
            qid = page.get("pageprops", {}).get("wikibase_item")
            if qid:
                return qid
    except Exception:
        return None
    return None


def get_official_website_from_wikidata(qid: str) -> Optional[str]:
    try:
        res = request_get(f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json", retries=2)
        if not res or res.status_code != 200:
            return None
        claims = res.json().get("entities", {}).get(qid, {}).get("claims", {})
        for claim in claims.get("P856", []):
            value = claim.get("mainsnak", {}).get("datavalue", {}).get("value")
            cleaned = clean_url(value)
            if cleaned:
                return cleaned
    except Exception:
        return None
    return None


EXCLUDED_OFFICIAL_DOMAINS = [
    "wikipedia.org",
    "wikidata.org",
    "twitter.com",
    "x.com",
    "facebook.com",
    "instagram.com",
    "youtube.com",
    "line.me",
    "ameblo.jp",
    "go2senkyo.com",
    "jimin.jp",
    "cdp-japan.jp",
    "o-ishin.jp",
    "new-kokumin.jp",
    "reiwa-shinsengumi.com",
    "komei.or.jp",
]


def score_official_candidate(url: str, name: str, party: str) -> int:
    parsed = urlparse(url)
    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    nk = name_key(name).lower()
    roman_hint = ""
    score = 0

    if any(ex in host for ex in EXCLUDED_OFFICIAL_DOMAINS):
        score -= 100
    if url.startswith("https://"):
        score += 5
    if host.startswith("www."):
        score += 1
    if any(word in host + path for word in ["koenkai", "support", "office", "official", "giin"]):
        score += 5
    if any(ch in host + path for ch in nk):
        score += 2
    if party and party in url:
        score -= 5
    return score


def extract_candidate_urls_from_wikipedia(page_url: str, name: str, party: str) -> List[str]:
    text = get_text(page_url)
    if not text:
        return []

    soup = BeautifulSoup(text, "html.parser")
    candidates: List[str] = []

    # infobox 優先
    for table in soup.select("table.infobox, table.infobox.vevent"):
        for link in table.select("a[href]"):
            url = clean_url(link.get("href"))
            if url:
                candidates.append(url)

    # 外部リンクの中でも「公式」を含むものを優先
    for link in soup.select("a.external, a[href^='http']"):
        label = link.get_text(" ", strip=True)
        url = clean_url(link.get("href"))
        if not url:
            continue
        if "公式" in label or "ホームページ" in label or "Web" in label or "サイト" in label:
            candidates.insert(0, url)
        else:
            candidates.append(url)

    unique = []
    seen = set()
    for url in candidates:
        host = urlparse(url).netloc.lower()
        key = host + urlparse(url).path.rstrip("/")
        if key not in seen:
            seen.add(key)
            unique.append(url)

    return sorted(unique, key=lambda u: score_official_candidate(u, name, party), reverse=True)


def search_engine_official_search(name: str, party: str) -> Optional[str]:
    queries = [
        f"{name} 公式サイト 国会議員",
        f"{name} 事務所 公式",
        f"{name} ホームページ",
    ]
    search_urls = []
    for q in queries:
        qq = quote(q)
        search_urls.extend([
            f"https://duckduckgo.com/html/?q={qq}",
            f"https://www.bing.com/search?q={qq}",
        ])
    candidates: List[str] = []
    for surl in search_urls:
        res = request_get(surl, retries=1)
        if not res or res.status_code >= 400:
            continue
        soup = BeautifulSoup(res.text, "html.parser")
        for a in soup.select("a[href]"):
            href = a.get("href") or ""
            if href.startswith("//duckduckgo.com/l/?"):
                qs = parse_qs(urlparse("https:" + href).query)
                href = qs.get("uddg", [href])[0]
            elif "bing.com/ck/a" in href:
                qs = parse_qs(urlparse(href).query)
                href = qs.get("u", [href])[0]
                if href.startswith("a1"):
                    try:
                        import base64
                        href = base64.urlsafe_b64decode(href[2:] + "===").decode("utf-8", "ignore")
                    except Exception:
                        pass
            href = unquote(href)
            cleaned = clean_url(href)
            if cleaned and score_official_candidate(cleaned, name, party) > -50:
                candidates.append(cleaned)
    unique = []
    seen = set()
    for u in candidates:
        parsed = urlparse(u)
        key = parsed.netloc.lower().removeprefix("www.") + parsed.path.rstrip("/")
        if key not in seen:
            seen.add(key)
            unique.append(u)
    if not unique:
        return None
    return sorted(unique, key=lambda u: score_official_candidate(u, name, party), reverse=True)[0]


def duckduckgo_official_search(name: str, party: str) -> Optional[str]:
    return search_engine_official_search(name, party)


def validate_official_url(url: str, name: str) -> Optional[str]:
    # アクセスできれば採用。403でもサイトとしては存在扱い。
    url = clean_url(url)
    if not url:
        return None

    candidates = [url]
    parsed = urlparse(url)
    if parsed.scheme == "http":
        candidates.append("https://" + parsed.netloc + parsed.path)
        if not parsed.netloc.startswith("www."):
            candidates.append("https://www." + parsed.netloc + parsed.path)
    elif parsed.scheme == "https" and not parsed.netloc.startswith("www."):
        candidates.append("https://www." + parsed.netloc + parsed.path)

    for candidate in candidates:
        res = request_get(candidate, retries=1)
        if res and res.status_code < 500:
            return res.url or candidate

    # 証明書だけ取れる場合はHTTPSサイトとして残す
    parsed = urlparse(url)
    host = parsed.hostname
    if host and extract_cert(host):
        return "https://" + host + (parsed.path if parsed.path else "/")

    return url


def enrich_member(member: Member) -> Member:
    override = OFFICIAL_URL_OVERRIDES.get(name_key(member.name)) or OFFICIAL_URL_OVERRIDES.get(member.name)
    if override:
        member.official_url = validate_official_url(override, member.name) or override
        member.official_url_source = "manual_override"

    title, wiki_url = search_wikipedia(member.name, member.chamber)
    member.wikipedia_title = title
    member.wikipedia_url = wiki_url

    if not member.official_url and title:
        qid = get_wikidata_qid(title)
        if qid:
            url = get_official_website_from_wikidata(qid)
            if url:
                member.official_url = validate_official_url(url, member.name)
                member.official_url_source = "wikidata_p856"

    if not member.official_url and wiki_url:
        for candidate in extract_candidate_urls_from_wikipedia(wiki_url, member.name, member.party):
            valid = validate_official_url(candidate, member.name)
            if valid:
                member.official_url = valid
                member.official_url_source = "wikipedia_external"
                break

    if not member.official_url:
        candidate = duckduckgo_official_search(member.name, member.party)
        if candidate:
            member.official_url = validate_official_url(candidate, member.name)
            member.official_url_source = "search_engine_fallback"

    return member


def decode_openssl_value(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    # opensslが \E8\87... のように出す場合を日本語に戻す
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
            patterns = [
                rf"{field}\s*=\s*([^,/]+)",
                rf"/{field}=([^/]+)",
            ]
            for pattern in patterns:
                match = re.search(pattern, text)
                if match:
                    return decode_openssl_value(match.group(1).strip())
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


def is_probable_gs_legislator_cert(
    party: str,
    subject_o: Optional[str],
    issuer_o: Optional[str],
    issuer_cn: Optional[str],
) -> bool:
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

    if not member.official_url:
        return ScanResult(
            chamber=member.chamber,
            name=member.name,
            party=member.party,
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
        )

    url = clean_url(member.official_url)
    assert url is not None

    cert_subject_cn = None
    cert_subject_o = None
    cert_issuer_o = None
    cert_issuer_cn = None
    is_https = False
    final_url = None
    status_code = None
    site_seal = False

    # HTTPで登録されていてもHTTPS版を先に試す。HTTPSサイト数の過少カウント対策。
    parsed0 = urlparse(url)
    scan_candidates = []
    if parsed0.scheme == "http":
        scan_candidates.append("https://" + parsed0.netloc + (parsed0.path or "/"))
        if not parsed0.netloc.startswith("www."):
            scan_candidates.append("https://www." + parsed0.netloc + (parsed0.path or "/"))
    scan_candidates.append(url)

    response = None
    for candidate in scan_candidates:
        response = request_get(candidate, retries=1)
        if response and response.status_code < 500:
            final_url = response.url
            status_code = response.status_code
            break

    if response:
        text = response.text or ""
        site_seal = detect_site_seal(text)
    else:
        notes.append("HTTP取得失敗")

    effective_url = final_url or url
    parsed = urlparse(effective_url)

    # final_urlがhttpでも、同一ホストのhttps証明書が取れるならHTTPS導入ありとしてカウント
    cert_hosts = []
    if parsed.hostname:
        if parsed.scheme == "https":
            cert_hosts.append(parsed.hostname)
        else:
            cert_hosts.append(parsed.hostname)
            if not parsed.hostname.startswith("www."):
                cert_hosts.insert(0, "www." + parsed.hostname)

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

    by_chamber: Dict[str, dict] = {}
    for r in results:
        row = by_chamber.setdefault(
            r.chamber or "不明",
            {"chamber": r.chamber or "不明", "total": 0, "with_site": 0, "https": 0, "gs": 0, "seal": 0, "gs_share": 0.0},
        )
        row["total"] += 1
        row["with_site"] += int(bool(r.official_url))
        row["https"] += int(r.is_https)
        row["gs"] += int(r.is_gs)
        row["seal"] += int(r.site_seal_found)
    for row in by_chamber.values():
        row["gs_share"] = pct(row["gs"], row["https"])

    by_party: Dict[str, dict] = {}
    for r in results:
        party = party_group(r.party)
        row = by_party.setdefault(
            party,
            {"party": party, "total": 0, "with_site": 0, "https": 0, "gs": 0, "seal": 0, "gs_share": 0.0},
        )
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
        "by_chamber": sorted(by_chamber.values(), key=lambda x: x["chamber"]),
        "by_party": sorted(by_party.values(), key=lambda row: party_order.get(row["party"], 999)),
        "display_parties": DISPLAY_PARTIES + ["その他"],
    }


def main() -> None:
    shugiin_members = get_shugiin_members()
    sangiin_members = get_sangiin_members()
    members = shugiin_members + sangiin_members

    members = sorted(
        {(m.chamber, name_key(m.name)): m for m in members}.values(),
        key=lambda m: (m.chamber, m.name),
    )

    print("Shugiin fetched:", len(shugiin_members), flush=True)
    print("Sangiin fetched:", len(sangiin_members), flush=True)
    print("Current members fetched:", len(members), flush=True)

    enriched: List[Member] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_ENRICH_WORKERS) as executor:
        futures = [executor.submit(enrich_member, m) for m in members]
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            try:
                enriched.append(future.result())
            except Exception as e:
                print("Enrich error:", type(e).__name__, flush=True)
            if i % 25 == 0:
                print(f"Enriched {i}/{len(members)}", flush=True)

    enriched = sorted(enriched, key=lambda m: (m.chamber, m.name))

    results: List[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as executor:
        futures = [executor.submit(scan_site, m) for m in enriched]
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            try:
                results.append(future.result())
            except Exception as e:
                print("Scan error:", type(e).__name__, flush=True)
            if i % 25 == 0:
                print(f"Scanned {i}/{len(enriched)}", flush=True)

    results = sorted(results, key=lambda r: (r.chamber, r.name))

    payload = {
        "generated_at": now_iso(),
        "summary": summarize(results),
        "results": [dict(asdict(r), party_group=party_group(r.party)) for r in results],
    }

    OUT_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {OUT_FILE} with {len(results)} rows", flush=True)



# =========================
# v5 fixes
# =========================
OFFICIAL_URL_OVERRIDES.update({
    "前原誠司": "https://www.maehara21.com/",
    "齋藤健": "https://saito-ken.jp/",
    "斎藤健": "https://saito-ken.jp/",
})


def get_official_website_from_wikidata_search(name: str) -> Optional[str]:
    try:
        res = request_get(
            "https://www.wikidata.org/w/api.php?" + requests.compat.urlencode({
                "action": "wbsearchentities",
                "format": "json",
                "language": "ja",
                "uselang": "ja",
                "search": name,
                "limit": 5,
            }),
            retries=2,
        )
        if not res or res.status_code >= 500:
            return None
        for item in res.json().get("search", []):
            qid = item.get("id")
            if not qid:
                continue
            url = get_official_website_from_wikidata(qid)
            if url:
                return url
    except Exception:
        return None
    return None


def extract_urls_from_search_html(search_url: str, name: str, party: str) -> List[str]:
    res = request_get(search_url, retries=1)
    if not res or res.status_code >= 500:
        return []
    soup = BeautifulSoup(res.text, "html.parser")
    urls: List[str] = []
    for a in soup.select("a[href]"):
        href = a.get("href") or ""
        if href.startswith("/url?") or "duckduckgo.com/l/" in href or "/ck/a" in href:
            qs = parse_qs(urlparse(href).query)
            href = qs.get("q", qs.get("uddg", qs.get("u", [href])))[0]
        href = unquote(href)
        url = clean_url(href)
        if not url:
            continue
        host = urlparse(url).netloc.lower()
        if any(bad in host for bad in ["google.", "bing.", "yahoo.", "duckduckgo.", "wikipedia.", "wikidata.", "facebook.", "twitter.", "x.com", "youtube.", "instagram."]):
            continue
        if score_official_candidate(url, name, party) > -30:
            urls.append(url)
    seen = set()
    unique = []
    for u in urls:
        key = urlparse(u).netloc.lower().removeprefix("www.") + urlparse(u).path.rstrip("/")
        if key not in seen:
            seen.add(key)
            unique.append(u)
    return sorted(unique, key=lambda u: score_official_candidate(u, name, party), reverse=True)


def search_engine_official_search_v5(name: str, party: str) -> Optional[str]:
    q = f'{name} 公式サイト 国会議員'
    searches = [
        "https://duckduckgo.com/html/?" + requests.compat.urlencode({"q": q}),
        "https://www.bing.com/search?" + requests.compat.urlencode({"q": q}),
    ]
    for search_url in searches:
        for candidate in extract_urls_from_search_html(search_url, name, party)[:5]:
            valid = validate_official_url(candidate, name)
            if valid:
                return valid
    return None


def parse_sangiin_page(url: str) -> List[Member]:
    text = get_text(url)
    if not text:
        return []
    soup = BeautifulSoup(text, "html.parser")
    members: List[Member] = []
    short_to_full = {short: full for full, short in PARTY_SHORT.items()}
    short_tokens = sorted(short_to_full.keys(), key=len, reverse=True)
    short_re = "|".join(map(re.escape, short_tokens))

    for tr in soup.select("tr"):
        cells = [re.sub(r"\s+", " ", c.get_text(" ", strip=True)) for c in tr.select("td,th")]
        if len(cells) < 3:
            continue
        joined = " ".join(cells)
        pm = re.search(rf"(^|\s)({short_re})(\s|$)", joined) if short_re else None
        if not pm:
            continue
        party = short_to_full.get(pm.group(2), normalize_party(pm.group(2)))
        for cell in cells[:3]:
            candidate = clean_name(re.sub(r"（.*?）|\(.*?\)", "", cell))
            if is_person_name(candidate) and not re.fullmatch(r"[ぁ-んァ-ンー・ 　]+", candidate) and len(candidate) <= 12:
                members.append(Member("参議院", candidate, party))
                break

    page_text = soup.get_text("\n")
    lines = [re.sub(r"\s+", " ", line).strip() for line in page_text.splitlines()]
    line_re = re.compile(
        rf"^([一-龥々〆ヵヶぁ-んァ-ンー・ 　]{{2,40}})\s+"
        rf"([ぁ-んァ-ンー・ 　]{{2,80}})\s+"
        rf"({short_re})\s+"
        rf"(.*?)\s+令和\d+年\d+月\d+日"
    )
    for line in lines:
        m = line_re.match(line)
        if not m:
            continue
        members.append(Member("参議院", clean_name(m.group(1)), short_to_full.get(m.group(3), normalize_party(m.group(3)))))

    return list({(m.chamber, name_key(m.name)): m for m in members if m.name}.values())


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
    best_url = None
    for url in candidate_urls:
        members = parse_sangiin_page(url)
        if len(members) > len(best):
            best = members
            best_url = url
        if len(best) >= 240:
            break
    if len(best) >= 50:
        print(f"Sangiin source: {best_url} ({len(best)} members)", flush=True)
        return best
    wiki = get_sangiin_members_from_wikipedia()
    return wiki if len(wiki) > len(best) else best


def enrich_member(member: Member) -> Member:
    override = OFFICIAL_URL_OVERRIDES.get(name_key(member.name)) or OFFICIAL_URL_OVERRIDES.get(member.name)
    if override:
        member.official_url = validate_official_url(override, member.name) or override
        member.official_url_source = "manual_override"

    title, wiki_url = search_wikipedia(member.name, member.chamber)
    member.wikipedia_title = title
    member.wikipedia_url = wiki_url

    if not member.official_url and title:
        qid = get_wikidata_qid(title)
        if qid:
            url = get_official_website_from_wikidata(qid)
            if url:
                member.official_url = validate_official_url(url, member.name)
                member.official_url_source = "wikidata_p856"

    if not member.official_url:
        url = get_official_website_from_wikidata_search(member.name)
        if url:
            member.official_url = validate_official_url(url, member.name)
            member.official_url_source = "wikidata_search_p856"

    if not member.official_url and wiki_url:
        for candidate in extract_candidate_urls_from_wikipedia(wiki_url, member.name, member.party):
            valid = validate_official_url(candidate, member.name)
            if valid:
                member.official_url = valid
                member.official_url_source = "wikipedia_external"
                break

    if not member.official_url:
        candidate = search_engine_official_search_v5(member.name, member.party)
        if candidate:
            member.official_url = candidate
            member.official_url_source = "search_engine_fallback_v5"

    return member


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
    }

if __name__ == "__main__":
    main()
