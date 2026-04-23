#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import concurrent.futures
import datetime as dt
import json
import re
import socket
import ssl
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


OUT_FILE = Path("data.json")
USER_AGENT = "DietCertDashboard/1.1 (+GitHub Actions)"
TIMEOUT = 20
MAX_ENRICH_WORKERS = 12
MAX_SCAN_WORKERS = 20

HEADERS = {"User-Agent": USER_AGENT}

session = requests.Session()
session.headers.update(HEADERS)

GS_KEYWORDS = [
    "globalsign",
    "global sign",
    "gmo globalsign",
]

SITE_SEAL_PATTERNS = [
    r"globalsign",
    r"siteseal",
    r"sslpr",
    r"secure site seal",
    r"実在証明・盗聴対策シール",
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

# 衆院一覧ページに出やすい会派名の候補
SHUGIIN_PARTIES = {
    "自由民主党",
    "立憲民主党",
    "日本維新の会",
    "公明党",
    "国民民主党",
    "日本共産党",
    "れいわ新選組",
    "参政党",
    "日本保守党",
    "社会民主党",
    "チームみらい",
    "無所属",
    "中道改革連合",
    "減税日本・ゆうこく連合",
}


@dataclass
class Member:
    chamber: str
    name: str
    party: str
    wikipedia_title: Optional[str] = None
    wikipedia_url: Optional[str] = None
    official_url: Optional[str] = None


@dataclass
class ScanResult:
    chamber: str
    name: str
    party: str
    wikipedia_title: Optional[str]
    source_url: Optional[str]
    official_url: Optional[str]
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


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def get_text(url: str) -> Optional[str]:

    try:

        response = session.get(url, timeout=TIMEOUT)

        response.raise_for_status()

        response.encoding = response.apparent_encoding

        return response.text

    except Exception:

        return None


def normalize_party(value: str) -> str:
    if not value:
        return ""
    value = value.strip()
    compact = re.sub(r"\s+", "", value)
    compact = re.split(r"[／/・]", compact)[0]
    return PARTY_NORMALIZATION.get(compact, value)


def clean_name(name: str) -> str:
    name = name.replace("　", " ").strip()
    name = re.sub(r"\s*\[.*?\]", "", name)
    name = re.sub(r"[君氏]+$", "", name).strip()
    return name


def clean_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None

    url = url.strip()
    if url.startswith("//"):
        url = "https:" + url
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    parsed = urlparse(url)
    if not parsed.netloc:
        return None
    return url


def is_person_name(text: str) -> bool:
    return bool(re.fullmatch(r"[一-龥々〆ヵヶぁ-んァ-ンーA-Za-z・ 　]{2,40}", text))


def get_shugiin_members() -> List[Member]:
    url = "https://ja.wikipedia.org/wiki/衆議院議員一覧"
    html = get_text(url)
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text("\n")

    lines = [re.sub(r"\s+", " ", line).strip() for line in text.splitlines()]
    lines = [line for line in lines if line]

    members: List[Member] = []

    for i in range(len(lines) - 1):
        name = lines[i]
        party_line = lines[i + 1]

        if not re.fullmatch(r"[一-龥々〆ヵヶぁ-んァ-ンーA-Za-z・ 　]{2,40}", name):
            continue
        if not (party_line.startswith("（") and party_line.endswith("）")):
            continue

        party = normalize_party(party_line.strip("（）").strip())
        if party not in SHUGIIN_PARTIES:
            continue

        members.append(
            Member(
                chamber="衆議院",
                name=clean_name(name),
                party=party,
            )
        )

    dedup = {(m.chamber, m.name): m for m in members}
    return list(dedup.values())


def search_wikipedia(name: str, chamber: str) -> Tuple[Optional[str], Optional[str]]:
    api = "https://ja.wikipedia.org/w/api.php"

    for query in [f"{name} (政治家)", f"{name} {chamber}", name]:
        try:
            response = session.get(
                api,
                params={
                    "action": "query",
                    "list": "search",
                    "format": "json",
                    "srsearch": query,
                    "srlimit": 5,
                },
                timeout=TIMEOUT,
            )
            response.raise_for_status()
            items = response.json().get("query", {}).get("search", [])
        except Exception:
            continue

        for item in items:
            title = item.get("title")
            if title and (name.replace(" ", "") in title.replace(" ", "") or title.startswith(name)):
                wiki_url = f"https://ja.wikipedia.org/wiki/{requests.utils.quote(title.replace(' ', '_'))}"
                return title, wiki_url

    return None, None


def get_wikidata_qid(title: str) -> Optional[str]:
    try:
        response = session.get(
            "https://ja.wikipedia.org/w/api.php",
            params={
                "action": "query",
                "prop": "pageprops",
                "titles": title,
                "format": "json",
            },
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        pages = response.json().get("query", {}).get("pages", {})

        for page in pages.values():
            qid = page.get("pageprops", {}).get("wikibase_item")
            if qid:
                return qid
    except Exception:
        return None

    return None


def get_official_website_from_wikidata(qid: str) -> Optional[str]:
    try:
        response = session.get(
            f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json",
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        claims = response.json().get("entities", {}).get(qid, {}).get("claims", {})

        for claim in claims.get("P856", []):
            value = claim.get("mainsnak", {}).get("datavalue", {}).get("value")
            cleaned = clean_url(value)
            if cleaned:
                return cleaned
    except Exception:
        return None

    return None


def get_official_website_from_wikipedia(page_url: str) -> Optional[str]:
    html = get_text(page_url)
    if not html:
        return None

    soup = BeautifulSoup(html, "html.parser")

    for table in soup.select("table.infobox, table.infobox.vevent"):
        for link in table.select("a[href]"):
            href = link.get("href", "")
            if href.startswith("http"):
                return clean_url(href)

    for link in soup.select("a.external"):
        href = link.get("href", "")
        if href.startswith("http"):
            return clean_url(href)

    return None


def enrich_member(member: Member) -> Member:
    title, wiki_url = search_wikipedia(member.name, member.chamber)
    official_url = None

    if title:
        qid = get_wikidata_qid(title)
        if qid:
            official_url = get_official_website_from_wikidata(qid)
        if not official_url and wiki_url:
            official_url = get_official_website_from_wikipedia(wiki_url)

    member.wikipedia_title = title
    member.wikipedia_url = wiki_url
    member.official_url = official_url
    return member


def extract_cert(hostname: str, port: int = 443) -> Optional[dict]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_socket:
                return tls_socket.getpeercert()
    except Exception:
        return None


def parse_name_tuple(name_tuple) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for rdn in name_tuple or ():
        for key, val in rdn:
            result[key] = val
    return result


def contains_gs(*texts: Optional[str]) -> bool:
    joined = " ".join(text or "" for text in texts).lower()
    return any(keyword in joined for keyword in GS_KEYWORDS)


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

    normalized_party = normalize_party(party)
    normalized_subject = normalize_party(subject_o)

    return normalized_party == normalized_subject or bool(
        normalized_party and (normalized_party in subject_o or subject_o in normalized_party)
    )


def detect_site_seal(html: str) -> bool:
    haystack = (html or "").lower()
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

    url = member.official_url
    parsed = urlparse(url)
    hostname = parsed.hostname

    cert_subject_cn = None
    cert_subject_o = None
    cert_issuer_o = None
    cert_issuer_cn = None
    is_https = parsed.scheme.lower() == "https"

    if is_https and hostname:
        cert = extract_cert(hostname, parsed.port or 443)
        if cert:
            subject = parse_name_tuple(cert.get("subject"))
            issuer = parse_name_tuple(cert.get("issuer"))
            cert_subject_cn = subject.get("commonName")
            cert_subject_o = subject.get("organizationName")
            cert_issuer_o = issuer.get("organizationName")
            cert_issuer_cn = issuer.get("commonName")
        else:
            notes.append("証明書取得に失敗")

    try:
        response = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        final_url = response.url
        status_code = response.status_code
        html = response.text or ""
        site_seal = detect_site_seal(html)

        if not is_https and final_url.lower().startswith("https://"):
            final_host = urlparse(final_url).hostname
            if final_host:
                cert = extract_cert(final_host, 443)
                if cert:
                    subject = parse_name_tuple(cert.get("subject"))
                    issuer = parse_name_tuple(cert.get("issuer"))
                    cert_subject_cn = subject.get("commonName")
                    cert_subject_o = subject.get("organizationName")
                    cert_issuer_o = issuer.get("organizationName")
                    cert_issuer_cn = issuer.get("commonName")
                    is_https = True

        is_gs = contains_gs(cert_issuer_o, cert_issuer_cn)
        is_gs_leg = is_probable_gs_legislator_cert(
            member.party,
            cert_subject_o,
            cert_issuer_o,
            cert_issuer_cn,
        )

        return ScanResult(
            chamber=member.chamber,
            name=member.name,
            party=member.party,
            wikipedia_title=member.wikipedia_title,
            source_url=member.wikipedia_url,
            official_url=member.official_url,
            final_url=final_url,
            status="ok",
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

    except Exception as error:
        return ScanResult(
            chamber=member.chamber,
            name=member.name,
            party=member.party,
            wikipedia_title=member.wikipedia_title,
            source_url=member.wikipedia_url,
            official_url=member.official_url,
            final_url=None,
            status="request_error",
            http_status=None,
            cert_subject_cn=cert_subject_cn,
            cert_subject_o=cert_subject_o,
            cert_issuer_o=cert_issuer_o,
            cert_issuer_cn=cert_issuer_cn,
            is_https=is_https,
            is_gs=contains_gs(cert_issuer_o, cert_issuer_cn),
            is_gs_legislator_cert=is_probable_gs_legislator_cert(
                member.party,
                cert_subject_o,
                cert_issuer_o,
                cert_issuer_cn,
            ),
            site_seal_found=False,
            notes=notes + [f"HTTP取得失敗: {type(error).__name__}"],
        )


def summarize(results: List[ScanResult]) -> dict:
    total_members = len(results)
    with_site = sum(1 for result in results if result.official_url)
    https_count = sum(1 for result in results if result.is_https)
    gs_count = sum(1 for result in results if result.is_gs)
    gs_legislator_count = sum(1 for result in results if result.is_gs_legislator_cert)
    site_seal_count = sum(1 for result in results if result.site_seal_found)

    def pct(numerator: int, denominator: int) -> float:
        return round((numerator / denominator * 100) if denominator else 0.0, 1)

    by_party: Dict[str, dict] = {}

    for result in results:
        party = result.party or "不明"

        by_party.setdefault(
            party,
            {"party": party, "total": 0, "with_site": 0, "gs_leg": 0, "gs": 0, "seal": 0},
        )

        by_party[party]["total"] += 1
        if result.official_url:
            by_party[party]["with_site"] += 1
        if result.is_gs_legislator_cert:
            by_party[party]["gs_leg"] += 1
        if result.is_gs:
            by_party[party]["gs"] += 1
        if result.site_seal_found:
            by_party[party]["seal"] += 1

    return {
        "generated_at": now_iso(),
        "total_members": total_members,
        "with_site": with_site,
        "https_count": https_count,
        "gs_count": gs_count,
        "gs_legislator_count": gs_legislator_count,
        "site_seal_count": site_seal_count,
        "gs_share_all_members": pct(gs_legislator_count, total_members),
        "gs_share_sites_only": pct(gs_legislator_count, with_site),
        "site_seal_share_sites_only": pct(site_seal_count, with_site),
        "by_party": sorted(by_party.values(), key=lambda row: (-row["with_site"], row["party"])),
    }


def main() -> None:
    shugiin_members = get_shugiin_members()
    sangiin_members = get_sangiin_members()
    def get_sangiin_members() -> List[Member]:

    url = "https://www.sangiin.go.jp/japanese/joho1/kousei/giin/221/giin.htm"

    html = get_text(url)

    if not html:

        return []

    soup = BeautifulSoup(html, "html.parser")

    text = soup.get_text("\n")

    party_map = {

        "自民": "自由民主党",

        "立憲": "立憲民主党",

        "維新": "日本維新の会",

        "公明": "公明党",

        "民主": "国民民主党",

        "参政": "参政党",

        "共産": "日本共産党",

        "れ新": "れいわ新選組",

        "保守": "日本保守党",

        "沖縄": "沖縄の風",

        "みら": "チームみらい",

        "社民": "社会民主党",

        "無所属": "無所属",

    }

    members: List[Member] = []

    pattern = re.compile(

        r"([一-龥々〆ヵヶぁ-んァ-ンー ]{2,40})\s+"

        r"([ぁ-んー ]{2,60})\s+"

        r"(自民|立憲|維新|公明|民主|参政|共産|れ新|保守|沖縄|みら|社民|無所属)\s+"

        r"(\S+)\s+"

        r"(令和\d+年\d+月\d+日)"

    )

    for match in pattern.finditer(text):

        name = clean_name(match.group(1))

        party_abbr = match.group(3)

        members.append(

            Member(

                chamber="参議院",

                name=name,

                party=party_map[party_abbr],

            )

        )

    dedup = {(m.chamber, m.name): m for m in members}

    return list(dedup.values())
    members = shugiin_members + sangiin_members

    members = sorted(
        {(m.chamber, m.name): m for m in members}.values(),
        key=lambda m: (m.chamber, m.name),
    )

    print(f"Shugiin fetched: {len(shugiin_members)}")
    print(f"Sangiin fetched: {len(sangiin_members)}")
    print(f"Current members fetched: {len(members)}")

    enriched: List[Member] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_ENRICH_WORKERS) as executor:
        futures = [executor.submit(enrich_member, member) for member in members]
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            enriched.append(future.result())
            if i % 25 == 0:
                print(f"Enriched {i}/{len(members)}")

    enriched = sorted(enriched, key=lambda member: (member.chamber, member.name))

    results: List[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as executor:
        futures = [executor.submit(scan_site, member) for member in enriched]
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            results.append(future.result())
            if i % 25 == 0:
                print(f"Scanned {i}/{len(enriched)}")

    results = sorted(results, key=lambda result: (result.chamber, result.name))

    payload = {
        "generated_at": now_iso(),
        "summary": summarize(results),
        "results": [asdict(result) for result in results],
    }

    OUT_FILE.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Wrote {OUT_FILE} with {len(results)} rows")


if __name__ == "__main__":
    main()
