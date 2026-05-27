import json
import ssl
import socket
import csv
import requests
import tempfile
from datetime import datetime
from urllib.parse import urlparse
from email.utils import parsedate_to_datetime

MEMBERS_FILE = "members.json"
URLS_FILE = "urls.json"
OUT_JSON = "data.json"
OUT_CSV = "data.csv"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; DaiBot/1.0)"
}

DISPLAY_PARTIES = [
    "自由民主党",
    "国民民主党",
    "立憲民主党",
    "れいわ新選組",
    "中道改革連合",
    "その他"
]


def load_input():
    """
    collect_urls.py の新形式 members.json を優先して読む。
    なければ旧形式 urls.json を読む。
    """
    try:
        with open(MEMBERS_FILE, encoding="utf-8") as f:
            members = json.load(f)

        if isinstance(members, list):
            return members
    except:
        pass

    with open(URLS_FILE, encoding="utf-8") as f:
        urls = json.load(f)

    members = []
    for name, url in urls.items():
        members.append({
            "name": name,
            "chamber": "不明",
            "party": "",
            "wiki_url": "",
            "official_url": url,
            "url": url,
            "official_url_source": "urls.json"
        })

    return members


def normalize_url(url):
    if not url:
        return None

    url = str(url).strip()

    if not url:
        return None

    if url.startswith("//"):
        return "https:" + url

    if url.startswith("http://"):
        return "https://" + url.replace("http://", "", 1)

    if not url.startswith("http://") and not url.startswith("https://"):
        return "https://" + url

    return url


def get_host(url):
    try:
        return urlparse(url).hostname
    except:
        return None


def decode_cert_from_der(der_cert):
    """
    DER形式の証明書をPython標準ライブラリで読みやすい辞書へ変換する。
    """
    try:
        pem = ssl.DER_cert_to_PEM_cert(der_cert)

        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".pem", encoding="utf-8") as tmp:
            tmp.write(pem)
            tmp_path = tmp.name

        return ssl._ssl._test_decode_cert(tmp_path)
    except:
        return None


def get_cert_info(host):
    """
    サーバ証明書を取得する。
    検証エラーでも証明書情報を取れるように、unverified context を使う。
    """
    if not host:
        return None

    try:
        ctx = ssl._create_unverified_context()

        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)

                if not der_cert:
                    return None

                cert = decode_cert_from_der(der_cert)

                if not cert:
                    return None

                cert["_tls_version"] = ssock.version()
                cert["_cipher"] = ssock.cipher()[0] if ssock.cipher() else ""

                return cert
    except:
        return None


def name_from_tuple_list(items):
    """
    subject / issuer の tuple を dict化する。
    """
    parts = {}

    if not items:
        return parts

    for item in items:
        for key, value in item:
            parts[key] = value

    return parts


def get_subject_parts(cert):
    if not cert:
        return {}
    return name_from_tuple_list(cert.get("subject"))


def get_issuer_parts(cert):
    if not cert:
        return {}
    return name_from_tuple_list(cert.get("issuer"))


def get_issuer_name(cert):
    parts = get_issuer_parts(cert)

    return (
        parts.get("organizationName")
        or parts.get("commonName")
        or ""
    )


def get_issuer_cn(cert):
    parts = get_issuer_parts(cert)
    return parts.get("commonName") or ""


def get_subject_o(cert):
    parts = get_subject_parts(cert)
    return parts.get("organizationName") or ""


def get_subject_cn(cert):
    parts = get_subject_parts(cert)
    return parts.get("commonName") or ""


def cert_not_after(cert):
    if not cert:
        return ""

    raw = cert.get("notAfter") or ""

    if not raw:
        return ""

    try:
        dt = parsedate_to_datetime(raw)
        return dt.strftime("%Y-%m-%d")
    except:
        return raw


def is_globalsign(cert):
    if not cert:
        return False

    issuer = get_issuer_name(cert) + " " + get_issuer_cn(cert)
    subject = get_subject_o(cert) + " " + get_subject_cn(cert)

    return "GlobalSign" in issuer or "GlobalSign" in subject


def check_https_and_html(url):
    """
    HTTPSでページHTMLを取得する。
    失敗した場合はHTTPも試す。
    """
    if not url:
        return False, None, ""

    check_url = normalize_url(url)

    try:
        r = requests.get(
            check_url,
            headers=HEADERS,
            timeout=12,
            allow_redirects=True
        )
        return True, r.url, r.text
    except:
        pass

    # HTTPSでページ取得できない場合、HTTPも確認
    try:
        http_url = check_url.replace("https://", "http://", 1)
        r = requests.get(
            http_url,
            headers=HEADERS,
            timeout=12,
            allow_redirects=True
        )
        return r.url.startswith("https://"), r.url, r.text
    except:
        return False, check_url, ""


def has_gs_site_seal(html):
    if not html:
        return False

    h = html.lower()

    keywords = [
        "globalsign",
        "seal.globalsign",
        "ssl.globalsign",
        "secure.globalsign",
        "site seal",
        "sitesell",
        "gs_noscript",
        "globalsign.com/seal",
        "jp.globalsign.com"
    ]

    return any(k.lower() in h for k in keywords)


def normalize_party(party):
    if not party:
        return ""

    p = str(party).replace(" ", "").replace("　", "")

    mapping = {
        "自民": "自由民主党",
        "自民党": "自由民主党",
        "自由民主": "自由民主党",
        "自由民主党": "自由民主党",
        "国民": "国民民主党",
        "国民民主": "国民民主党",
        "国民民主党": "国民民主党",
        "立民": "立憲民主党",
        "立憲": "立憲民主党",
        "立憲民主": "立憲民主党",
        "立憲民主党": "立憲民主党",
        "れいわ": "れいわ新選組",
        "れいわ新選組": "れいわ新選組",
        "中道改革連合": "中道改革連合",
        "減税日本・ゆうこく連合": "その他"
    }

    return mapping.get(p, party)


def party_group(party):
    p = normalize_party(party)

    if p in DISPLAY_PARTIES and p != "その他":
        return p

    return "その他"


def empty_chamber_row(chamber):
    return {
        "chamber": chamber,
        "total": 0,
        "with_site": 0,
        "https": 0,
        "gs": 0,
        "seal": 0,
        "gs_share": 0
    }


def empty_party_row(party):
    return {
        "party": party,
        "total": 0,
        "with_site": 0,
        "https": 0,
        "gs": 0,
        "seal": 0,
        "gs_share": 0
    }


def add_to_row(row, r):
    row["total"] += 1
    row["with_site"] += 1 if r.get("official_url") else 0
    row["https"] += 1 if r.get("is_https") else 0
    row["gs"] += 1 if r.get("is_gs") else 0
    row["seal"] += 1 if r.get("site_seal_found") else 0


def finalize_row(row):
    if row["https"]:
        row["gs_share"] = round(row["gs"] / row["https"] * 100, 1)
    else:
        row["gs_share"] = 0

    return row


def build_summary(results):
    by_chamber = {
        "衆議院": empty_chamber_row("衆議院"),
        "参議院": empty_chamber_row("参議院"),
        "不明": empty_chamber_row("不明")
    }

    by_party = {
        p: empty_party_row(p)
        for p in DISPLAY_PARTIES
    }

    for r in results:
        chamber = r.get("chamber") or "不明"

        if chamber not in by_chamber:
            by_chamber[chamber] = empty_chamber_row(chamber)

        add_to_row(by_chamber[chamber], r)

        pg = r.get("party_group") or "その他"

        if pg not in by_party:
            by_party[pg] = empty_party_row(pg)

        add_to_row(by_party[pg], r)

    total_members = len(results)
    with_site = sum(1 for r in results if r.get("official_url"))
    https_count = sum(1 for r in results if r.get("is_https"))
    gs_count = sum(1 for r in results if r.get("is_gs"))
    site_seal_count = sum(1 for r in results if r.get("site_seal_found"))

    target_parties = ["自由民主党", "立憲民主党", "れいわ新選組", "国民民主党"]
    target = [
        r for r in results
        if normalize_party(r.get("party")) in target_parties and r.get("is_https")
    ]
    target_gs = [r for r in target if r.get("is_gs")]

    gs_leg = [r for r in results if r.get("is_gs_legislator_cert")]
    seal_on_gs_leg = [r for r in gs_leg if r.get("site_seal_found")]

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_members": total_members,
        "with_site": with_site,
        "https_count": https_count,
        "gs_count": gs_count,
        "site_seal_count": site_seal_count,
        "gs_share_target_parties": round(len(target_gs) / len(target) * 100, 1) if target else 0,
        "gs_share_target_parties_numerator": len(target_gs),
        "gs_share_target_parties_denominator": len(target),
        "site_seal_share_gs_legislator_cert": round(len(seal_on_gs_leg) / len(gs_leg) * 100, 1) if gs_leg else 0,
        "site_seal_share_gs_legislator_cert_numerator": len(seal_on_gs_leg),
        "site_seal_share_gs_legislator_cert_denominator": len(gs_leg),
        "by_chamber": [
            finalize_row(by_chamber["衆議院"]),
            finalize_row(by_chamber["参議院"]),
            finalize_row(by_chamber["不明"])
        ],
        "by_party": [
            finalize_row(by_party[p])
            for p in DISPLAY_PARTIES
        ],
        "display_parties": DISPLAY_PARTIES
    }


def scan_member(member):
    name = member.get("name") or member.get("名前") or ""
    chamber = member.get("chamber") or member.get("院") or "不明"
    party = member.get("party") or member.get("党") or ""
    wiki_url = member.get("wiki_url") or ""
    official_url = member.get("official_url") or member.get("url")

    print("▶", chamber, party, name, official_url)

    base = {
        "name": name,
        "chamber": chamber,
        "party": party,
        "party_group": party_group(party),
        "wiki_url": wiki_url,
        "official_url": official_url,
        "url": official_url,
        "official_url_source": member.get("official_url_source") or "",
        "party_profile_url": member.get("party_profile_url") or "",
        "final_url": None,
        "is_https": False,
        "https": False,
        "cert_exists": False,
        "is_gs": False,
        "gs": False,
        "globalsign_cert": False,
        "is_gs_legislator_cert": False,
        "site_seal_found": False,
        "globalsign_site_seal": False,
        "cert_subject_o": "",
        "cert_subject_cn": "",
        "cert_issuer_o": "",
        "cert_issuer_cn": "",
        "issuer": "",
        "cert_not_after": "",
        "tls_version": "",
        "cipher": "",
        "notes": []
    }

    if not official_url:
        base["notes"].append("公式URLなし")
        return base

    check_url = normalize_url(official_url)
    input_host = get_host(check_url)

    https_ok, final_url, html = check_https_and_html(check_url)
    final_host = get_host(final_url) or input_host

    # リダイレクト後のホストで証明書を取得
    cert = get_cert_info(final_host)

    if not cert and input_host and input_host != final_host:
        # 念のため元ホストも確認
        cert = get_cert_info(input_host)

    cert_exists = bool(cert)

    issuer_o = get_issuer_name(cert)
    issuer_cn = get_issuer_cn(cert)
    subject_o = get_subject_o(cert)
    subject_cn = get_subject_cn(cert)

    is_gs = is_globalsign(cert)
    seal = has_gs_site_seal(html)

    base.update({
        "final_url": final_url,
        "is_https": bool(cert_exists or https_ok),
        "https": bool(cert_exists or https_ok),
        "cert_exists": cert_exists,
        "is_gs": is_gs,
        "gs": is_gs,
        "globalsign_cert": is_gs,
        "is_gs_legislator_cert": is_gs,
        "site_seal_found": seal,
        "globalsign_site_seal": seal,
        "cert_subject_o": subject_o,
        "cert_subject_cn": subject_cn,
        "cert_issuer_o": issuer_o,
        "cert_issuer_cn": issuer_cn,
        "issuer": issuer_o or issuer_cn,
        "cert_not_after": cert_not_after(cert),
        "tls_version": cert.get("_tls_version", "") if cert else "",
        "cipher": cert.get("_cipher", "") if cert else ""
    })

    if not cert_exists:
        base["notes"].append("証明書取得不可")

    if final_url and final_url != check_url:
        base["notes"].append("リダイレクトあり")

    print("  HTTPS:", base["is_https"])
    print("  CA:", base["issuer"])
    print("  GS証明書:", base["is_gs"])
    print("  GSサイトシール:", base["site_seal_found"])

    return base


def main():
    members = load_input()
    results = []

    for i, member in enumerate(members, start=1):
        print(f"[{i}/{len(members)}]")
        result = scan_member(member)
        results.append(result)

        # 途中保存
        summary = build_summary(results)
        output = {
            "generated_at": summary["generated_at"],
            "summary": summary,
            "results": results
        }

        with open(OUT_JSON, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, indent=2)

    summary = build_summary(results)

    output = {
        "generated_at": summary["generated_at"],
        "summary": summary,
        "results": results
    }

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    fieldnames = [
        "name",
        "chamber",
        "party",
        "party_group",
        "wiki_url",
        "official_url",
        "final_url",
        "is_https",
        "cert_exists",
        "issuer",
        "cert_issuer_o",
        "cert_issuer_cn",
        "cert_subject_o",
        "cert_subject_cn",
        "cert_not_after",
        "is_gs",
        "site_seal_found",
        "tls_version",
        "cipher",
        "official_url_source",
        "notes"
    ]

    with open(OUT_CSV, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for r in results:
            row = r.copy()
            row["notes"] = " / ".join(row.get("notes", []))
            writer.writerow({k: row.get(k, "") for k in fieldnames})

    print("完了")
    print(f"- {OUT_JSON} 作成")
    print(f"- {OUT_CSV} 作成")


if __name__ == "__main__":
    main()
