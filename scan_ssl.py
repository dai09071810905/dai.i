import json
import ssl
import socket
import csv
import requests
from urllib.parse import urlparse

CACHE_FILE = "urls.json"
OUT_JSON = "data.json"
OUT_CSV = "data.csv"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; DaiBot/1.0)"
}

def normalize_url(url):
    if not url:
        return None

    if url.startswith("http://"):
        return "https://" + url.replace("http://", "", 1)

    if not url.startswith("https://"):
        return "https://" + url

    return url

def get_cert(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert()
    except:
        return None

def get_issuer_name(cert):
    if not cert or "issuer" not in cert:
        return ""

    parts = {}
    for item in cert["issuer"]:
        for key, value in item:
            parts[key] = value

    return parts.get("organizationName") or parts.get("commonName") or str(parts)

def is_globalsign(cert):
    issuer = get_issuer_name(cert)
    return "GlobalSign" in issuer

def check_https(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
        return True, r.url, r.text
    except:
        return False, url, ""

def has_gs_site_seal(html):
    if not html:
        return False

    keywords = [
        "globalsign",
        "GlobalSign",
        "site seal",
        "sitesell",
        "seal.globalsign",
        "ssl.globalsign",
        "secure.globalsign",
        "globalsign.com"
    ]

    return any(k in html for k in keywords)

def main():
    urls = json.load(open(CACHE_FILE, encoding="utf-8"))
    results = []

    for name, url in urls.items():
        print("▶", name, url)

        if not url:
            results.append({
                "name": name,
                "url": None,
                "final_url": None,
                "https": False,
                "issuer": "",
                "globalsign_cert": False,
                "globalsign_site_seal": False
            })
            continue

        check_url = normalize_url(url)
        host = urlparse(check_url).hostname

        if not host:
            continue

        cert = get_cert(host)
        https_ok, final_url, html = check_https(check_url)

        issuer = get_issuer_name(cert)
        gs_cert = is_globalsign(cert)
        gs_seal = has_gs_site_seal(html)

        results.append({
            "name": name,
            "url": url,
            "final_url": final_url,
            "https": bool(cert) or https_ok,
            "issuer": issuer,
            "globalsign_cert": gs_cert,
            "globalsign_site_seal": gs_seal
        })

        print("  HTTPS:", bool(cert) or https_ok)
        print("  CA:", issuer)
        print("  GS証明書:", gs_cert)
        print("  GSサイトシール:", gs_seal)

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    with open(OUT_CSV, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "name",
            "url",
            "final_url",
            "https",
            "issuer",
            "globalsign_cert",
            "globalsign_site_seal"
        ])
        writer.writeheader()
        writer.writerows(results)

if __name__ == "__main__":
    main()
