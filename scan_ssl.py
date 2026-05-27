from __future__ import annotations

import json
import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import requests
import urllib3
from cryptography import x509
from cryptography.x509.oid import NameOID

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IN_FILE = Path("urls.json")
OUT_FILE = Path("data.json")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; diet-member-ssl-checker/1.0)"
}

GS_SEAL_HINTS = (
    "seal.globalsign.com",
    "ssif1.globalsign.com",
    "ssif2.globalsign.com",
    "globalsign.com/siteseal",
    "globalsign.com/site-seal",
    "siteseal",
    "site seal",
)


def save_json(path: Path, data: list[dict]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def force_https_url(url: str | None) -> str | None:
    if not url:
        return None

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.netloc:
        return None

    return urlunparse(
        (
            "https",
            parsed.netloc,
            parsed.path or "/",
            "",
            parsed.query,
            "",
        )
    )


def issuer_text(cert: x509.Certificate) -> str:
    parts: list[str] = []

    for oid in [NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME]:
        for attr in cert.issuer.get_attributes_for_oid(oid):
            if attr.value and attr.value not in parts:
                parts.append(attr.value)

    return " / ".join(parts) or cert.issuer.rfc4514_string()


def get_certificate_issuer(url: str | None) -> tuple[bool, str | None, str | None]:
    """
    戻り値:
    - HTTPS証明書を取得できたか
    - issuer
    - error

    期限切れや自己署名でも、TLS接続できればissuer取得を試みます。
    """
    https_url = force_https_url(url)

    if not https_url:
        return False, None, "official URLなし"

    parsed = urlparse(https_url)
    host = parsed.hostname
    port = parsed.port or 443

    if not host:
        return False, None, "hostなし"

    try:
        server_name = host.encode("idna").decode("ascii")
        context = ssl._create_unverified_context()

        with socket.create_connection((server_name, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=server_name) as ssock:
                der = ssock.getpeercert(binary_form=True)

        if not der:
            return False, None, "証明書を取得できませんでした"

        cert = x509.load_der_x509_certificate(der)

        return True, issuer_text(cert), None

    except Exception as e:
        return False, None, str(e)


def fetch_html(url: str | None) -> str:
    if not url:
        return ""

    candidates: list[str] = []

    https_url = force_https_url(url)

    if https_url:
        candidates.append(https_url)

    if url not in candidates:
        candidates.append(url)

    for candidate in candidates:
        try:
            res = requests.get(
                candidate,
                headers=HEADERS,
                timeout=12,
                allow_redirects=True,
                verify=False,
            )

            content_type = res.headers.get("content-type", "").lower()

            if res.status_code < 400 and ("html" in content_type or res.text):
                return res.text or ""

        except Exception:
            continue

    return ""


def has_gs_site_seal(html: str) -> bool:
    if not html:
        return False

    lower = html.lower()

    if any(hint in lower for hint in GS_SEAL_HINTS):
        return "globalsign" in lower or "ssif" in lower or "siteseal" in lower

    return "globalsign" in lower and (
        "seal" in lower or "ssif" in lower or "siteseal" in lower
    )


def scan_one(row: dict) -> dict:
    official = row.get("official")

    has_https, issuer, cert_error = get_certificate_issuer(official)

    html = fetch_html(official)
    gs_seal = has_gs_site_seal(html)

    issuer_lower = (issuer or "").lower()
    gs_cert = "globalsign" in issuer_lower

    return {
        **row,
        "https": has_https,
        "issuer": issuer,
        "gs_cert": gs_cert,
        "gs_seal": gs_seal,
        "error": row.get("error") or cert_error,
    }


def main() -> None:
    if not IN_FILE.exists():
        raise SystemExit("urls.json がありません。先に python collect_urls.py を実行してください。")

    rows = json.loads(IN_FILE.read_text(encoding="utf-8"))

    if not isinstance(rows, list):
        raise SystemExit("urls.json の形式が不正です。")

    max_workers = int(os.getenv("MAX_WORKERS", "12"))

    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_one, row) for row in rows]

        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)

            name = result.get("name", "")
            issuer = result.get("issuer") or "-"

            print(
                f"[{i}/{len(rows)}] {name} "
                f"https={result['https']} "
                f"gs_cert={result['gs_cert']} "
                f"gs_seal={result['gs_seal']} "
                f"issuer={issuer}"
            )

            if i % 20 == 0:
                save_json(OUT_FILE, results)
                print(f"checkpoint: {len(results)} 件保存")

    results.sort(key=lambda x: (x.get("house") or "", x.get("name") or ""))

    save_json(OUT_FILE, results)

    print(f"完了: {OUT_FILE} に {len(results)} 件保存しました")


if __name__ == "__main__":
    main()
