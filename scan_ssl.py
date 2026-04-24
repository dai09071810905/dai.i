import json, ssl, socket
from urllib.parse import urlparse

CACHE_FILE = "urls.json"
OUT_FILE = "data.json"

def get_cert(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return cert
    except:
        return None

def is_gs(cert):
    if not cert:
        return False
    issuer = dict(x[0] for x in cert['issuer'])
    return "GlobalSign" in str(issuer)

def main():
    urls = json.load(open(CACHE_FILE))
    results = []

    for name, url in urls.items():
        host = urlparse(url).hostname
        cert = get_cert(host)

        results.append({
            "name": name,
            "url": url,
            "https": bool(cert),
            "gs": is_gs(cert)
        })

    json.dump(results, open(OUT_FILE, "w"), indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()
