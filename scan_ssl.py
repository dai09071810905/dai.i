for name, url in urls.items():
    host = urlparse(url).hostname

    if not host:
        results.append({
            "name": name,
            "url": url,
            "https": False,
            "gs": False
        })
        continue

    cert = get_cert(host)
