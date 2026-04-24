import requests, json, re, time
from bs4 import BeautifulSoup
from urllib.parse import quote

CACHE_FILE = "urls.json"

def load_cache():
    try:
        return json.load(open(CACHE_FILE))
    except:
        return {}

def save_cache(cache):
    json.dump(cache, open(CACHE_FILE, "w"), ensure_ascii=False, indent=2)

def get_wiki_members():
    url = "https://ja.wikipedia.org/wiki/衆議院議員一覧"
    html = requests.get(url).text
    soup = BeautifulSoup(html, "html.parser")

    members = []
    for a in soup.select("a[href^='/wiki/']"):
        name = a.text.strip()
        if len(name) >= 2 and "議員" not in name:
            members.append(name)

    return list(set(members))

def get_wikipedia_url(name):
    return f"https://ja.wikipedia.org/wiki/{quote(name)}"

def get_official_from_wiki(name):
    try:
        url = get_wikipedia_url(name)
        html = requests.get(url, timeout=5).text
        soup = BeautifulSoup(html, "html.parser")

        # infobox
        for a in soup.select("table.infobox a[href]"):
            href = a.get("href")
            if href and "http" in href:
                return href

        # 外部リンク
        for a in soup.select("#外部リンク a[href]"):
            href = a.get("href")
            if href and "http" in href:
                return href
    except:
        pass
    return None

def main():
    cache = load_cache()
    members = get_wiki_members()

    for name in members:
        if name in cache:
            continue

        url = get_official_from_wiki(name)

        if url:
            print("✔", name, url)
            cache[name] = url
        else:
            print("✖", name)

        time.sleep(0.2)

    save_cache(cache)

if __name__ == "__main__":
    main()
