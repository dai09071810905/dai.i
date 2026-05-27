"""
collect_urls.py  (v3)
衆議院議員の公式URLを収集して urls.json に出力する。

修正点まとめ:
  1. get_members()  : wikitable の td 内リンクだけを対象 /
                      rel="mw:WikiLink" + title 属性で正確に名前取得
  2. extract_official_url(): #外部リンク セレクターのDOM traversal バグを修正 /
                              SNS・Wikipedia ドメインを除外 /
                              infobox の「公式HP」ラベルを優先
  3. get_wiki_page(): 曖昧さ回避判定を class + テキスト両方で確認
  4. try_jimin()   : 複数セレクターで対応
  5. main()        : import json をファイル先頭に移動 / 10件ごと中間保存
  6. 全般          : SKIP_DOMAINS 定数追加 / タイムアウト・エラー処理強化
"""

import re
import json
import time
import urllib.parse
import requests
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; research bot)"}

# SNS・Wikipedia など「公式HPではないドメイン」を除外
SKIP_DOMAINS = (
    "wikipedia.org", "wikimedia.org",
    "twitter.com", "x.com",
    "facebook.com", "instagram.com",
    "youtube.com", "youtu.be",
    "linkedin.com", "ameblo.jp",
    "note.com",
)

# 人名に含まれるはずのない語（部分一致で除外）
SKIP_WORDS = re.compile(
    r"委員|議会|政党|選挙|制度|内閣|大臣|政府|国会|衆議院|参議院"
    r"|裁判|司法|立法|行政|都道府県|市町村|自治|条例|憲法|法律|法案"
    r"|予算|税|補助|公共|政策|改革|連合|同盟|協会|連盟|組合|財団"
    r"|大学|学校|研究|機関|センター|庁|省|局|部|課"
    r"|北海道|青森|岩手|宮城|秋田|山形|福島|茨城|栃木|群馬|埼玉|千葉"
    r"|東京|神奈川|新潟|富山|石川|福井|山梨|長野|岐阜|静岡|愛知|三重"
    r"|滋賀|京都|大阪|兵庫|奈良|和歌山|鳥取|島根|岡山|広島|山口"
    r"|徳島|香川|愛媛|高知|福岡|佐賀|長崎|熊本|大分|宮崎|鹿児島|沖縄"
    r"|ブロック|比例|小選挙区|名簿|選挙区|ファイル"
)

# 人名パターン: 漢字2〜4字 + 漢字1〜4字（姓名）、または漢字3〜6字
NAME_PATTERN = re.compile(
    r'^[一-龥々]{2,4}[\u3000\s]?[一-龥々]{1,4}$'
    r'|^[一-龥々]{3,6}$'
)


# ──────────────────────────────────────────
# Wikipedia 検索 API
# ──────────────────────────────────────────
def search_wikipedia(name: str) -> str | None:
    """名前でWikipediaを検索し、最初にヒットした記事URLを返す。"""
    api_url = "https://ja.wikipedia.org/w/api.php"
    params = {
        "action": "query",
        "list": "search",
        "srsearch": name,
        "format": "json",
        "srlimit": 1,
    }
    try:
        res = requests.get(api_url, params=params, headers=HEADERS, timeout=10)
        data = res.json()
        hits = data.get("query", {}).get("search", [])
        if hits:
            title = hits[0]["title"]
            return f"https://ja.wikipedia.org/wiki/{urllib.parse.quote(title)}"
    except Exception as e:
        print(f"  [search_wikipedia] error: {e}")
    return None


# ──────────────────────────────────────────
# Wikipediaページ取得
# ──────────────────────────────────────────
def get_wiki_page(name: str) -> tuple[str | None, str | None]:
    """
    (wiki_url, html) を返す。
    直接URLが曖昧さ回避ページなら検索にフォールバック。
    取得できない場合は (None, None)。
    """
    direct_url = f"https://ja.wikipedia.org/wiki/{urllib.parse.quote(name)}"
    try:
        res = requests.get(direct_url, headers=HEADERS, timeout=10)
        if res.status_code == 200:
            # 曖昧さ回避ページの判定（class とテキスト両方で確認）
            soup_check = BeautifulSoup(res.text[:8000], "lxml")
            is_disambig = bool(
                soup_check.find(class_="disambiguation")
                or soup_check.find(class_="dmbox-disambig")
                or "曖昧さ回避" in res.text[:4000]
            )
            if not is_disambig:
                return direct_url, res.text
    except Exception as e:
        print(f"  [get_wiki_page] direct fetch error ({name}): {e}")

    # フォールバック: 検索API
    fallback_url = search_wikipedia(name)
    if fallback_url and fallback_url != direct_url:
        try:
            res2 = requests.get(fallback_url, headers=HEADERS, timeout=10)
            if res2.status_code == 200:
                return fallback_url, res2.text
        except Exception as e:
            print(f"  [get_wiki_page] fallback fetch error ({name}): {e}")

    return None, None


# ──────────────────────────────────────────
# 公式URL抽出
# ──────────────────────────────────────────
def extract_official_url(html: str) -> str | None:
    """
    WikipediaページのHTMLから公式URLを抽出する。
    優先順位:
      ① infobox 内の「公式/ホームページ/website」ラベル付きリンク
      ② infobox 内の最初の http リンク（SNS・Wikipedia除外）
      ③ 外部リンクセクションの最初の http リンク（SNS・Wikipedia除外）

    【バグ修正】旧コードの `soup.select("#外部リンク a[href]")` は
    <span id="外部リンク"> の「内側」を探すため一件もヒットしなかった。
    正しくは親 <h2>/<h3> の次の兄弟 <ul> を辿る必要がある。
    """
    soup = BeautifulSoup(html, "lxml")

    def is_valid(href: str) -> bool:
        return (
            href.startswith("http")
            and not any(d in href for d in SKIP_DOMAINS)
        )

    # ① infobox: 「公式」「ホームページ」「website」ラベルを優先
    for row in soup.select("table.infobox tr"):
        th = row.find("th")
        td = row.find("td")
        if not th or not td:
            continue
        label = th.get_text().lower()
        if any(k in label for k in ["公式", "ホームページ", "website", "hp", "ウェブ"]):
            for a in td.find_all("a", href=True):
                href = a["href"]
                if is_valid(href):
                    return href

    # ② infobox: ラベル問わず最初の有効リンク
    for a in soup.select("table.infobox a[href]"):
        href = a.get("href", "")
        if is_valid(href):
            return href

    # ③ 外部リンクセクション（正しい DOM traversal）
    #
    #  Wikipediaの実際のHTML構造:
    #    <h2 id="外部リンク">…</h2>
    #    <ul>
    #      <li><a href="https://...">公式HP</a></li>
    #    </ul>
    #
    #  旧コードの `#外部リンク a[href]` は <span id="外部リンク"> の子を探すため
    #  常に0件だった。h2/h3 の find_next_siblings で <ul> を辿るのが正解。
    for section_id in ["外部リンク", "外部リンク_1", "External_links"]:
        target = soup.find(id=section_id)
        if not target:
            continue
        # id が span に付いているケース: 親 heading に上がる
        heading = (
            target
            if target.name in ["h2", "h3", "h4"]
            else target.find_parent(["h2", "h3", "h4"])
        )
        if not heading:
            continue
        for sibling in heading.find_next_siblings():
            if sibling.name in ["h2", "h3"]:
                break  # 次のセクションに到達したら終了
            if sibling.name in ["ul", "div"]:
                for a in sibling.find_all("a", href=True):
                    href = a["href"]
                    if is_valid(href):
                        return href

    return None


# ──────────────────────────────────────────
# 自民党サイト フォールバック
# ──────────────────────────────────────────
def try_jimin(name: str) -> str | None:
    search_url = f"https://www.jimin.jp/member/?q={urllib.parse.quote(name)}"
    try:
        res = requests.get(search_url, headers=HEADERS, timeout=10)
        if res.status_code != 200:
            return None
        soup = BeautifulSoup(res.text, "lxml")

        for selector in [
            "a.member-link",
            "a.c-member__link",
            ".memberList a[href]",
            ".member-list a[href]",
            # ❌ "article a[href]"  ← 削除: 広すぎてナビリンクを返す
        ]:
            a_tag = soup.select_one(selector)
            if a_tag and a_tag.get("href"):
                href = a_tag["href"]
                if href.startswith("/"):
                    href = "https://www.jimin.jp" + href
                # ✅ URLに /member/ が含まれるか確認してから返す
                if "/member/" in href:
                    return href
    except Exception as e:
        print(f"  [try_jimin] error ({name}): {e}")
    return None


# ──────────────────────────────────────────
# 議員一覧取得
# ──────────────────────────────────────────
def get_members() -> list[dict]:
    """
    Wikipediaの衆議院議員一覧から議員名とWikipedia URLを収集する。

    【修正ポイント】
    旧コード: ページ全体の <a> を走査 → 非議員リンクが大量混入
    新コード: table.wikitable の td 内にある a[rel="mw:WikiLink"] を使う
              title 属性に議員名が直接入っており正確

    実際のHTML構造:
      <table class="wikitable">
        <td>
          <a rel="mw:WikiLink" href="//ja.wikipedia.org/wiki/加藤貴弘"
             title="加藤貴弘">加藤貴弘</a>
        </td>
      </table>
    """
    list_url = "https://ja.wikipedia.org/wiki/衆議院議員一覧"
    try:
        html = requests.get(list_url, headers=HEADERS, timeout=15).text
    except Exception as e:
        print(f"[get_members] fetch error: {e}")
        return []

    soup = BeautifulSoup(html, "lxml")
    members: list[dict] = []
    seen: set[str] = set()

    # wikitable の td 内にある WikiLink だけを対象にする
    # ページ全体リンクを走査する旧方式より精度が大幅に向上
    for a in soup.select('table.wikitable td a[rel="mw:WikiLink"]'):
        title_attr = a.get("title", "").strip()
        href = a.get("href", "")

        if not title_attr or not href:
            continue

        # 名前空間リンク除外（ファイル・カテゴリ・選挙区等）
        if any(ns in title_attr for ns in [
            "ファイル:", "File:", "Template:", "Wikipedia:",
            "Category:", "第", "区",
        ]):
            continue

        # title から曖昧さ回避suffix除去
        # 例: 「鈴木貴子 (政治家)」→「鈴木貴子」
        name = re.split(r'[\s　（(]', title_attr)[0].strip()

        # 人名パターンチェック
        if not NAME_PATTERN.match(name):
            continue

        # 除外ワードチェック
        if SKIP_WORDS.search(name):
            continue

        # 重複除外
        if name in seen:
            continue
        seen.add(name)

        # URL正規化
        if href.startswith("//"):
            wiki_url = "https:" + href
        elif href.startswith("/wiki/"):
            wiki_url = "https://ja.wikipedia.org" + href
        else:
            continue

        members.append({"name": name, "wiki": wiki_url})

    print(f"議員候補数: {len(members)}")
    return members


# ──────────────────────────────────────────
# メイン
# ──────────────────────────────────────────
def main():
    import sys

    members = get_members()
    if not members:
        print("ERROR: 議員リストの取得に失敗しました。", file=sys.stderr)
        sys.exit(1)

    results: list[dict] = []
    total = len(members)

    for i, member in enumerate(members, 1):
        name = member["name"]
        wiki_url = member["wiki"]
        print(f"[{i}/{total}] {name} ...")

        wiki_url_actual, html = get_wiki_page(name)
        if not html:
            print(f"  → Wikipediaページ取得失敗, スキップ")
            time.sleep(0.5)
            continue

        official_url = extract_official_url(html)

        # フォールバック: 自民党サイト
        if not official_url:
            official_url = try_jimin(name)

        if official_url:
            print(f"  → {official_url}")
            results.append({
                "name": name,
                "wiki": wiki_url_actual or wiki_url,
                "official": official_url,
            })
        else:
            print(f"  → 公式URL見つからず")

        # 10件ごとに中間保存（途中クラッシュ対策）
        if i % 10 == 0:
            with open("urls.json", "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"  ── チェックポイント保存: {len(results)} 件 ──")

        time.sleep(0.8)  # Wikipedia へのレートリミット

    # 最終保存
    with open("urls.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"\n完了: {len(results)} / {total} 件の公式URLを収集しました。")
    print("出力: urls.json")

    # 0件なら CI にエラーを通知
    if not results:
        print("ERROR: 公式URLが1件も収集できませんでした。", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
