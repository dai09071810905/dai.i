#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import concurrent.futures, datetime as dt, json, re, socket, ssl
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

OUT_FILE = Path("data.json")
USER_AGENT = "DietCertDashboard/1.0 (+GitHub Actions)"
TIMEOUT = 20
MAX_ENRICH_WORKERS = 12
MAX_SCAN_WORKERS = 20
HEADERS = {"User-Agent": USER_AGENT}
session = requests.Session()
session.headers.update(HEADERS)
GS_KEYWORDS = ["globalsign", "global sign", "gmo globalsign"]
SITE_SEAL_PATTERNS = [r"globalsign", r"siteseal", r"sslpr", r"secure site seal", r"実在証明・盗聴対策シール"]
PARTY_NORMALIZATION = {
    "自民":"自由民主党","自由民主":"自由民主党","自由民主党":"自由民主党",
    "立民":"立憲民主党","立憲":"立憲民主党","立憲民主":"立憲民主党","立憲民主党":"立憲民主党",
    "維新":"日本維新の会","日本維新":"日本維新の会","日本維新の会":"日本維新の会",
    "公明":"公明党","公明党":"公明党",
    "国民":"国民民主党","国民民主":"国民民主党","国民民主党":"国民民主党",
    "共産":"日本共産党","日本共産":"日本共産党","日本共産党":"日本共産党",
    "れいわ":"れいわ新選組","れいわ新選組":"れいわ新選組",
    "参政":"参政党","参政党":"参政党",
    "社民":"社会民主党","社会民主党":"社会民主党",
    "保守":"日本保守党","日本保守党":"日本保守党",
    "無所属":"無所属","無":"無所属",
}
@dataclass
class Member:
    chamber:str; name:str; party:str
    wikipedia_title:Optional[str]=None; wikipedia_url:Optional[str]=None; official_url:Optional[str]=None
@dataclass
class ScanResult:
