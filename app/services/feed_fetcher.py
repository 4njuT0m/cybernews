"""
feed_fetcher.py — Live intelligence feed ingestion.
Sources:
  - The Hacker News RSS (feedparser)
  - SecurityWeek RSS    (feedparser)
  - BleepingComputer    (feedparser)
  - Krebs on Security   (feedparser)
  - Dark Reading        (feedparser)
  - CISA KEV API        (requests → JSON)

Deduplicates by URL. Falls back to mock data when feeds are unreachable.
"""
import logging
import re
from datetime import datetime, timezone
from typing import List, Dict, Any

import feedparser
import requests

logger = logging.getLogger(__name__)

# UPGRADE 1: Expanded RSS Feeds for broader intelligence gathering
RSS_FEEDS = [
    {"url": "https://feeds.feedburner.com/TheHackersNews", "source": "The Hacker News"},
    {"url": "https://www.securityweek.com/feed/",          "source": "SecurityWeek"},
    {"url": "https://www.bleepingcomputer.com/feed/",      "source": "BleepingComputer"},
    {"url": "https://krebsonsecurity.com/feed/",           "source": "Krebs on Security"},
    {"url": "https://www.darkreading.com/rss.xml",         "source": "Dark Reading"},
]

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

SEVERITY_KEYWORDS = {
    "Critical": ["critical", "rce", "remote code execution", "unauthenticated", "cvss 9", "cvss 10", "zero-day", "0-day"],
    "High":     ["high", "privilege escalation", "authentication bypass", "sql injection", "ransomware", "apt"],
    "Medium":   ["medium", "xss", "csrf", "dos", "phishing"],
    "Low":      ["low", "information disclosure", "advisory"],
}

CATEGORY_KEYWORDS = {
    "Vulnerability":  ["cve-", "vulnerability", "patch", "exploit", "rce", "bypass", "injection"],
    "Breach":         ["breach", "leak", "exfiltrat", "stolen", "exposed", "hack"],
    "Threat Actor":   ["apt", "lazarus", "lockbit", "ransomware group", "threat actor", "nation-state"],
    "Malware":        ["malware", "trojan", "backdoor", "rat ", "botnet", "rootkit", "spyware"],
    "Advisory":       ["advisory", "warning", "alert", "cisa", "kev", "catalog"],
    "Supply Chain":   ["supply chain", "npm", "pypi", "open source", "package"],
    "Patch":          ["patch tuesday", "security update", "fixes", "update release"],
}


def _infer_severity(text: str) -> str:
    text_lower = text.lower()
    for severity, keywords in SEVERITY_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            return severity
    return "Medium"


def _infer_category(text: str) -> str:
    text_lower = text.lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            return category
    return "General"


def _extract_cve(text: str):
    match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None


def _parse_date(entry) -> datetime:
    """Parse feedparser date struct into Python datetime (UTC-aware → naive)."""
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        return datetime(*entry.published_parsed[:6])
    return datetime.utcnow()


# ── RSS ─────────────────────────────────────────────────────────────────────

def fetch_rss_feeds() -> List[Dict[str, Any]]:
    articles = []
    for feed_cfg in RSS_FEEDS:
        try:
            logger.info("Fetching RSS: %s", feed_cfg["url"])
            d = feedparser.parse(
                feed_cfg["url"],
                agent="CyberNews/2.0 (+https://cybernews.app)"
            )
            # UPGRADE 2: Reduced to top 10 per feed to protect Gemini API rate limits
            for entry in d.entries[:10]:
                title   = getattr(entry, "title",   "Untitled")
                summary = getattr(entry, "summary", "") or ""
                # Strip HTML tags from summary
                summary = re.sub(r"<[^>]+>", "", summary).strip()[:1000]
                combined = f"{title} {summary}"

                articles.append({
                    "title":        title,
                    "source":       feed_cfg["source"],
                    "url":          getattr(entry, "link", ""),
                    "published_at": _parse_date(entry),
                    "summary":      summary,
                    "severity":     _infer_severity(combined),
                    "category":     _infer_category(combined),
                    "cve_id":       _extract_cve(combined),
                    "raw_content":  summary,
                    "ai_processed": False,
                })
        except Exception as exc:
            logger.error("RSS fetch error (%s): %s", feed_cfg["source"], exc)

    return articles


# ── CISA KEV ────────────────────────────────────────────────────────────────

def fetch_cisa_kev() -> List[Dict[str, Any]]:
    articles = []
    try:
        logger.info("Fetching CISA KEV catalog")
        r = requests.get(CISA_KEV_URL, timeout=15,
                         headers={"User-Agent": "CyberNews/2.0"})
        r.raise_for_status()
        data = r.json()

        # Only last 30 days
        cutoff = datetime.utcnow().replace(tzinfo=None)
        from datetime import timedelta
        cutoff = cutoff - timedelta(days=30)

        for vuln in data.get("vulnerabilities", []):
            try:
                date_added = datetime.strptime(vuln["dateAdded"], "%Y-%m-%d")
            except (KeyError, ValueError):
                date_added = datetime.utcnow()

            if date_added < cutoff:
                continue

            title   = f"CISA KEV: {vuln.get('vulnerabilityName', vuln.get('cveID', 'Unknown'))}"
            summary = vuln.get("shortDescription", "") or ""
            action  = vuln.get("requiredAction", "")
            if action:
                summary += f" Required action: {action}"

            ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")
            severity = "Critical" if ransomware == "Known" else "High"

            url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{vuln.get('cveID','')}"

            articles.append({
                "title":        title[:500],
                "source":       "CISA KEV",
                "url":          url,
                "published_at": date_added,
                "summary":      summary[:1000],
                "severity":     severity,
                "category":     "Vulnerability",
                "cve_id":       vuln.get("cveID"),
                "raw_content":  summary,
                "ai_processed": False,
            })
    except Exception as exc:
        logger.error("CISA KEV fetch error: %s", exc)

    return articles


# ── Upsert to DB ─────────────────────────────────────────────────────────────

def upsert_articles(app, articles: List[Dict[str, Any]]) -> int:
    """Insert articles that don't already exist (by URL). Returns count inserted."""
    saved = 0
    with app.app_context():
        from app import db
        from app.models import NewsArticle
        for a in articles:
            if not a.get("url"):
                continue
            if NewsArticle.query.filter_by(url=a["url"]).first():
                continue  # already exists
            article = NewsArticle(**{k: v for k, v in a.items()
                                     if hasattr(NewsArticle, k)})
            db.session.add(article)
            saved += 1
        try:
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.error("DB upsert error: %s", exc)
            saved = 0
    return saved


def fetch_all_feeds(app) -> int:
    """Fetch all sources and persist new articles. Returns total saved."""
    articles = fetch_rss_feeds() + fetch_cisa_kev()
    saved = upsert_articles(app, articles)
    logger.info("Feed fetch complete: %d new articles saved", saved)
    return saved