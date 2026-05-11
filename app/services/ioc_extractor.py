"""
ioc_extractor.py — Extract Indicators of Compromise from article text.
Uses regex patterns as a fast pre-pass before optional Gemini enrichment.
IOC types: ip, cve, hash_md5, hash_sha256, domain, email
"""
import re
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

# Patterns
_PATTERNS = {
    "cve":        re.compile(r"\bCVE-\d{4}-\d{4,7}\b",                  re.IGNORECASE),
    "ip":         re.compile(r"\b(?!10\.\d+\.\d+\.\d+)(?!192\.168\.\d+\.\d+)(?!172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\d{1,3}(?:\.\d{1,3}){3}\b"),
    "hash_md5":   re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "hash_sha256":re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "domain":     re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|gov|edu|ru|cn|de|uk|co)\b",
                             re.IGNORECASE),
}

# Skip list — common false positives
_SKIP_VALUES = {
    "0.0.0.0", "255.255.255.255", "127.0.0.1",
    "example.com", "test.com", "localhost.com",
}


def extract_iocs(text: str) -> List[Dict[str, str]]:
    """Return deduplicated list of {type, value} dicts."""
    if not text:
        return []

    found = []
    seen  = set()

    for ioc_type, pattern in _PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0)
            key   = (ioc_type, value.lower())
            if key in seen or value in _SKIP_VALUES:
                continue
            seen.add(key)
            found.append({"type": ioc_type, "value": value})

    return found


def save_iocs(app, article_id: int, iocs: List[Dict[str, str]]) -> int:
    """Persist IOCs to DB. Skips duplicates. Returns count saved."""
    saved = 0
    with app.app_context():
        from app import db
        from app.models import IOC
        for ioc in iocs:
            exists = IOC.query.filter_by(
                article_id=article_id,
                type=ioc["type"],
                value=ioc["value"],
            ).first()
            if exists:
                continue
            db.session.add(IOC(
                article_id=article_id,
                type=ioc["type"],
                value=ioc["value"],
            ))
            saved += 1
        try:
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.error("IOC save error: %s", exc)
    return saved