"""
gemini_service.py — AI enrichment via Google Gemini.
One API call per article returns: ai_summary, severity, iocs[], mitre_tags[].
Gracefully degrades to rule-based fallback when GEMINI_API_KEY is not set.
Rate-limited to 14 requests/min (free tier is 15).
"""
import json
import logging
import re
import time
from typing import Dict, Any

logger = logging.getLogger(__name__)

MITRE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

PROMPT_TEMPLATE = """You are a cybersecurity analyst. Analyze the following article and respond ONLY with a valid JSON object. No markdown, no backticks, no explanation — raw JSON only.

Article title: {title}
Article summary: {summary}

Return exactly this JSON schema:
{{
  "ai_summary": "2-3 sentence analyst summary of the threat",
  "severity": "one of: Critical | High | Medium | Low",
  "iocs": [
    {{"type": "cve|ip|domain|hash_md5|hash_sha256", "value": "the IOC value"}}
  ],
  "mitre_tags": [
    {{
      "technique_id": "T1234 or T1234.001",
      "technique_name": "name of the technique",
      "tactic": "one of the 14 MITRE tactics",
      "confidence": "high|medium|low"
    }}
  ]
}}

MITRE tactics allowed: {tactics}
Keep iocs list to clearly identified indicators only. Keep mitre_tags to 1-3 most relevant techniques.
"""


def _fallback_analysis(title: str, summary: str) -> Dict[str, Any]:
    """Rule-based analysis when Gemini is unavailable."""
    from app.services.feed_fetcher import _infer_severity, _infer_category, _extract_cve
    text = f"{title} {summary}"
    sev  = _infer_severity(text)
    cve  = _extract_cve(text)

    iocs = []
    if cve:
        iocs.append({"type": "cve", "value": cve})

    return {
        "ai_summary":  f"{sev} severity intelligence report. {summary[:200]}",
        "severity":    sev,
        "iocs":        iocs,
        "mitre_tags":  [],
    }


def analyze_article(title: str, summary: str, api_key: str) -> Dict[str, Any]:
    """
    Send one article to Gemini. Returns structured analysis dict.
    Falls back to rule-based analysis on any error.
    """
    if not api_key:
        logger.debug("No GEMINI_API_KEY — using fallback analysis")
        return _fallback_analysis(title, summary)

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model  = genai.GenerativeModel("gemini-1.5-flash")
        prompt = PROMPT_TEMPLATE.format(
            title=title[:300],
            summary=summary[:800],
            tactics=", ".join(MITRE_TACTICS),
        )
        response = model.generate_content(prompt)
        raw      = response.text.strip()

        # Strip markdown fences if Gemini wraps JSON in ```json ... ```
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$",          "", raw)

        result = json.loads(raw)

        # Validate required keys
        for key in ("ai_summary", "severity", "iocs", "mitre_tags"):
            if key not in result:
                raise ValueError(f"Missing key: {key}")

        # Normalise severity
        if result["severity"] not in ("Critical", "High", "Medium", "Low"):
            result["severity"] = "Medium"

        return result

    except Exception as exc:
        logger.warning("Gemini error (%s): %s — using fallback", title[:40], exc)
        return _fallback_analysis(title, summary)


def process_unanalyzed_articles(app, max_articles: int = 10) -> int:
    """
    Find articles where ai_processed=False, send to Gemini, save results.
    Respects 14 req/min rate limit with 4-second sleep between calls.
    Returns count processed.
    """
    processed = 0
    with app.app_context():
        from app import db
        from app.models import NewsArticle, IOC, MitreTag
        from app.services.ioc_extractor import extract_iocs, save_iocs

        api_key  = app.config.get("GEMINI_API_KEY", "")
        articles = (NewsArticle.query
                    .filter_by(ai_processed=False)
                    .order_by(NewsArticle.published_at.desc())
                    .limit(max_articles)
                    .all())

        for article in articles:
            try:
                result = analyze_article(
                    article.title,
                    article.summary or article.title,
                    api_key,
                )

                # Update article
                article.ai_summary   = result.get("ai_summary")
                article.severity     = result.get("severity", article.severity)
                article.ai_processed = True

                # Save AI-extracted IOCs
                for ioc_data in result.get("iocs", []):
                    if ioc_data.get("value"):
                        exists = IOC.query.filter_by(
                            article_id=article.id,
                            type=ioc_data["type"],
                            value=ioc_data["value"],
                        ).first()
                        if not exists:
                            db.session.add(IOC(
                                article_id=article.id,
                                type=ioc_data.get("type", "unknown"),
                                value=ioc_data["value"],
                            ))

                # Save MITRE tags
                for tag in result.get("mitre_tags", []):
                    if tag.get("technique_id"):
                        db.session.add(MitreTag(
                            article_id     = article.id,
                            technique_id   = tag["technique_id"],
                            technique_name = tag.get("technique_name", ""),
                            tactic         = tag.get("tactic", ""),
                            confidence     = tag.get("confidence", "medium"),
                            ai_suggested   = True,
                        ))

                # Also run regex IOC extraction
                regex_iocs = extract_iocs(f"{article.title} {article.summary or ''}")
                for ioc_data in regex_iocs:
                    exists = IOC.query.filter_by(
                        article_id=article.id,
                        type=ioc_data["type"],
                        value=ioc_data["value"],
                    ).first()
                    if not exists:
                        db.session.add(IOC(
                            article_id=article.id,
                            type=ioc_data["type"],
                            value=ioc_data["value"],
                        ))

                db.session.commit()
                processed += 1
                logger.info("AI processed: [%d] %s", article.id, article.title[:50])

                # Rate limiting: 4 sec between Gemini calls
                if api_key:
                    time.sleep(4)

            except Exception as exc:
                db.session.rollback()
                logger.error("Failed to process article %d: %s", article.id, exc)
                # Mark as processed to avoid infinite retry on broken articles
                try:
                    article.ai_processed = True
                    db.session.commit()
                except Exception:
                    db.session.rollback()

    return processed