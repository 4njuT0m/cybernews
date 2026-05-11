import logging
from flask import Blueprint, jsonify, request, session
from app.blueprints.auth import bearer_required, write_audit

logger = logging.getLogger(__name__)
api_bp = Blueprint("api", __name__)


# ── Session-authenticated (browser fetch() calls) ──────────────────────────

def _require_session():
    """Return (None, None) if session OK, else (response, code)."""
    if "username" not in session:
        return jsonify({"error": "Authentication required"}), 401
    return None, None


@api_bp.route("/news")
def get_news():
    """
    GET /api/news
    Filters: ?category= &severity= &source= &q= &date_from= &date_to=
    Clearance redaction applied server-side.
    """
    err, code = _require_session()
    if err:
        return err, code

    from app.models import NewsArticle
    role = session.get("role", "analyst_l1")

    query = NewsArticle.query

    cat  = request.args.get("category", "")
    sev  = request.args.get("severity", "")
    src  = request.args.get("source",   "")
    q    = request.args.get("q",        "").strip()
    dfrom = request.args.get("date_from", "")
    dto   = request.args.get("date_to",   "")

    if cat:  query = query.filter(NewsArticle.category.ilike(cat))
    if sev:  query = query.filter(NewsArticle.severity.ilike(sev))
    if src:  query = query.filter(NewsArticle.source.ilike(src))
    if q:
        like = f"%{q}%"
        query = query.filter(
            NewsArticle.title.ilike(like) | NewsArticle.summary.ilike(like)
        )
    if dfrom:
        from datetime import datetime
        try:
            query = query.filter(NewsArticle.published_at >= datetime.strptime(dfrom, "%Y-%m-%d"))
        except ValueError:
            pass
    if dto:
        from datetime import datetime
        try:
            query = query.filter(NewsArticle.published_at <= datetime.strptime(dto, "%Y-%m-%d"))
        except ValueError:
            pass

    articles = query.order_by(NewsArticle.published_at.desc()).limit(100).all()
    return jsonify([a.to_dict(role=role) for a in articles])


@api_bp.route("/stats")
def get_stats():
    err, code = _require_session()
    if err:
        return err, code

    from app.models import NewsArticle, IOC, Incident
    total    = NewsArticle.query.count()
    critical = NewsArticle.query.filter_by(severity="Critical").count()
    high     = NewsArticle.query.filter_by(severity="High").count()
    sources  = len(set(
        r[0] for r in NewsArticle.query.with_entities(NewsArticle.source).distinct().all()
    ))
    ioc_count = IOC.query.count()
    open_inc  = Incident.query.filter_by(status="open").count()

    return jsonify({
        "total":       total,
        "critical":    critical,
        "high":        high,
        "sources":     sources,
        "ioc_count":   ioc_count,
        "open_incidents": open_inc,
    })


@api_bp.route("/iocs")
def get_iocs():
    err, code = _require_session()
    if err:
        return err, code

    from app.models import IOC
    role     = session.get("role", "analyst_l1")
    ioc_type = request.args.get("type", "")

    query = IOC.query
    if ioc_type:
        query = query.filter(IOC.type.ilike(ioc_type))

    iocs = query.order_by(IOC.first_seen.desc()).limit(200).all()
    result = []
    for ioc in iocs:
        d = ioc.to_dict()
        if role == "analyst_l1":
            d["value"] = "[REDACTED]"
        result.append(d)
    return jsonify(result)


@api_bp.route("/news/<int:news_id>", methods=["DELETE"])
def delete_news(news_id: int):
    err, code = _require_session()
    if err:
        return err, code
    if session.get("role") != "admin":
        return jsonify({"error": "Admin role required"}), 403

    from app import db
    from app.models import NewsArticle
    article = NewsArticle.query.get(news_id)
    if not article:
        return jsonify({"error": "Not found"}), 404

    db.session.delete(article)
    db.session.commit()
    write_audit("DELETE_NEWS", session.get("username"), f"id={news_id}")
    return jsonify({"success": True})


# ── Bearer-token-protected (external scripts) ──────────────────────────────

@api_bp.route("/admin/reports", methods=["GET"])
@bearer_required
def bearer_get_reports():
    from app.models import NewsArticle
    articles = NewsArticle.query.order_by(NewsArticle.published_at.desc()).all()
    return jsonify({"count": len(articles), "reports": [a.to_dict(role="admin") for a in articles]})


@api_bp.route("/admin/reports", methods=["POST"])
@bearer_required
def bearer_add_report():
    from datetime import datetime
    from app import db
    from app.models import NewsArticle

    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    required = ["title", "source", "date", "category", "severity", "summary"]
    missing  = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing: {', '.join(missing)}"}), 400

    url = data.get("url") or f"https://api.cybernews/{int(datetime.utcnow().timestamp())}"
    if NewsArticle.query.filter_by(url=url).first():
        url += f"-{int(datetime.utcnow().timestamp())}"

    try:
        pub = datetime.strptime(data["date"], "%Y-%m-%d")
    except ValueError:
        pub = datetime.utcnow()

    article = NewsArticle(
        title=data["title"], source=data["source"], url=url,
        published_at=pub, category=data["category"],
        severity=data["severity"], summary=data["summary"],
        internal_ip=data.get("internal_ip",""),
        internal_note=data.get("internal_note",""),
        ai_processed=False,
    )
    db.session.add(article)
    db.session.commit()
    return jsonify({"success": True, "id": article.id}), 201


@api_bp.route("/admin/reports/<int:report_id>", methods=["DELETE"])
@bearer_required
def bearer_delete_report(report_id: int):
    from app import db
    from app.models import NewsArticle
    article = NewsArticle.query.get(report_id)
    if not article:
        return jsonify({"error": "Not found"}), 404
    db.session.delete(article)
    db.session.commit()
    return jsonify({"success": True})


# ── Health check — no auth ─────────────────────────────────────────────────

@api_bp.route("/health")
def health():
    from app import db
    import sqlalchemy
    ok = False
    try:
        db.session.execute(sqlalchemy.text("SELECT 1"))
        ok = True
    except Exception:
        pass
    return jsonify({"status": "ok" if ok else "degraded", "database": "connected" if ok else "unreachable"}), (200 if ok else 503)