import logging
from flask import Blueprint, jsonify, render_template, request, session
from app.blueprints.auth import role_required, write_audit

logger   = logging.getLogger(__name__)
admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/dashboard")
@role_required("admin")
def dashboard():
    from app.models import User, NewsArticle, AuditLog, Incident

    users       = User.query.order_by(User.role).all()
    news        = NewsArticle.query.order_by(NewsArticle.published_at.desc()).limit(100).all()
    audit_lines = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    incidents   = Incident.query.order_by(Incident.created_at.desc()).limit(20).all()

    return render_template(
        "admin.html",
        username=session["username"],
        role=session["role"],
        display_name=session["display_name"],
        clearance=session["clearance"],
        users=[u.to_dict() for u in users],
        news=[n.to_dict(role="admin") for n in news],
        audit_lines=[a.to_dict() for a in audit_lines],
        incidents=[i.to_dict() for i in incidents],
    )


@admin_bp.route("/reports", methods=["POST"])
@role_required("admin")
def add_report():
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

    # Prevent duplicate URLs
    url = data.get("url") or f"https://cybernews.internal/{data['title'][:40].replace(' ','-')}"
    if NewsArticle.query.filter_by(url=url).first():
        url = url + f"-{int(datetime.utcnow().timestamp())}"

    try:
        pub_date = datetime.strptime(data["date"], "%Y-%m-%d")
    except ValueError:
        pub_date = datetime.utcnow()

    article = NewsArticle(
        title         = data["title"],
        source        = data["source"],
        url           = url,
        published_at  = pub_date,
        category      = data["category"],
        severity      = data["severity"],
        summary       = data["summary"],
        internal_ip   = data.get("internal_ip", ""),
        internal_note = data.get("internal_note", ""),
        ai_processed  = False,
    )
    db.session.add(article)
    db.session.commit()
    write_audit("ADD_REPORT", session.get("username"), f"title={data['title'][:60]}")

    return jsonify({"success": True, "report": article.to_dict(role="admin")}), 201


@admin_bp.route("/reports/<int:report_id>", methods=["DELETE"])
@role_required("admin")
def delete_report(report_id: int):
    from app import db
    from app.models import NewsArticle

    article = NewsArticle.query.get(report_id)
    if not article:
        return jsonify({"error": "Not found"}), 404

    db.session.delete(article)
    db.session.commit()
    write_audit("DELETE_REPORT", session.get("username"), f"id={report_id}")
    return jsonify({"success": True})


@admin_bp.route("/incidents", methods=["POST"])
@role_required("admin", "analyst_l2")
def create_incident():
    from app import db
    from app.models import Incident

    data = request.get_json(force=True, silent=True)
    if not data or not data.get("title"):
        return jsonify({"error": "title is required"}), 400

    inc = Incident(
        title       = data["title"],
        severity    = data.get("severity", "Medium"),
        status      = data.get("status", "open"),
        description = data.get("description", ""),
    )
    db.session.add(inc)
    db.session.commit()
    write_audit("CREATE_INCIDENT", session.get("username"), f"title={data['title'][:60]}")
    return jsonify({"success": True, "incident": inc.to_dict()}), 201


@admin_bp.route("/incidents/<int:inc_id>", methods=["PATCH"])
@role_required("admin", "analyst_l2")
def update_incident(inc_id: int):
    from app import db
    from app.models import Incident

    inc  = Incident.query.get(inc_id)
    if not inc:
        return jsonify({"error": "Not found"}), 404

    data = request.get_json(force=True, silent=True) or {}
    if "status"      in data: inc.status      = data["status"]
    if "severity"    in data: inc.severity    = data["severity"]
    if "description" in data: inc.description = data["description"]
    db.session.commit()
    write_audit("UPDATE_INCIDENT", session.get("username"), f"id={inc_id}")
    return jsonify({"success": True, "incident": inc.to_dict()})