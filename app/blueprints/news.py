import logging
from flask import Blueprint, render_template, session
from app.blueprints.auth import login_required

logger  = logging.getLogger(__name__)
news_bp = Blueprint("news", __name__)


@news_bp.route("/")
@login_required
def index():
    return render_template(
        "index.html",
        username=session["username"],
        role=session["role"],
        display_name=session["display_name"],
        clearance=session["clearance"],
    )


@news_bp.route("/iocs")
@login_required
def iocs():
    from app import db
    from app.models import IOC, NewsArticle
    role    = session["role"]
    all_iocs = (
        db.session.query(IOC, NewsArticle.title)
        .join(NewsArticle, IOC.article_id == NewsArticle.id)
        .order_by(IOC.first_seen.desc())
        .limit(200)
        .all()
    )
    ioc_list = []
    for ioc, article_title in all_iocs:
        d = ioc.to_dict()
        d["article_title"] = article_title
        # L1 sees type + first_seen but NOT raw value
        if role == "analyst_l1":
            d["value"] = "[REDACTED]"
        ioc_list.append(d)

    return render_template(
        "iocs.html",
        username=session["username"],
        role=role,
        display_name=session["display_name"],
        clearance=session["clearance"],
        iocs=ioc_list,
    )


@news_bp.route("/incidents")
@login_required
def incidents():
    from app.models import Incident
    role      = session["role"]
    query     = Incident.query.order_by(Incident.created_at.desc())
    all_inc   = query.all()
    return render_template(
        "incidents.html",
        username=session["username"],
        role=role,
        display_name=session["display_name"],
        clearance=session["clearance"],
        incidents=[i.to_dict() for i in all_inc],
    )