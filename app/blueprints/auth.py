import logging
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
from flask import (Blueprint, flash, jsonify, redirect, render_template,
                   request, session, url_for)

logger  = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__)

MAX_FAILED = 5          # lock account after this many bad passwords
LOCK_MINUTES = 15       # how long the lockout lasts


# ── Decorators ─────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "username" not in session:
                return redirect(url_for("auth.login", next=request.path))
            if session.get("role") not in roles:
                logger.warning("403: user=%s role=%s path=%s",
                               session.get("username"), session.get("role"), request.path)
                return render_template(
                    "error.html", code=403,
                    title="Access Denied",
                    message="Your clearance level is insufficient for this resource.",
                ), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def bearer_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask import current_app
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "Missing Authorization header"}), 401
        token = header.split(" ", 1)[1].strip()
        if token != current_app.config["BEARER_TOKEN"]:
            return jsonify({"error": "Invalid bearer token"}), 403
        return f(*args, **kwargs)
    return decorated


# ── Audit helper ────────────────────────────────────────────────────────────

def write_audit(event: str, username: str = "anonymous", extra: str = ""):
    try:
        from app import db
        from app.models import AuditLog
        db.session.add(AuditLog(
            event=event,
            username=username,
            ip_address=request.remote_addr,
            extra=extra,
        ))
        db.session.commit()
    except Exception as exc:
        logger.error("Audit write failed: %s", exc)


# ── Routes ──────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("news.index"))

    error = None

    if request.method == "POST":
        from app import db
        from app.models import User

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        # Account locked?
        if user and user.is_locked():
            remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60) + 1
            error = f"Account locked. Try again in {remaining} minute(s)."
            write_audit("LOGIN_LOCKED", username)

        elif user and bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            # Success — reset failure counter
            user.failed_attempts = 0
            user.locked_until    = None
            user.last_login      = datetime.utcnow()
            db.session.commit()

            session.permanent    = True
            session["username"]  = user.username
            session["role"]      = user.role
            session["display_name"] = user.display_name
            session["clearance"] = user.clearance

            write_audit("LOGIN_SUCCESS", username)
            logger.info("Login OK: %s from %s", username, request.remote_addr)

            return redirect(request.args.get("next") or url_for("news.index"))

        else:
            # Failed — increment counter, maybe lock
            if user:
                user.failed_attempts += 1
                if user.failed_attempts >= MAX_FAILED:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=LOCK_MINUTES)
                    write_audit("LOGIN_LOCKOUT", username,
                                f"locked for {LOCK_MINUTES} min")
                db.session.commit()

            write_audit("LOGIN_FAILURE", username,
                        f"ip={request.remote_addr}")
            logger.warning("Login FAIL: %s from %s", username, request.remote_addr)
            error = "Invalid credentials. Access denied."

    return render_template("login.html", error=error)


@auth_bp.route("/logout")
def logout():
    username = session.get("username", "anonymous")
    write_audit("LOGOUT", username)
    session.clear()
    return redirect(url_for("auth.login"))