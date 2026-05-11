from datetime import datetime
from app import db


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------
class User(db.Model):
    __tablename__ = "users"

    id              = db.Column(db.Integer, primary_key=True)
    username        = db.Column(db.String(80),  unique=True, nullable=False, index=True)
    password_hash   = db.Column(db.String(255), nullable=False)
    role            = db.Column(db.String(30),  nullable=False, default="analyst_l1")
    display_name    = db.Column(db.String(100), nullable=False)
    clearance       = db.Column(db.String(50),  nullable=False, default="Level 1 Analyst")
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    last_login      = db.Column(db.DateTime, nullable=True)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until    = db.Column(db.DateTime, nullable=True)

    assigned_incidents = db.relationship(
        "Incident", back_populates="assignee",
        foreign_keys="Incident.assigned_to_id"
    )

    def is_locked(self):
        return bool(self.locked_until and self.locked_until > datetime.utcnow())

    def to_dict(self):
        return {
            "id":           self.id,
            "username":     self.username,
            "role":         self.role,
            "display_name": self.display_name,
            "clearance":    self.clearance,
            "created_at":   self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


# ---------------------------------------------------------------------------
# NewsArticle
# ---------------------------------------------------------------------------
class NewsArticle(db.Model):
    __tablename__ = "news_articles"

    id            = db.Column(db.Integer, primary_key=True)
    title         = db.Column(db.String(500), nullable=False)
    source        = db.Column(db.String(100), nullable=False, index=True)
    url           = db.Column(db.String(1000), unique=True, nullable=False)
    published_at  = db.Column(db.DateTime, nullable=True, index=True)
    category      = db.Column(db.String(50),  nullable=False, default="General", index=True)
    severity      = db.Column(db.String(20),  nullable=False, default="Medium",  index=True)
    summary       = db.Column(db.Text, nullable=True)
    ai_summary    = db.Column(db.Text, nullable=True)
    raw_content   = db.Column(db.Text, nullable=True)
    epss_score    = db.Column(db.Float, nullable=True)
    cve_id        = db.Column(db.String(30), nullable=True, index=True)
    internal_ip   = db.Column(db.String(100), nullable=True)
    internal_note = db.Column(db.Text, nullable=True)
    fetched_at    = db.Column(db.DateTime, default=datetime.utcnow)
    ai_processed  = db.Column(db.Boolean, default=False, nullable=False, index=True)

    iocs       = db.relationship("IOC",       back_populates="article", cascade="all, delete-orphan")
    mitre_tags = db.relationship("MitreTag",  back_populates="article", cascade="all, delete-orphan")

    def to_dict(self, role: str = "analyst_l1") -> dict:
        redact = role == "analyst_l1"
        return {
            "id":            self.id,
            "title":         self.title,
            "source":        self.source,
            "url":           self.url,
            "date":          self.published_at.strftime("%Y-%m-%d") if self.published_at else "",
            "published_at":  self.published_at.isoformat()          if self.published_at else None,
            "category":      self.category,
            "severity":      self.severity,
            "summary":       self.summary,
            "ai_summary":    self.ai_summary,
            "epss_score":    self.epss_score,
            "cve_id":        self.cve_id,
            "internal_ip":   "[REDACTED]"                          if redact else self.internal_ip,
            "internal_note": "[REDACTED — INSUFFICIENT CLEARANCE]" if redact else self.internal_note,
            "mitre_tags":    [t.to_dict() for t in self.mitre_tags],
            "iocs":          [] if redact else [i.to_dict() for i in self.iocs],
            "fetched_at":    self.fetched_at.isoformat() if self.fetched_at else None,
        }

    def __repr__(self):
        return f"<NewsArticle {self.id}: {self.title[:50]}>"


# ---------------------------------------------------------------------------
# IOC
# ---------------------------------------------------------------------------
class IOC(db.Model):
    __tablename__ = "iocs"

    id         = db.Column(db.Integer, primary_key=True)
    article_id = db.Column(db.Integer, db.ForeignKey("news_articles.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    type       = db.Column(db.String(20),  nullable=False)   # ip | domain | hash | cve | url
    value      = db.Column(db.String(500), nullable=False)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)

    article = db.relationship("NewsArticle", back_populates="iocs")

    __table_args__ = (
        db.UniqueConstraint("article_id", "type", "value", name="uq_ioc"),
    )

    def to_dict(self):
        return {
            "id":         self.id,
            "article_id": self.article_id,
            "type":       self.type,
            "value":      self.value,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
        }

    def __repr__(self):
        return f"<IOC {self.type}:{self.value}>"


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------
class Incident(db.Model):
    __tablename__ = "incidents"

    id             = db.Column(db.Integer, primary_key=True)
    title          = db.Column(db.String(300), nullable=False)
    severity       = db.Column(db.String(20),  nullable=False, default="Medium")
    status         = db.Column(db.String(20),  nullable=False, default="open", index=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    description    = db.Column(db.Text, nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at     = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    assignee = db.relationship("User", back_populates="assigned_incidents",
                               foreign_keys=[assigned_to_id])

    def to_dict(self):
        return {
            "id":          self.id,
            "title":       self.title,
            "severity":    self.severity,
            "status":      self.status,
            "assigned_to": self.assignee.display_name if self.assignee else None,
            "description": self.description,
            "created_at":  self.created_at.isoformat() if self.created_at else None,
            "updated_at":  self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self):
        return f"<Incident {self.id}: {self.title[:40]} [{self.status}]>"


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------
class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id         = db.Column(db.Integer, primary_key=True)
    event      = db.Column(db.String(50),  nullable=False, index=True)
    username   = db.Column(db.String(80),  nullable=False, default="anonymous")
    ip_address = db.Column(db.String(50),  nullable=True)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    extra      = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id":         self.id,
            "event":      self.event,
            "username":   self.username,
            "ip_address": self.ip_address,
            "timestamp":  self.timestamp.isoformat() if self.timestamp else None,
            "extra":      self.extra,
        }

    def __repr__(self):
        return f"<AuditLog {self.event} by {self.username}>"


# ---------------------------------------------------------------------------
# MitreTag
# ---------------------------------------------------------------------------
class MitreTag(db.Model):
    __tablename__ = "mitre_tags"

    id             = db.Column(db.Integer, primary_key=True)
    article_id     = db.Column(db.Integer, db.ForeignKey("news_articles.id", ondelete="CASCADE"),
                               nullable=False, index=True)
    technique_id   = db.Column(db.String(20),  nullable=False)   # e.g. T1059.001
    technique_name = db.Column(db.String(200), nullable=False)
    tactic         = db.Column(db.String(100), nullable=True)     # e.g. Execution
    confidence     = db.Column(db.String(10),  nullable=True, default="medium")
    ai_suggested   = db.Column(db.Boolean, default=True)

    article = db.relationship("NewsArticle", back_populates="mitre_tags")

    def to_dict(self):
        return {
            "technique_id":   self.technique_id,
            "technique_name": self.technique_name,
            "tactic":         self.tactic,
            "confidence":     self.confidence,
            "ai_suggested":   self.ai_suggested,
        }

    def __repr__(self):
        return f"<MitreTag {self.technique_id}>"