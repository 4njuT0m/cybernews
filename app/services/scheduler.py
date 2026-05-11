"""
scheduler.py — Background job runner using APScheduler.
Runs inside the Flask process, not as a separate service.

Jobs:
  - fetch_and_process(): Every N minutes — fetch feeds + run AI
  - Gunicorn safety: uses a DB advisory lock so only one worker runs the job
"""
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger    = logging.getLogger(__name__)
_scheduler = None


def _job(app):
    """The main background job. Wrapped in app context."""
    with app.app_context():
        # Advisory lock: only one Gunicorn worker runs this at a time
        from app import db
        import sqlalchemy
        try:
            result = db.session.execute(
                sqlalchemy.text("SELECT pg_try_advisory_lock(12345)")
            ).scalar()
            if not result:
                logger.debug("Scheduler: another worker holds the lock — skipping")
                return
        except Exception:
            # SQLite doesn't support advisory locks — just run the job
            pass

        try:
            logger.info("Scheduler: starting feed fetch")
            from app.services.feed_fetcher import fetch_all_feeds
            saved = fetch_all_feeds(app)
            logger.info("Scheduler: %d new articles saved", saved)

            logger.info("Scheduler: starting AI processing")
            from app.services.gemini_service import process_unanalyzed_articles
            max_per_run = app.config.get("SCHEDULER_MAX_ARTICLES_PER_RUN", 10)
            processed = process_unanalyzed_articles(app, max_articles=max_per_run)
            logger.info("Scheduler: %d articles AI-processed", processed)

        except Exception as exc:
            logger.error("Scheduler job error: %s", exc)

        finally:
            # Release advisory lock
            try:
                db.session.execute(sqlalchemy.text("SELECT pg_advisory_unlock(12345)"))
                db.session.commit()
            except Exception:
                pass


def start_scheduler(app):
    global _scheduler

    if _scheduler is not None and _scheduler.running:
        logger.debug("Scheduler already running — skipping start")
        return

    interval_minutes = app.config.get("SCHEDULER_INTERVAL_MINUTES", 30)

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        func=_job,
        args=[app],
        trigger=IntervalTrigger(minutes=interval_minutes),
        id="feed_fetch_job",
        name="Fetch feeds + AI process",
        replace_existing=True,
        max_instances=1,
    )
    _scheduler.start()
    logger.info("Scheduler started — interval: %d min", interval_minutes)

    # Run immediately on startup (in a thread so it doesn't block startup)
    import threading
    t = threading.Thread(target=_job, args=[app], daemon=True)
    t.start()