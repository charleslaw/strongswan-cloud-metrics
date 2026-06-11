import logging
import os
import sqlite3
import time

from . import config

logger = logging.getLogger(__name__)


def init_db():
    os.makedirs(config.STATE_DIR, exist_ok=True)
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS interventions (
                id       INTEGER PRIMARY KEY,
                ts       REAL    NOT NULL,
                ike_key  TEXT    NOT NULL,
                child_sa TEXT    NOT NULL,
                action   TEXT    NOT NULL DEFAULT 'initiate',
                outcome  TEXT
            )
        """)


def last_reinit_ts(child_sa):
    """Returns unix timestamp of the most recent reinit for child_sa, or None."""
    try:
        with sqlite3.connect(config.DB_PATH) as conn:
            row = conn.execute(
                "SELECT ts FROM interventions WHERE child_sa = ? "
                "ORDER BY ts DESC LIMIT 1",
                (child_sa,),
            ).fetchone()
        return row[0] if row else None
    except Exception as exc:
        logger.error("DB read failed: %s", exc)
        return None


def record_reinit(ike_key, child_sa):
    try:
        with sqlite3.connect(config.DB_PATH) as conn:
            conn.execute(
                "INSERT INTO interventions (ts, ike_key, child_sa) VALUES (?, ?, ?)",
                (time.time(), ike_key, child_sa),
            )
    except Exception as exc:
        logger.error("DB write failed: %s", exc)


def last_service_restart_ts():
    """Returns unix timestamp of the most recent service restart, or None."""
    try:
        with sqlite3.connect(config.DB_PATH) as conn:
            row = conn.execute(
                "SELECT ts FROM interventions WHERE action = 'service_restart' "
                "ORDER BY ts DESC LIMIT 1"
            ).fetchone()
        return row[0] if row else None
    except Exception as exc:
        logger.error("DB read failed: %s", exc)
        return None


def record_service_restart():
    try:
        with sqlite3.connect(config.DB_PATH) as conn:
            conn.execute(
                "INSERT INTO interventions (ts, ike_key, child_sa, action) VALUES (?, ?, ?, ?)",
                (time.time(), "__service__", "__service__", "service_restart"),
            )
    except Exception as exc:
        logger.error("DB write failed: %s", exc)
