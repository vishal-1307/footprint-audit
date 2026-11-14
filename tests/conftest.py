from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Set before app.main is imported so SessionMiddleware gets a stable key.
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("APP_PASSWORD", "test-password")
os.environ.setdefault("SECURE_COOKIES", "0")
os.environ.setdefault("SCAN_CONCURRENCY", "2")

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture()
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_PATH", str(db_path))
    from app import db

    db.init_db(db_path)
    return db_path
