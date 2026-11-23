import os
from datetime import timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
_configured_project_roots = os.environ.get("SPLYNTARA_ALLOWED_PROJECT_ROOTS")
_project_roots = (
    _configured_project_roots.split(os.pathsep)
    if _configured_project_roots is not None
    else [str(Path.home())]
)


class Config:
    DATABASE = BASE_DIR / "instance" / "splyntara.db"
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024
    AUTH_ENABLED = True
    ALLOWED_PROJECT_ROOTS = tuple(
        Path(root.strip()).expanduser()
        for root in _project_roots
        if root.strip()
    )
    HISTORY_RETENTION = 50
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Strict"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    LOGIN_RATE_LIMIT_ATTEMPTS = 5
    LOGIN_RATE_LIMIT_WINDOW_SECONDS = 900