"""Validated configuration loaded only when the application starts."""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent


def integer(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class Settings:
    token: str = ""
    admin_ids: frozenset[int] = frozenset()
    request_timeout: int = 10
    scan_timeout: int = 40
    max_concurrent_scans: int = 3
    max_urls_per_message: int = 3
    user_cooldown_seconds: int = 5
    max_external_scripts: int = 4
    max_response_bytes: int = 1048576
    monitor_db: Path = ROOT / "data/monitor.sqlite3"
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv(ROOT / ".env", override=False)
        token = os.getenv("BOT_TOKEN", "").strip()
        if not token or token == "replace_with_a_new_bot_token":
            raise ValueError("Set BOT_TOKEN in .env or the process environment")
        try:
            admins = frozenset(
                int(item.strip()) for item in os.getenv("ADMIN_IDS", "").split(",") if item.strip()
            )
        except ValueError as exc:
            raise ValueError("ADMIN_IDS must contain numeric Telegram user IDs") from exc
        if any(item <= 0 for item in admins):
            raise ValueError("ADMIN_IDS must contain positive Telegram user IDs")
        db = Path(os.getenv("MONITOR_DB", "data/monitor.sqlite3"))
        level = os.getenv("LOG_LEVEL", "INFO").upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
            raise ValueError("LOG_LEVEL must be DEBUG, INFO, WARNING, or ERROR")
        return cls(
            token=token,
            admin_ids=admins,
            request_timeout=integer("REQUEST_TIMEOUT", 10, 1, 60),
            scan_timeout=integer("SCAN_TIMEOUT", 40, 5, 180),
            max_concurrent_scans=integer("MAX_CONCURRENT_SCANS", 3, 1, 20),
            max_urls_per_message=integer("MAX_URLS_PER_MESSAGE", 3, 1, 10),
            user_cooldown_seconds=integer("USER_COOLDOWN_SECONDS", 5, 1, 300),
            max_external_scripts=integer("MAX_EXTERNAL_SCRIPTS", 4, 0, 10),
            max_response_bytes=integer("MAX_RESPONSE_BYTES", 1048576, 4096, 4194304),
            monitor_db=db if db.is_absolute() else ROOT / db,
            log_level=level,
        )
