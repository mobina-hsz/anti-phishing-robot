"""Explicit outcomes prevent network failures from becoming safety claims."""

from dataclasses import dataclass, field
from enum import StrEnum


class Status(StrEnum):
    SUSPICIOUS = "suspicious"
    NOT_DETECTED = "not_detected"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class CheckResult:
    status: Status
    reason: str
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class Page:
    url: str
    text: str
    content_type: str = "text/html"


@dataclass(frozen=True)
class ScanResult:
    url: str
    phishing: CheckResult
    keylogger: CheckResult
    elapsed_ms: int
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def status(self) -> Status:
        statuses = {self.phishing.status, self.keylogger.status}
        if Status.SUSPICIOUS in statuses:
            return Status.SUSPICIOUS
        if Status.INCONCLUSIVE in statuses:
            return Status.INCONCLUSIVE
        return Status.NOT_DETECTED
