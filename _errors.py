"""Error codes and the single exception type raised by this package."""
from __future__ import annotations

from typing import Optional
from enum import StrEnum
MAX_DETAIL_CHARS = 512


class Code(StrEnum):
    """Stable, machine-readable outcome codes."""

    OK = "OK"
    SETTLED = "SETTLED"

    # Encoding
    CANONICAL_FORM = "CANONICAL_FORM"
    VERSION_UNSUPPORTED = "VERSION_UNSUPPORTED"

    # Token / chain
    TOKEN_MALFORMED = "TOKEN_MALFORMED"
    TOKEN_TOO_LARGE = "TOKEN_TOO_LARGE"
    TOKEN_SIGNATURE = "TOKEN_SIGNATURE"
    TOKEN_NOT_YET_VALID = "TOKEN_NOT_YET_VALID"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    CHAIN_BROKEN = "CHAIN_BROKEN"
    HOLDER_MISMATCH = "HOLDER_MISMATCH"
    CONTEXT_DRIFT = "CONTEXT_DRIFT"
    SCOPE_WIDENED = "SCOPE_WIDENED"
    TOO_DEEP = "TOO_DEEP"
    UNKNOWN_ISSUER = "UNKNOWN_ISSUER"
    MODEL_MISMATCH = "MODEL_MISMATCH"

    # Proof of possession
    POP_REQUIRED = "POP_REQUIRED"
    POP_MALFORMED = "POP_MALFORMED"
    POP_MISMATCH = "POP_MISMATCH"
    POP_BAD_SIGNATURE = "POP_BAD_SIGNATURE"
    POP_STALE = "POP_STALE"
    POP_BINDING = "POP_BINDING"
    CB_MISMATCH = "CB_MISMATCH"

    # Authorization
    POLICY_DENIED = "POLICY_DENIED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    WRONG_HOLDER = "WRONG_HOLDER"
    WRONG_AUDIENCE = "WRONG_AUDIENCE"
    WRONG_SESSION = "WRONG_SESSION"
    WRONG_TASK = "WRONG_TASK"
    NOT_ENROLLED = "NOT_ENROLLED"

    # State
    REVOKED = "REVOKED"
    REPLAY = "REPLAY"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    BUDGET_CAP_CHANGED = "BUDGET_CAP_CHANGED"
    STATE_UNAVAILABLE = "STATE_UNAVAILABLE"
    EVIDENCE_BROKEN = "EVIDENCE_BROKEN"
    INTERNAL = "INTERNAL"


def _printable(text: str) -> str:
    return "".join(c if 0x20 <= ord(c) < 0x7F else "?" for c in text)


class Reject(Exception):
    """Raised for every authorization or protocol failure.

    `code` is stable and safe to branch on. `detail` is sanitized ASCII
    intended for operators, not for callers to parse.
    """

    __slots__ = ("code", "detail")

    def __init__(
        self,
        code: Code,
        detail: str = "",
        *,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = _printable(detail)[:MAX_DETAIL_CHARS]
        if cause is not None:
            self.__cause__ = cause