"""Canonical encodings. Exactly one byte sequence per signed object."""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from ._errors import Code, Reject
from ._constants import (
    MAX_STRING_CHARS,   
    MAX_LIST_ITEMS,
    MAX_OBJECT_KEYS,
    MAX_KEY_CHARS,
    MAX_NESTING,
    MAX_INT
)

def _reject_float(text: str) -> None:
    raise Reject(Code.CANONICAL_FORM, f"floats not permitted: {text!r}")

def _reject_constant(text: str) -> None:
    raise Reject(Code.CANONICAL_FORM, f"non-finite: {text!r}")

def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise Reject(Code.CANONICAL_FORM, f"duplicate key: {key!r}")
        seen.add(key)
    return dict(pairs)


def _has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in text)


def _bounded_int(s: str) -> int:
    if len(s.lstrip("-")) > 16:
        raise Reject(Code.CANONICAL_FORM, "integer too large")
    n = int(s)
    if abs(n) > MAX_INT:
        raise Reject(Code.CANONICAL_FORM, "integer out of safe range")
    return n


def _validate(value: Any, depth: int = 0) -> None:
    if depth > MAX_NESTING:
        raise Reject(Code.CANONICAL_FORM, "nesting too deep")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_INT:
            raise Reject(Code.CANONICAL_FORM, "integer out of safe range")
        return
    if isinstance(value, float):
        raise Reject(Code.CANONICAL_FORM, "float")
    if isinstance(value, str):
        if len(value) > MAX_STRING_CHARS:
            raise Reject(Code.CANONICAL_FORM, "string too long")
        if _has_surrogate(value):
            raise Reject(Code.CANONICAL_FORM, "unpaired surrogate")
        return
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_LIST_ITEMS:
            raise Reject(Code.CANONICAL_FORM, "list too long")
        for item in value:
            _validate(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > MAX_OBJECT_KEYS:
            raise Reject(Code.CANONICAL_FORM, "object too large")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > MAX_KEY_CHARS:
                raise Reject(Code.CANONICAL_FORM, "bad key")
            if _has_surrogate(key):
                raise Reject(Code.CANONICAL_FORM, "surrogate in key")
            _validate(item, depth + 1)
        return
    raise Reject(Code.CANONICAL_FORM,
                 f"unserialisable {type(value).__name__}")


def encode(obj: dict) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, integers only."""
    _validate(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def decode(raw: bytes) -> dict:
    """Parse canonical JSON, rejecting any non-canonical spelling."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Reject(Code.CANONICAL_FORM, f"utf8: {exc}") from None
    try:
        obj = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
            parse_int=_bounded_int
        )
    except Reject:
        raise
    except Exception as exc:
        raise Reject(Code.CANONICAL_FORM, f"json: {exc}") from None
    if not isinstance(obj, dict):
        raise Reject(Code.CANONICAL_FORM, "not an object")
    if encode(obj) != raw:
        raise Reject(Code.CANONICAL_FORM, "not canonical")
    return obj


def loads_strict(raw: bytes) -> Any:
    """Envelope parser. Canonicality is enforced by re-encoding the result."""
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_reject_duplicates,
        parse_float=_reject_float,
        parse_constant=_reject_constant,
        parse_int=_bounded_int

    )


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64d(text: str) -> bytes:
    if not isinstance(text, str):
        raise Reject(Code.CANONICAL_FORM, "b64 input must be str")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:
        raise Reject(Code.CANONICAL_FORM, f"b64: {exc}") from None
    if b64e(raw) != text:
        raise Reject(Code.CANONICAL_FORM, "non-canonical b64")
    return raw


def sha256_tag(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(bytes(data)).hexdigest()