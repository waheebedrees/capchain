"""Proof of possession and enrollment envelopes."""
from __future__ import annotations

import hmac
import secrets
from typing import Optional

from . import _canonical as  canonical
from ._errors import Code, Reject
from ._keys import BaseWorkloadKey, thumbprint, verify_signature
from ._wire import  Signed,  is_int
from ._constants import (
    CTX_ENROLL,
    CTX_POP,
    ENROLL_FIELDS,
    MAX_AGENT_ID_CHARS,
    MAX_NONCE_CHARS,
    POP_FIELDS,
    WIRE_VERSION,
    EXPORTER_LENGTH,
    MIN_NONCE_CHARS,
)

def _require_channel_binding(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != EXPORTER_LENGTH:
        raise Reject(Code.CB_MISMATCH, "channel binding required")
    return bytes(value)


def _require_text(value: str, name: str, limit: int) -> str:
    if not isinstance(value, str) or not 0 < len(value) <= limit:
        raise ValueError(f"bad {name}")
    return value


def _check_timestamp(value: object, now: int, max_skew: int) -> None:
    if not is_int(value):
        raise Reject(Code.POP_MALFORMED, "ts")
    if abs(now - value) > max_skew:
        raise Reject(Code.POP_STALE, f"ts={value} now={now}")


def _check_channel_binding(body: dict, expected: object) -> None:
    binding = _require_channel_binding(expected)
    presented = body.get("cb")
    if not isinstance(presented, str) or not hmac.compare_digest(
        presented.encode("ascii", "replace"), canonical.b64e(binding).encode("ascii")
    ):
        raise Reject(Code.CB_MISMATCH, "exporter mismatch")


def make_proof_of_possession(
    key: BaseWorkloadKey,
    *,
    token: bytes,
    verifier_id: str,
    resource: str,
    action: str,
    body: bytes,
    channel_binding: bytes,
    now: int,
    nonce: Optional[str] = None,
) -> bytes:
    """Sign a single-use proof binding this request to this TLS connection."""
    _require_text(verifier_id, "verifier_id", MAX_AGENT_ID_CHARS)
    _require_text(resource, "resource", 128)
    _require_text(action, "action", 128)
    if nonce is not None and not (
        isinstance(nonce, str) and MIN_NONCE_CHARS <= len(nonce) <= MAX_NONCE_CHARS
    ):
        raise ValueError(f"nonce must be {MIN_NONCE_CHARS}..{MAX_NONCE_CHARS} chars")

    binding = _require_channel_binding(channel_binding)
    raw = canonical.encode(
        {
            "ver": WIRE_VERSION,
            "typ": "pop",
            "aud": verifier_id,
            "ath": canonical.sha256_tag(token),
            "res": resource,
            "act": action,
            "ph": canonical.sha256_tag(body),
            "ts": now,
            "nonce": nonce or secrets.token_hex(16),
            "cb": canonical.b64e(binding),
        }
    )
    return Signed(raw, key.sign(CTX_POP, raw), key.public_key).encode()


def verify_proof_of_possession(
    envelope: Signed,
    *,
    cnf: str,
    verifier_id: str,
    token: bytes,
    resource: str,
    action: str,
    body: bytes,
    channel_binding: bytes,
    now: int,
    max_skew: int,
) -> str:
    """Verify a proof and return its nonce for single-use consumption."""
    if thumbprint(envelope.public_key) != cnf:
        raise Reject(Code.POP_MISMATCH, "proof key is not the token cnf")

    verify_signature(
        envelope.public_key,
        envelope.signature,
        CTX_POP,
        envelope.body_raw,
        Code.POP_BAD_SIGNATURE,
        "pop",
    )

    body_fields = canonical.decode(envelope.body_raw)
    if (
        set(body_fields) != POP_FIELDS
        or not is_int(body_fields["ver"])
        or body_fields["ver"] != WIRE_VERSION
        or body_fields["typ"] != "pop"
    ):
        raise Reject(Code.POP_MALFORMED, "shape/ver/typ")

    _check_timestamp(body_fields["ts"], now, max_skew)

    for name, expected in (
        ("aud", verifier_id),
        ("ath", canonical.sha256_tag(token)),
        ("res", resource),
        ("act", action),
        ("ph", canonical.sha256_tag(body)),
    ):
        if body_fields[name] != expected:
            raise Reject(Code.POP_BINDING, name)

    nonce = body_fields["nonce"]
    if not isinstance(nonce, str) or not MIN_NONCE_CHARS <= len(nonce) <= MAX_NONCE_CHARS:
        raise Reject(Code.POP_MALFORMED, "nonce")

    _check_channel_binding(body_fields, channel_binding)
    return nonce


def make_enrollment(
    key: BaseWorkloadKey,
    *,
    issuer_id: str,
    channel_binding: bytes,
    now: int,
) -> bytes:
    """Sign a proof that this workload controls this key on this connection."""
    _require_text(issuer_id, "issuer_id", MAX_AGENT_ID_CHARS)
    raw = canonical.encode(
        {
            "ver": WIRE_VERSION,
            "typ": "enroll",
            "aud": issuer_id,
            "cb": canonical.b64e(_require_channel_binding(channel_binding)),
            "ts": now,
        }
    )
    return Signed(raw, key.sign(CTX_ENROLL, raw), key.public_key).encode()


def verify_enrollment(
    raw: bytes,
    *,
    issuer_id: str,
    channel_binding: bytes,
    now: int,
    max_skew: int = 30,
) -> str:
    """Verify an enrollment proof and return the key thumbprint.

    The caller binds the returned thumbprint to the TLS peer identity; this
    function never sees, and must never be given, a caller-supplied identity.
    """
    envelope = Signed.decode(raw)
    verify_signature(
        envelope.public_key,
        envelope.signature,
        CTX_ENROLL,
        envelope.body_raw,
        Code.POP_BAD_SIGNATURE,
        "enroll",
    )

    body = canonical.decode(envelope.body_raw)
    if (
        set(body) != ENROLL_FIELDS
        or not is_int(body["ver"])
        or body["ver"] != WIRE_VERSION
        or body["typ"] != "enroll"
        or body["aud"] != issuer_id
    ):
        raise Reject(Code.POP_BINDING, "enroll shape/ver/typ/aud")

    _check_timestamp(body["ts"], now, max_skew)
    _check_channel_binding(body, channel_binding)
    return thumbprint(envelope.public_key)