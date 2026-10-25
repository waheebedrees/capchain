"""Workload keys and the root trust anchor."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
from collections.abc import Iterable, Mapping
from pathlib import Path

from cryptography.exceptions import (
    InvalidSignature,
)
from cryptography.hazmat.primitives import (
    serialization,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._canonical import b64e
from ._constants import (
    HEX,
    PRIVATE_SEED_BYTES,
    PUBLIC_KEY_BYTES,
    THUMBPRINT_HEX_CHARS,
)
from ._errors import RejectError as Reject


def save_raw(path: Path, data: bytes, mode: int) -> None:
    """Write `data` to `path` atomically with the given mode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    import tempfile

    fd, tmp = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=f".{path.name}.",
    )
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        elif mode != 0o600:
            os.chmod(tmp, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        try:
            dfd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def thumbprint(public_key: bytes) -> str:
    """SHA-256 of a raw Ed25519 public key, lowercase hex."""
    if not isinstance(public_key, bytes) or len(public_key) != PUBLIC_KEY_BYTES:
        raise ValueError(f"public key must be {PUBLIC_KEY_BYTES} raw bytes")
    return hashlib.sha256(public_key).hexdigest()


def spki_thumbprint(pub: bytes) -> str:
    """Lowercase hex sha256 of a 32-byte raw public key (R4).

    A module-level function, not a  method: a derived value
    on an interface is a divergence bug waiting to happen.

    Preconditions:  `pub` is exactly PUBLIC_KEY_BYTES bytes.
    Postconditions: returns THUMBPRINT_HEX_CHARS lowercase hex chars.
    Raises:         ValueError on wrong-length input.  This is a
                    programming error on an in-memory value, not a
                    Reject: Reject is for untrusted input and for
                    boundary failures, and this is neither.
    """
    return thumbprint(pub)


def is_thumbprint(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == THUMBPRINT_HEX_CHARS
        and all(c in HEX for c in value)
    )


def domain_separate(context: str | bytes, message: bytes) -> bytes:
    if isinstance(context, str):
        context = context.encode("ascii")
    return context + b"\x00" + message


def verify_signature(
    public_key: bytes,
    signature: bytes,
    context: str | bytes,
    message: bytes,
    code: str,
    detail: str,
) -> None:
    """Verify an Ed25519 signature under a domain-separation context."""
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            domain_separate(context, message),
        )
    except (InvalidSignature, ValueError):
        raise Reject(code, detail) from None


class BaseWorkloadKey:
    """An Ed25519 key belonging to one workload.

    Generate at boot and enroll it, or load a 32-byte seed from secure
    storage for a long-lived root. `agent_id` is optional metadata; the
    binding that matters is `thumbprint == parent block's cnf`.
    """

    __slots__ = (
        "_private",
        "_public",
        "_thumbprint",
        "agent_id",
    )

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        agent_id: str | None = None,
    ) -> None:
        self._private = private_key
        self._public = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self._thumbprint = thumbprint(self._public)
        self.agent_id = agent_id

    @classmethod
    def generate(cls, *, agent_id: str | None = None) -> BaseWorkloadKey:
        return cls(
            Ed25519PrivateKey.generate(),
            agent_id=agent_id,
        )

    @classmethod
    def from_seed(
        cls,
        seed: bytes,
        *,
        agent_id: str | None = None,
    ) -> BaseWorkloadKey:
        if not isinstance(seed, bytes) or len(seed) != PRIVATE_SEED_BYTES:
            raise ValueError(f"seed must be {PRIVATE_SEED_BYTES} bytes")
        return cls(
            Ed25519PrivateKey.from_private_bytes(seed),
            agent_id=agent_id,
        )

    @property
    def public_key(self) -> bytes:
        return self._public

    @property
    def thumbprint(self) -> str:
        """The value that appears as `cnf` in a token block."""
        return self._thumbprint

    def sign(self, context: str, message: bytes) -> bytes:
        """Internal: sign under a domain-separation context."""
        return self._private.sign(domain_separate(context, message))

    def __repr__(self) -> str:
        return f"WorkloadKey(agent_id={self.agent_id!r}, thumbprint={self._thumbprint[:16]}...)"


class TrustedRoots:
    """Root issuer IDs mapped to their raw Ed25519 public keys.

    This is the only key material a gateway needs. Intermediate workloads
    are authenticated by the chain itself.
    """

    __slots__ = ("_by_thumbprint",)

    def __init__(
        self,
        issuers: Mapping[str, bytes | Iterable[bytes]],
    ) -> None:
        self._by_thumbprint: dict[str, tuple[str, bytes]] = {}

        for issuer_id, keys in issuers.items():
            if not isinstance(issuer_id, str) or not issuer_id:
                raise ValueError("issuer ID must be a non-empty string")

            key_list = [keys] if isinstance(keys, (bytes, bytearray)) else list(keys)
            if not key_list:
                raise ValueError(f"{issuer_id}: at least one key required")

            for key in key_list:
                if not isinstance(key, (bytes, bytearray)):
                    raise ValueError(f"{issuer_id}: keys must be raw bytes")
                raw = bytes(key)
                if len(raw) != PUBLIC_KEY_BYTES:
                    raise ValueError(f"{issuer_id}: key must be {PUBLIC_KEY_BYTES} bytes")
                kid = thumbprint(raw)
                existing = self._by_thumbprint.get(kid)
                if existing is not None and existing[0] != issuer_id:
                    raise ValueError(f"key bound to both {existing[0]} and {issuer_id}")
                self._by_thumbprint[kid] = (
                    issuer_id,
                    raw,
                )

    def issuer_for(self, public_key: bytes) -> str | None:
        entry = self._by_thumbprint.get(thumbprint(public_key))
        if entry is None or not hmac.compare_digest(entry[1], public_key):
            return None
        return entry[0]

    def as_wire_config(
        self,
    ) -> dict[str, list[str]]:
        """Base64 view, for writing config files or logs."""
        out: dict[str, list[str]] = {}
        for (
            issuer_id,
            raw,
        ) in self._by_thumbprint.values():
            out.setdefault(issuer_id, []).append(b64e(raw))
        return out
