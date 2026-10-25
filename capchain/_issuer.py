"""Issuer role: enroll workload keys, then mint tokens for them."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from ._chain import mint
from ._errors import Code
from ._errors import RejectError as Reject
from ._keys import BaseWorkloadKey
from ._proofs import verify_enrollment
from ._scope import MODELS, Model, Scope
from ._storage import (
    EnrollmentStore,
    InMemoryEnrollments,
)
from ._tls import TlsAdapter


def _now(clock: Callable[[], int], override: int | None) -> int:
    if override is None:
        return clock()
    if type(override) is not int or override < 0:
        raise ValueError("now must be a non-negative integer timestamp")
    return override


@dataclass(frozen=True, slots=True)
class EnrolledKey:
    """A workload identity bound to a key thumbprint.

    Returned by `TokenIssuer.enroll`. If enrollment happened on another
    node, reconstruct this from your enrollment store before issuing.
    """

    holder: str
    key_thumbprint: str


class TokenIssuer:
    """Mints root tokens for workloads whose keys are enrolled.

    Enrollment is required in both models: the enrolled key is what
    authorizes delegation, and in KEY_BOUND it also signs every request.
    """

    def __init__(
        self,
        *,
        agent_id: str,
        root_key: BaseWorkloadKey,
        tls: TlsAdapter,
        enrollments: EnrollmentStore | None = None,
        enrollment_max_skew: int = 30,
        clock: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        if not isinstance(agent_id, str) or not agent_id:
            raise ValueError("agent_id must be a non-empty string")
        if root_key.agent_id not in (
            None,
            agent_id,
        ):
            raise ValueError("root key agent_id does not match issuer agent_id")
        if type(enrollment_max_skew) is not int or enrollment_max_skew < 0:
            raise ValueError(
                "enrollment_max_skew must be a non-negative int "
                "(0 means strict; will reject any clock skew on a real fleet)"
            )

        self.agent_id = agent_id
        self._root_key = root_key
        self._tls = tls
        self._enrollments = enrollments if enrollments is not None else InMemoryEnrollments()
        self._skew = enrollment_max_skew
        self._clock = clock

    def enroll(
        self,
        *,
        tls_socket: object,
        proof: bytes,
        now: int | None = None,
    ) -> EnrolledKey:
        """Bind the proved key to the TLS peer identity on this connection."""
        timestamp = _now(self._clock, now)
        peer_id = self._tls.peer_id(tls_socket)
        binding = self._tls.channel_binding(tls_socket)

        key_thumbprint = verify_enrollment(
            proof,
            issuer_id=self.agent_id,
            channel_binding=binding,
            now=timestamp,
            max_skew=self._skew,
        )

        try:
            self._enrollments.add(peer_id, key_thumbprint, timestamp)
        except Reject:
            raise
        except Exception as exc:
            raise Reject(
                Code.STATE_UNAVAILABLE,
                f"enrollment store: {type(exc).__name__}",
            ) from exc

        return EnrolledKey(
            holder=peer_id,
            key_thumbprint=key_thumbprint,
        )

    def issue(
        self,
        *,
        enrolled_key: EnrolledKey,
        session_id: str,
        task: str,
        scope: Scope,
        ttl_seconds: int,
        model: str = Model.KEY_BOUND,
        max_depth: int = 1,
        now: int | None = None,
    ) -> bytes:
        """Mint a token. Enrollment expiry does not revoke issued tokens;
        use the revocation store and keep TTLs short."""
        if not isinstance(enrolled_key, EnrolledKey):
            raise TypeError("enrolled_key must be an EnrolledKey")
        if model not in MODELS:
            raise ValueError(f"unknown model {model!r}")

        timestamp = _now(self._clock, now)

        try:
            self._enrollments.require(
                enrolled_key.holder,
                enrolled_key.key_thumbprint,
                timestamp,
            )
        except Reject:
            raise
        except Exception as exc:
            raise Reject(
                Code.STATE_UNAVAILABLE,
                f"enrollment store: {type(exc).__name__}",
            ) from exc

        return mint(
            self._root_key,
            issuer=self.agent_id,
            holder=enrolled_key.holder,
            cnf=enrolled_key.key_thumbprint,
            session_id=session_id,
            task=task,
            scope=scope,
            ttl_seconds=ttl_seconds,
            now=timestamp,
            model=model,
            max_depth=max_depth,
        ).encode()
