"""capchain — capability chains for AI agent authorization (wire v2).

Three roles:

    WorkloadKey   a workload's key: enroll it, prove possession, delegate
    TokenIssuer   enroll keys and mint root tokens
    Gateway       authorize an incoming request

Everything else in this package is an implementation detail.

Trust rule: peer identity and channel binding come from the live TLS
socket through a TlsAdapter; session and task come from server-side
state through ServerContext. No authorization input is ever read from
a request header, body, or query parameter.
"""


from __future__ import annotations

from ._chain import attenuate as _attenuate
from ._errors import Code, Reject
from ._evidence import Evidence
from ._gateway import Call, Gateway, Permit, Policy, ServerContext
from ._issuer import EnrolledKey, TokenIssuer
from ._keys import TrustedRoots,BaseWorkloadKey, thumbprint
from ._proofs import make_enrollment, make_proof_of_possession
from ._scope import ANY, Model, Scope
from ._storage import (
    BudgetLedger,
    EnrollmentStore,
    InMemoryBudgetLedger,
    InMemoryEnrollments,
    InMemoryReplayStore,
    InMemoryRevocationStore,
    ReplayStore,
    RevocationStore,
    RedisBudgetLedger,
    RedisEvidenceLog,
    RedisEnrollments,
    RedisReplayStore,
    RedisRevocationStore,
    ReservationState,
    PostgresBudgetLedger,
    PostgresEnrollments,
    PostgresEvidenceLog,
    PostgresReplayStore,
    PostgresRevocationStore,
    InMemoryEvidenceLog,
    Stores,StoreSpec, migrate
)
from ._tls import MutualTlsAdapter, TlsAdapter, channel_binding

from ._wire import  Token  as _Token
import capchain._constants as CONSTANTS
from . import _storage as storage
from ._constants import MAX_STRING_CHARS
  

__version__ = "2.0.0"


class WorkloadKey(BaseWorkloadKey):
    """A workload's Ed25519 key, with the operations a workload performs."""

    __slots__ = ()

    def enrollment_proof(
        self, *, issuer_id: str, channel_binding: bytes, now: int
    ) -> bytes:
        """Prove control of this key to an issuer over the current connection."""
        return make_enrollment(
            self, issuer_id=issuer_id, channel_binding=channel_binding, now=now
        )

    def proof_of_possession(
        self,
        *,
        token: bytes,
        verifier_id: str,
        resource: str,
        action: str,
        body: bytes,
        channel_binding: bytes,
        now: int,
        nonce: str | None = None,
    ) -> bytes:
        """Sign a single-use proof for one request on the current connection."""
        return make_proof_of_possession(
            self,
            token=token,
            verifier_id=verifier_id,
            resource=resource,
            action=action,
            body=body,
            channel_binding=channel_binding,
            now=now,
            nonce=nonce,
        )

    def delegate(
        self,
        token: bytes,
        *,
        holder: str,
        key_thumbprint: str,
        scope: Scope,
        ttl_seconds: int,
        now: int,
    ) -> bytes:
        """Narrow a token and hand it to another workload.

        This key must be the one named by the token's leaf `cnf`.
        """
        return _attenuate(
            _Token.decode(token),
            self,
            holder=holder,
            cnf=key_thumbprint,
            scope=scope,
            ttl_seconds=ttl_seconds,
            now=now,
        ).encode()


def _str_set(name: str, values) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{name} must be an iterable, not a single value")
    try:
        out = frozenset(values)
    except TypeError as e:
        raise ValueError(f"bad {name}") from e
    if not all(
        isinstance(x, str) and 0 < len(x) <= MAX_STRING_CHARS for x in out
    ):
        raise ValueError(f"{name}: non-empty strings only")
    return out


def make_scope(*, tools, budget_micros, audience, domains=()):
    """Build a Scope from iterables. `audience` must be non-empty.

    Argument order matches Scope's field order, so `audience` and
    `domains` are not accidentally swapped.
    """
    return Scope(
        tools=_str_set("tools", tools),
        budget_micros=budget_micros,
        audience=_str_set("audience", audience),
        domains=_str_set("domains", domains),
    )


def make_policy(*, root_issuers, edges, max_depth=4):
    """Build a Policy from iterables.

    `edges` must be an iterable of 2-element (source, target) pairs.
    Strings are rejected rather than unpacked into characters, and
    malformed edges raise instead of being silently dropped, so a typo
    in configuration surfaces as an error instead of a quieter policy.
    """
    if isinstance(edges, (str, bytes)):
        raise ValueError(
            "edges must be an iterable of (source, target) pairs, not a string"
        )

    normalized: set[tuple[str, str]] = set()
    for edge in edges:
        if isinstance(edge, (str, bytes)):
            raise ValueError(
                f"edge must be a (source, target) pair, not a string: {edge!r}"
            )
        try:
            pair = tuple(edge)
        except TypeError as e:
            raise ValueError(f"bad edge {edge!r}: {e}") from e
        if len(pair) != 2:
            raise ValueError(
                f"edge must have exactly 2 elements: {pair!r}"
            )
        source, target = pair
        if not (
            isinstance(source, str)
            and 0 < len(source) <= MAX_STRING_CHARS
            and isinstance(target, str)
            and 0 < len(target) <= MAX_STRING_CHARS
        ):
            raise ValueError(
                f"edge elements must be non-empty strings: {pair!r}"
            )
        normalized.add((source, target))

    return Policy(
        _str_set("root_issuers", root_issuers),
        frozenset(normalized),
        max_depth,
    )






__all__ = [
    # Roles
    "WorkloadKey",
    "TokenIssuer",
    "Gateway",
    # Values
    "TrustedRoots",
    "EnrolledKey",
    "Scope",
    "Policy",
    "ServerContext",
    "Call",
    "Permit",
    "Model",
    "ANY",
    "thumbprint",
    # TLS
    "TlsAdapter",
    "MutualTlsAdapter",
    "channel_binding",
    # Errors
    "Code",
    "Reject",
    # Evidence
    "Evidence",
    "EvidenceStore",
    "InMemoryEvidenceLog",
    # Store protocols and development implementations
    "EnrollmentStore",
    "ReplayStore",
    "BudgetLedger",
    "RevocationStore",
    "InMemoryEnrollments",
    "InMemoryReplayStore",
    "InMemoryBudgetLedger",
    "InMemoryRevocationStore",
    "make_scope", "make_policy",
    "Stores",
    "StoreSpec",
    "migrate",
    "RedisBudgetLedger",
    "RedisEvidenceLog",
    "RedisEnrollments",
    "RedisReplayStore",
    "RedisRevocationStore",
    "ReservationState",
    "PostgresBudgetLedger",
    "PostgresEnrollments",
    "PostgresEvidenceLog",
    "PostgresReplayStore",
    "PostgresRevocationStore",
    "storage",
    "CONSTANTS",
    "__version__",
]
