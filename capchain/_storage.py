"""State protocols and single-process implementations.

The in-memory classes are for development and tests. Production deployments
must supply durable, shared implementations (Postgres, Redis) of the same
protocols; otherwise replay protection and budgets are per-process only.
Storage backends for capchain, selected by type.

    stores = Stores.open("memory")                        # one process, tests
    stores = Stores.open("redis", redis_url=...)          # all five in Redis
    stores = Stores.open("database", postgres_dsn=...)    # all five in PostgreSQL
    stores = Stores.from_env()                            # per-store type

Production, when more than one gateway process is running:

    replay=redis  revocation=redis  enrollments=redis
    ledger=postgres  evidence=postgres

Only the issuer and the gateways open a Stores. Agent containers do not:
delegation and proof-of-possession are signatures, not database calls.

    Gateway(..., **stores.as_gateway_kwargs())
    TokenIssuer(..., **stores.as_issuer_kwargs())

Env:
    CAPCHAIN_ENV=production          memory is refused; Redis policy is checked
    CAPCHAIN_STORE=redis             default type for every store
    CAPCHAIN_STORE_REPLAY=redis      override one store (also LEDGER,
    CAPCHAIN_STORE_LEDGER=postgres     REVOCATION, EVIDENCE, ENROLLMENTS)
    CAPCHAIN_REDIS_URL=redis://redis:6379/0
    CAPCHAIN_POSTGRES_DSN=postgresql://capchain@postgres/capchain
    CAPCHAIN_REDIS_PREFIX=capchain
    CAPCHAIN_POSTGRES_SCHEMA=capchain
    CAPCHAIN_REPLAY_TTL=300          must be > 2 x PoP skew
    CAPCHAIN_ENROLL_TTL=3600
    CAPCHAIN_ENROLL_MAX_PER_PEER=8

Redis: maxmemory-policy noeviction. A Redis ledger also needs AOF
(appendonly yes); PostgreSQL is the ledger you want.
"""

from __future__ import annotations
from typing import Callable, Optional
import re
import os
import logging
import hashlib
import redis.exceptions
import redis

import threading
import uuid
from dataclasses import dataclass


import json

import threading
from typing import Optional, Protocol, TypeVar, Any

from contextlib import contextmanager
import uuid
import time


from ._constants import GENESIS_HASH, BudgetPath
from ._chain import is_thumbprint
from ._errors import Reject, Code
from ._evidence import Evidence
from . import _canonical as canonical


_log = logging.getLogger("capchain.store")

_TYPES = {"memory", "sqlite", "postgres", "redis"}
_ALIASES = {
    "mem": "memory", "memory": "memory",
    "redis": "redis",
    "postgres": "postgres", "postgresql": "postgres",
    "database": "postgres", "db": "postgres",
}
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_GENESIS = "0" * 64
_SOCKET_TIMEOUT = 5.0
_STATEMENT_TIMEOUT_MS = 5000


def _kind(value: str) -> str:
    kind = _ALIASES.get(value.strip().lower())
    if kind is None:
        raise ValueError(
            f"unknown store type {value!r}; use memory, database, or redis")
    return kind


def _ident(name: str, value: str) -> str:
    if not _IDENT.fullmatch(value):
        raise ValueError(f"bad {name}")
    return value


def _now() -> int:
    return int(time.time())


def _budget_tag(cid: str) -> str:
    return hashlib.sha256(cid.encode()).hexdigest()[:16]


def _replay_key(prefix: str, key: tuple[str, ...]) -> str:
    body = ":".join(f"{len(part)}:{part}" for part in key)
    return f"{prefix}:replay:{body}"


@dataclass(frozen=True, slots=True)
class StoreSpec:
    type: str
    redis_url: Optional[str] = None
    postgres_dsn: Optional[str] = None
    prefix: str = "capchain"
    schema: str = "capchain"
    ttl_seconds: Optional[int] = None
    max_per_peer: int = 8


class ReservationState:
    RESERVED = "reserved"
    DISPATCHED = "dispatched"
    SETTLED = "settled"
    CANCELLED = "cancelled"


@dataclass(slots=True)
class SpendHandle:
    cid: str
    amount: int
    handle: str
    path: BudgetPath
    state: str = ReservationState.RESERVED


class EnrollmentStore(Protocol):
    """Bindings from workload identity to enrolled key thumbprint."""

    def add(self, peer_id: str, key_thumbprint: str, now: int) -> None: ...
    def require(self, peer_id: str, key_thumbprint: str, now: int) -> None: ...


class ReplayStore(Protocol):
    """Single-use nonce store. `ttl_seconds` must exceed 2x the PoP skew."""

    @property
    def ttl_seconds(self) -> int: ...
    def consume(self, key: tuple[str, ...], now: int) -> bool: ...


class BudgetLedger(Protocol):
    def reserve(
        self, cid: str, root_cap: int, path: BudgetPath, amount: int,
        *,
        expires_at: Optional[int] = None,
        now: Optional[int] = None,
    ) -> Optional[SpendHandle]: ...


    def mark_dispatched(self, handle: SpendHandle) -> None: ...
    def settle(self, handle: SpendHandle, actual: int) -> None: ...
    def commit(self, handle: SpendHandle) -> None: ...
    def refund(self, handle: SpendHandle) -> None: ...
    def remaining(self, cid: str) -> int: ...


class RevocationStore(Protocol):
    def find_revoked(
        self,
        *,
        agents: tuple[str, ...] = (),
        kids: tuple[str, ...] = (),
        cids: tuple[str, ...] = (),
        jtis: tuple[str, ...] = (),
    ) -> Optional[tuple[str, str]]: ...


class EvidenceStore(Protocol):
    def append(self, draft: dict) -> Evidence: ...
    def verify_integrity(self) -> bool: ...
    def records(self) -> tuple[Evidence, ...]: ...


class InMemoryEnrollments:
    """Development enrollment store with a fixed TTL."""

    def __init__(self, ttl_seconds: int = 3600) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ttl = ttl_seconds
        self._entries: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()

    def add(self, peer_id: str, key_thumbprint: str, now: int) -> None:
        with self._lock:
            self._entries[(peer_id, key_thumbprint)] = now + self._ttl

    def require(self, peer_id: str, key_thumbprint: str, now: int) -> None:
        with self._lock:
            expires_at = self._entries.get((peer_id, key_thumbprint))
        if expires_at is None or expires_at <= now:
            raise Reject(Code.NOT_ENROLLED,
                         "key not enrolled for this identity")


class InMemoryReplayStore:
    """Development nonce store. Not shared across processes."""

    def __init__(self, ttl_seconds: int = 300) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ttl = ttl_seconds
        self._live: dict[tuple[str, ...], int] = {}
        self._lock = threading.Lock()

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def consume(self, key: tuple[str, ...], now: int) -> bool:
        with self._lock:
            if len(self._live) > 10_000:
                self._live = {k: e for k, e in self._live.items() if e > now}
            expires_at = self._live.get(key)
            if expires_at is not None and expires_at > now:
                return False
            self._live[key] = now + self._ttl
            return True


class InMemoryBudgetLedger:
    """Development ledger. Enforces root and per-hop caps under one lock.

    Entries for a `cid` are evicted once its recorded `expires_at` has
    passed and no spend for that `cid` is outstanding, so the ledger does
    not grow without bound in a long-lived process. Eviction is
    opportunistic — triggered inside `reserve` when the cid table
    exceeds `EVICT_ABOVE` — so no background sweeper is required.

    Once a chain's leaf has expired, `verify_chain` rejects any token for
    that `cid`, so eviction cannot race a future reserve. The
    `_outstanding` check prevents eviction from breaking an in-flight
    permit whose `settle`/`commit`/`refund` still needs the row.
    """

    EVICT_ABOVE: int = 10_000
    """Sweep when the cid table exceeds this many entries."""

    def __init__(self) -> None:
        self._root_cap: dict[str, int] = {}
        self._remaining: dict[str, int] = {}
        self._hop_cap: dict[tuple[str, str], int] = {}
        self._hop_spent: dict[tuple[str, str], int] = {}
        self._outstanding: dict[str, SpendHandle] = {}
        self._expires_at: dict[str, int] = {}
        self._lock = threading.Lock()

    def _purge_locked(self, now: int) -> int:
        """Drop every expired cid with no outstanding spend. Caller holds
        the lock. Returns the number of cids evicted."""
        outstanding_cids = {h.cid for h in self._outstanding.values()}
        dead = [
            cid for cid, exp in self._expires_at.items()
            if exp <= now and cid not in outstanding_cids
        ]
        if not dead:
            return 0
        for cid in dead:
            self._expires_at.pop(cid, None)
            self._root_cap.pop(cid, None)
            self._remaining.pop(cid, None)
        live = self._root_cap.keys()
        self._hop_cap = {k: v for k,
                         v in self._hop_cap.items() if k[0] in live}
        self._hop_spent = {
            k: v for k, v in self._hop_spent.items() if k[0] in live
        }
        return len(dead)

    def purge_expired(self, now: int) -> int:
        """Explicit sweep. Returns cids evicted. Optional — `reserve`
        calls this opportunistically on its own."""
        with self._lock:
            return self._purge_locked(now)

    def remaining(self, cid: str) -> int:
        with self._lock:
            return self._remaining.get(cid, 0)

    def reserve(
        self, cid: str, root_cap: int, path: BudgetPath, amount: int,
        *, expires_at: Optional[int] = None, now: Optional[int] = None,
    ) -> Optional[SpendHandle]:
        if amount < 0 or root_cap < 0 or not path:
            raise ValueError("bad reserve arguments")

        with self._lock:
            if now is not None and len(self._root_cap) > self.EVICT_ABOVE:
                self._purge_locked(now)

            existing = self._root_cap.get(cid)
            if existing is None:
                self._root_cap[cid] = root_cap
                self._remaining[cid] = root_cap
                if expires_at is not None:
                    self._expires_at[cid] = expires_at
            elif existing != root_cap:
                raise Reject(Code.BUDGET_CAP_CHANGED, f"cid {cid}")

            if self._remaining[cid] < amount:
                return None

            for jti, cap in path:
                recorded = self._hop_cap.get((cid, jti))
                if recorded is None:
                    self._hop_cap[(cid, jti)] = cap
                elif recorded != cap:
                    raise Reject(Code.BUDGET_CAP_CHANGED, f"jti {jti}")
                if self._hop_spent.get((cid, jti), 0) + amount > cap:
                    return None

            self._remaining[cid] -= amount
            for jti, _ in path:
                self._hop_spent[(cid, jti)] = self._hop_spent.get(
                    (cid, jti), 0) + amount

            handle = SpendHandle(
                cid=cid, amount=amount, handle=uuid.uuid4().hex, path=path
            )
            self._outstanding[handle.handle] = handle
            return handle

    def mark_dispatched(self, handle: SpendHandle) -> None:
        with self._lock:
            record = self._outstanding.get(handle.handle)
            if record is None or record.state != ReservationState.RESERVED:
                raise Reject(Code.INTERNAL, "dispatch from invalid state")
            record.state = handle.state = ReservationState.DISPATCHED

    def settle(self, handle: SpendHandle, actual: int) -> None:
        if type(actual) is not int or actual < 0:
            raise Reject(Code.INTERNAL, "actual must be a non-negative int")

        with self._lock:
            record = self._outstanding.get(handle.handle)
            if record is None:
                raise Reject(Code.INTERNAL, "settle: handle not found")
            if record.state != ReservationState.DISPATCHED:
                raise Reject(
                    Code.INTERNAL,
                    f"settle from {record.state}; call mark_dispatched first",
                )

            delta = actual - record.amount
            if delta != 0:
                if self._remaining[record.cid] - delta < 0:
                    raise Reject(Code.BUDGET_EXHAUSTED, "root cap on settle")
                updated: dict[tuple[str, str], int] = {}
                for jti, cap in record.path:
                    spent = self._hop_spent.get((record.cid, jti), 0) + delta
                    if spent < 0 or spent > cap:
                        raise Reject(Code.BUDGET_EXHAUSTED,
                                     f"hop {jti} on settle")
                    updated[(record.cid, jti)] = spent
                self._remaining[record.cid] -= delta
                self._hop_spent.update(updated)
                record.amount = actual

            record.state = ReservationState.SETTLED
            handle.amount, handle.state = record.amount, record.state

    def commit(self, handle: SpendHandle) -> None:
        with self._lock:
            self._outstanding.pop(handle.handle, None)

    def refund(self, handle: SpendHandle) -> None:
        with self._lock:
            record = self._outstanding.get(handle.handle)
            if record is None or record.state != ReservationState.RESERVED:
                return
            self._outstanding.pop(handle.handle, None)
            self._remaining[record.cid] = (
                self._remaining.get(record.cid, 0) + record.amount
            )
            for jti, _ in record.path:
                key = (record.cid, jti)
                self._hop_spent[key] = max(
                    0, self._hop_spent.get(key, 0) - record.amount)
            handle.state = ReservationState.CANCELLED


class InMemoryRevocationStore:
    """Development revocation store."""

    def __init__(self) -> None:
        self._agents: set[str] = set()
        self._kids: set[str] = set()
        self._cids: set[str] = set()
        self._jtis: set[str] = set()
        self._lock = threading.Lock()

    def revoke_agent(self, agent_id: str) -> None:
        with self._lock:
            self._agents.add(agent_id)

    def revoke_key(self, key_thumbprint: str) -> None:
        with self._lock:
            self._kids.add(key_thumbprint)

    def revoke_chain(self, cid: str) -> None:
        with self._lock:
            self._cids.add(cid)

    def revoke_token(self, jti: str) -> None:
        with self._lock:
            self._jtis.add(jti)

    def find_revoked(
        self,
        *,
        agents: tuple[str, ...] = (),
        kids: tuple[str, ...] = (),
        cids: tuple[str, ...] = (),
        jtis: tuple[str, ...] = (),
    ) -> Optional[tuple[str, str]]:
        with self._lock:
            for kind, candidates, revoked in (
                ("agent", agents, self._agents),
                ("kid", kids, self._kids),
                ("cid", cids, self._cids),
                ("jti", jtis, self._jtis),
            ):
                for candidate in candidates:
                    if candidate in revoked:
                        return (kind, candidate)
        return None


class InMemoryEvidenceLog:
    """Development evidence log. Use an append-only durable store in production."""

    def __init__(self) -> None:
        self._head = GENESIS_HASH
        self._records: list[Evidence] = []
        self._lock = threading.Lock()

    def append(self, draft: dict) -> Evidence:
        with self._lock:
            record = Evidence(
                prev_hash=self._head,
                **{k: v for k, v in draft.items() if k != "prev_hash"},
            )
            self._records.append(record)
            self._head = record.digest()
            return record

    def verify_integrity(self) -> bool:
        with self._lock:
            previous = GENESIS_HASH
            for record in self._records:
                if record.prev_hash != previous:
                    return False
                previous = record.digest()
            return previous == self._head

    def records(self) -> tuple[Evidence, ...]:
        with self._lock:
            return tuple(self._records)


def _check_redis(clients: _Clients, env: str) -> None:
    for client in clients._redis.values():
        try:
            policy = client.config_get("maxmemory-policy").get(
                "maxmemory-policy", "noeviction")
        except Exception as e:
            if env == "production":
                raise RuntimeError(
                    "cannot verify Redis maxmemory-policy") from e
            _log.warning("capchain: Redis policy check skipped: %s",
                         type(e).__name__)
            continue
        if policy != "noeviction":
            raise RuntimeError(
                f"Redis maxmemory-policy is {policy!r}; capchain requires "
                f"noeviction (evicting a nonce or a revocation fails open)")
        if env == "production":
            info = client.info("persistence")
            if not info.get("aof_enabled"):
                _log.warning("capchain: Redis AOF is off; do not use this "
                             "Redis as the budget ledger")


@dataclass
class Stores:
    replay: ReplayStore
    ledger: BudgetLedger
    revocation: RevocationStore
    evidence: EvidenceStore
    enrollments: EnrollmentStore
    env: str
    _close: Callable[[], None]

    @classmethod
    def open(cls, type: str = "memory", *,
             redis_url: Optional[str] = None,
             postgres_dsn: Optional[str] = None,
             replay: Optional[str] = None,
             ledger: Optional[str] = None,
             revocation: Optional[str] = None,
             evidence: Optional[str] = None,
             enrollments: Optional[str] = None,
             env: Optional[str] = None,
             prefix: str = "capchain",
             schema: str = "capchain",
             replay_ttl: int = 300,
             enroll_ttl: int = 3600,
             enroll_max_per_peer: int = 8) -> "Stores":
        """`type` is the default. Pass ledger='database' to override one."""
        def spec(override: Optional[str], ttl: Optional[int]) -> StoreSpec:
            return StoreSpec(
                type=_kind(override or type),
                redis_url=redis_url, postgres_dsn=postgres_dsn,
                prefix=prefix, schema=_ident("schema", schema),
                ttl_seconds=ttl, max_per_peer=enroll_max_per_peer)
        return cls._build(
            replay=spec(replay, replay_ttl),
            ledger=spec(ledger, None),
            revocation=spec(revocation, None),
            evidence=spec(evidence, None),
            enrollments=spec(enrollments, enroll_ttl),
            env=env or os.environ.get("CAPCHAIN_ENV", "development"))

    @classmethod
    def from_env(cls) -> "Stores":
        default = os.environ.get("CAPCHAIN_STORE", "memory")
        redis_url = os.environ.get("CAPCHAIN_REDIS_URL")
        dsn = os.environ.get("CAPCHAIN_POSTGRES_DSN")
        prefix = os.environ.get("CAPCHAIN_REDIS_PREFIX", "capchain")
        schema = os.environ.get("CAPCHAIN_POSTGRES_SCHEMA", "capchain")
        max_per_peer=int(os.environ.get("CAPCHAIN_ENROLL_MAX_PER_PEER", "8"))
        def one(name: str, ttl_env: str,
                default_ttl: Optional[int]) -> StoreSpec:
            # ttl_env is explicit; the store's TTL variable name does not
            # always match its store name (see ENROLL below).
            raw_ttl = os.environ.get(ttl_env)
            ttl = int(raw_ttl) if raw_ttl is not None else default_ttl
            
            spec = StoreSpec(
                type=_kind(os.environ.get(f"CAPCHAIN_STORE_{name}", default)),
                redis_url=os.environ.get(
                    f"CAPCHAIN_{name}_REDIS_URL", redis_url),
                postgres_dsn=os.environ.get(
                    f"CAPCHAIN_{name}_POSTGRES_DSN", dsn),
                prefix=prefix, schema=_ident("schema", schema),
                ttl_seconds=ttl,
                max_per_peer=max_per_peer
            )
            return spec
        return cls._build(
            replay=one("REPLAY", "CAPCHAIN_REPLAY_TTL", 300),
            ledger=one("LEDGER", "CAPCHAIN_LEDGER_TTL", None),
            revocation=one("REVOCATION", "CAPCHAIN_REVOCATION_TTL", None),
            evidence=one("EVIDENCE", "CAPCHAIN_EVIDENCE_TTL", None),
            enrollments=one("ENROLLMENTS", "CAPCHAIN_ENROLL_TTL", 3600),
            env=os.environ.get("CAPCHAIN_ENV", "development"))

    @classmethod
    def _build(cls, *, replay: StoreSpec, ledger: StoreSpec,
               revocation: StoreSpec, evidence: StoreSpec,
               enrollments: StoreSpec, env: str) -> "Stores":
        specs = (("replay", replay), ("ledger", ledger),
                 ("revocation", revocation), ("evidence", evidence),
                 ("enrollments", enrollments))
        if env == "production":
            for name, spec in specs:
                if spec.type == "memory":
                    raise RuntimeError(
                        f"{name}: memory is process-local and is refused "
                        f"when CAPCHAIN_ENV=production")
        clients = _Clients()
        try:
            built = cls(
                replay=_open_replay(replay, clients),
                ledger=_open_ledger(ledger, clients),
                revocation=_open_revocation(revocation, clients),
                evidence=_open_evidence(evidence, clients),
                enrollments=_open_enrollments(enrollments, clients),
                env=env, _close=clients.close)
            built.ping()
            _check_redis(clients, env)
        except BaseException:
            # Any client opened before the failure must be closed,
            # otherwise a crash-loop leaks fds against healthy backends.
            clients.close()
            raise
        _log.info("capchain stores env=%s replay=%s ledger=%s "
                  "revocation=%s evidence=%s enrollments=%s",
                  env, replay.type, ledger.type, revocation.type,
                  evidence.type, enrollments.type)
        if ledger.type == "redis":
            _log.warning("capchain: Redis ledger survives only its AOF "
                         "window; prefer database for the ledger")
        if evidence.type == "redis":
            _log.warning("capchain: Redis evidence is not an insert-only "
                         "log; prefer database for evidence")
        return built

    def as_gateway_kwargs(self) -> dict:
        return {"ledger": self.ledger, "replay": self.replay,
                "revocation": self.revocation, "evidence": self.evidence}

    def as_issuer_kwargs(self) -> dict:
        return {"enrollments": self.enrollments}

    def ping(self) -> None:
        for store in (self.replay, self.ledger, self.revocation,
                      self.evidence, self.enrollments):
            ping = getattr(store, "ping", None)
            if ping is not None:
                ping()

    def close(self) -> None:
        self._close()

    def __enter__(self) -> "Stores":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class _Clients:
    def __init__(self) -> None:
        self._redis: dict[str, object] = {}
        self.pg: dict[str, object] = {}
        self._redis_urls: list[str] = []

    def redis(self, url: Optional[str], prefix: str) -> tuple[object, str]:
        if not url:
            raise ValueError(
                "redis store requires redis_url / CAPCHAIN_REDIS_URL")
        client = self._redis.get(url)
        if client is None:
            try:
                import redis
            except ImportError as e:
                raise RuntimeError("pip install 'redis>=5'") from e
            client = redis.Redis.from_url(
                url, decode_responses=True,
                socket_timeout=_SOCKET_TIMEOUT,
                health_check_interval=30)
            self._redis[url] = client
            self._redis_urls.append(url)
        return client, prefix

    def pool(self, dsn: Optional[str], schema: str) -> object:
        if not dsn:
            raise ValueError(
                "database store requires postgres_dsn / CAPCHAIN_POSTGRES_DSN")
        key = dsn + "\0" + schema
        pool = self.pg.get(key)
        if pool is None:
            try:
                from psycopg_pool import ConnectionPool
            except ImportError as e:
                raise RuntimeError(
                    "pip install 'psycopg[binary]>=3.1' 'psycopg-pool>=3.2'") from e
            pool = ConnectionPool(
                dsn, min_size=1, max_size=8, timeout=_SOCKET_TIMEOUT,
                kwargs={"autocommit": False,
                        "options": f"-c search_path={schema}"},
                open=True)
            self.pg[key] = pool
        return pool

    def close(self) -> None:
        for client in self._redis.values():
            client.close()
        for pool in self.pg.values():
            pool.close()
        self._redis.clear()
        self.pg.clear()


def _open_replay(spec: StoreSpec, clients: _Clients) -> object:
    ttl = spec.ttl_seconds or 300
    if spec.type == "memory":
        try:
            return InMemoryReplayStore(ttl_seconds=ttl)
        except TypeError:
            return InMemoryReplayStore(ttl_seconds=ttl)
    if spec.type == "redis":
        client, prefix = clients.redis(spec.redis_url, spec.prefix)
        return RedisReplayStore(client, ttl_seconds=ttl, prefix=prefix)
    return PostgresReplayStore(clients.pool(spec.postgres_dsn, spec.schema),
                               ttl_seconds=ttl)


def _open_ledger(spec: StoreSpec, clients: _Clients) -> object:
    if spec.type == "memory":
        return InMemoryBudgetLedger()
    if spec.type == "redis":
        client, prefix = clients.redis(spec.redis_url, spec.prefix)
        return RedisBudgetLedger(client, prefix=prefix)
    return PostgresBudgetLedger(clients.pool(spec.postgres_dsn, spec.schema))


def _open_revocation(spec: StoreSpec, clients: _Clients) -> object:
    if spec.type == "memory":
        return InMemoryRevocationStore()
    if spec.type == "redis":
        client, prefix = clients.redis(spec.redis_url, spec.prefix)
        return RedisRevocationStore(client, prefix=prefix)
    return PostgresRevocationStore(clients.pool(spec.postgres_dsn, spec.schema))


def _open_evidence(spec: StoreSpec, clients: _Clients) -> object:
    if spec.type == "memory":
        return InMemoryEvidenceLog()
    if spec.type == "redis":
        client, prefix = clients.redis(spec.redis_url, spec.prefix)
        return RedisEvidenceLog(client, prefix=prefix)
    return PostgresEvidenceLog(clients.pool(spec.postgres_dsn, spec.schema))


def _open_enrollments(spec: StoreSpec, clients: _Clients) -> object:
    ttl = spec.ttl_seconds or 3600
    if spec.type == "memory":
        return InMemoryEnrollments(ttl_seconds=ttl)
    if spec.type == "redis":
        client, prefix = clients.redis(spec.redis_url, spec.prefix)
        return RedisEnrollments(client, ttl_seconds=ttl,
                                max_per_peer=spec.max_per_peer, prefix=prefix)
    return PostgresEnrollments(clients.pool(spec.postgres_dsn, spec.schema),
                               ttl_seconds=ttl, max_per_peer=spec.max_per_peer)


def _dump_path(path: tuple) -> str:
    return json.dumps([[j, c] for j, c in path], separators=(",", ":"))


def _load_path(raw: str) -> tuple:
    return tuple((j, int(c)) for j, c in json.loads(raw))


def _check_path(path: tuple) -> tuple:
    if not path:
        raise ValueError("empty budget path")
    jtis = [j for j, _ in path]
    if len(jtis) != len(set(jtis)):
        raise ValueError("duplicate jti in budget path")
    return tuple(sorted(path, key=lambda item: item[0]))


def _budget_tag(cid: str) -> str:
    return hashlib.sha256(cid.encode()).hexdigest()[:16]


def _replay_key(prefix: str, key: tuple[str, ...]) -> str:
    body = ":".join(f"{len(part)}:{part}" for part in key)
    return f"{prefix}:replay:{body}"


def _evidence(draft: dict, prev_hash: str) -> Evidence:
    fields = {k: v for k, v in draft.items() if k != "prev_hash"}
    jtis = fields.get("jtis", ())
    if not isinstance(jtis, tuple):
        fields["jtis"] = tuple(jtis)
    return Evidence(prev_hash=prev_hash, **fields)


def _dump_evidence(ev: Evidence) -> str:
    return json.dumps({
        "action_id": ev.action_id, "code": ev.code, "cid": ev.cid,
        "jtis": list(ev.jtis), "peer_id": ev.peer_id, "issuer": ev.issuer,
        "holder": ev.holder, "action": ev.action, "resource": ev.resource,
        "payload_hash": ev.payload_hash, "cost_micros": ev.cost_micros,
        "ts": ev.ts, "pop_thumbprint": ev.pop_thumbprint,
        "channel_bound": ev.channel_bound, "prev_hash": ev.prev_hash,
        "verifier": ev.verifier, "related_id": ev.related_id,
    }, sort_keys=True, separators=(",", ":"))


def _load_evidence(raw: str) -> Evidence:
    d = json.loads(raw)
    d["jtis"] = tuple(d["jtis"])
    return Evidence(**d)


_RESERVE_LUA = """
local amount = tonumber(ARGV[1])
local root_cap = tonumber(ARGV[2])
local n = #KEYS - 2
if amount == nil or root_cap == nil or amount < 0 or root_cap < 0 or n < 1 then
  return {'err', 'INTERNAL', 'bad reserve'}
end
if #ARGV ~= 6 + n then
  return {'err', 'INTERNAL', 'hop arity'}
end
local chain_exists = redis.call('EXISTS', KEYS[1]) == 1
if chain_exists then
  if tonumber(redis.call('HGET', KEYS[1], 'root_cap')) ~= root_cap then
    return {'err', 'BUDGET_CAP_CHANGED', 'cid'}
  end
end
local hop_exists = {}
for i = 1, n do
  local cap = tonumber(ARGV[6 + i])
  if redis.call('EXISTS', KEYS[2 + i]) == 1 then
    hop_exists[i] = 1
    if tonumber(redis.call('HGET', KEYS[2 + i], 'cap')) ~= cap then
      return {'err', 'BUDGET_CAP_CHANGED', 'jti'}
    end
  else
    hop_exists[i] = 0
  end
end
local remaining = root_cap
if chain_exists then
  remaining = tonumber(redis.call('HGET', KEYS[1], 'remaining'))
end
local fits = remaining >= amount
if fits then
  for i = 1, n do
    local spent = 0
    if hop_exists[i] == 1 then
      spent = tonumber(redis.call('HGET', KEYS[2 + i], 'spent'))
    end
    if spent + amount > tonumber(ARGV[6 + i]) then
      fits = false
      break
    end
  end
end
if not chain_exists then
  redis.call('HSET', KEYS[1], 'root_cap', root_cap, 'remaining', root_cap)
end
for i = 1, n do
  if hop_exists[i] == 0 then
    redis.call('HSET', KEYS[2 + i], 'cap', tonumber(ARGV[6 + i]), 'spent', 0)
  end
end
if not fits then
  return {'full'}
end
redis.call('HINCRBY', KEYS[1], 'remaining', -amount)
for i = 1, n do
  redis.call('HINCRBY', KEYS[2 + i], 'spent', amount)
end
redis.call('HSET', KEYS[2], 'cid', ARGV[4], 'amount', amount,
           'path', ARGV[5], 'state', 'reserved', 'created_at', ARGV[6])
return {'ok'}
"""

_DISPATCH_LUA = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  return {'err', 'INTERNAL', 'dispatch: bad state'}
end
if redis.call('HGET', KEYS[1], 'state') ~= 'reserved' then
  return {'err', 'INTERNAL', 'dispatch: bad state'}
end
redis.call('HSET', KEYS[1], 'state', 'dispatched')
return {'ok'}
"""

_SETTLE_LUA = """
local actual = tonumber(ARGV[1])
if actual == nil or actual < 0 then
  return {'err', 'INTERNAL', 'actual'}
end
if redis.call('EXISTS', KEYS[2]) == 0 then
  return {'err', 'INTERNAL', 'settle: handle lost'}
end
local state = redis.call('HGET', KEYS[2], 'state')
if state ~= 'dispatched' then
  return {'err', 'INTERNAL', 'settle from ' .. tostring(state)}
end
local reserved = tonumber(redis.call('HGET', KEYS[2], 'amount'))
local delta = actual - reserved
if delta ~= 0 then
  local remaining = tonumber(redis.call('HGET', KEYS[1], 'remaining'))
  if remaining - delta < 0 then
    return {'err', 'BUDGET_EXHAUSTED', 'root on settle'}
  end
  local n = #KEYS - 2
  for i = 1, n do
    local spent = tonumber(redis.call('HGET', KEYS[2 + i], 'spent'))
    local cap = tonumber(redis.call('HGET', KEYS[2 + i], 'cap'))
    local next_spent = spent + delta
    if next_spent < 0 or next_spent > cap then
      return {'err', 'BUDGET_EXHAUSTED', 'hop on settle'}
    end
  end
  redis.call('HINCRBY', KEYS[1], 'remaining', -delta)
  for i = 1, n do
    redis.call('HINCRBY', KEYS[2 + i], 'spent', delta)
  end
end
redis.call('HSET', KEYS[2], 'amount', actual, 'state', 'settled')
return {'ok'}
"""

_REFUND_LUA = """
if redis.call('EXISTS', KEYS[2]) == 0 then
  return {'ok'}
end
if redis.call('HGET', KEYS[2], 'state') ~= 'reserved' then
  return {'ok'}
end
local amount = tonumber(redis.call('HGET', KEYS[2], 'amount'))
redis.call('HINCRBY', KEYS[1], 'remaining', amount)
local n = #KEYS - 2
for i = 1, n do
  local spent = tonumber(redis.call('HGET', KEYS[2 + i], 'spent')) - amount
  if spent < 0 then spent = 0 end
  redis.call('HSET', KEYS[2 + i], 'spent', spent)
end
redis.call('DEL', KEYS[2])
return {'ok'}
"""

_ENROLL_ADD = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[2])
redis.call('ZREM', KEYS[1], ARGV[1])
while redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[4]) do
  redis.call('ZPOPMIN', KEYS[1])
end
redis.call('ZADD', KEYS[1], ARGV[3], ARGV[1])
return 1
"""

_ENROLL_REQUIRE = """
local exp = redis.call('ZSCORE', KEYS[1], ARGV[1])
if not exp then return 0 end
if tonumber(exp) <= tonumber(ARGV[2]) then
  redis.call('ZREM', KEYS[1], ARGV[1])
  return 0
end
return 1
"""


def _lua_reply(raw: object) -> str:
    if not isinstance(raw, (list, tuple)) or not raw:
        raise Reject(Code.STATE_UNAVAILABLE, "bad redis script reply")
    kind = raw[0]
    if kind in ("ok", "full"):
        return str(kind)
    if kind == "err":
        code = raw[1] if len(raw) > 1 else Code.INTERNAL
        detail = raw[2] if len(raw) > 2 else ""
        raise Reject(str(code), str(detail))
    raise Reject(Code.STATE_UNAVAILABLE, "bad redis script reply")


class RedisReplayStore:
    def __init__(self, client: object, ttl_seconds: int, prefix: str) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self._r = client
        self._ttl = ttl_seconds
        self._prefix = prefix

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def consume(self, key: tuple[str, ...], now: int) -> bool:
        # SET NX is the consume. A Redis error propagates; the Authorizer
        # turns it into STATE_UNAVAILABLE. Never return True on failure.
        # `now` is unused: expiry is relative, so a skewed Redis clock
        # cannot extend a nonce past ttl_seconds.
        del now
        return bool(self._r.set(
            _replay_key(self._prefix, key), "1", nx=True, ex=self._ttl))

    def ping(self) -> None:
        self._r.ping()


class RedisBudgetLedger:
    """Atomic per cid. Keys share a hash tag so a Redis Cluster slot holds
    one chain. Prefer Postgres: this survives only the AOF window."""

    def __init__(self, client: object, prefix: str) -> None:
        self._r = client
        self._prefix = prefix
        self._reserve = client.register_script(_RESERVE_LUA)
        self._dispatch = client.register_script(_DISPATCH_LUA)
        self._settle = client.register_script(_SETTLE_LUA)
        self._refund = client.register_script(_REFUND_LUA)

    def _chain(self, cid: str) -> str:
        return f"{self._prefix}:budget:{{{_budget_tag(cid)}}}:chain"

    def _hop(self, cid: str, jti: str) -> str:
        return f"{self._prefix}:budget:{{{_budget_tag(cid)}}}:hop:{jti}"

    def _res(self, cid: str, handle: str) -> str:
        return f"{self._prefix}:budget:{{{_budget_tag(cid)}}}:res:{handle}"

    def _hops(self, cid: str, path: tuple) -> tuple[str, ...]:
        return tuple(self._hop(cid, jti) for jti, _ in _check_path(path))

    def remaining(self, cid: str) -> int:
        val = self._r.hget(self._chain(cid), "remaining")
        return int(val) if val is not None else 0

    def reserve(
        self, cid: str, root_cap: int, path: tuple, amount: int,
        *, expires_at: Optional[int] = None, now: Optional[int] = None,
    ) -> Optional[SpendHandle]:
        if amount < 0 or root_cap < 0:
            raise ValueError("bad reserve args")
        ordered = _check_path(path)
        handle = uuid.uuid4().hex
        keys = (self._chain(cid), self._res(cid, handle), *self._hops(cid, path))
        args = [
            amount, root_cap, handle, cid, _dump_path(path),
            now if now is not None else _now(),         # ← use caller's clock
            *[cap for _, cap in ordered],
        ]
        if _lua_reply(self._reserve(keys=list(keys), args=args)) == "full":
            return None
        return SpendHandle(cid=cid, amount=amount, handle=handle, path=path)

    def mark_dispatched(self, handle: SpendHandle) -> None:
        _lua_reply(self._dispatch(keys=[self._res(handle.cid, handle.handle)]))
        handle.state = ReservationState.DISPATCHED            # ← ADD


    def settle(self, handle: SpendHandle, actual: int) -> None:
        if type(actual) is not int or actual < 0:
            raise Reject(Code.INTERNAL, "actual must be a non-negative int")
        keys = [self._chain(handle.cid), self._res(handle.cid, handle.handle),
                *self._hops(handle.cid, handle.path)]
        _lua_reply(self._settle(keys=keys, args=[actual]))
        handle.amount = actual                                # ← ADD
        handle.state = ReservationState.SETTLED               # ← ADD

    def commit(self, handle: SpendHandle) -> None:
        self._r.delete(self._res(handle.cid, handle.handle))

    def refund(self, handle: SpendHandle) -> None:
        keys = [self._chain(handle.cid), self._res(handle.cid, handle.handle),
                *self._hops(handle.cid, handle.path)]
        _lua_reply(self._refund(keys=keys))
        handle.state = ReservationState.CANCELLED

    def ping(self) -> None:
        self._r.ping()


class RedisRevocationStore:
    def __init__(self, client: object, prefix: str) -> None:
        self._r = client
        self._prefix = prefix

    def _key(self, kind: str) -> str:
        return f"{self._prefix}:revoked:{kind}"

    def revoke_agent(self, value: str) -> None:
        self._r.sadd(self._key("agent"), value)

    def revoke_key(self, value: str) -> None:
        self._r.sadd(self._key("kid"), value)

    def revoke_chain(self, value: str) -> None:
        self._r.sadd(self._key("cid"), value)

    def revoke_token(self, value: str) -> None:
        self._r.sadd(self._key("jti"), value)

    def find_revoked(self, *, agents: tuple[str, ...] = (),
                     kids: tuple[str, ...] = (), cids: tuple[str, ...] = (),
                     jtis: tuple[str, ...] = ()) -> Optional[tuple[str, str]]:
        pairs = [("agent", agents), ("kid", kids),
                 ("cid", cids), ("jti", jtis)]
        pipe = self._r.pipeline()
        flat: list[tuple[str, str]] = []
        for kind, items in pairs:
            for item in items:
                pipe.sismember(self._key(kind), item)
                flat.append((kind, item))
        if not flat:
            return None
        for hit, pair in zip(pipe.execute(), flat):
            if hit:
                return pair
        return None

    def ping(self) -> None:
        self._r.ping()


class RedisEnrollments:
    def __init__(self, client: object, ttl_seconds: int, max_per_peer: int,
                 prefix: str) -> None:
        if ttl_seconds <= 0 or max_per_peer <= 0:
            raise ValueError("ttl_seconds and max_per_peer must be > 0")
        self._r = client
        self._ttl = ttl_seconds
        self._max = max_per_peer
        self._prefix = prefix
        self._add = client.register_script(_ENROLL_ADD)
        self._require = client.register_script(_ENROLL_REQUIRE)

    def _key(self, peer_id: str) -> str:
        return f"{self._prefix}:enroll:{peer_id}"

    def add(self, peer_id: str, cnf: str, now: int) -> None:
        self._add(keys=[self._key(peer_id)],
                  args=[cnf, now, now + self._ttl, self._max])

    def require(self, peer_id: str, cnf: str, now: int) -> None:
        if not self._require(keys=[self._key(peer_id)], args=[cnf, now]):
            raise Reject(Code.NOT_ENROLLED,
                         "key not enrolled for this SPIFFE ID")

    def revoke(self, peer_id: str, cnf: Optional[str] = None) -> None:
        if cnf is None:
            self._r.delete(self._key(peer_id))
        else:
            self._r.zrem(self._key(peer_id), cnf)

    def ping(self) -> None:
        self._r.ping()


class RedisEvidenceLog:
    def __init__(self, client: object, prefix: str) -> None:
        import redis.exceptions as _redis_exc
        self._r = client
        self._watch_error = _redis_exc.WatchError
        self._head = f"{prefix}:evidence:head"
        self._log = f"{prefix}:evidence:log"

    def append(self, draft: dict) -> Evidence:
        for _ in range(8):
            with self._r.pipeline() as pipe:
                try:
                    pipe.watch(self._head)
                    head = pipe.get(self._head) or _GENESIS
                    ev = _evidence(draft, head)
                    pipe.multi()
                    pipe.rpush(self._log, _dump_evidence(ev))
                    pipe.set(self._head, ev.digest())
                    pipe.execute()
                    return ev
                except self._watch_error:
                    continue
        raise Reject(Code.STATE_UNAVAILABLE, "evidence contention")

    def verify_integrity(self) -> bool:
        prev = _GENESIS
        for raw in self._r.lrange(self._log, 0, -1):
            ev = _load_evidence(raw)
            # Byte-level check: catches a stored row that was edited in
            # Redis without updating its digest and the head. Re-encoding
            # the parsed object and comparing to the stored bytes proves
            # the stored record is canonical for its fields.
            if _dump_evidence(ev) != raw:
                return False
            if ev.prev_hash != prev:
                return False
            prev = ev.digest()
        head = self._r.get(self._head) or _GENESIS
        return prev == head

    def records(self) -> tuple[Evidence, ...]:
        return tuple(_load_evidence(raw)
                     for raw in self._r.lrange(self._log, 0, -1))

    def ping(self) -> None:
        self._r.ping()


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS replay_nonces (
    key TEXT PRIMARY KEY,
    expires_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS budget_chains (
    cid TEXT PRIMARY KEY,
    expires_at BIGINT,
    root_cap BIGINT NOT NULL CHECK (root_cap >= 0),
    remaining BIGINT NOT NULL CHECK (remaining >= 0)
);
CREATE TABLE IF NOT EXISTS budget_hops (
    cid TEXT NOT NULL REFERENCES budget_chains(cid),
    jti TEXT NOT NULL,
    cap BIGINT NOT NULL CHECK (cap >= 0),
    spent BIGINT NOT NULL CHECK (spent >= 0),
    PRIMARY KEY (cid, jti),
    CHECK (spent <= cap)
);
CREATE TABLE IF NOT EXISTS budget_reservations (
    handle TEXT PRIMARY KEY,
    cid TEXT NOT NULL REFERENCES budget_chains(cid),
    amount BIGINT NOT NULL CHECK (amount >= 0),
    path_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'dispatched', 'settled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS budget_reservations_reap
    ON budget_reservations (created_at) WHERE state = 'reserved';
CREATE TABLE IF NOT EXISTS revocations (
    kind TEXT NOT NULL CHECK (kind IN ('agent', 'kid', 'cid', 'jti')),
    value TEXT NOT NULL,
    PRIMARY KEY (kind, value)
);
CREATE TABLE IF NOT EXISTS evidence_head (
    id INT PRIMARY KEY CHECK (id = 1),
    head TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    seq BIGSERIAL PRIMARY KEY,
    prev_hash TEXT NOT NULL UNIQUE,
    digest TEXT NOT NULL UNIQUE,
    body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollments (
    peer_id TEXT NOT NULL,
    cnf TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    enrolled_at BIGINT NOT NULL,
    PRIMARY KEY (peer_id, cnf)
);
CREATE INDEX IF NOT EXISTS enrollments_peer_order
    ON enrollments (peer_id, enrolled_at);
"""


def _statements(sql: str) -> list[str]:
    out, buf = [], []
    for line in sql.splitlines():
        if line.strip().startswith("--"):
            continue
        buf.append(line)
        if line.rstrip().endswith(";"):
            stmt = "\n".join(buf).strip().rstrip(";").strip()
            if stmt:
                out.append(stmt)
            buf = []
    if buf and "".join(buf).strip():
        raise ValueError("schema statement missing semicolon")
    return out


def migrate(dsn: Optional[str] = None, schema: str = "capchain") -> None:
    """Create the schema. Run once from an init container, not from agents."""
    import psycopg
    dsn = dsn or os.environ["CAPCHAIN_POSTGRES_DSN"]
    schema = _ident("schema", schema)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
        conn.execute(f"SET search_path TO {schema}")
        for stmt in _statements(SCHEMA_SQL):
            conn.execute(stmt)
        conn.execute(
            "INSERT INTO evidence_head (id, head) VALUES (1, %s) "
            "ON CONFLICT (id) DO NOTHING", (_GENESIS,))


class _Pg:
    def __init__(self, pool: object) -> None:
        self._pool = pool

    def _conn(self):
        return self._pool.connection()

    def _timeout(self, cur: object) -> None:
        cur.execute("SELECT set_config('statement_timeout', %s, true)",
                    (str(_STATEMENT_TIMEOUT_MS),))

    def ping(self) -> None:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")


class PostgresReplayStore(_Pg):
    def __init__(self, pool: object, ttl_seconds: int) -> None:
        super().__init__(pool)
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self._ttl = ttl_seconds

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def consume(self, key: tuple[str, ...], now: int) -> bool:
        encoded = _replay_key("nonce", key)
        expires = now + self._ttl
        with self._conn() as conn, conn.transaction(), conn.cursor() as cur:
            self._timeout(cur)
            # Insert, or take over a row whose verifier-clock expiry has passed.
            cur.execute(
                """
                INSERT INTO replay_nonces (key, expires_at) VALUES (%s, %s)
                ON CONFLICT (key) DO UPDATE SET expires_at = EXCLUDED.expires_at
                WHERE replay_nonces.expires_at <= %s
                RETURNING key
                """, (encoded, expires, now))
            return cur.fetchone() is not None

    def prune(self, now: int) -> int:
        with self._conn() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute(
                "DELETE FROM replay_nonces WHERE expires_at <= %s", (now,))
            return cur.rowcount


class PostgresBudgetLedger(_Pg):
    """Lock order is always chain, then hops sorted by jti, then the
    reservation. Same order in every method, so concurrent reserves of
    one cid cannot deadlock."""

    def remaining(self, cid: str) -> int:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT remaining FROM budget_chains WHERE cid = %s", (cid,))
            row = cur.fetchone()
            return int(row[0]) if row else 0

    def reserve(
        self, cid: str, root_cap: int, path: tuple, amount: int,
        *, expires_at: Optional[int] = None, now: Optional[int] = None,
    ) -> Optional[SpendHandle]:
        
        if amount < 0 or root_cap < 0:
            raise ValueError("bad reserve args")
        ordered = _check_path(path)
        with self._conn() as conn, conn.transaction(), conn.cursor() as cur:
            self._timeout(cur)
            cur.execute(
                """INSERT INTO budget_chains (cid, root_cap, remaining)
                VALUES (%s, %s, %s) ON CONFLICT (cid) DO NOTHING""",
                (cid, root_cap, root_cap),
            )
            cur.execute(
                "SELECT root_cap, remaining FROM budget_chains "
                "WHERE cid = %s FOR UPDATE",
                (cid,),
            )
            cur.execute(
                "SELECT root_cap, remaining FROM budget_chains WHERE cid = %s FOR UPDATE",
                (cid,))
            db_root, db_rem = cur.fetchone()
            if db_root != root_cap:
                raise Reject(Code.BUDGET_CAP_CHANGED, f"cid {cid}")
            fits = db_rem >= amount
            for jti, cap in ordered:
                cur.execute(
                    """INSERT INTO budget_hops (cid, jti, cap, spent)
                       VALUES (%s, %s, %s, 0) ON CONFLICT (cid, jti) DO NOTHING""",
                    (cid, jti, cap))
                cur.execute(
                    """SELECT cap, spent FROM budget_hops
                       WHERE cid = %s AND jti = %s FOR UPDATE""", (cid, jti))
                db_cap, db_spent = cur.fetchone()
                if db_cap != cap:
                    raise Reject(Code.BUDGET_CAP_CHANGED, f"jti {jti}")
                if db_spent + amount > db_cap:
                    fits = False
            if not fits:
                return None  # commits the cap rows; does not deduct
            cur.execute(
                "UPDATE budget_chains SET remaining = remaining - %s WHERE cid = %s",
                (amount, cid))
            for jti, _ in ordered:
                cur.execute(
                    """UPDATE budget_hops SET spent = spent + %s
                       WHERE cid = %s AND jti = %s""", (amount, cid, jti))
            handle = uuid.uuid4().hex
            cur.execute(
                """INSERT INTO budget_reservations (handle, cid, amount, path_json, state)
                   VALUES (%s, %s, %s, %s, 'reserved')""",
                (handle, cid, amount, _dump_path(path)))
            return SpendHandle(cid=cid, amount=amount, handle=handle, path=path)


    def mark_dispatched(self, handle: SpendHandle) -> None:
        with self._conn() as conn, conn.transaction(), conn.cursor() as cur:
            self._timeout(cur)
            cur.execute("SELECT cid FROM budget_chains WHERE cid = %s FOR UPDATE",
                        (handle.cid,))
            cur.execute(
                """UPDATE budget_reservations SET state = 'dispatched'
                WHERE handle = %s AND state = 'reserved'""", (handle.handle,))
            if cur.rowcount != 1:
                raise Reject(Code.INTERNAL, "dispatch: bad state")
        handle.state = ReservationState.DISPATCHED         
        

    def settle(self, handle: SpendHandle, actual: int) -> None:
        if type(actual) is not int or actual < 0:
            raise Reject(Code.INTERNAL, "actual must be a non-negative int")
        ordered = _check_path(handle.path)
        with self._conn() as conn, conn.transaction(), conn.cursor() as cur:
            self._timeout(cur)
            cur.execute(
                "SELECT remaining FROM budget_chains WHERE cid = %s FOR UPDATE",
                (handle.cid,))
            chain = cur.fetchone()
            if chain is None:
                raise Reject(Code.INTERNAL, "settle: chain lost")
            cur.execute(
                """SELECT amount, state FROM budget_reservations
                   WHERE handle = %s FOR UPDATE""", (handle.handle,))
            row = cur.fetchone()
            if row is None:
                raise Reject(Code.INTERNAL, "settle: handle lost")
            reserved, state = row
            if state != ReservationState.DISPATCHED:
                raise Reject(Code.INTERNAL, f"settle from {state}")
            delta = actual - int(reserved)
            hops = []
            for jti, _ in ordered:
                cur.execute(
                    """SELECT cap, spent FROM budget_hops
                       WHERE cid = %s AND jti = %s FOR UPDATE""",
                    (handle.cid, jti))
                hops.append(cur.fetchone())
            if delta != 0:
                if int(chain[0]) - delta < 0:
                    raise Reject(Code.BUDGET_EXHAUSTED, "root on settle")
                for jti, (cap, spent) in zip((j for j, _ in ordered), hops):
                    nxt = int(spent) + delta
                    if nxt < 0 or nxt > int(cap):
                        raise Reject(Code.BUDGET_EXHAUSTED,
                                     f"hop {jti} on settle")
                cur.execute(
                    "UPDATE budget_chains SET remaining = remaining - %s WHERE cid = %s",
                    (delta, handle.cid))
                for jti, _ in ordered:
                    cur.execute(
                        """UPDATE budget_hops SET spent = spent + %s
                           WHERE cid = %s AND jti = %s""",
                        (delta, handle.cid, jti))
            cur.execute(
                """UPDATE budget_reservations SET amount = %s, state = 'settled'
                   WHERE handle = %s""", (actual, handle.handle))
            handle.amount = actual                              # ← ADD
            handle.state = ReservationState.SETTLED             # ← ADD
            
    
    def commit(self, handle: SpendHandle) -> None:
        with self._conn() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute("DELETE FROM budget_reservations WHERE handle = %s",
                        (handle.handle,))

    def refund(self, handle: SpendHandle) -> None:
        ordered = _check_path(handle.path)
        with self._conn() as conn, conn.transaction(), conn.cursor() as cur:
            self._timeout(cur)
            cur.execute(
                "SELECT remaining FROM budget_chains WHERE cid = %s FOR UPDATE",
                (handle.cid,))
            for jti, _ in ordered:
                cur.execute(
                    """SELECT spent FROM budget_hops
                       WHERE cid = %s AND jti = %s FOR UPDATE""",
                    (handle.cid, jti))
            cur.execute(
                """DELETE FROM budget_reservations
                   WHERE handle = %s AND state = 'reserved' RETURNING amount""",
                (handle.handle,))
            row = cur.fetchone()
            if row is None:
                return
            handle.state = ReservationState.CANCELLED           
            amount = int(row[0])
            cur.execute(
                "UPDATE budget_chains SET remaining = remaining + %s WHERE cid = %s",
                (amount, handle.cid))

            for jti, _ in ordered:
                cur.execute(
                    """UPDATE budget_hops SET spent = GREATEST(0, spent - %s)
                       WHERE cid = %s AND jti = %s""",
                    (amount, handle.cid, jti))

    def refund_abandoned(self, older_than_seconds: int) -> int:
        """Refund RESERVED rows older than this. The cutoff must be longer
        than any request you still have in flight, or a call that later
        succeeds is no longer holding its budget."""
        if older_than_seconds <= 0:
            raise ValueError("older_than_seconds must be > 0")
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT handle, cid, amount, path_json FROM budget_reservations
                   WHERE state = 'reserved'
                     AND created_at < now() - make_interval(secs => %s)""",
                (older_than_seconds,))
            rows = cur.fetchall()
        n = 0
        for handle, cid, amount, path_json in rows:
            self.refund(SpendHandle(
                cid=cid, amount=int(amount), handle=handle,
                path=_load_path(path_json)))
            n += 1
        return n


class PostgresRevocationStore(_Pg):
    def _add(self, kind: str, value: str) -> None:
        with self._conn() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute(
                """INSERT INTO revocations (kind, value) VALUES (%s, %s)
                   ON CONFLICT DO NOTHING""", (kind, value))

    def revoke_agent(self, value: str) -> None:
        self._add("agent", value)

    def revoke_key(self, value: str) -> None:
        self._add("kid", value)

    def revoke_chain(self, value: str) -> None:
        self._add("cid", value)

    def revoke_token(self, value: str) -> None:
        self._add("jti", value)

    def find_revoked(self, *, agents: tuple[str, ...] = (),
                     kids: tuple[str, ...] = (), cids: tuple[str, ...] = (),
                     jtis: tuple[str, ...] = ()) -> Optional[tuple[str, str]]:
        groups = (("agent", agents), ("kid", kids),
                  ("cid", cids), ("jti", jtis))
        if not any(items for _, items in groups):
            return None
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT kind, value FROM revocations
                WHERE (kind = 'agent' AND value = ANY(%s))
                   OR (kind = 'kid' AND value = ANY(%s))
                   OR (kind = 'cid' AND value = ANY(%s))
                   OR (kind = 'jti' AND value = ANY(%s))
                """,
                (list(agents), list(kids), list(cids), list(jtis)))
            found = {(kind, value) for kind, value in cur.fetchall()}
        for kind, items in groups:
            for item in items:
                if (kind, item) in found:
                    return (kind, item)
        return None


class PostgresEvidenceLog(_Pg):
    def append(self, draft: dict) -> Evidence:
        with self._conn() as conn, conn.transaction(), conn.cursor() as cur:
            self._timeout(cur)
            cur.execute(
                "SELECT head FROM evidence_head WHERE id = 1 FOR UPDATE")
            row = cur.fetchone()
            if row is None:
                raise Reject(Code.STATE_UNAVAILABLE, "evidence head missing")
            ev = _evidence(draft, row[0])
            cur.execute(
                """INSERT INTO evidence (prev_hash, digest, body)
                   VALUES (%s, %s, %s)""",
                (ev.prev_hash, ev.digest(), _dump_evidence(ev)))
            cur.execute("UPDATE evidence_head SET head = %s WHERE id = 1",
                        (ev.digest(),))
            return ev

    def verify_integrity(self) -> bool:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT head FROM evidence_head WHERE id = 1")
            head = cur.fetchone()
            cur.execute("SELECT body, digest FROM evidence ORDER BY seq")
            rows = cur.fetchall()
        prev = _GENESIS
        for body, digest in rows:
            ev = _load_evidence(body)
            if ev.prev_hash != prev or ev.digest() != digest:
                return False
            prev = digest
        return head is not None and prev == head[0]

    def records(self) -> tuple[Evidence, ...]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT body FROM evidence ORDER BY seq")
            return tuple(_load_evidence(row[0]) for row in cur.fetchall())


class PostgresEnrollments(_Pg):
    def __init__(self, pool: object, ttl_seconds: int, max_per_peer: int) -> None:
        super().__init__(pool)
        if ttl_seconds <= 0 or max_per_peer <= 0:
            raise ValueError("ttl_seconds and max_per_peer must be > 0")
        self._ttl = ttl_seconds
        self._max = max_per_peer

    def add(self, peer_id: str, cnf: str, now: int) -> None:
        with self._conn() as conn, conn.transaction(), conn.cursor() as cur:
            self._timeout(cur)
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))", (peer_id,))
            cur.execute(
                "DELETE FROM enrollments WHERE peer_id = %s AND expires_at <= %s",
                (peer_id, now))
            cur.execute(
                """INSERT INTO enrollments (peer_id, cnf, expires_at, enrolled_at)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (peer_id, cnf) DO UPDATE
                   SET expires_at = EXCLUDED.expires_at,
                       enrolled_at = EXCLUDED.enrolled_at""",
                (peer_id, cnf, now + self._ttl, now))
            cur.execute(
                """DELETE FROM enrollments WHERE peer_id = %s AND cnf NOT IN (
                       SELECT cnf FROM enrollments WHERE peer_id = %s
                       ORDER BY enrolled_at DESC LIMIT %s)""",
                (peer_id, peer_id, self._max))

    def require(self, peer_id: str, cnf: str, now: int) -> None:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT expires_at FROM enrollments
                   WHERE peer_id = %s AND cnf = %s""", (peer_id, cnf))
            row = cur.fetchone()
        if row is None or int(row[0]) <= now:
            raise Reject(Code.NOT_ENROLLED,
                         "key not enrolled for this SPIFFE ID")

    def revoke(self, peer_id: str, cnf: Optional[str] = None) -> None:
        with self._conn() as conn, conn.transaction(), conn.cursor() as cur:
            if cnf is None:
                cur.execute(
                    "DELETE FROM enrollments WHERE peer_id = %s", (peer_id,))
            else:
                cur.execute(
                    "DELETE FROM enrollments WHERE peer_id = %s AND cnf = %s",
                    (peer_id, cnf))


def _draft(action_id: str = "a1") -> dict:
    return {
        "action_id": action_id, "code": Code.OK, "cid": "c", "jtis": ("j",),
        "peer_id": "spiffe://t/a", "issuer": "spiffe://t/m",
        "holder": "spiffe://t/a", "action": "infer", "resource": "llm",
        "payload_hash": "sha256:" + "ab" * 32, "cost_micros": 1, "ts": 1,
        "pop_thumbprint": "", "channel_bound": False, "verifier": "spiffe://t/g",
        "related_id": "",
    }


def check_contract(stores: Stores) -> None:
    now = _now()
    assert stores.replay.consume(("pop", "n1"), now) is True
    assert stores.replay.consume(("pop", "n1"), now) is False

    path = (("j1", 500), ("j0", 1000))
    first = stores.ledger.reserve("cid-1", 1000, path, 100)
    assert first is not None and stores.ledger.remaining("cid-1") == 900
    stores.ledger.refund(first)
    assert stores.ledger.remaining("cid-1") == 1000
    second = stores.ledger.reserve("cid-1", 1000, path, 100)
    stores.ledger.mark_dispatched(second)
    stores.ledger.refund(second)  # dispatched: not refundable
    assert stores.ledger.remaining("cid-1") == 900
    stores.ledger.settle(second, 80)
    assert stores.ledger.remaining("cid-1") == 920
    stores.ledger.commit(second)
    try:
        stores.ledger.reserve("cid-1", 999, path, 1)
        raise AssertionError("cap change was accepted")
    except Reject as e:
        assert e.code == Code.BUDGET_EXHAUSTED or e.code == Code.BUDGET_CAP_CHANGED
        assert e.code == Code.BUDGET_CAP_CHANGED

    stores.revocation.revoke_key("abc")
    assert stores.revocation.find_revoked(kids=("abc",)) == ("kid", "abc")
    assert stores.revocation.find_revoked(kids=("nope",)) is None

    stores.evidence.append(_draft("a1"))
    stores.evidence.append(_draft("a2"))
    assert stores.evidence.verify_integrity()
    assert len(stores.evidence.records()) >= 2

    stores.enrollments.add("spiffe://t/a", "k-old", now)
    stores.enrollments.add("spiffe://t/a", "k-new", now)
    stores.enrollments.require("spiffe://t/a", "k-new", now)
    try:
        stores.enrollments.require("spiffe://t/a", "missing", now)
        raise AssertionError("missing enrollment was accepted")
    except Reject as e:
        assert e.code == Code.NOT_ENROLLED


def selftest() -> int:
    failures = 0
    with Stores.open("memory") as stores:
        try:
            check_contract(stores)
            print("  [ok]   memory")
        except Exception as e:
            failures += 1
            print(f"  [FAIL] memory: {type(e).__name__}: {e}")
    url = os.environ.get("CAPCHAIN_TEST_REDIS")
    if url:
        prefix = f"capchain:test:{uuid.uuid4().hex}"
        try:
            with Stores.open("redis", redis_url=url, prefix=prefix,
                             env="development") as stores:
                check_contract(stores)
            print("  [ok]   redis")
        except Exception as e:
            failures += 1
            print(f"  [FAIL] redis: {type(e).__name__}: {e}")
    dsn = os.environ.get("CAPCHAIN_TEST_POSTGRES")
    if dsn:
        schema = "capchain_test_" + uuid.uuid4().hex[:12]
        try:
            migrate(dsn, schema)
            with Stores.open("database", postgres_dsn=dsn, schema=schema,
                             env="development") as stores:
                check_contract(stores)
            print("  [ok]   database")
        except Exception as e:
            failures += 1
            print(f"  [FAIL] database: {type(e).__name__}: {e}")
    print(f"store selftest: {failures} failure(s)")
    return failures


if __name__ == "__main__":
    raise SystemExit(selftest())
