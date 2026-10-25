"""Minting, attenuation, and chain verification."""
from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from typing import Optional

from ._errors import Code, Reject
from ._keys import TrustedRoots, BaseWorkloadKey, is_thumbprint, thumbprint, verify_signature
from ._scope import MODELS, Scope
from ._wire import (
    Token,
    bounded_str,
    is_int,
    link_hash,
    sign_block,
    derive_jti
)

from ._constants import (
    SIGNATURE_BYTES,
    LINK_LABEL,
    MAX_BLOCKS,
    MAX_TOKEN_BYTES,
    BLOCK_FIELDS,
    MAX_CID_CHARS,
    MAX_JTI_CHARS,
    BudgetPath,
    MAX_SESSION_ID_CHARS,
    MAX_TASK_CHARS,
    GENESIS_LINK,
    WIRE_VERSION,
    CTX_BLOCK,
    MAX_ENVELOPE_BYTES,
    MAX_AGENT_ID_CHARS,   
)



@dataclass(frozen=True, slots=True)
class Verdict:
    """Everything a verifier learns from a cryptographically valid chain."""

    model: str
    cid: str
    issuer: str
    holder: str
    cnf: str
    path: tuple[str, ...]
    jtis: tuple[str, ...]
    kids: tuple[str, ...]
    budget_path: BudgetPath
    scope: Scope
    root_scope: Scope
    session_id: str
    task: str
    expires_at: int
    depth: int


def mint(
    root_key: BaseWorkloadKey,
    *,
    issuer: str,
    holder: str,
    cnf: str,
    session_id: str,
    task: str,
    scope: Scope,
    ttl_seconds: int,
    now: int,
    model: str,
    max_depth: int = 1,
) -> Token:
    """Create a root token. Callers should use TokenIssuer, which also
    enforces that `cnf` is enrolled for `holder`."""
    if not (
        bounded_str(issuer, MAX_AGENT_ID_CHARS)
        and bounded_str(holder, MAX_AGENT_ID_CHARS)
        and bounded_str(session_id, MAX_SESSION_ID_CHARS)
        and bounded_str(task, MAX_TASK_CHARS)
    ):
        raise ValueError("bad identity or context field")
    if not is_thumbprint(cnf):
        raise ValueError("cnf must be 64 lowercase hex characters")
    if model not in MODELS:
        raise ValueError(f"unknown model {model!r}")
    if not isinstance(scope, Scope):
        raise ValueError("scope must be a Scope")
    if not (is_int(ttl_seconds) and ttl_seconds > 0):
        raise ValueError("ttl_seconds must be a positive int")
    if not (is_int(now) and now >= 0):
        raise ValueError("now must be a non-negative int")
    if not (is_int(max_depth) and 0 <= max_depth < MAX_BLOCKS):
        raise ValueError("max_depth out of range")

    cid = secrets.token_hex(16)
    return Token(
        (
            sign_block(
                root_key,
                {
                    "ver": WIRE_VERSION,
                    "typ": "authority",
                    "cid": cid,
                    "jti": cid,
                    "iss": issuer,
                    "holder": holder,
                    "cnf": cnf,
                    "sid": session_id,
                    "task": task,
                    "scope": scope.to_body(),
                    "nbf": now,
                    "exp": now + ttl_seconds,
                    "max_depth": max_depth,
                    "prev": GENESIS_LINK,
                    "model": model,
                },
            ),
        )
    )


def attenuate(
    parent: Token,
    key: BaseWorkloadKey,
    *,
    holder: str,
    cnf: str,
    scope: Scope,
    ttl_seconds: int,
    now: int,
) -> Token:
    """Append a narrowed delegation block signed by the current holder."""
    if not parent.blocks:
        raise Reject(Code.TOKEN_MALFORMED, "empty parent")
    if not bounded_str(holder, MAX_AGENT_ID_CHARS) or not is_thumbprint(cnf):
        raise ValueError("bad holder or cnf")
    if not isinstance(scope, Scope):
        raise ValueError("scope must be a Scope")
    if not (is_int(ttl_seconds) and ttl_seconds > 0) or not is_int(now):
        raise ValueError("bad ttl_seconds or now")

    leaf = parent.blocks[-1]
    body = leaf.body()

    # The field-set check above only verifies names; validate types before
    # arithmetic. Anything we touch below must be the type we expect, or the
    # error must be a Reject, not a TypeError.
    for name in ("max_depth", "nbf", "exp"):
        if not is_int(body[name]):
            raise Reject(Code.TOKEN_MALFORMED, f"parent leaf {name}")

    if key.thumbprint != body["cnf"]:
        raise Reject(Code.HOLDER_MISMATCH, "signing key is not the leaf cnf")

    if set(body) != BLOCK_FIELDS:
        raise Reject(Code.TOKEN_MALFORMED, "parent leaf field set")
    if key.thumbprint != body["cnf"]:
        raise Reject(Code.HOLDER_MISMATCH, "signing key is not the leaf cnf")
    if key.agent_id is not None and key.agent_id != body["holder"]:
        raise Reject(
            Code.HOLDER_MISMATCH,
            f"key agent_id {key.agent_id} != leaf holder {body['holder']}",
        )
    if len(parent.blocks) > body["max_depth"]:
        raise Reject(Code.TOO_DEEP, "max_depth reached")
    if not scope.is_subset_of(Scope.from_body(body["scope"])):
        raise Reject(Code.SCOPE_WIDENED, "child scope exceeds parent")

    expires_at = min(body["exp"], now + ttl_seconds)
    if expires_at <= now:
        raise Reject(Code.TOKEN_EXPIRED, "parent already expired")

    prev = link_hash(leaf)
    jti = derive_jti(prev, body["holder"], scope)

    return Token(
        parent.blocks
        + (
            sign_block(
                key,
                {
                    "ver": WIRE_VERSION,
                    "typ": "delegation",
                    "cid": body["cid"],
                    "jti": jti,
                    "iss": body["holder"],
                    "holder": holder,
                    "cnf": cnf,
                    "sid": body["sid"],
                    "task": body["task"],
                    "scope": scope.to_body(),
                    "nbf": max(now, body["nbf"]),
                    "exp": expires_at,
                    "max_depth": body["max_depth"],
                    "prev": prev,
                    "model": body["model"],
                },
            ),
        )
    )


def verify_chain(
    raw_token: bytes,
    *,
    roots: TrustedRoots,
    now: int,
    max_depth: int,
    skew: int = 0,
) -> Verdict:
    """Validate signatures, linkage, monotonicity, and validity windows.

    Raises Reject on any failure. Performs no policy, state, or request
    checks; those belong to the Gateway.
    """
    if not is_int(skew) or skew < 0:
        raise ValueError("skew must be a non-negative int")
    token = Token.decode(raw_token)
    depth = len(token.blocks) - 1
    if depth > max_depth:
        raise Reject(
            Code.TOO_DEEP, f"depth {depth} exceeds policy {max_depth}")
    previous: Optional[dict] = None
    previous_scope: Optional[Scope] = None
    root_scope: Optional[Scope] = None
    previous_link = GENESIS_LINK
    previous_nbf = previous_exp = 0

    path: list[str] = []
    jtis: list[str] = []
    kids: list[str] = []
    budget_path: list[tuple[str, int]] = []
    model = cid = session_id = task = ""

    for index, block in enumerate(token.blocks):

        # Authenticate before interpreting anything in the body.
        verify_signature(
            block.signer_public_key,
            block.signature,
            CTX_BLOCK,
            block.body_raw,
            Code.TOKEN_SIGNATURE,
            f"block {index}",
        )
        body = block.body()
        if set(body) != BLOCK_FIELDS:
            raise Reject(Code.TOKEN_MALFORMED, f"block {index} field set")
        if not is_int(body["ver"]):
            raise Reject(Code.TOKEN_MALFORMED, f"block {index} ver type")
        if body["ver"] != WIRE_VERSION:
            raise Reject(Code.VERSION_UNSUPPORTED, f"block {index}")
        if body["prev"] != previous_link:
            raise Reject(Code.CHAIN_BROKEN, f"block {index}")

        issuer = body["iss"]
        holder = body["holder"]
        jti = body["jti"]
        cnf = body["cnf"]
        if not (
            bounded_str(issuer, MAX_AGENT_ID_CHARS)
            and bounded_str(holder, MAX_AGENT_ID_CHARS)
            and bounded_str(jti, MAX_JTI_CHARS)
            and is_thumbprint(cnf)
        ):
            raise Reject(Code.TOKEN_MALFORMED, f"block {index} fields")

        if index == 0:
            if body["typ"] != "authority":
                raise Reject(Code.TOKEN_MALFORMED, "block 0 typ")
            if roots.issuer_for(block.signer_public_key) != issuer:
                raise Reject(Code.UNKNOWN_ISSUER,
                             f"root key not bound to {issuer}")

            model = body["model"]
            if model not in MODELS:
                raise Reject(Code.MODEL_MISMATCH, f"block 0 model {model!r}")

            cid, session_id, task = body["cid"], body["sid"], body["task"]
            if not (
                bounded_str(cid, MAX_CID_CHARS)
                and bounded_str(session_id, MAX_SESSION_ID_CHARS)
                and bounded_str(task, MAX_TASK_CHARS)
            ):
                raise Reject(Code.TOKEN_MALFORMED, "block 0 context")

            declared_depth = body["max_depth"]
            if not is_int(declared_depth) or not 0 <= declared_depth < MAX_BLOCKS:
                raise Reject(Code.TOKEN_MALFORMED, "max_depth")
            if depth > declared_depth:
                raise Reject(Code.TOO_DEEP, f"{depth} > {declared_depth}")

            path.append(issuer)
        else:
            assert previous is not None
            if body["typ"] != "delegation":
                raise Reject(Code.TOKEN_MALFORMED, f"block {index} typ")
            if thumbprint(block.signer_public_key) != previous["cnf"]:
                raise Reject(Code.HOLDER_MISMATCH,
                             f"block {index} signer != prev cnf")
            if issuer != previous["holder"]:
                raise Reject(Code.HOLDER_MISMATCH,
                             f"block {index} iss != prev holder")
            if body["model"] != model:
                raise Reject(Code.CONTEXT_DRIFT, f"block {index} model")
            if not is_int(body["max_depth"]) or (
                body["cid"],
                body["sid"],
                body["task"],
                body["max_depth"],
            ) != (cid, session_id, task, previous["max_depth"]):
                raise Reject(Code.CONTEXT_DRIFT, f"block {index}")

        if holder != path[-1]:
            path.append(holder)
        scope = Scope.from_body(body["scope"])
        if previous_scope is not None and not scope.is_subset_of(previous_scope):
            raise Reject(Code.SCOPE_WIDENED, f"block {index}")
        if index == 0:
            if jti != cid:
                raise Reject(Code.TOKEN_MALFORMED, "block 0 jti != cid")
            root_scope = scope
        else:
            if not hmac.compare_digest(
                jti, derive_jti(previous_link, issuer, scope)
            ):
                raise Reject(Code.CHAIN_BROKEN, f"block {index} jti")

        nbf, exp = body["nbf"], body["exp"]
        if not (is_int(nbf) and is_int(exp)) or nbf < 0 or exp <= nbf:
            raise Reject(Code.TOKEN_MALFORMED, f"block {index} time")
        if index > 0 and (nbf < previous_nbf or exp > previous_exp):
            raise Reject(Code.CONTEXT_DRIFT, f"block {index} time widened")
        if jti in jtis:
            raise Reject(Code.TOKEN_MALFORMED, f"block {index} duplicate jti")
        if now + skew < nbf:
            raise Reject(
                Code.TOKEN_NOT_YET_VALID,
                f"block {index}: now={now} nbf={nbf} skew={skew}",
            )
        if now - skew >= exp:
            raise Reject(
                Code.TOKEN_EXPIRED,
                f"block {index}: now={now} exp={exp} skew={skew}",
            )

        jtis.append(jti)
        kids.append(thumbprint(block.signer_public_key))
        budget_path.append((jti, scope.budget_micros))

        previous, previous_scope, previous_link = body, scope, link_hash(block)
        previous_nbf, previous_exp = nbf, exp

    assert previous is not None and previous_scope is not None and root_scope is not None

    return Verdict(
        model=model,
        cid=cid,
        issuer=path[0],
        holder=previous["holder"],
        cnf=previous["cnf"],
        path=tuple(path),
        jtis=tuple(jtis),
        kids=tuple(kids),
        budget_path=tuple(budget_path),
        scope=previous_scope,
        root_scope=root_scope,
        session_id=session_id,
        task=task,
        expires_at=previous["exp"],
        depth=depth,
    )
