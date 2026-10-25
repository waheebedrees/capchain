"""Wire v2 structures: blocks, tokens, and signed envelopes."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from capchain._scope import Scope

from . import _canonical as canonical
from ._errors import Code, Reject
from ._keys import  BaseWorkloadKey
from ._constants import (
    SIGNATURE_BYTES,
    PUBLIC_KEY_BYTES,
    LINK_LABEL,
    MAX_BLOCKS,
    MAX_TOKEN_BYTES,
    MAX_ENVELOPE_BYTES,
    WIRE,
    WIRE_VERSION,
    CTX_BLOCK,
)


def bounded_str(value: object, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit


def is_int(value: object) -> bool:
    return type(value) is int


@dataclass(frozen=True, slots=True)
class Block:
    """One link in a capability chain."""

    body_raw: bytes
    signature: bytes
    signer_public_key: bytes

    def body(self) -> dict:
        return canonical.decode(self.body_raw)


def link_hash(block: Block) -> str:
    """Length-prefixed hash binding a block to its successor's `prev`."""

    def framed(data: bytes) -> bytes:
        return len(data).to_bytes(4, "big") + data

    return hashlib.sha256(
        LINK_LABEL
        + framed(block.body_raw)
        + framed(block.signature)
        + framed(block.signer_public_key)
    ).hexdigest()


def sign_block(key: BaseWorkloadKey, body: dict) -> Block:
    raw = canonical.encode(body)
    return Block(raw, key.sign(CTX_BLOCK, raw), key.public_key)


def derive_jti(prev_link: str, issuer: str, scope: Scope) -> str:
    """Content-addressed jti: siblings from the same (parent block, issuer,
    scope) share one ledger hop, so a delegator's total spend in a given
    scope is bounded by that scope's budget even when split across children.
    """
    h = hashlib.sha256()
    h.update(f"capchain/{WIRE}/attenuate-jti\x00".encode("ascii"))
    h.update(prev_link.encode("ascii"))
    h.update(b"\x00")
    h.update(issuer.encode("utf-8"))
    h.update(b"\x00")
    h.update(canonical.encode(scope.to_body()))
    return h.hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class Token:
    """An ordered chain of blocks. Encodes to exactly one byte sequence."""

    blocks: tuple[Block, ...]

    def encode(self) -> bytes:
        return json.dumps(
            {
                "v": WIRE_VERSION,
                "blocks": [
                    {
                        "b": canonical.b64e(b.body_raw),
                        "s": canonical.b64e(b.signature),
                        "k": canonical.b64e(b.signer_public_key),
                    }
                    for b in self.blocks
                ],
            },
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")

    @staticmethod
    def decode(raw: bytes) -> "Token":
        if not isinstance(raw, (bytes, bytearray)):
            raise Reject(Code.TOKEN_MALFORMED, "token must be bytes")
        raw = bytes(raw)
        if len(raw) > MAX_TOKEN_BYTES:
            raise Reject(Code.TOKEN_TOO_LARGE, str(len(raw)))

        try:
            document = canonical.loads_strict(raw)
        except Reject as exc:
            raise Reject(Code.TOKEN_MALFORMED,
                         f"json: {exc.detail or exc.code}") from None
        except Exception as exc:
            raise Reject(Code.TOKEN_MALFORMED,
                         f"json: {type(exc).__name__}") from None

        if not isinstance(document, dict) or set(document) != {"v", "blocks"}:
            raise Reject(Code.TOKEN_MALFORMED, "envelope shape")
        if not is_int(document["v"]):
            raise Reject(Code.TOKEN_MALFORMED, "version must be int")
        if document["v"] != WIRE_VERSION:
            raise Reject(Code.VERSION_UNSUPPORTED, f"v={document['v']}")

        raw_blocks = document["blocks"]
        if not isinstance(raw_blocks, list) or not 1 <= len(raw_blocks) <= MAX_BLOCKS:
            raise Reject(Code.TOKEN_MALFORMED, "block list")

        blocks: list[Block] = []
        for index, entry in enumerate(raw_blocks):
            if not isinstance(entry, dict) or set(entry) != {"b", "s", "k"}:
                raise Reject(Code.TOKEN_MALFORMED, f"block {index} shape")
            try:
                block = Block(canonical.b64d(entry["b"]), canonical.b64d(
                    entry["s"]), canonical.b64d(entry["k"]))
            except Reject as exc:
                raise Reject(Code.TOKEN_MALFORMED,
                             f"block {index}: {exc.code}") from None
            if (
                len(block.signature) != SIGNATURE_BYTES
                or len(block.signer_public_key) != PUBLIC_KEY_BYTES
            ):
                raise Reject(Code.TOKEN_MALFORMED, f"block {index} lengths")
            blocks.append(block)

        token = Token(tuple(blocks))
        if token.encode() != raw:
            raise Reject(Code.TOKEN_MALFORMED, "non-canonical envelope")
        return token


@dataclass(frozen=True, slots=True)
class Signed:
    """A detached signed body: proof of possession or enrollment."""

    body_raw: bytes
    signature: bytes
    public_key: bytes

    def encode(self) -> bytes:
        return json.dumps(
            {
                "b": canonical.b64e(self.body_raw),
                "s": canonical.b64e(self.signature),
                "k": canonical.b64e(self.public_key),
            },
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")

    @staticmethod
    def decode(raw: bytes) -> "Signed":
        if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_ENVELOPE_BYTES:
            raise Reject(Code.POP_MALFORMED, "size")
        raw = bytes(raw)
        try:
            document = canonical.loads_strict(raw)
            if not isinstance(document, dict) or set(document) != {"b", "s", "k"}:
                raise Reject(Code.POP_MALFORMED, "shape")
            envelope = Signed(
                canonical.b64d(document["b"]), canonical.b64d(document["s"]), canonical.b64d(document["k"])
            )
        except Reject as exc:
            raise Reject(Code.POP_MALFORMED, exc.detail or exc.code) from None
        except Exception as exc:
            raise Reject(Code.POP_MALFORMED, type(exc).__name__) from None

        if (
            len(envelope.signature) != SIGNATURE_BYTES
            or len(envelope.public_key) != PUBLIC_KEY_BYTES
        ):
            raise Reject(Code.POP_MALFORMED, "lengths")
        if envelope.encode() != raw:
            raise Reject(Code.POP_MALFORMED, "non-canonical envelope")
        return envelope
