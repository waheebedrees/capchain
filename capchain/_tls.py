"""TLS adapter: the only place peer identity and channel binding enter."""

from __future__ import annotations

import ctypes
import logging
import os
import re
import ssl
from collections.abc import Callable
from typing import Protocol, runtime_checkable

from ._constants import (
    EXPORTER_LENGTH,
    MAX_AGENT_ID_CHARS,
)
from ._errors import Code
from ._errors import RejectError as Reject

_SPIFFE_RE = re.compile(r"spiffe://[a-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)+")

RFC9266_LABEL = b"EXPORTER-Channel-Binding"
RFC9266_CONTEXT = b""  # spec: zero-length string, not None

log = logging.getLogger(__name__)


class ChannelBindingError(Exception):  # type: ignore[no-redef]
    code = "UNAVAILABLE"


@runtime_checkable
class TlsAdapter(Protocol):
    def peer_id(self, tls_socket: object) -> str: ...
    def channel_binding(self, tls_socket: object) -> bytes: ...


def _is_spiffe_id(s: object) -> bool:
    if not (isinstance(s, str) and len(s) <= MAX_AGENT_ID_CHARS and _SPIFFE_RE.fullmatch(s)):
        return False
    return all(seg not in (".", "..") for seg in s.split("/")[3:])


def spiffe_id_from_sslsocket(
    tls_socket: object,
) -> str:
    """Reference peer_id for a Python ssl.SSLSocket with mTLS.

    Reads the peer certificate from the live socket and returns its SPIFFE
    URI SAN. The socket must belong to a context that verifies peers: a
    socket that merely *has* a certificate is not enough, because with
    CERT_NONE the peer controls that certificate.
    """
    if not isinstance(tls_socket, ssl.SSLSocket):
        raise Reject(
            Code.INTERNAL,
            "peer_id: not an SSLSocket",
        )

    context = getattr(tls_socket, "context", None)
    if context is None or context.verify_mode != ssl.CERT_REQUIRED:
        raise Reject(
            Code.POLICY_DENIED,
            "peer_id: TLS context does not verify peers",
        )

    try:
        cert = tls_socket.getpeercert()
    except (ValueError, OSError) as exc:
        raise Reject(
            Code.POLICY_DENIED,
            f"peer_id: {type(exc).__name__}",
        ) from None
    if not cert:
        raise Reject(
            Code.POLICY_DENIED,
            "peer_id: no peer certificate",
        )

    for kind, value in cert.get("subjectAltName", ()):
        if kind == "URI" and isinstance(value, str) and value.startswith("spiffe://"):
            return value
    raise Reject(
        Code.POLICY_DENIED,
        "peer_id: no SPIFFE URI SAN",
    )


def _load_openssl():
    if os.name != "nt":
        raise NotImplementedError("Windows-only ctypes binding in this demo.")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetModuleHandleW.restype = ctypes.c_void_p
    for name in (
        "libssl-3",
        "libssl-3-x64",
        "libssl-1_1",
        "libssl-1_1-x64",
    ):
        h = kernel32.GetModuleHandleW(name)
        if h:
            return ctypes.CDLL(name, handle=h)

    raise RuntimeError("could not locate libssl in this process")


def _ssl_pointer(ssl_obj) -> int:
    inner = ssl_obj._sslobj

    # PyObject_HEAD size for *this* interpreter, then skip `Socket`
    head = object.__basicsize__  # 16 on normal 64-bit builds
    ptr_size = ctypes.sizeof(ctypes.c_void_p)
    ptr = ctypes.c_void_p.from_address(id(inner) + head + ptr_size).value
    if not ptr:
        raise RuntimeError("null SSL*")
    return ptr


if os.name == "nt":
    _SSL = _load_openssl()
    _SSL.SSL_export_keying_material.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_int,
    ]
    _SSL.SSL_export_keying_material.restype = ctypes.c_int
    _SSL.SSL_get_version.argtypes = [ctypes.c_void_p]
    _SSL.SSL_get_version.restype = ctypes.c_char_p


def native_export_keying_material(
    ssl_obj,
    length=EXPORTER_LENGTH,
    label=RFC9266_LABEL,
    context=RFC9266_CONTEXT,
) -> bytes:
    """Sync; the C call is microseconds.  Do not block on it from async code
    unless the SSL object is thread-safe to touch (it is, but you should
    hold a reference so it doesn't get GC'd)."""

    if isinstance(label, str):
        label = label.encode("ASCII")

    if isinstance(context, str):
        context = context.encode("ASCII")

    ptr = _ssl_pointer(ssl_obj)
    out = ctypes.create_string_buffer(length)
    use_ctx = 1 if context is not None else 0
    ctx = context or b""
    rc = _SSL.SSL_export_keying_material(
        ptr,
        out,
        length,
        label,
        len(label),
        ctx,
        len(ctx),
        use_ctx,
    )
    if rc != 1:
        raise RuntimeError(f"SSL_export_keying_material returned {rc}")
    return out.raw


def channel_binding(
    sslsock: ssl.SSLSocket,
    length=EXPORTER_LENGTH,
    label=RFC9266_LABEL,
    context=RFC9266_CONTEXT,
) -> bytes:

    try:
        material = native_export_keying_material(
            sslsock,
            length=length,
            label=label,
            context=context,
        )

    except (
        RuntimeError,
        ssl.SSLError,
        ValueError,
    ) as exc:
        raise ChannelBindingError(
            "NO_CHANNEL_BINDING",
            f"export_keying_material unavailable: {exc}",
        ) from None
    if not material:
        raise ChannelBindingError(
            "NO_CHANNEL_BINDING",
            "empty exporter output",
        )
    return material


class MutualTlsAdapter:
    """Default adapter. Validates the SPIFFE trust domain, not just the scheme.

    `trust_domains` is required and has no default. Enumerating the domains
    you trust is the decision that makes `peer_id` meaningful; leaving it
    implicit is how a gateway ends up accepting `spiffe://evil.example/...`.

    The default `peer_id` reads the verified peer certificate from an
    `ssl.SSLSocket`. Pass a different callable only for a non-`ssl` stack,
    and read the certificate from that stack's verified peer identity — not
    from a header or request field.
    """

    __slots__ = (
        "_binder",
        "_peer_id",
        "_trust_domains",
    )

    def __init__(
        self,
        peer_id: Callable[[object], str] | None = None,
        *,
        trust_domains: frozenset[str],
        binder: Callable[[object], bytes] = channel_binding,
    ) -> None:
        if not isinstance(trust_domains, frozenset) or not trust_domains:
            raise ValueError("trust_domains must be a non-empty frozenset")
        for td in trust_domains:
            if not isinstance(td, str) or not td or "/" in td:
                raise ValueError(f"invalid trust domain: {td!r}")
        self._peer_id = peer_id if peer_id is not None else spiffe_id_from_sslsocket
        self._trust_domains = trust_domains
        self._binder = binder

    def peer_id(self, tls_socket: object) -> str:
        value = self._peer_id(tls_socket)
        if not isinstance(value, str):
            raise Reject(
                Code.POLICY_DENIED,
                "peer identity must be a string",
            )
        if not _is_spiffe_id(value):
            raise Reject(
                Code.POLICY_DENIED,
                "peer identity is not a valid SPIFFE ID",
            )
        if not value.startswith("spiffe://"):
            raise Reject(
                Code.POLICY_DENIED,
                "peer identity is not a SPIFFE ID",
            )
        rest = value[len("spiffe://") :]
        slash = rest.find("/")
        if slash <= 0:
            raise Reject(
                Code.POLICY_DENIED,
                "malformed SPIFFE ID",
            )
        trust_domain = rest[:slash]
        if trust_domain not in self._trust_domains:
            raise Reject(
                Code.POLICY_DENIED,
                f"untrusted SPIFFE trust domain {trust_domain!r}",
            )
        return value

    def channel_binding(self, tls_socket: object) -> bytes:
        return self._binder(tls_socket)
