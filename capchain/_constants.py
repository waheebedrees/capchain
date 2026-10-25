"""capchain constants.

Single source of truth for wire version, domain-separation labels, size
limits, field sets, and the canonical JSON bounds. Every constant that
affects the wire format or a size bound lives here.

This module is a leaf: it imports nothing from the package. Any module
may import from it without creating a cycle.

Invariant: every domain label derives from WIRE_VERSION. Bumping
WIRE_VERSION invalidates every label in the file simultaneously - a
signature under an old label must not verify under a new one.
"""
from __future__ import annotations



# Wire version and derived labels

WIRE_VERSION: int = 2
"""Mandatory first field of every signed payload. A verifier that does
not understand a version MUST raise VERSION_UNSUPPORTED, never attempt
to interpret the rest."""

WIRE: str = f"v{WIRE_VERSION}"
"""Label component derived from WIRE_VERSION. Every domain string below
is built from it."""

CTX_BLOCK: bytes = f"capchain/{WIRE}/block".encode("ascii")
CTX_POP: bytes = f"capchain/{WIRE}/pop".encode("ascii")
CTX_ENROLL: bytes = f"capchain/{WIRE}/enroll".encode("ascii")
LINK_LABEL: bytes = f"capchain/{WIRE}/block-link".encode("ascii")

BudgetPath = tuple[tuple[str, int], ...]
"""((jti, cap), ...) from root to leaf."""

# Sentinels

ANY: str = "*"
"""The only wildcard in Scope. An empty frozenset means NOTHING, never
everything. Using emptiness as 'unrestricted' is a silent attenuation
bypass on the parent side of is_subset_of."""

GENESIS_PREV_HASH: str = "0" * 64
"""Sentinel for Block.prev on block 0. Not a hash of anything; chosen
so it cannot collide with a real link hash (sha256 hex of a non-empty
byte string)."""

GENESIS_LINK: str = GENESIS_PREV_HASH
"""Alias used by _wire and _chain."""

GENESIS_HASH: str = GENESIS_PREV_HASH
"""Alias used by _evidence for the first prev_hash."""

HEX: frozenset[str] = frozenset("0123456789abcdef")

# Key and signature sizes

PUBLIC_KEY_BYTES: int = 32
PRIVATE_SEED_BYTES: int = 32
SIGNATURE_BYTES: int = 64
THUMBPRINT_HEX_CHARS: int = 64

# Proof and channel binding

EXPORTER_LENGTH: int = 32
"""RFC 9266 exporter length. Canonical name; RFC9266_LENGTH is an alias."""

RFC9266_LENGTH: int = EXPORTER_LENGTH
"""Alias for EXPORTER_LENGTH; matches RFC 9266 terminology."""

MIN_NONCE_CHARS: int = 16
MAX_NONCE_CHARS: int = 64

# Envelope and frame sizes

MAX_POP_BYTES: int = 8 * 1024
MAX_ENVELOPE_BYTES: int = MAX_POP_BYTES
"""Alias: the PoP and enrollment envelopes share the same byte budget."""

MAX_TOKEN_BYTES: int = 32 * 1024
MAX_BLOCKS: int = 16

MAX_FRAME_BYTES: int = 1 << 20
"""Outer message-framing limit for transports that frame capchain
payloads. Not enforced by the wire layer itself."""

# Canonical JSON
MAX_IDENT_CHARS = 128

MAX_STRING_CHARS: int = 512
MAX_KEY_CHARS: int = 64
MAX_OBJECT_KEYS: int = 128
MAX_LIST_ITEMS: int = 256
MAX_NESTING: int = 8
MAX_DEPTH: int = MAX_NESTING
"""Alias for MAX_NESTING; both names appear in call sites."""

MAX_INT: int = 2**53
"""JSON is decoded by many languages. Anything above 2**53 loses
precision in IEEE-754 doubles, so two conforming parsers can disagree
on the value after a round-trip. Reject rather than silently truncate."""

# Identity and context

MAX_AGENT_ID_CHARS: int = 512
MAX_SESSION_ID_CHARS: int = 128
MAX_TASK_CHARS: int = 512
MAX_CID_CHARS: int = 128
MAX_JTI_CHARS: int = 128
MAX_URI_CHARS: int = 512
MAX_RESOURCE_CHARS: int = 128
MAX_ACTION_CHARS: int = 128

# Scope

MAX_TOOLS: int = 128
MAX_DOMAINS: int = 128
MAX_AUDIENCE: int = 128

MAX_SCOPE_TOOLS: int = MAX_TOOLS
MAX_SCOPE_DOMAINS: int = MAX_DOMAINS
MAX_SCOPE_AUDIENCE: int = MAX_AUDIENCE
"""Aliases retained for call sites that use the MAX_SCOPE_* spelling."""

# Errors

MAX_DETAIL_CHARS: int = 512
MAX_REJECT_DETAIL: int = MAX_DETAIL_CHARS
"""Alias for MAX_DETAIL_CHARS."""

# Evidence

MAX_EVIDENCE_WINDOW: int = 10_000
MAX_PAYLOAD_HASH_CHARS: int = 71
"""len('sha256:') + 64 hex chars."""

# Pinning

MAX_PIN_VALUE_BYTES: int = 4096

# Field-set shapes

BLOCK_FIELDS: frozenset[str] = frozenset(
    {
        "ver", "typ", "cid", "jti", "iss", "holder", "cnf", "sid",
        "task", "scope", "nbf", "exp", "max_depth", "prev", "model",
    }
)
POP_FIELDS: frozenset[str] = frozenset(
    {"ver", "typ", "aud", "ath", "res", "act", "ph", "ts", "nonce", "cb"}
)
ENROLL_FIELDS: frozenset[str] = frozenset({"ver", "typ", "aud", "cb", "ts"})
SCOPE_FIELDS: frozenset[str] = frozenset(
    {"tools", "budget", "domains", "audience"})
