"""Hash-chained audit records."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import _canonical as canonical


@dataclass(frozen=True, slots=True)
class Evidence:
    """One immutable audit record.

    On an admission record, `cost_micros` is the reservation. The settled
    amount appears on a follow-up SETTLED record linked by `related_id`.
    """

    action_id: str
    code: str
    cid: str
    jtis: tuple[str, ...]
    peer_id: str
    issuer: str
    holder: str
    action: str
    resource: str
    payload_hash: str
    cost_micros: int
    ts: int
    pop_thumbprint: str
    channel_bound: bool
    prev_hash: str
    verifier: str = ""
    related_id: str = ""

    def digest(self) -> str:
        return hashlib.sha256(
            canonical.encode(
                {
                    "action_id": self.action_id,
                    "code": self.code,
                    "cid": self.cid,
                    "jtis": list(self.jtis),
                    "peer_id": self.peer_id,
                    "issuer": self.issuer,
                    "holder": self.holder,
                    "action": self.action,
                    "resource": self.resource,
                    "payload_hash": self.payload_hash,
                    "cost_micros": self.cost_micros,
                    "ts": self.ts,
                    "pop_thumbprint": self.pop_thumbprint,
                    "channel_bound": self.channel_bound,
                    "prev_hash": self.prev_hash,
                    "verifier": self.verifier,
                    "related_id": self.related_id,
                }
            )
        ).hexdigest()
