"""Capability scope and the two presentation models."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ._constants import (
    ANY,
    MAX_AUDIENCE,
    MAX_DOMAINS,
    MAX_INT,
    MAX_STRING_CHARS,
    MAX_TOOLS,
    SCOPE_FIELDS,
)
from ._errors import Code
from ._errors import RejectError as Reject


class Model:
    """How a token is bound to its presenter."""

    PEER_BOUND = "peer_bound"
    """mTLS peer identity must equal the leaf holder. No per-request proof."""

    KEY_BOUND = "key_bound"
    """PEER_BOUND plus a single-use proof of possession on every request."""


MODELS = frozenset({Model.PEER_BOUND, Model.KEY_BOUND})


def _normalize(name: str, values: Iterable[str], limit: int) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{name} must be a collection of strings, not a string")
    result = frozenset(values)
    for item in result:
        if not isinstance(item, str) or not item or len(item) > MAX_STRING_CHARS:
            raise ValueError(f"{name} must contain non-empty strings")
    if ANY in result and len(result) != 1:
        raise ValueError(f"{name}: '{ANY}' must be the only member")
    if len(result) > limit:
        raise ValueError(f"too many {name}")
    return result


@dataclass(frozen=True, slots=True)
class Scope:
    """What a token permits.

    tools      "resource:action" strings the request must match.
    audience   verifier IDs allowed to accept the token. Never empty.
    domains    target hosts. Empty means no domain access; {"*"} means any.
    budget     spend ceiling in micros for this hop.

    Narrowing is monotone: a subset scope never grants more than its parent.
    """

    tools: frozenset[str]
    budget_micros: int
    audience: frozenset[str]
    domains: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "tools",
            _normalize("tools", self.tools, MAX_TOOLS),
        )
        object.__setattr__(
            self,
            "audience",
            _normalize(
                "audience",
                self.audience,
                MAX_AUDIENCE,
            ),
        )
        object.__setattr__(
            self,
            "domains",
            _normalize(
                "domains",
                self.domains,
                MAX_DOMAINS,
            ),
        )
        if not self.audience:
            raise ValueError("audience must not be empty")
        if type(self.budget_micros) is not int or self.budget_micros < 0:
            raise ValueError("budget_micros must be a non-negative int")
        if self.budget_micros > MAX_INT:
            raise ValueError(f"budget_micros must be <= {MAX_INT}")

    def allows_tool(self, tool: str) -> bool:
        return ANY in self.tools or tool in self.tools

    def allows_verifier(self, verifier_id: str) -> bool:
        return ANY in self.audience or verifier_id in self.audience

    def allows_domain(self, host: str) -> bool:
        return ANY in self.domains or host in self.domains

    def is_subset_of(self, parent: Scope) -> bool:
        if ANY not in parent.tools and not self.tools <= parent.tools:
            return False
        if self.budget_micros > parent.budget_micros:
            return False
        if ANY not in parent.domains and not self.domains <= parent.domains:
            return False
        return not (ANY not in parent.audience and not self.audience <= parent.audience)

    def to_body(self) -> dict:
        return {
            "tools": sorted(self.tools),
            "budget": self.budget_micros,
            "domains": sorted(self.domains),
            "audience": sorted(self.audience),
        }

    @staticmethod
    def from_body(body: object) -> Scope:
        if not isinstance(body, dict) or set(body) != SCOPE_FIELDS:
            raise Reject(
                Code.TOKEN_MALFORMED,
                "scope shape",
            )

        sets: dict[str, frozenset[str]] = {}
        for name in (
            "tools",
            "domains",
            "audience",
        ):
            values = body[name]
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                raise Reject(
                    Code.TOKEN_MALFORMED,
                    f"scope.{name}",
                )
            if values != sorted(set(values)):
                raise Reject(
                    Code.TOKEN_MALFORMED,
                    f"scope.{name} not sorted/unique",
                )
            sets[name] = frozenset(values)

        budget = body["budget"]
        if type(budget) is not int:
            raise Reject(
                Code.TOKEN_MALFORMED,
                "scope.budget",
            )

        try:
            return Scope(
                tools=sets["tools"],
                budget_micros=budget,
                audience=sets["audience"],
                domains=sets["domains"],
            )
        except ValueError as exc:
            raise Reject(Code.TOKEN_MALFORMED, str(exc)) from None
