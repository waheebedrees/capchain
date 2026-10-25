# capchain

A capability-chain primitive for machine-to-machine authorization. Tokens are
append-only chains of Ed25519-signed blocks; a gateway validates the chain, binds
it to the presenting workload via mTLS, verifies an optional per-request proof of
possession, checks the request against the chain's scope and against server-held
context, reserves budget, and writes an audit record — in that order, before any
side effect is permitted.

---

## 1. What capchain is and is not

**Is**: a verified primitive for *"may this workload, on this connection, spend
this much of this chain's authority on this one request, and did the charge
actually happen?"* Every admit and every denial produces an evidence record that
is joined to the settlement.

**Is not**: a policy engine, an IdP, a secrets store, an HSM, a rate limiter, a
workload identity system. It consumes identity from mTLS, authority from a signed
token, and returns a `Permit` or raises `Reject`.

If you are building a policy engine, capchain is the *bottom* of it — the part
that answers "was this chain valid, is this the right peer, is this request in
scope, is this within budget." Business rules (per-tenant quotas, time-of-day,
body-content conditions) are layered above.

---

## 2. Threat model

### 2.1 Assets

| Asset | Where it lives | Loss mode |
|---|---|---|
| Issuer root private key | Issuer process / HSM / KMS | Forge any chain from this issuer |
| Holder private key | Workload process | Impersonate holder; spend its budget |
| Token bytes | Wire, logs, message queues | Bounded by TTL, revocation, and (in KEY_BOUND) the private key |
| PoP envelope | One TLS connection | Single-use nonce; bound to channel |
| Budget headroom | Ledger (memory/Redis/Postgres) | Exhaustion / lock-up |
| Evidence chain | Evidence store | Loss of audit; detectable via hash chain |
| Peer identity | TLS handshake | All of `WRONG_HOLDER`, `WRONG_AUDIENCE`, `enroll` binding |

### 2.2 Adversary classes

| Adversary | Capabilities | Defeated by |
|---|---|---|
| **A1 — Passive network** | Reads wire traffic | TLS. Nothing token-level is cleartext. |
| **A2 — Token exfiltration** | Reads token from a log / queue / memory dump | KEY_BOUND: thief lacks `cnf` private key → `POP_MISMATCH`. |
| **A3 — Proof relay** | Captures a valid `(token, proof)` and replays on a different connection | RFC 9266 channel binding → `CB_MISMATCH`. Same connection: nonce reuse → `REPLAY`. |
| **A4 — Peer impersonation** | Connects with attacker cert | Gateway's `TlsAdapter.peer_id` reads the SAN → `WRONG_HOLDER`. |
| **A5 — Scope probing** | Sends requests that should fail policy to learn what is allowed | Nonce burned *before* peer/policy checks — probing costs a nonce per attempt. |
| **A6 — Delegation abuse** | Holds a delegated token, tries to widen | `attenuate` rejects at signing; `verify_chain` rejects at verify. |
| **A7 — Compromised workload process** | Full control of one leaf | Short TTL + `RevocationStore.revoke_key(cnf)` + `revoke_agent(holder)`. |
| **A8 — Compromised issuer** | Signing key | *Not defended.* Rotate, revoke, re-mint. |
| **A9 — Compromised gateway** | Executable, dependencies | *Not defended.* The gateway is a trusted component. |
| **A10 — Misconfigured TlsAdapter** | `peer_id` reads a header | *Not detectable.* Section 3. |
| **A11 — TLS-terminating sidecar** | Terminates TLS in front of the app | `peer_id` returns sidecar cert; `channel_binding` returns app↔sidecar. *Both guarantees lost.* Section 11.4. |
| **A12 — Quantum adversary** | Harvest-now-decrypt-later against long-lived chains | Ed25519 is *not* post-quantum. Use short TTLs; long-lived root is at risk. |

### 2.3 Attacker capabilities explicitly *out of scope*

- Control of the issuer root private key.
- Control of the workload's own private key (not just its token).
- Control of the gateway binary or its dependencies.
- Physical access to the host, memory, or storage.
- Side-channel attacks on the JIT/interpreter/CPU (not a goal of this library).
- Denial of service (no rate limiting built in; put it in front).

---

## 3. Trust boundaries and inputs

Three inputs determine *who* the requester is and *what connection they are on*.
Every other check compares against these. Get one of them from the wrong source
and the entire protocol is defeated silently.

| Input | Source | Where the library reads it | If misconfigured |
|---|---|---|---|
| **Peer identity** | The peer's certificate SAN, from the verified TLS handshake | `TlsAdapter.peer_id(tls_socket)` | A1–A6 all pass; attacker is whoever they claim to be |
| **Channel binding** | RFC 9266 exporter over the current handshake | `TlsAdapter.channel_binding(tls_socket)` | A3 succeeds — PoP relayable |
| **Session / task / domain** | Server-side state, out of band from the request | `ServerContext(...)` fields | Attacker crosses sessions, tasks, or hosts |

The library cannot verify these are correctly populated. `MutualTlsAdapter`
requires explicit `trust_domains` and reads the SAN from `getpeercert()`; the
default `peer_id` requires an `ssl.SSLSocket` in `CERT_REQUIRED` mode. That is
all that can be enforced in code. Everything else is a code-review or
deployment-checkbox obligation.

---

## 4. Cryptographic construction

### 4.1 Domain separation

Every signature is over `context_bytes || 0x00 || message`, where context is
one of four derived labels:

```
CTX_BLOCK  = b"capchain/v2/block"
CTX_POP    = b"capchain/v2/pop"
CTX_ENROLL = b"capchain/v2/enroll"
LINK_LABEL = b"capchain/v2/block-link"
```

Derived from `WIRE_VERSION` at module load. Bumping the version invalidates
every label simultaneously — a signature under `v2/block` cannot verify under
`v3/block` even if the message is identical.

The four labels are disjoint. A block signed under `CTX_BLOCK` cannot be
reinterpreted as a PoP or an enrollment (or as a `LINK_LABEL`-prefixed preimage)
because the leading bytes differ. This is what prevents cross-context signature
reuse — a block's signature is not a PoP, and a PoP's signature is not an
enrollment.

### 4.2 Canonical encoding

**Block bodies**: canonical JSON. `sort_keys=True`, `separators=(",", ":")`,
`ensure_ascii=False`, no floats, no `NaN`/`Infinity`, no duplicate keys,
integers only (bounded to ±2⁵³ at parse *and* validate time), bounded
string/key/nesting/list/object lengths. `decode()` re-encodes and compares —
any non-canonical spelling of a valid body is `CANONICAL_FORM`.

**Why this matters**: an Ed25519 signature is over the *bytes*. If two
encodings of the same logical object existed, a signature over one would not
verify against the other, and a *verifier* that parsed the alternate spelling
would either reject (safe) or interpret the fields differently (unsafe). The
canonical form removes the ambiguity entirely; there is exactly one byte
sequence per signed body.

**Envelopes**: JSON, insertion-ordered, *not* sorted. `Token.encode()` produces
`{"v":2,"blocks":[...]}`; `Token.decode()` does not use `canonical.decode` (which
would reject the unsorted form) but does re-encode and compare
(`token.encode() != raw` → reject). Same for `Signed`. **Do not** call
`canonical.decode` on an envelope; **do** call it on block bodies and PoP/enroll
bodies. The distinction is load-bearing.

### 4.3 Wire format

**Token envelope** (bytes → ASCII JSON):

```json
{"v":2,"blocks":[{"b":"<b64url>","s":"<b64url>","k":"<b64url>"},...]}
```

`b` = block body bytes, `s` = Ed25519 signature (64 bytes), `k` = signer raw
public key (32 bytes). All base64url without padding.

**Block body** (canonical JSON, one per chain link):

```
ver        2
typ        "authority" (block 0) | "delegation" (subsequent)
cid        chain id, same in every block
jti        block id, unique per block
iss        issuer identity: block 0 is the root; else previous holder
holder     the workload that now holds it
cnf        thumbprint of the key that may delegate or prove
sid        session id (from server state)
task       task label (from server state)
scope      {"tools":[s...], "budget":int, "domains":[s...], "audience":[s...]}
nbf, exp   validity window (POSIX seconds; nested: child ≤ parent)
max_depth  max number of delegations allowed (0 = leaf only)
prev       link_hash(prev block) | "0"*64 for block 0
model      "key_bound" | "peer_bound"
```

**Link hash** (framed SHA-256 over body, signature, and signer key):

```
sha256(
  LINK_LABEL
  || u32be(len(body))  || body
  || u32be(len(sig))   || sig
  || u32be(len(pubkey))|| pubkey
).hexdigest()
```

Length framing prevents concatenation ambiguity. The link hash binds *all three*
components — a body altered independently of its signature breaks the successor
link, not just the signature check.

**PoP body** (canonical JSON):

```
ver=2  typ="pop"
aud    verifier identity
ath    "sha256:" + hex(sha256(token_bytes))
res, act    resource and action strings
ph     "sha256:" + hex(sha256(request_body))
ts     POSIX seconds
nonce  single-use; 16–64 chars
cb     b64url(channel_binding_value)
```

**Enrollment body** (canonical JSON): `{ver=2, typ="enroll", aud, cb, ts}`.

### 4.4 Ed25519

Chosen for: signature verification is ~10× faster than RSA-2048; keys are 32
bytes; no per-signature randomness (deterministic nonce from hash of message
and key). Not chosen for: post-quantum security (it has none), batch
verification (not needed here — one signature per block), or key blinding
(`ed25519-dalek` has it; `cryptography` does not expose it). If you need
post-quantum guarantees, capchain is the wrong primitive — swap the underlying
signature scheme is a wire-format change (v3).

---

## 5. Verification sequence

`Gateway._admit` runs the checks below, in this order. The order is not
arbitrary; each step is justified by what it protects.

| # | Check | Failure code | Why here |
|---|---|---|---|
| 1 | `verify_chain(token, roots, now, max_depth, skew=self._chain_skew)` | `TOKEN_*`, `CHAIN_*`, `SCOPE_*`, `TOO_DEEP`, `UNKNOWN_ISSUER`, `MODEL_MISMATCH` | Signature over the whole chain before *any* field is interpreted. Prevents type-confusion attacks on malformed bodies. |
| 2 | `verdict.model ∈ gateway.allowed_models` | `POLICY_DENIED` | Before PoP — the model determines whether PoP is required and, if so, under what rules. |
| 3 | (KEY_BOUND) `verify_proof_of_possession(...)` | `POP_*`, `CB_MISMATCH` | Signature over the PoP body, then field bindings `aud`, `ath`, `res`, `act`, `ph`, `ts`, `cb`. Establishes key possession — the only step in the pipeline that does. |
| 4 | (KEY_BOUND) `replay.consume(nonce)` | `REPLAY`, `STATE_UNAVAILABLE` | Nonce burned **before** any peer, audience, policy, or scope check. A failed probe costs a nonce per attempt (A5). |
| 5 | (PEER_BOUND) `proof` MUST be absent | `MODEL_MISMATCH` | A peer-bound token with a proof suggests the client is confused about which model it holds; rejecting is better than guessing. |
| 6 | `peer_id == verdict.holder` | `WRONG_HOLDER` | Presenter identity from mTLS vs. chain leaf. |
| 7 | `verdict.scope.allows_verifier(gateway.agent_id)` | `WRONG_AUDIENCE` | Chain says which verifier is allowed. |
| 8 | `policy.allows_root(verdict.issuer)` | `POLICY_DENIED` | Root is in the gateway's trust set. |
| 9 | Every `(path[i], path[i+1])` ∈ `policy.edges` | `POLICY_DENIED` | Delegation topology allowed. |
| 10 | `verdict.scope.allows_tool(call.tool)` | `SCOPE_MISMATCH` | Request tool in leaf scope. |
| 11 | Domain check (if `ServerContext.domain` present; else per `domain_required_tools`) | `SCOPE_MISMATCH` | Target host in leaf scope. |
| 12 | `verdict.session_id == context.session_id` | `WRONG_SESSION` | Server-side session binding. |
| 13 | `verdict.task == context.task` | `WRONG_TASK` | Server-side task binding. |
| 14 | `cost_model(call, context, verdict)` | `INTERNAL` if missing/raising/non-int/negative | **Only after** identity, possession, audience, policy, scope, session, and task have all passed. Reads authenticated inputs only. |
| 15 | `reserve_micros ≤ verdict.scope.budget_micros` | `BUDGET_EXHAUSTED` | Fast reject before touching stores. |
| 16 | `revocation.find_revoked(agents, kids, cids, jtis)` | `REVOKED`, `STATE_UNAVAILABLE` | Any hop, any key, chain, or specific block revoked. |
| 17 | `ledger.reserve(cid, root_cap, path, amount, expires_at=…, now=…)` | `BUDGET_EXHAUSTED`, `BUDGET_CAP_CHANGED`, `STATE_UNAVAILABLE` | Reserve against root and every hop cap atomically. |
| 18 | Evidence admission record (`code=OK`) | `EVIDENCE_BROKEN` | If evidence cannot be written, reservation is refunded and admission is denied. |

### 5.1 Why the cost model is step 14 and not step 3

The cost model may query a pricing service or database. If it ran before the
identity and possession checks, an unauthenticated peer could drive backend
load from a connection it never had authority over — and, if the cost model
has side effects (a billing table, a remote "attempted" log, a per-call
charge), bill the operator for requests that would be rejected at step 3 or
step 10.

The trade-off is that a *broken* cost model does consume a nonce (step 4) and
does touch the replay store before failing at step 14 with `INTERNAL`. A
misconfigured cost model at startup therefore costs one nonce per attempt until
it is fixed. That is the correct side of the trade: a lost nonce is bounded,
per-process, and self-corrects when the model is fixed; unbounded pricing load
from an unauthenticated peer is not.

AEGIS/1 §10.1.1 states this normatively: *"Steps 1–13 before step 14. The
cost model may query a pricing service or database. Running it before
identity, possession, and scope are established lets an unauthorized peer
drive backend load — and bill someone for the privilege."* The pipeline above
is that ordering.

### 5.2 Skew tolerance

`verify_chain` accepts a `skew: int = 0` parameter. The tolerance applies
symmetrically:

- `now + skew < nbf` → `TOKEN_NOT_YET_VALID` (the token is too far in the
  future, even accounting for the verifier's clock being behind).
- `now - skew >= exp` → `TOKEN_EXPIRED` (the token is too far in the past,
  even accounting for the verifier's clock being ahead).

`skew=0` is strict and is the safe default for a verifier whose clock is
trusted. Set it to the fleet's NTP drift budget in production.

The gateway plumbs this through with a `chain_max_skew` constructor argument
which defaults to `pop_max_skew`. The two are split so a deployment with a slow
chain refresh cycle can widen the chain tolerance without widening the PoP
window. `Gateway.verify()` uses the same `_chain_skew`, so a CLI pre-flight
check and `_admit` cannot disagree about the same token at the same moment.

### 5.3 On denial

`_record_denial` appends an evidence record with `code = <original rejection
code>`. If the evidence store itself fails during denial recording, the failure
is logged and the original rejection is re-raised — the caller sees the actual
security decision, not `EVIDENCE_BROKEN`. The contrast with admission (step 18)
is deliberate: admission must fail closed when evidence cannot be written,
because admission has not happened until evidence exists; denial has already
happened by the time `_record_denial` runs, and the record is audit, not gate.

### 5.4 On success and exit

`Gateway.authorize` yields a `Permit`. `Permit.settle` writes the `SETTLED`
evidence record **before** the ledger (see §9.1). At exit from the `with` block:

| State at exit | Normal exit | Exception exit |
|---|---|---|
| `RESERVED` | refund | refund |
| `DISPATCHED` | commit + raise `INTERNAL` | commit silently, re-raise |
| `SETTLED` | commit | commit |
| `CANCELLED` | no-op | no-op |

A `DISPATCHED` state on clean exit means the caller marked the permit as
dispatched but never called `settle`. The side effect may have occurred, so the
reservation commits at the reserved amount and the exit raises `INTERNAL`
because the accounting is incomplete. Reconcile out of band against the
admission evidence record.

---

## 6. Properties

What the protocol guarantees when §3 inputs are correct and §2.3 is respected:

**P1 — Unforgeable capability.** Every block after 0 is signed by a key whose
thumbprint equals the parent's `cnf`. A third party cannot append a block on
another's behalf. (`verify_chain` block N>0: `thumbprint(signer) == prev.cnf`.)

**P2 — Monotone narrowing.** Scope is a subset of the parent's, at every hop,
for tools, budget, domains, and audience. Enforced on the signer side
(`attenuate`) and verifier side (`verify_chain`). Composition: transitivity
means leaf scope ⊆ root scope.

**P3 — Context drift detection.** `cid`, `sid`, `task`, `model`, `max_depth`
must match the root's across every block. `nbf` may only increase; `exp` may
only decrease. `attenuate` writes these correctly; `verify_chain` enforces them.

**P4 — Identity binding.** In `KEY_BOUND`, the PoP is signed by `cnf`, and
`cnf == holder`'s enrolled key. In `PEER_BOUND`, `peer_id == holder`. Either
way, holding the token is not sufficient to use it.

**P5 — Replay resistance.** PoP nonces are single-use, and consumption precedes
peer, policy, scope, and session checks. Cross-connection replay fails on
channel binding; same-connection replay fails on nonce.

**P6 — Budget at every hop.** A reservation is charged against root and every
hop cap; overrunning any cap fails. `settle` is bounded by the same caps.

**P7 — Tamper-evident audit.** Every admit and every denial is a record in a
hash chain. `evidence.verify_integrity()` detects deletion, insertion, and
modification.

**P8 — Evidence-before-ledger on settle.** `SETTLED` evidence is written first;
the ledger follows. A ledger failure after evidence success is reconcilable;
the reverse is not.

What is *not* guaranteed:

- **P1–P8 do not survive a compromised `TlsAdapter`.** If `peer_id` reads a
  header, P4 fails silently.
- **P2–P8 do not survive a compromised root key.** A1 with the root key can
  forge any chain.
- **P4–P5 do not survive a compromised leaf key.** A7 is a full compromise of
  that leaf's remaining TTL and budget.

---

## 7. Known attacks and their mitigations

| Attack | Mitigation | Reference |
|---|---|---|
| Token replay across connections | Channel binding to RFC 9266 exporter | §5 step 3 |
| Proof replay on same connection | Single-use nonce, burn before policy | §5 step 4 |
| Token theft from logs | KEY_BOUND requires `cnf` private key | §5 step 3 |
| Delegation scope widening | `Scope.is_subset_of` on sign + verify | §5 step 1, `attenuate` |
| Chain extension past `max_depth` | `len(blocks) > max_depth` check | §5 step 1 |
| Cross-issuer token use | `TrustedRoots.issuer_for(signer_pubkey)` | §5 step 1 |
| Type-confusion on block body | Signature verify *before* field access | §5 step 1 |
| Non-canonical JSON bypass | Re-encode-compare on `decode` | §4.2 |
| Cross-context signature reuse | Disjoint domain separation labels | §4.1 |
| Budget bypass via settle overrun | `settle` bounded by root and hop caps | §5 step 17 |
| Evidence tampering | Hash chain + `verify_integrity()` | §5 step 18 |
| Revocation bypass | Any of agent, key, chain, or jti | §5 step 16 |
| Session hijack across sessions | `ServerContext` binding | §5 steps 12–13 |
| Cross-tenant replay | `audience` + `ServerContext` | §5 steps 7, 12 |
| Cost-model DoS from unauthenticated peer | Cost model after all identity/possession checks | §5 step 14, §5.1 |
| Clock-skew-induced spurious rejection | `skew` parameter on `verify_chain` | §5 step 1, §5.2 |

---

## 8. Failure modes — fail-open or fail-closed?

Every check in §5 either admits or raises `Reject`. **There are no fail-open
paths** on the verifier side. Explicitly:

| Failure | Behavior |
|---|---|
| Chain signature invalid | `TOKEN_SIGNATURE` — denied |
| Chain too deep | `TOO_DEEP` — denied |
| Model not allowed | `POLICY_DENIED` — denied |
| PoP missing (KEY_BOUND) | `POP_REQUIRED` — denied |
| PoP malformed / wrong signature / wrong binding / stale | `POP_*` — denied |
| Channel binding mismatch | `CB_MISMATCH` — denied |
| Replay store raises | `STATE_UNAVAILABLE` — denied |
| Nonce already consumed | `REPLAY` — denied |
| Peer identity mismatch | `WRONG_HOLDER` — denied |
| Wrong audience | `WRONG_AUDIENCE` — denied |
| Root not in policy | `POLICY_DENIED` — denied |
| Edge not in policy | `POLICY_DENIED` — denied |
| Tool not in scope | `SCOPE_MISMATCH` — denied |
| Domain not in scope | `SCOPE_MISMATCH` — denied |
| Session mismatch | `WRONG_SESSION` — denied |
| Task mismatch | `WRONG_TASK` — denied |
| Cost model missing / raising / invalid | `INTERNAL` — denied |
| Reservation exceeds leaf cap | `BUDGET_EXHAUSTED` — denied |
| Revocation store raises | `STATE_UNAVAILABLE` — denied |
| Revoked agent/key/chain/token | `REVOKED` — denied |
| Ledger reserve returns `None` | `BUDGET_EXHAUSTED` — denied |
| Ledger reserve raises | `STATE_UNAVAILABLE` — denied |
| Admission evidence append fails | `EVIDENCE_BROKEN` — denied (reservation refunded) |
| Settlement evidence append fails | `EVIDENCE_BROKEN` — ledger untouched (charge stands at reserve) |

The evidence-before-ledger ordering at settle means a ledger failure after
evidence success **does not fail the request** — the tool ran, the charge is
real, and the operator reconciles from evidence. This is the one place the
protocol allows a partial state, and it is deliberate (see §9.1).

The tool itself may still fail after authorization; that is application error
handling, not a capchain failure.

---

## 9. Operational properties

### 9.1 Evidence is the source of truth on settle

`Permit.settle(actual)` writes the `SETTLED` evidence record **before** calling
`ledger.settle`. Rationale:

- **Evidence first**: if the ledger fails, the evidence has the actual cost and
  a `related_id` pointing at the admission record. Operator can reconcile the
  ledger against evidence.
- **Ledger first** (previously): if evidence fails, the ledger has moved but
  there is no settled record and no join key. The state cannot be reconstructed
  from the ledger alone.

The trade-off: a `SETTLED` record exists for a call the ledger has not yet
accepted. Reconciliation is idempotent on `action_id`; a background job can
read `SETTLED` records with `cost_micros != ledger.amount` and correct the
ledger.

### 9.2 Revocation semantics

`RevocationStore.find_revoked` is consulted with:

```python
agents = (verdict.path,)  # every workload on the path
kids = (verdict.kids + (verdict.cnf,),)  # every signing key
cids = ((verdict.cid,),)  # the chain
jtis = (verdict.jtis,)  # every block
```

Effective revocation levels:

| Revoke | Effect |
|---|---|
| `revoke_agent(spiffe_id)` | Every token whose path includes this identity |
| `revoke_key(cnf_hex)` | Every token signed by this key (all delegations *under* it) |
| `revoke_chain(cid)` | Every token in this root mint |
| `revoke_token(jti)` | Every token whose path includes this block |

Revocation is checked *after* PoP, so revoking a key does not prevent the
revoked key from burning a nonce. That is a deliberate trade: revocation is
rare, and a revoked peer that must consume a nonce to be rejected is
marginally less useful to an attacker.

### 9.3 Key custody model

Three keys, three processes, three trust levels:

| Key | Holder | Compromise impact | Recommended custody |
|---|---|---|---|
| Issuer root | Issuer process, ideally HSM/KMS | **Full** — forges any chain from that issuer | HSM, isolated process, no delegation running alongside |
| Intermediate holder | Each delegating workload | Bounded to that workload's subtree | Process-scoped seed in secure storage |
| Leaf holder | Each calling workload | Bounded to leaf TTL and remaining budget | Process-scoped, rotated on schedule |

If two of these are in the same process, the lower-trust party can forge the
higher-trust party's signatures, and the chain's guarantees degrade to the
weakest link. This is the discipline the protocol assumes but cannot enforce.

### 9.4 Rotation

- **TLS SVIDs** rotate on the platform's schedule (SPIRE / cert-manager). Each
  rotation changes `peer_id`'s source material but not the `peer_id` value — the
  SPIFFE ID is stable.
- **capchain keys** do **not** rotate automatically. A new `WorkloadKey` has a
  new `thumbprint`, so a new enrollment and re-issue of every token bound to it
  is required. Enrollments expire (`CAPCHAIN_ENROLL_TTL`, default 1 hour);
  tokens outlive enrollment, so a token issued before expiry remains valid
  until its own `exp`. To force invalidation, revoke the old key thumbprint.
- **Issuer root** rotation means a new key in `TrustedRoots` and a new entry in
  `Policy.root_issuers`. Old chains stop verifying once the old key is removed.

---

## 10. Deployment topologies

### 10.1 Single-node (development)

```
issuer ──── gateway ──── tool
       \         /
        in-memory stores
```

One process per role; all three stores in-memory. Cross-process replay
protection does **not** exist. Fine for `python -m capchain.selftest`. Not
fine for anything else with more than one gateway replica.

### 10.2 Multi-replica (production)

```
                        ┌── gateway 1 ──┐
issuer ── token ──► ... ──── gateway 2 ──┼──► tool
                        └── gateway N ──┘
                              │
                              ▼
                    Redis (replay, revocation, enrollments)
                    PostgreSQL (ledger, evidence)
```

All five stores shared and durable. `CAPCHAIN_ENV=production` refuses memory.
Prefer PostgreSQL for `ledger` and `evidence` (append-only semantics, AOF is a
weaker guarantee for Redis). See §12.5 for throughput limits.

### 10.3 Cross-domain (federated)

```
domain A issuer ──┐
                  ├─► gateway C (TrustedRoots has both A and B)
domain B issuer ──┘
```

A gateway trusts multiple roots by listing them in `TrustedRoots` and
`Policy.root_issuers`. Cross-domain delegation requires the edges to be
explicitly enumerated in the gateway's `Policy` — there is no implicit
federation.

### 10.4 Air-gapped / on-prem

Same as 10.2; only the Redis/Postgres URLs differ. All cryptographic
operations are local; the library never calls out to a third-party service.

---

## 11. TLS integration

The `TlsAdapter` is a two-method protocol. Your TLS stack determines which
implementation you use.

### 11.1 `ssl.SSLSocket` (sync server)

```python
tls = MutualTlsAdapter(trust_domains=frozenset({"spire.lab.acme"}))
```

Default `peer_id` reads `getpeercert()["subjectAltName"]` for a URI SAN starting
with `spiffe://`, and requires `context.verify_mode == ssl.CERT_REQUIRED`.
Default `channel_binding` calls `SSLSocket.export_keying_material(b"EXPORTER-
Channel-Binding", 32, None)` — Python 3.12+.

### 11.2 `asyncio.StreamWriter`

```python
class AsyncioTlsAdapter:
    def __init__(self, *, trust_domains):
        self._inner = MutualTlsAdapter(trust_domains=trust_domains)

    def peer_id(self, writer):
        return self._inner.peer_id(writer.get_extra_info("socket"))

    def channel_binding(self, writer):
        return self._inner.channel_binding(writer.get_extra_info("socket"))
```

### 11.3 gRPC / aiohttp / other

Provide your own `TlsAdapter` subclass. The contract is: `peer_id` returns the
verified SPIFFE ID from the peer certificate; `channel_binding` returns 32
bytes from the RFC 9266 exporter. **Both must read from the live connection,
not from request metadata.**

### 11.4 Service mesh — **read this**

If a sidecar (Istio, Linkerd, Cilium) terminates TLS, `getpeercert()` returns
the **sidecar's** certificate and `export_keying_material` returns the
app↔sidecar binding. Consequences:

- Every workload looks like the same peer to `peer_id`.
- Every PoP is bound to the wrong handshake.

Fixes, in order of preference:

1. **Passthrough TLS for these ports** — the app owns the handshake.
   (Istio: `traffic.sidecar.istio.io/excludeInboundPorts`.)
2. **Don't terminate TLS in the mesh for these connections.**
3. **Read the SPIFFE ID from a mesh-supplied attribute** — **only** if the
   mesh is the sole writer of that attribute. This reintroduces A10.

There is no way to make channel binding work through a TLS-terminating sidecar.
The exporter is bound to the end-to-end handshake by construction.

---

## 12. Storage

### 12.1 Protocol

| Store | Interface | Required operations |
|---|---|---|
| `EnrollmentStore` | identity → key binding | `add`, `require` |
| `ReplayStore` | single-use nonce | `consume(key, now) → bool`; `ttl_seconds` |
| `BudgetLedger` | reserve / dispatch / settle / refund / commit | `reserve(cid, root_cap, path, amount, *, expires_at=None, now=None)`, `mark_dispatched`, `settle`, `commit`, `refund`, `remaining` |
| `RevocationStore` | revoked set | `find_revoked(agents=, kids=, cids=, jtis=) → Optional[(kind, value)]` |
| `EvidenceStore` | hash-chained log | `append(draft) → Evidence`, `verify_integrity() → bool`, `records() → tuple` |

### 12.2 Backends

| Backend | Consistency | Durability | Suitable for |
|---|---|---|---|
| `memory` | Per-process | None | Development, tests |
| `redis` (`noeviction`, AOF) | Per-slot atomic (Lua) | Within AOF window | `replay`, `revocation`, `enrollments` |
| `postgres` | Full ACID | Durable | **`ledger`, `evidence`**; also all others |

The library refuses `memory` when `CAPCHAIN_ENV=production`. Redis raises at
startup if `maxmemory-policy != noeviction` (an eviction of a nonce or a
revocation is a silent fail-open).

### 12.3 Consistency model

- **PoP replay**: linearizable per nonce. `SET NX EX` on Redis; `INSERT … ON
  CONFLICT DO UPDATE WHERE expires_at <= now` on Postgres.
- **Budget**: linearizable per `cid`. `PostgresBudgetLedger` uses `FOR UPDATE`
  on `budget_chains` with a fixed lock order (chain → hops sorted by `jti` →
  reservation row). `RedisBudgetLedger` uses a single Lua script per
  `(reserve|settle|refund)` operation, keyed by a hash tag so Redis Cluster
  holds one `cid` in one slot.
- **Revocation**: eventually consistent. A `revoke_*` call is visible on the
  next `find_revoked`; there is no "wait until revoked everywhere."
- **Evidence**: linearizable per backend. `PostgresEvidenceLog` serializes on
  a single `SELECT … FOR UPDATE` on `evidence_head` — required for the hash
  chain, but caps global admit throughput.

### 12.4 The `handle.state` invariant

Every `BudgetLedger` implementation that mutates a reservation **MUST** also
update the corresponding fields on the `SpendHandle` that was passed in, after
the store has committed:

| Method | Required handle update |
|---|---|
| `mark_dispatched(handle)` | `handle.state = ReservationState.DISPATCHED` |
| `settle(handle, actual)` | `handle.amount = actual; handle.state = ReservationState.SETTLED` |
| `refund(handle)` | `handle.state = ReservationState.CANCELLED` (only if the refund was accepted) |

**Why this is normative.** `Permit.settle` reads `self._spend.state` to guard
the state machine. A store that updates only its backend (Postgres row, Redis
hash) leaves the caller looking at a stale Python object. The store has
committed, the row says `dispatched`, but `Permit.settle` rejects with
`settle from reserved`.

The update **MUST** happen after the store's transaction commits. If the
transaction rolls back, the handle stays in its prior state and the caller's
retry sees the same reservation.

### 12.5 Throughput limits

- **Postgres evidence**: one admit per round trip on the primary. Hundreds per
  second. If you need more, shard evidence by `cid` or batch in a
  compensating asynchronous log — at the cost of synchronous audit.
- **Postgres ledger, hot `cid`**: one operation per round trip on that `cid`.
  Sharding by `cid` prefix works if chains are largely independent.
- **Redis ledger**: one Lua script per chain slot. Atomic, fast, serialized
  per `cid`.

The evidence serialization is the dominant limit for multi-tenant workloads.

### 12.6 Required maintenance

Two jobs are not scheduled by the library:

```python
# Replay nonces (Postgres only). Redis auto-expires.
stores.replay.prune(now=int(time.time()))

# Abandoned reservations (both backends). Cutoff must exceed any in-flight
# request; otherwise a request that later dispatches will find its reservation
# gone and fail with INTERNAL (denied, no budget lost).
stores.ledger.refund_abandoned(older_than_seconds=3600)
```

`refund_abandoned` is the mitigation for abandoned reservations. Without it, a
crashed gateway permanently locks budget for abandoned permits.

### 12.7 Schema evolution

`migrate()` uses `CREATE TABLE IF NOT EXISTS`. When you add a column to the
schema, `IF NOT EXISTS` is a no-op for existing tables — the column does not
appear, and the code that references it fails with `UndefinedColumn`.

The fix pattern: a separate `ALTER_SQL` block, run after `SCHEMA_SQL` in
`migrate()`, that contains `ALTER TABLE … ADD COLUMN IF NOT EXISTS …`
statements. Every future column addition goes into `ALTER_SQL`, not into the
`CREATE TABLE` body. `migrate()` becomes actually idempotent — it can bring
any schema state forward to the current one, not just create a fresh one.

---

## 13. Integration patterns

### 13.1 Recommended: `permit.execute`

```python
with gateway.authorize(...) as permit:
    result = permit.execute(
        lambda: tool.call(payload),
        settle=lambda r: r.cost_micros,
    )
```

Handles `mark_dispatched → run → settle` in one call. Cannot end in the
ambiguous `DISPATCHED`-without-settle state. **Use this unless you have a
specific reason not to.**

### 13.2 Manual (streaming, non-return-value cost)

```python
with gateway.authorize(...) as permit:
    permit.mark_dispatched()
    cost = 0
    for chunk in tool.stream(payload):
        cost += chunk.cost
        yield chunk
    permit.settle(cost)
```

If the loop raises after `mark_dispatched`, the reservation commits at the
reserved amount (charge is real; the side effect partially happened). Reconcile
out of band against evidence.

### 13.3 Inspect-only (`Gateway.verify`)

```python
verdict = gateway.verify(token=token)
# Side-effect free: no PoP consumed, no budget reserved, no evidence written.
print(
    verdict.path,
    verdict.scope,
    verdict.budget_path,
)
```

For CLI tools, pre-flight checks, and admin views.

---

## 14. Comparison to related work

**This section is deliberately honest about where capchain is worse than the
alternatives.** The point of a comparison is to help you choose correctly, not
to claim capchain wins on every dimension. It doesn't.

### 14.1 Positioning

Capchain is a **protocol** for capability-authorized operations, not a pure
**token format**. It bundles:

1. A signed, append-only token format (like Macaroons or Biscuit).
2. A per-request proof of possession (like DPoP, but Ed25519-only and
   channel-bound).
3. A server-side budget ledger with atomic reservation (unique to capchain).
4. A hash-chained evidence log with admission→settlement join (unique to
   capchain).
5. Server-held context binding for session and task (unique to capchain).

No single item in this list is a capchain-only idea. The **combination** is
what distinguishes it. If you need all five together, no other system here
provides them together. If you need three or fewer, one of the simpler
alternatives is probably a better fit.

### 14.2 Comparison table

| Dimension | capchain | Macaroons | Biscuit | zcaps | GNAP | JWT (DPoP) |
|---|---|---|---|---|---|---|
| **Wire format** | JSON envelopes, Ed25519 blocks | base64 + HMAC-SHA256 | protobuf + Ed25519 | CBOR + Ed25519 | JSON (opaque) | JWT |
| **Monotone narrowing** | ✓ (signed at each hop) | ✓ (caveats) | ✓ (Datalog rules) | ✓ (signed at each hop) | ✓ (via resource server) | ✗ (bearer snapshot) |
| **Offline delegation** | ✓ | ✓ | ✓ | ✓ | ✗ (grant negotiation) | ✗ |
| **Third-party caveats** | ✗ | ✓ | ✗ | ✗ | ✓ (via interaction) | ✗ |
| **Structured policy language** | ✗ (flat scope) | ✗ | ✓ (Datalog) | ✗ (fixed shape) | ✗ | ✗ |
| **Per-request PoP** | ✓ Ed25519 (key-bound model) | ✗ | ✗ | ✗ | ✓ (DPoP) | ✓ (DPoP) |
| **TLS channel binding inside the signed token** | ✓ RFC 9266 (mandatory in key-bound) | ✗ | ✗ | ✗ | partial (via DPoP, optional) | partial (via DPoP, optional) |
| **Peer identity binding (mTLS) as an enforced property** | ✓ (mandatory) | ✗ | ✗ | ✗ | ✓ (optional) | ✓ (optional) |
| **Server-held context (session/task)** | ✓ (mandatory check) | ✗ | ✗ | ✗ | ✗ | ✗ |
| **Budget ledger with atomic reserve** | ✓ (per hop, root + child) | ✗ (out of scope) | ✗ (out of scope) | ✗ (out of scope) | ✗ (out of scope) | ✗ (out of scope) |
| **Hash-chained evidence** | ✓ | ✗ (out of scope) | ✗ (out of scope) | ✗ (out of scope) | ✗ (out of scope) | ✗ (out of scope) |
| **Revocation** | ✓ (agent / key / chain / block) | ✓ (online check) | ✓ (block list) | ✓ (revocation ids) | ✓ | ✓ (CRL/OCSP) |
| **Standardized** | ✗ (this document only) | ✓ (IETF draft adjacent) | ✓ | ✓ (IETF draft) | ✓ RFC 9635 | ✓ RFC 7519 |
| **Reference implementation** | This | libmacaroons, etc. | biscuit-python | zcap-py | Various | Various |
| **Cross-vendor interop** | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Post-quantum** | ✗ (Ed25519) | ✗ (HMAC-SHA256 is PQ-resistant only against forgery, not against an active attacker who can break the HMAC chain) | ✗ (Ed25519) | ✗ (Ed25519) | ✗ (EdDSA) | ✗ (EdDSA) |

A `✓ (out of scope)` in the last three columns is not a weakness — it means
those systems deliberately don't attempt the capability. Comparing "capchain
has a ledger" against "Macaroons don't" is only meaningful if you need a ledger.

### 14.3 Where capchain is genuinely better

Three properties are stronger than any of the alternatives in this table:

**1. Budget accounting.** No other capability system has a server-side ledger
that atomically reserves budget before a side effect, settles at the actual
cost after, and tracks the spend per hop as well as against the root cap. This
is what makes *"how much has this delegation's subtree spent?"* a question the
protocol can answer, not just a policy-layer approximation.

**2. Evidence.** Every admission and every settlement is a hash-chained record
with an `action_id` join between them. `verify_integrity()` detects deletion,
insertion, and modification. This is a compliance-grade audit trail. Macaroons,
Biscuit, zcaps, and JWT are token formats — they don't produce audit records;
you have to build that above them.

**3. Server-held context binding.** A token is bound not just to a holder and
a scope, but to a session and a task, both sourced from server-side state, not
from the request. Cross-session and cross-task replay are structurally
impossible — they don't depend on the caller behaving correctly. GNAP and JWT
have no equivalent; you have to build the check into your application.

### 14.4 Where capchain is genuinely worse

Three properties are weaker than at least one alternative:

**1. No third-party caveats.** Macaroons allow a caveat that requires
verification by a third party (e.g., "an external service must confirm this
token is still valid at the time of use"). Capchain has no equivalent — the
chain is strictly linear, and revocation is the only external check. **If you
need dynamic third-party approval as part of token verification, Macaroons are
the right tool.**

**2. No structured policy language.** Biscuit's Datalog lets you express
conditions like `amount < 1000 AND request.account IN allowed_accounts`. Capchain's
`Scope` is a flat list of `resource:action` strings, a budget, a domain list,
and an audience. Rich conditional policy is layered *above* capchain, not
inside the token. **If you need to express the policy in the token itself,
Biscuit is the right tool.**

**3. No standardization and no cross-vendor interop.** Macaroons, Biscuit,
zcaps, GNAP, and JWT all have wire-format specifications and multiple
independent implementations. Capchain's wire format is documented here and
nowhere else. A capchain token produced by this library will not verify in a
capchain implementation written from scratch by another team, because the
wire format, canonical encoding, and protocol layer are this project's
choice. **If you need to interoperate with another organization's capability
system, none of this applies to you — pick a standardized format.**

Two more minor gaps worth naming honestly:

**4. Ed25519 only.** No algorithm negotiation. If your compliance profile
requires ECDSA-P256 or RSA-3072 (some government profiles do), capchain cannot
be used without a wire-format change. Biscuit and zcaps are also Ed25519-only;
GNAP and JWT support algorithm negotiation.

**5. Serialization bottleneck in the evidence chain.** The `PostgresEvidenceLog`
serializes on a single `SELECT … FOR UPDATE` on `evidence_head`. This is
required for the hash chain to be correct but caps global admit throughput at
the evidence-write rate. Hundreds per second, not thousands. If you need more,
you have to shard evidence or batch it — both of which compromise the
synchronous audit guarantee. This is a real limitation; the alternatives
(which don't attempt evidence) don't have it.

### 14.5 When to use something else

- **Need cross-vendor interop?** Use JWT or Biscuit. Capchain's wire format is
  not standardized and does not aim to be.
- **Need complex conditional policy in the token?** Use Biscuit. Its Datalog
  can express conditions over request contents that capchain's flat scope
  cannot.
- **Need third-party caveats?** Use Macaroons. Capchain's chain is strictly
  linear.
- **Already have OAuth and just need PoP?** Use DPoP with your existing OAuth.
  Capchain adds budget, evidence, and context binding; if you don't need those,
  DPoP is a smaller change.
- **Need algorithm negotiation or post-quantum?** None of these systems is
  post-quantum. If you need PQ signatures, you need a different primitive
  entirely (SPHINCS+, ML-DSA / Dilithium).
- **Need very high throughput?** The evidence-chain serialization is the
  bottleneck. If you need thousands of admits per second on a single tenant,
  you'll want to batch evidence asynchronously, which means giving up the
  "every admit has a synchronous audit record" property.

### 14.6 The honest summary

Capchain = (Macaroons-like chain) + (Biscuit-like signing) + (DPoP-like PoP) +
(mTLS peer binding) + (budget ledger) + (evidence chain) + (server-held
context). Each of the seven pieces exists elsewhere. **The combination is what
capchain adds; the individual pieces are not improvements over the systems that
invented them.**

If you need the combination — capability + budget + evidence + server-held
context — no other system in this table provides it, and capchain is the right
choice despite the gaps above. If you need two or three of those properties,
one of the simpler alternatives is almost certainly a better fit. The honest
answer to "should I use capchain?" is: *only if you can name which of the seven
properties you need, and you need at least four of them.*

The comparison table above shows capchain as `✓` in many rows and other systems
as `✗`. That is misleading on its own. **The correct reading is: capchain is a
larger system with more capabilities and more complexity. That is a tradeoff,
not a win.** For the majority of use cases, one of the smaller systems is the
right choice, and capchain is overkill. It exists because a narrow class of
deployments needs all seven properties together and no other system provides
them.

---

## 15. Known open issues

### Constructor-enforced (working as intended)

- **C1** — `MutualTlsAdapter` requires explicit `trust_domains`. Default
  `peer_id` reads the verified SAN and requires `CERT_REQUIRED`.
- **C2** — `cost_model` is a required callable; `None` fails closed at step 14
  with `INTERNAL` rather than running the request without pricing.

### Known limitations

- **L1** — Ed25519 only. No algorithm negotiation.
- **L2** — Evidence serialization limits global admit throughput (see §12.5).
- **L3** — No third-party caveats; the chain is strictly linear.
- **L4** — No structured policy language; flat scope only.
- **L5** — No standardization and no cross-vendor interop.
- **L6** — Post-quantum insecure.

These are design choices, not defects to be fixed. §14.4 explains when they
matter and §14.5 says what to use instead.

---

## 16. Code path audit

Where a security engineer should look, in order:

| File | What to audit |
|---|---|
| `_chain.py:verify_chain` | Signature-before-interpret ordering; every field check; nesting constraints; `skew` application on `nbf`/`exp` |
| `_gateway.py:_admit` | The 18-step sequence in §5; step 4 (nonce burn) is the load-bearing one for probing resistance; step 14 (cost model) must be after step 13 |
| `_gateway.py:Permit.settle` | Evidence-before-ledger ordering (§9.1); `self._cost` assignment after `ledger.settle` (M2) |
| `_gateway.py:authorize` | Exit state matrix (§5.4); `try/except log` around `_record_denial` in both handlers (§5.3) |
| `_proofs.py:verify_proof_of_possession` | `aud`, `ath`, `res`, `act`, `ph`, `ts`, `cb` — every one is a binding |
| `_tls.py:spiffe_id_from_sslsocket` | Requires `CERT_REQUIRED` (C1 fix); reads SAN, not CN |
| `_tls.py:channel_binding` | RFC 9266 arity (`None` context, not `b""`) |
| `_keys.py:domain_separate` | Accepts `str \| bytes`; the NUL separator is mandatory |
| `_canonical.py:_validate` | Every field bound; `MAX_INT` enforced at parse *and* validate |
| `_canonical.py:Canonical.loads_strict` | `parse_int=_bounded_int` — enforced at both entry points |
| `store.py:RedisBudgetLedger._RESERVE_LUA` | The atomicity of reserve is here, not in Python |
| `store.py:PostgresBudgetLedger` | Lock ordering: chain, hops by `jti`, then reservation; consistent across reserve / settle / refund |
| `store.py:PostgresBudgetLedger.mark_dispatched/settle/refund` | Each updates `handle.state` (§12.4) after the transaction commits |

Every function above has a corresponding test in `selftest.py` or
`store.py:check_contract`. Read the tests to see the intended invariants.

---

## 17. Self-test coverage

```
python -m capchain.selftest       # 42 checks, core
```

The core self-test covers: enrollment (binding, wrong connection); issuance
(unenrolled); key-bound flow (valid, replay, missing proof, wrong connection,
wrong key, wrong body, wrong peer, wrong session, nonce burned by denial);
peer-bound flow (valid, wrong peer, PoP with peer-bound); delegation (valid,
wrong key, scope widening, depth, malformed parent leaf); domain scoping;
budget (reserve, exhaust, cap exceeded, refund-before-dispatch,
charge-after-dispatch); revocation; evidence integrity; trust-domain
allowlist; cost model failure modes; evidence/ledger ordering; chain skew
tolerance (freshly-issued, both directions); denial-doesn't-mask.

The storage contract test covers: reserve → refund → reserve → dispatch →
settle → commit; cap-change rejection; revocation; evidence hash chain;
enrollment cap; `handle.state` at each transition (reserved / dispatched /
settled / cancelled); reserve with `expires_at` and `now` kwargs.

**Not covered**: TLS integration end-to-end (see §11.4), fuzzing of malformed
tokens (the decoder is defensive but not fuzz-tested in this repository),
side-channel timing on signature verification (Ed25519 verify is constant-time;
the surrounding JSON parsing is not), Postgres/Redis behavior under concurrent
load (the atomicity claims in §12.3 are enforced by SQL/Lua but not
stress-tested here).

---

## 18. Production readiness checklist

Before running more than one gateway replica:

**Trust**
- [ ] `TrustedRoots` populated with the *public keys* of known issuers (not just their IDs)
- [ ] `Policy.edges` enumerates every allowed `(issuer, holder)` pair
- [ ] `Policy.root_issuers` matches the gateway's intended trust set
- [ ] `MutualTlsAdapter(trust_domains=...)` set explicitly; no default

**TLS**
- [ ] TLS is end-to-end for these ports (no terminating sidecar)
- [ ] `ssl.SSLContext.verify_mode == CERT_REQUIRED`
- [ ] `Gateway._tls` and `TokenIssuer._tls` are the same class instance (same config)

**Keys**
- [ ] Issuer root in a **different process** from any delegating workload
- [ ] Issuer root in HSM or KMS for any deployment past dev
- [ ] Leaf key rotation on a schedule; revocation of old keys tested

**Stores**
- [ ] `CAPCHAIN_ENV=production`; `memory` refused
- [ ] `ledger` and `evidence` on PostgreSQL (or explicitly accepted Redis caveat)
- [ ] Redis `maxmemory-policy noeviction` (module raises if not)
- [ ] Redis AOF enabled if Redis is the ledger (module warns if not)
- [ ] `migrate()` run from an init container
- [ ] Schema evolution via `ALTER_SQL` (not `CREATE TABLE IF NOT EXISTS`) — see §12.7
- [ ] `prune()` and `refund_abandoned()` scheduled
- [ ] Every `BudgetLedger` implementation updates `handle.state` — see §12.4

**Cost / budget**
- [ ] `cost_model` is a callable returning an upper bound; `None` fails closed
- [ ] Reservation upper bounds ≥ actual costs under realistic load (otherwise ledger absorbs overruns)

**PoP / clock**
- [ ] `pop_max_skew` matches your clock-drift budget
- [ ] `chain_max_skew` set to your chain-issuance-to-verification budget
- [ ] `replay.ttl_seconds > 2 * pop_max_skew` (constructor raises if not)

**Network**
- [ ] Egress from workloads restricted to issuer + gateway only
- [ ] Clock sync (NTP) within `pop_max_skew`

**Audit**
- [ ] Evidence store is append-only at the storage layer (not just "we don't delete")
- [ ] Backups of `evidence_head` and the full log are tested for `verify_integrity()` round-trip

**Revocation**
- [ ] Admin path to `revoke_agent` / `revoke_key` / `revoke_chain` / `revoke_token` exists
- [ ] Revocation playbook tested end-to-end (revoke a key, confirm next call `REVOKED`)

---

## 19. Quick start

```python
import time
import capchain as cc
from capchain import Stores

ISSUER = "spiffe://example.org/issuer"
WORKER = "spiffe://example.org/worker"
GATEWAY = "spiffe://example.org/gateway"

# Application-supplied TLS sockets (ssl.SSLSocket in CERT_REQUIRED mode).
workload_tls_socket = ...
issuer_side_tls_socket = ...
gateway_tls_socket = ...

tls = cc.MutualTlsAdapter(trust_domains=frozenset({"example.org"}))

issuer_key = cc.WorkloadKey.generate(agent_id=ISSUER)
worker_key = cc.WorkloadKey.generate(agent_id=WORKER)

with Stores.open("memory") as stores:  # "database" or "redis" in prod
    issuer = cc.TokenIssuer(
        agent_id=ISSUER,
        root_key=issuer_key,
        tls=tls,
        **stores.as_issuer_kwargs(),
    )
    gateway = cc.Gateway(
        agent_id=GATEWAY,
        roots=cc.TrustedRoots({ISSUER: issuer_key.public_key}),
        policy=cc.make_policy(root_issuers={ISSUER}, edges=set()),
        tls=tls,
        cost_model=lambda call, ctx, verdict: 10_000,
        **stores.as_gateway_kwargs(),
    )

    enrolled = issuer.enroll(
        tls_socket=issuer_side_tls_socket,
        proof=worker_key.enrollment_proof(
            issuer_id=ISSUER,
            channel_binding=tls.channel_binding(workload_tls_socket),
            now=int(time.time()),
        ),
    )

    token = issuer.issue(
        enrolled_key=enrolled,
        session_id="session-123",
        task="summarize",
        scope=cc.make_scope(
            tools={"llm:infer"},
            budget_micros=1_000_000,
            audience={GATEWAY},
        ),
        ttl_seconds=300,
        model=cc.Model.KEY_BOUND,
        max_depth=0,
    )

    body = b'{"prompt":"..."}'
    proof = worker_key.proof_of_possession(
        token=token,
        verifier_id=GATEWAY,
        resource="llm",
        action="infer",
        body=body,
        channel_binding=tls.channel_binding(workload_tls_socket),
        now=int(time.time()),
    )

    with gateway.authorize(
        tls_socket=gateway_tls_socket,
        token=token,
        proof=proof,
        call=cc.Call(
            resource="llm",
            action="infer",
            body=body,
        ),
        context=cc.ServerContext(
            session_id="session-123",
            task="summarize",
        ),
    ) as permit:
        result = permit.execute(
            lambda: invoke_tool(body),
            settle=measure_cost,
        )
```

---

## 20. Environment variables

```
CAPCHAIN_ENV=production              memory is refused; Redis policy is checked
CAPCHAIN_STORE=redis                 default type for every store
CAPCHAIN_STORE_REPLAY=redis          per-store override
CAPCHAIN_STORE_LEDGER=postgres       (also REVOCATION, EVIDENCE, ENROLLMENTS)
CAPCHAIN_REDIS_URL=redis://redis:6379/0
CAPCHAIN_POSTGRES_DSN=postgresql://capchain@postgres/capchain
CAPCHAIN_REDIS_PREFIX=capchain
CAPCHAIN_POSTGRES_SCHEMA=capchain
CAPCHAIN_REPLAY_TTL=300              must be > 2 x PoP skew
CAPCHAIN_ENROLL_TTL=3600
CAPCHAIN_ENROLL_MAX_PER_PEER=8
```

---

## 21. Non-goals

capchain does not:

- Store secrets or provider credentials.
- Decide business authorization beyond scope + policy + budget + revocation.
- Provide identity; identity comes from mTLS.
- Provide post-quantum security.
- Provide rate limiting or DoS defense.
- Provide a structured policy language (use Biscuit or zcaps if you need one).
- Guarantee anything if the issuer root key or the gateway binary is compromised.

It provides a **verified primitive** on top of which such a system can be
built. Once `authorize` yields a permit, the caller knows: the chain was
valid; the holder is the peer; the scope covers the request; the session and
task match server state; revocation was checked; the budget is reserved;
evidence has been recorded. Everything else is your policy.
