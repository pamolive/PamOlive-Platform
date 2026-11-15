# Proposed ADR — Bounded public V1 material inspection

Status: **prototype proposal awaiting Root and independent review**, 15 November
2026. Implements only the outside-repository source tranche authorized by
`p2-r1b1-root-implementation-decision-20261115.md`; it does not accept an ADR for
the product, supersede ADR-020/022 or modify an existing repository.

The problem is that public trust rules are mixed with Django, settings and SQL.
Importing those modules into a future Vault keeps Web trust coupling; a Web
Boolean invents authority. Copying the entire action/enrollment/counter path
would introduce unresolved double consumption. This proposal instead ports only
the public V1 registry/checkpoint checks into an isolated bytes-only library.

Two explicit API/context/result families separate archival validity from current
material freshness. Caller expectations are provisioned outside the request;
frozen Python objects do not prove this operational provenance. Whole history,
old eligible custody and all five owner maps are mandatory. There is no suffix
or independently authenticated ownership-state shortcut in this tranche.

Signed V1 body text, unknown fields, domains and signature-map commitments are
preserved. Root explicitly retains Python equality for checkpoint revisions,
including signed floats/bools; strict context and registry revisions remain
separate. Parser/encoder bounds are a new acceptance profile, never a silent
rewrite of historical evidence. Optional shorter current registry TTL is also
reported as a new restriction rather than falsely equated with recognized_registry.

The library exposes no filesystem/SQL/HTTP discovery, consumer, signer, provider,
secret or effect. It does not prove possession, enrollment consumption, counters,
live membership, independently controlled humans, mTLS, anti-rollback storage,
V2 transcript binding or action permission. A compromised in-process caller can
forge Python objects; downstream services must not treat this result type as a
bearer capability or substitute it for their complete authorization procedure.

Consequence: bounded temporary duplication of P0 public rules. The correspondence
matrix, static signed oracles and frozen prior real-P0 witness are maintenance
inputs. Separate installed-wheel/closed-material qualification, Native AppSec
review and Root review precede any integration. No current P0 consumer changes,
database migrations, key rotations, release calls or archive re-signing follow.
No delivery/image/service/P2-production gate is lifted by local source tests.
