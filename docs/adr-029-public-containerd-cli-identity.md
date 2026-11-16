# ADR029 — Exact typed containerd CLI identity for public metadata

Accepted source choice by Root; integration/publication and native measurement remain pending.

The real 1e66 prerequisite run43822757117 refused after a stable CTR tool and a complete normal-rc0 version subprocess. Its format DATA states another redacted package, version2.4.2 with a v prefix and no suffix. This does not disclose or prove a package label. No Plugins/storage/PG result is inferred.

Containerd v2.4.2 prints cmd.Name, version.Package and cmd.Version separated by spaces and a terminal LF. Its Makefile links version.Package from PACKAGE. Docker's maintained packaging defaults PKG_NAME to containerd and forwards it as PACKAGE. The legacy Docker packaging Dockerfile explicitly defaults PACKAGE to containerd.io and its rules forward PACKAGE. These are two finite, documented build identities, not aliases of the upstream module path or proof of this runner's actual tool origin.

Decision: ROOT3 carries cli_identity={package:exact string,version:exact string}, replacing ROOT2's version-only field. Admit only a complete stdout line built from a finite source table: github.com/containerd/containerd/v2 at 2.2.3 and 2.4.2, and containerd/containerd.io at 2.4.2. For each, the existing plain or v-prefixed literal is retained separately; no suffix, extra line, spacing change or other label/version is admitted. The plain strings and their v forms are distinct recorded identities. Parent validation requires this exact pair and ROOT3 only. Historical ROOT1/ROOT2 packets are not a current fallback.

Unknown output continues to be refused with the existing bounded/redacted ROOT2 diagnostic mechanism, including its strict inner-H1/tool/no-post-query conditions, adapted to the ROOT3 field. The format diagnostic cannot select an approved expected identity. Static source review, rather than observed DATA, defines the finite table. Tool path/type/link/owner/mode/size/hash, exact environment, commands, root frontend, nested H1, timeouts and false authority remain unchanged. The PG sorted-Ulimits source and all twelve composed PG payload rows remain exact.

Alternatives: keeping diagnostics only preserves refusal but cannot receive the independently documented packaging representation. Replacing the host CLI adds installation and daemon compatibility work outside this read-only scope. A wildcard parser or normalization to one label would erase provenance distinctions; both are rejected. A version-only extension is rejected because the parent would lose the package/version distinction.

This is a bounded CLI compatibility proposal for metadata collection, not a containerd server/image/profile admission. Tool SHA measurements remain observed DATA, never expected-digest authority. The actual full package from 1e66 remains unknown until a new complete normal-H1 line matches. Root integration and independent review precede the next trial. No operational profile, A1/WV authority or CVE closure follows.

Primary sources read:

- [v2.4.2 ctr VersionPrinter](https://raw.githubusercontent.com/containerd/containerd/v2.4.2/cmd/ctr/app/main.go), lines54–56.
- [v2.4.2 Makefile](https://raw.githubusercontent.com/containerd/containerd/v2.4.2/Makefile), PACKAGE and GO_LDFLAGS.
- [Docker maintained packaging defaults](https://raw.githubusercontent.com/docker/packaging/20ab65bec3c652d3400b552083bb17c2a2ebfa45/pkg/containerd/Dockerfile), line28; [Debian rules](https://raw.githubusercontent.com/docker/packaging/20ab65bec3c652d3400b552083bb17c2a2ebfa45/pkg/containerd/deb/rules), line27.
- [Legacy packaging default](https://raw.githubusercontent.com/docker/containerd-packaging/4179daadda73869df656240bf5446a72f15d1a21/dockerfiles/deb.dockerfile), lines105–106; [Debian rules](https://raw.githubusercontent.com/docker/containerd-packaging/4179daadda73869df656240bf5446a72f15d1a21/debian/rules), line36. The legacy default REF is1.7; its explicit PACKAGE override mechanism is proof of the label mechanism, not proof of a shipped2.4.2 artifact.

Exact fetched DATA bytes/hashes accompany this proposal. Mutable branch source is vendor/TLS evidence, not cryptographic release authentication.
