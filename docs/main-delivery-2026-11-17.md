# Development delivery to main — 17 November 2026

The owner explicitly requested publication of the reviewed development changes
to main. PR #23 (Chrome cache, source dfb1296) and PR #24 (Expat solver and archive
modes, source e718be9) were merged with normal merge commits. Their CI failures
remain visible. Repository protections were inspected and were not changed.
No force push, image promotion, deployment or NAS access accompanies this work.

The read-only qualification source adds ten preflight tests and four independent
parent-observer tests. All fourteen pass locally without skips or attempted
external execution, networking, ctypes or SQL. An independent reviewer repeated
the fourteen tests and verified all eleven source pins. The top-level namespace
remains unchanged; no global qualification initializer is introduced. A dedicated
CI job runs these pure tests and retains their result. It does not execute the
Linux measurement, networking setup or privileged B2 receiver.

The local full secret scan covered 1,463 tracked files before integration with
the two merged branches. Its only new findings were eleven verified public
source hashes, reviewed individually. Existing baseline decisions and detector
settings are preserved. The integrated revision must receive its own CI results;
prior branch results are not transferred to it.

## Exact historical evidence and unresolved qualifications

On e841fb8, PostgreSQL reported 1,726 tests including 42 skips: 1,684 passed,
zero failures or errors. Directory reported 130 tests without skips. Independent
image evidence reception found 349 OS matches, including 110 High matches in
35 untriaged policy groups, and zero compiled matches. The image policy refused.
These are results for e841fb8, not the newly integrated tree.

On dfb1296, 153 pure bootstrap tests passed. The Linux canonical APT cache fixture
passed and the real simulate/install calls completed, followed by a strict
tool-parent refusal. The exact failing role or parent was not established.
There is no accepted installed/2 receipt or successful browser/UI qualification.
The branch restriction still skips the browser job on main.

On e718be9, the 82 Expat pure tests passed. Source archive mode validation and
the Linux capture build completed. The first kernel oracle child then exited
with SIGILL; capture refused before repository authentication and solving.
There is no approved material set, successful kernel fence or new qualified image.

The complete B2 privileged receiver and further diagnostic proposals remain
separate, unintegrated work. Four independently identified B2 source blockers
must be corrected and reviewed before commissioning it. The read-only subset
does not provide that commissioning or authority.

Next work remains Linux failure diagnosis, the remaining image-policy findings,
exact-revision PostgreSQL/P0/restore regressions, and independently received
qualification evidence. No production readiness is claimed.
