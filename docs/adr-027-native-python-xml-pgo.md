# ADR-027 — Explicit optimization policy for the two native Python XML extensions

Status: architecture accepted and implementation reviewed independently on 2026-11-16. Integrated preparation: 48 pure tests pass without skips or external execution; actual Linux qualification remains required. This ADR does not qualify a native build.

## Problem and observed evidence

The received 699 python-config.json (SHA256 215ba62294449b7be6d4c07e624dbef7b870bf9d64bd4d38f909bd76e689fa8b) reports CPython 3.12.16, GCC 14.2.0, PGO and LTO configuration. PY_STDMODULE_CFLAGS contains exactly the profile tokens -fprofile-use and -fprofile-correction. The previous builder rejected them before compilation. Its separate exact exception for -fuse-linker-plugin already permits the observed LTO options. The configuration receipt is evidence of inherited options, not possession of the original training profiles or successful compilation against the proposed Expat SDK.

CPython enables PGO with --enable-optimizations and treats LTO separately. GCC profile-use consumes previously generated data; profile-correction smooths inconsistent counters. These are optimization settings, while ABI compatibility still requires the existing source/header/capsule/provider/runtime checks. [CPython performance options](https://docs.python.org/3.12/using/configure.html#performance-options), [GCC 14.2 optimization options](https://gcc.gnu.org/onlinedocs/gcc-14.2.0/gcc/Optimize-Options.html).

## Accepted architecture and implementation

Root explicitly selected xml-local-no-pgo-v1 for this bounded two-extension rebuild. In the PY_STDMODULE_CFLAGS role only, accept exactly the observed adjacent, ordered profile pair, remove those two tokens, then pass every remaining token through the existing validator. The pair must occur once each; missing, duplicate, reordered, parameterized or other profile options refuse. Selection must be explicit in the source policy and build receipt; no default inference from a compiler error, no retry fallback, and no generic relaxation of flags(). No external profile data is imported. The CLI requires --optimization-policy xml-local-no-pgo-v1 and main/abi require the named keyword; no implicit default policy exists in the build entrypoints.

The implementation closes PGO-MODEL-01 by rejecting profile/AutoFDO families, branch-probabilities, vpt, coverage and -p/-pg in the generic validator, preserving only the exact existing -fuse-linker-plugin exception. No profile pair is admitted by flags() itself. The consumed roles CC, LDSHARED, CCSHARED, PY_LDFLAGS, PY_LDFLAGS_NODIST, LIBS and SYSLIBS remain subject to that validator before the first compiler call. PY_CFLAGS_NODIST also contains the pair in receipt699 but is recorded as original provenance, not consumed a second time or granted a new exception. The inherited raw sysconfig dictionary is never rewritten.

The historical design model and its 21-check counter-proof remain unchanged: three prohibited feedback variants were accepted there. They are not retroactively called PASS. The new real abi/argv/main tests reject those variants under the new candidate.

This changes optimization provenance and makes no performance-equivalence claim. Preserve all other tokens and their order, including LTO, -fuse-linker-plugin, visibility, PIC, warnings and -Werror. Preserve existing explicit header-directory translations. No PIE option is observed in this receipt; this policy grants no authority to remove a future PIE option. Keep the exact ABI guards, matching producer/consumer capsule headers, authenticated materials, SDK Expat 2.10 validation, header traces, ELF/provider checks, bounded XML oracles and full CI gates. Compilation and those checks remain necessary; token acceptance alone proves none of them.

## Alternatives

| Option | Benefit | Cost and decision |
| --- | --- | --- |
| Explicit local no-PGO | Small, maintainable change; avoids unknown inherited profiles | Recommended for the correction objective; performance remains unqualified |
| Isolated PGO for both extensions | Trains the exact new modules without rebuilding Python | Feasible separate implementation, more processes/profile evidence and failure states |
| Whole CPython rebuild with PGO | Uses the native interpreter build/training machinery | Changes interpreter/libpython, headers/sysconfig and a wider consumer surface; disproportionate first step for two modules |

PGO preservation is not itself a user requirement. A future choice of either alternative requires its own explicit policy; failure must never select another option automatically.

For isolated PGO, use authenticated matching sources and qualified SDK, the same compiler and stable source/output paths, fresh bounded private profile directories, and fixed generation/use commands. Preserve every non-PGO option. Generation flags must apply to compilation and linking. Train both staged modules in fresh isolated Python children, verify their actual module paths/providers, run a bounded serial corpus, and require normal exit plus complete H1 receipts before consuming profiles. GCC writes profiling data at program exit and derives filenames from output/source paths, so guessed profile filenames or killed-child success are unacceptable. [GCC 14.2 instrumentation options](https://gcc.gnu.org/onlinedocs/gcc-14.2.0/gcc/Instrumentation-Options.html).

Bind nonempty regular bounded profile bytes to the generator, compiler, source, SDK, corpus and stable paths. The final use phase must treat missing profiles as errors (-Werror=missing-profile), retain coverage-mismatch errors, and never suppress either. Deploy only final-use extensions, not generators or profile data. Successful training does not qualify performance or replace final native security tests. [GCC 14.2 warning options](https://gcc.gnu.org/onlinedocs/gcc-14.2.0/gcc/Warning-Options.html).

A whole CPython rebuild instead needs a separately pinned configure/build/training plan, explicit Expat linkage, and qualification of the resulting interpreter, libpython and extension ecosystem. It must not silently replace the current base interpreter during this small correction.

## Verification and receipt requirements

Pure tests must cover explicit policy selection, exact pair acceptance, duplicate/partial/reordered/path-valued/foreign profile rejection, generic other-role rejection, unchanged non-PGO token sequence and unchanged header aliases. Authentication, SDK and unknown-option failures must occur before compilation. Never weaken warnings or resource limits to obtain success.

Linux qualification must compile the real pair, check exact headers, ABI/ELF dependencies and provider/capsule behavior in both import orders, then run the existing nine XML cases, stdlib suites and complete CI. Isolated PGO additionally needs missing/corrupt/wrong-source/compiler/name profiles, interrupted training and foreign profile inputs to fail closed before final use. Performance is unqualified until separately measured; existing security/timeout oracles retain their bounds.

BUILD.json must preserve the original observed config and record policy/version, original and effective token arrays, exact removed pair, existing include translations, compiler/source/SDK/header/module hashes and commands. Record generated/imported profile status and phase receipts if applicable, performance_qualified=false, and no CVE or operational admission inferred from this ADR.

The E256 wide-test failure (make-buildw-check, UTF-16 without wchar_t) is a separate failure before Python extension compilation. This optimization policy does not repair, bypass or qualify that test. The wide-test adaptation is an independent change. Integration preserves the existing runner and failure-diagnostic tests and adds only the explicit build option and ten optimization-policy tests.
