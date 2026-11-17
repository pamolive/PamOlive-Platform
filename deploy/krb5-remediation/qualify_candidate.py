"""Same-build installed provider/SDK and real GSS synthetic consumer DATA."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from abi_data import LIBRARIES, capture
from common import ENV, command, read, record
from policy import HERE
from source_model import VERSION, json_value, need, sha


def main(build, output, runtime, sdk):
    build, output = Path(build), Path(output)
    output.mkdir(mode=0o700)
    comparison = json_value(read(build / "ABI-comparison-DATA.json", 4 * 1024**2))
    preserved = comparison.get("all_old_exports_preserved")
    need(type(preserved) is bool, "ABI_precondition_unknown")
    if not preserved:
        record(
            output / "QUALIFICATION-DATA.json",
            {
                "schema": "pamolive.krb5-candidate-DATA/1",
                "status": "ABI_PRECONDITION_REFUSED",
                "runtime_or_SDK_installed": False,
                "consumer_executed": False,
                "product_profile_v2_admitted": False,
                "operational_GO": False,
            },
        )
        return
    phase = ["install_candidate"]
    try:
        measure(build, output, runtime, sdk, phase)
    except Exception:
        # Preserve observer DATA. The workflow gate fails after TAR export.
        # No raw exception, extra command, cleanup claim or product admission.
        record(
            output / "QUALIFICATION-DATA.json",
            {
                "schema": "pamolive.krb5-candidate-DATA/1",
                "status": "MEASUREMENT_FAILED_OR_UNKNOWN",
                "phase": phase[0],
                "runtime_or_SDK_installed": None,
                "consumer_executed": None,
                "resources_released": None,
                "product_profile_v2_admitted": False,
                "operational_GO": False,
            },
        )


def measure(build, output, runtime, sdk, phase):
    # Exact ten names, no glob or package-manager network/recovery commands.
    from build_upgrade import RUNTIME, SDK

    packages = [str(Path(runtime) / f"{name}_{VERSION}_amd64.deb") for name in RUNTIME]
    packages += [str(Path(sdk) / f"{name}_{VERSION}_amd64.deb") for name in SDK]
    command(
        ["/usr/bin/dpkg", "--install", *packages],
        output,
        output / "install-candidate",
        seconds=120,
        cap=4 * 1024**2,
    )
    phase[0] = "active_provider_preflight"
    expected = json_value(read(build / "ABI-candidate.json", 4 * 1024**2))
    actual = capture(Path("/"))
    need(actual == expected, "installed_provider_not_same_build")
    names = sorted(
        [
            *LIBRARIES,
            "krb5-multidev",
            "libkrb5-dev",
            "libgssrpc4t64",
            "libkadm5clnt-mit12",
            "libkadm5srv-mit12",
            "libkdb5-10t64",
        ]
    )
    phase[0] = "installed_package_versions"
    versions = command(
        ["/usr/bin/dpkg-query", "--show", "--showformat=${Package}\t${Version}\n", *names],
        output,
        output / "installed-packages",
    )
    need(
        sorted(versions.decode().splitlines()) == [name + "\t" + VERSION for name in names],
        "SDK_runtime_version",
    )
    binary = output / "gss-consumer"
    phase[0] = "compile_GSS_consumer"
    command(
        [
            "/usr/bin/cc",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fPIE",
            "-pie",
            "-Wl,-z,relro,-z,now",
            "-I/usr/include/mit-krb5",
            str(HERE / "gss_consumer.c"),
            "-lgssapi_krb5",
            "-lkrb5",
            "-ldl",
            "-o",
            str(binary),
        ],
        output,
        output / "compile-GSS-consumer",
        seconds=60,
    )
    phase[0] = "GSS_consumer_witness"
    command(
        [
            "/usr/local/bin/python3.12",
            "-I",
            "-B",
            "-S",
            str(HERE / "consumer_worker.py"),
            str(output / "consumer"),
            str(binary),
        ],
        output,
        output / "GSS-consumer-worker",
        seconds=20,
        env=ENV,
    )
    consumer = json_value(read(output / "consumer/CONSUMER-DATA.json", 65536))
    record(
        output / "QUALIFICATION-DATA.json",
        {
            "schema": "pamolive.krb5-candidate-DATA/1",
            "status": "CANDIDATE_MEASUREMENT_COMPLETE",
            "version": VERSION,
            "runtime_SDK_same_build": True,
            "ABI": actual,
            "consumer": consumer,
            "compiled_consumer_sha256": sha(read(binary, 4 * 1024**2)),
            "real_KDC_or_AD_interoperability": "NOT_EXECUTED",
            "product_profile_v2_admitted": False,
            "CVE_closure": False,
            "operational_GO": False,
        },
    )


if __name__ == "__main__":
    need(len(sys.argv) == 5, "usage_build_new_output_runtime_sdk")
    main(*sys.argv[1:])
