"""Offline NATIVE qualification commands; NOT a preparation-PC test entrypoint."""

import io
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_debian import publish_build_failure
from common import HERE, check_materials, command, material, need, record, write_new
from python_cases import CASES
from wide_test_port import public_test_command


def main(materials, output):
    materials, output = Path(materials).resolve(), Path(output).resolve()
    check_materials(materials)
    output.mkdir(mode=0o700)
    command(
        [
            "/usr/bin/gcc",
            "-std=c11",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I/usr/include/x86_64-linux-gnu",
            str(HERE / "expat_regression.c"),
            "-o",
            str(output / "expat-regression"),
            "-lexpat",
        ],
        output,
        output / "compile-c",
        seconds=60,
    )
    command([str(output / "expat-regression")], output, output / "native-c", seconds=5)
    public_test_command(
        [
            "/usr/bin/gcc",
            "-std=c11",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DXML_UNICODE",
            "-I/usr/include/x86_64-linux-gnu",
            str(HERE / "expat_regression.c"),
            "-o",
            str(output / "expat-wide-regression"),
            "-lexpatw",
        ],
        output,
        output / "compile-c-wide",
        "wide-exported-c-compile",
        publish_build_failure,
        seconds=60,
    )
    public_test_command(
        [str(output / "expat-wide-regression")],
        output,
        output / "native-c-wide",
        "wide-exported-c-run",
        publish_build_failure,
        seconds=5,
    )
    public_test_command(
        [
            "/usr/bin/g++",
            "-std=c++11",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-DXML_UNICODE",
            "-I/usr/include/x86_64-linux-gnu",
            str(HERE / "expat_wide_abi_smoke.cpp"),
            "-o",
            str(output / "expat-wide-cpp-smoke"),
            "-lexpatw",
        ],
        output,
        output / "compile-cpp-wide",
        "wide-exported-cpp-compile",
        publish_build_failure,
        seconds=60,
    )
    public_test_command(
        [str(output / "expat-wide-cpp-smoke")],
        output,
        output / "native-cpp-wide",
        "wide-exported-cpp-run",
        publish_build_failure,
        seconds=5,
    )
    for case in CASES:
        command(
            ["/usr/local/bin/python3.12", "-I", "-B", "-S", str(HERE / "run_python_case.py"), case],
            output,
            output / case,
            seconds=5,
            cap=65536,
        )
    # CPython tests from verified exact-version source, never from an unrelated interpreter.
    raw = material(materials, "Python-3.12.16.tar.xz")
    tests = output / "stdlib"
    tests.mkdir()
    total, count = 0, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:xz") as archive:
        for row in archive:
            if not row.name.startswith("Python-3.12.16/Lib/test/"):
                continue
            relative = Path(row.name.removeprefix("Python-3.12.16/Lib/"))
            need(not relative.is_absolute() and ".." not in relative.parts, "test_path")
            if row.isdir():
                (tests / relative).mkdir(parents=True, exist_ok=True)
                continue
            need(row.isfile() and row.size <= 4 * 1024**2, "test_source_type")
            count += 1
            total += row.size
            need(count <= 12000 and total <= 96 * 1024**2, "test_source_budget")
            target = tests / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            write_new(target, archive.extractfile(row).read(row.size + 1))
    launcher = output / "stdlib-tests.py"
    write_new(
        launcher,
        (
            "import sys\nsys.path.insert(0, " + repr(str(tests)) + ")\n"
            "from test.libregrtest.main import main\nmain()\n"
        ).encode(),
    )
    command(
        [
            "/usr/local/bin/python3.12",
            "-I",
            "-B",
            "-S",
            str(launcher),
            "--timeout",
            "60",
            "--verbose",
            "test_pyexpat",
            "test_xml_etree",
            "test_xml_etree_c",
        ],
        output,
        output / "cpython-tests",
        seconds=240,
        cap=4 * 1024**2,
    )
    record(
        output / "QUALIFICATION.json",
        {
            "native_fixture": True,
            "wide_exported_C_regression": True,
            "wide_CXX_exported_ABI_smoke": True,
            "full_CXX_suite_claimed": False,
            "python_cases": list(CASES),
            "cpython_stdlib": ["test_pyexpat", "test_xml_etree", "test_xml_etree_c"],
            "fixed4_admitted": False,
            "remaining": [
                "full upstream narrow/wide logs",
                "ABI comparison",
                "UBSan source build on bounded attribute corpus",
                "exact-image inventory/new scan and consumers",
            ],
        },
    )


if __name__ == "__main__":
    need(len(sys.argv) == 3, "usage_materials_new_output")
    main(*sys.argv[1:])
