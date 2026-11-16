#!/bin/sh
# One reviewed FreeRDP build shared by guacd, the native fixture and runtime.
set -eu
version=3.33.1
source_sha256=4431bbf04d370545cfe2924b9d9f116b95c90c64ff156b2550bbaf82d34e7124
key_sha256=85de10471e0e4aa4958f8c2906794a5e59de492f38a0731720dec99ded82e026
signer=7703B333420E0AEF995EB4B3A49454A3FC909FD5
prefix=/opt/pamolive-freerdp
work=$(mktemp -d /tmp/pamolive-freerdp-XXXXXX)
cd "$work"
mkdir -m 700 gnupg
fetch() { curl --proto '=https' --tlsv1.2 --fail --show-error --silent --location --max-time 120 --retry 3 --output "$2" "$1"; }
fetch "https://pub.freerdp.com/releases/freerdp-$version.tar.gz" source.tar.gz
fetch "https://pub.freerdp.com/releases/freerdp-$version.tar.gz.asc" source.asc
fetch https://pub.freerdp.com/releases/akallabeth.asc signer.asc
printf '%s  %s\n' "$source_sha256" source.tar.gz | sha256sum -c -
printf '%s  %s\n' "$key_sha256" signer.asc | sha256sum -c -
gpg --homedir "$work/gnupg" --batch --import signer.asc
gpg --homedir "$work/gnupg" --batch --status-fd 1 --verify source.asc source.tar.gz > signature.status
awk -v signer="$signer" '$1 == "[GNUPG:]" && $2 == "VALIDSIG" && ($3 == signer || $NF == signer) { valid=1 } END { exit !valid }' signature.status
tar --no-same-owner --no-same-permissions -xzf source.tar.gz
printf '%s  %s\n' '7a3694d19f3fda9ea248905e1adf3b2048e911510420240f5c71a6aec2842500' /freerdp-jansson-compat.patch | sha256sum -c -
printf '%s  %s\n' '7405d890c6a108bca379021f7f81672a122f33ed4e754bbebc39652c050aacbb' "freerdp-$version/winpr/libwinpr/utils/json/jansson.c" | sha256sum -c -
patch --batch --forward --fuzz=0 -d "freerdp-$version" -p1 < /freerdp-jansson-compat.patch
cmake -S "freerdp-$version" -B build \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
  -DCMAKE_INSTALL_RPATH="$prefix/lib" -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON -DCMAKE_INTERPROCEDURAL_OPTIMIZATION:BOOL=OFF \
  -DBUILD_SHARED_LIBS=ON -DBUILD_TESTING=OFF -DWITH_MANPAGES=OFF -DWITH_SAMPLE=OFF \
  -DWITH_JSONC_REQUIRED=OFF -DWITH_CJSON_REQUIRED=OFF -DWITH_JANSSON_REQUIRED=ON -DWITH_JSON_DISABLED=OFF \
  -DWITH_CLIENT=OFF -DWITH_CLIENT_COMMON=ON -DWITH_SERVER=OFF -DWITH_SERVER_INTERFACE=OFF \
  -DWITH_CHANNELS=ON -DWITH_CLIENT_CHANNELS=ON -DWITH_SERVER_CHANNELS=OFF -DCHANNEL_URBDRC=OFF \
  -DWITH_X11=OFF -DWITH_WAYLAND=OFF -DWITH_CLIENT_SDL=OFF -DWITH_SIMD=OFF \
  -DWITH_FUSE=OFF -DWITH_EMBEDDED_CLI_IN_RDP_FILES=OFF -DWITH_CAIRO=ON \
  -DWITH_FFMPEG=OFF -DWITH_SWSCALE=OFF -DWITH_OPENH264=OFF -DWITH_JPEG=ON \
  -DWITH_ALSA=OFF -DWITH_PULSE=OFF -DWITH_OSS=OFF -DWITH_CUPS=OFF \
  -DWITH_PCSC=OFF -DWITH_OPENSSL=ON -DWITH_MBEDTLS=OFF -DWITH_KRB5=ON \
  -DWITH_FREERDP_DEPRECATED=ON -DWITHOUT_FREERDP_3x_DEPRECATED=OFF \
  -DWITH_CCACHE=OFF -DWITH_DEBUG_ALL=OFF -DWITH_DEBUG_NLA=OFF -DWITH_DEBUG_TRANSPORT=OFF
# Validate generated compiler/linker commands, not only CMake cache claims.
python - <<'PYBUILD'
import hashlib
import json
import shlex
from pathlib import Path
raw = Path("build/compile_commands.json").read_bytes()
commands = json.loads(raw)
if not commands:
    raise SystemExit("Missing generated compilation commands")
lines = [(entry.get("arguments") or shlex.split(entry["command"]), entry["file"]) for entry in commands]
# Refuse a successful CMake invocation which selected a different JSON backend.
json_sources = [Path(entry['file']).as_posix() for entry in commands
                if '/utils/json/' in Path(entry['file']).as_posix()]
if not any(path.endswith('/jansson.c') for path in json_sources) or any(
        path.endswith(('/c-json.c', '/json-c.c', '/json-stub.c')) for path in json_sources):
    raise SystemExit('Unexpected JSON backend compilation')
# CheckIPOSupported builds throwaway capability probes even when IPO is OFF.
# They are never installed or linked into a PamOlive target.
probe_roots = (Path("build/CMakeFiles/_CMakeLTOTest-C"),
               Path("build/CMakeFiles/_CMakeLTOTest-CXX"))
links = [path for path in Path("build").rglob("link.txt")
         if not any(path.is_relative_to(root) for root in probe_roots)]
if not links:
    raise SystemExit("Missing generated linker commands")
lines.extend((shlex.split(path.read_text()), str(path)) for path in links)
for arguments, origin in lines:
    for token in arguments:
        if token.startswith(("-flto", "-mavx")):
            raise SystemExit(f"Unexpected LTO/AVX compiler flag {token} in {origin}")
        if token.startswith("-march=") and token != "-march=x86-64":
            raise SystemExit("Non-baseline CPU compilation prohibited")
Path("compile-policy.json").write_text(json.dumps({
    "schema": "pamolive.native-compile-policy.v1", "verified": True,
    "compile_commands_sha256": hashlib.sha256(raw).hexdigest(),
    "compilation_commands": len(commands), "link_command_files": len(links),
    "prohibited_flag_prefixes": ["-flto", "-mavx"],
    "allowed_march": ["-march=x86-64"],
    "excluded_configuration_probe_roots": [str(root) for root in probe_roots],
}, sort_keys=True) + "\n")
PYBUILD
cmake --build build --parallel 1
cmake --install build
# Upstream installWithRPATH overrides CMAKE_INSTALL_RPATH with $ORIGIN.
# Keep PamOlive's loader policy literal and restricted to its root-owned prefix.
find "$prefix/lib" -type f -name '*.so*' -exec patchelf --set-rpath "$prefix/lib" {} +
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
test "$(pkg-config --modversion freerdp3)" = "$version"
test "$(pkg-config --modversion winpr3)" = "$version"
mkdir -p "$prefix/share/pamolive-freerdp"
printf '%s\n' "$version" > "$prefix/share/pamolive-freerdp/version.txt"
printf '%s\n' "$source_sha256" > "$prefix/share/pamolive-freerdp/source-sha256.txt"
printf '%s\n' "$signer" > "$prefix/share/pamolive-freerdp/signer-fingerprint.txt"
cp signature.status "$prefix/share/pamolive-freerdp/"
cp build/CMakeCache.txt "$prefix/share/pamolive-freerdp/build-options.txt"
cp compile-policy.json "$prefix/share/pamolive-freerdp/compile-policy.json"
printf '%s\n' "$prefix/lib" > "$prefix/share/pamolive-freerdp/rpath-policy.txt"
patchelf --version > "$prefix/share/pamolive-freerdp/rpath-tool.txt"
cp "freerdp-$version/LICENSE" "$prefix/share/pamolive-freerdp/LICENSE"
if test -f "freerdp-$version/NOTICE"; then
  cp "freerdp-$version/NOTICE" "$prefix/share/pamolive-freerdp/NOTICE"
fi
cp /freerdp-jansson-compat.patch "$prefix/share/pamolive-freerdp/"
