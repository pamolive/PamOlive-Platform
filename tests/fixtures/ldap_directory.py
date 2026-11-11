"""An actual disposable OpenLDAP server, Linux only, with synthetic data.

No LDAP codec/server is implemented here. slapd/slapadd provide the protocol.
Config, TLS material, password and server diagnostics stay in a private tempdir.
"""

import hashlib
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .oidc import tls_material


def available():
    try:
        import ldap
    except ImportError:
        return False
    return bool(shutil.which("slapd") and shutil.which("slapadd") and ldap.INIT_FD_AVAIL)


def fixture_directory_parent(platform):
    # Ubuntu's packaged slapd AppArmor profile permits private test files in
    # /var/tmp but can refuse inherited logs/config/keys under /tmp. Use the
    # existing permitted directory; never disable or rewrite that profile.
    return "/var/tmp" if platform == "posix" else None


def startup_failure_code(diagnostic):
    text = diagnostic.lower()
    if "permission denied" in text or "operation not permitted" in text:
        return "fixture_permission_refused"
    if "tls init def ctx failed" in text:
        return "fixture_tls_context_failed"
    if "lt_dlopenext failed" in text or "moduleload failed" in text:
        return "fixture_module_unavailable"
    if "address already in use" in text:
        return "fixture_port_in_use"
    return "fixture_startup_failed"


class LdapDirectoryPeer:
    base_dn = "ou=people,dc=lab"
    bind_dn = "cn=reader,dc=lab"

    def __init__(self):
        self.directory = tempfile.TemporaryDirectory(
            prefix="pamolive-openldap-", dir=fixture_directory_parent(os.name)
        )
        self.folder = Path(self.directory.name)
        os.chmod(self.folder, 0o700)
        self.process = None
        self.log = None
        try:
            self._start()
        except BaseException:
            self.close()
            raise

    def _start(self):
        _, self.ca_file = tls_material(self.folder)
        cert = x509.load_pem_x509_certificate(Path(self.ca_file).read_bytes())
        key_path = self.folder / "fixture-key.pem"
        os.chmod(key_path, 0o600)
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        # A synthetic FQDN avoids OpenLDAP's special localhost canonicalization.
        # The test resolver pins it to this fixture's loopback socket.
        cert = (
            x509.CertificateBuilder()
            .subject_name(cert.subject)
            .issuer_name(cert.issuer)
            .public_key(cert.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(cert.not_valid_before_utc)
            .not_valid_after(cert.not_valid_after_utc)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("directory.invalid")]), critical=False
            )
            .sign(key, hashes.SHA256())
        )
        Path(self.ca_file).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.pin = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        self.password = secrets.token_hex(32)
        ports = []
        for _ in range(2):
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                ports.append(sock.getsockname()[1])
        self.port, self.tls_port = ports
        self.url = f"ldap://directory.invalid:{self.port}"
        self.tls_url = f"ldaps://directory.invalid:{self.tls_port}"
        data = self.folder / "data"
        data.mkdir(mode=0o700)
        config = self.folder / "slapd.conf"
        config.write_text(
            "include /etc/ldap/schema/core.schema\n"
            "include /etc/ldap/schema/cosine.schema\n"
            "include /etc/ldap/schema/inetorgperson.schema\n"
            "include /etc/ldap/schema/nis.schema\n"
            f"pidfile {self.folder}/slapd.pid\nargsfile {self.folder}/slapd.args\n"
            "modulepath /usr/lib/ldap\nmoduleload back_mdb\n"
            f"TLSCACertificateFile {self.ca_file}\n"
            f"TLSCertificateFile {self.ca_file}\nTLSCertificateKeyFile {key_path}\n"
            'access to dn.base="" by * read\n'
            "access to attrs=userPassword by anonymous auth by * none\n"
            f'access to * by dn.exact="{self.bind_dn}" read by * none\n'
            "database mdb\nmaxsize 16777216\nsuffix dc=lab\n"
            f"rootdn cn=fixture-admin,dc=lab\nrootpw {secrets.token_hex(32)}\ndirectory {data}\n",
            encoding="utf-8",
        )
        os.chmod(config, 0o600)
        ldif = self.folder / "seed.ldif"
        ldif.write_text(
            "dn: dc=lab\nobjectClass: domain\ndc: lab\n\n"
            "dn: ou=people,dc=lab\nobjectClass: organizationalUnit\nou: people\n\n"
            f"dn: {self.bind_dn}\nobjectClass: inetOrgPerson\n"
            f"cn: reader\nsn: Synthetic\nuserPassword: {self.password}\n\n"
            "dn: uid=fixture,ou=people,dc=lab\nobjectClass: inetOrgPerson\n"
            "objectClass: posixAccount\nuid: fixture\ncn: Fixture\nsn: Synthetic\n"
            "uidNumber: 10001\ngidNumber: 10001\nhomeDirectory: /tmp/fixture\n\n",
            encoding="utf-8",
        )
        os.chmod(ldif, 0o600)
        self.log = (self.folder / "server.private.log").open("wb")
        os.chmod(self.folder / "server.private.log", 0o600)
        subprocess.run(
            ["slapadd", "-f", str(config), "-l", str(ldif)],
            stdout=self.log,
            stderr=self.log,
            check=True,
            timeout=15,
        )
        self.process = subprocess.Popen(
            [
                "slapd",
                "-f",
                str(config),
                "-h",
                f"ldap://127.0.0.1:{self.port} ldaps://127.0.0.1:{self.tls_port}",
                "-d",
                "256",
            ],
            stdout=self.log,
            stderr=self.log,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.log.flush()
                diagnostic = (self.folder / "server.private.log").read_text(errors="replace")
                code = startup_failure_code(diagnostic)
                # No raw log text, DN, key, password or filesystem path in CI.
                raise RuntimeError(
                    "Synthetic OpenLDAP fixture did not start: "
                    f"{code}, exit={self.process.returncode}."
                )
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("Synthetic OpenLDAP fixture startup timed out.")

    def authenticated_bind_count(self):
        self.log.flush()
        return (
            (self.folder / "server.private.log")
            .read_text(errors="replace")
            .count('BIND dn="' + self.bind_dn + '"')
        )

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        if self.log:
            self.log.close()
        self.directory.cleanup()
