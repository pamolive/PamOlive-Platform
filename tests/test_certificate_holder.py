import threading
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from wsgiref.simple_server import make_server

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from django.contrib.auth import get_user_model
from django.core.wsgi import get_wsgi_application
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.utils import timezone

from integrations import certificate_holder as holder
from platform_core.models import AuditEvent, ModuleActivation, Organization
from platform_core.tenancy import organization_context
from platform_modules.access import certificate_possession as proof
from platform_modules.access.services import ingest_event
from platform_modules.connectors.services import create_source
from platform_modules.identity.models import Credential, Identity

from .fixtures.oidc import tls_material
from .test_certificate_possession import certificate
from .test_oidc_tls import ThreadedWSGI, TLSHandler


class DetachedSignatureFormatsTests(SimpleTestCase):
    def test_p256_and_rsa_pss_detached_signature_parameters(self):
        message = b"synthetic detached signature interoperability"
        p256 = ec.generate_private_key(ec.SECP256R1())
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.assertEqual(
            holder._verify_detached(
                certificate(p256), p256.sign(message, ec.ECDSA(hashes.SHA256())), message
            ),
            "ECDSA-P256-SHA256",
        )
        cert = certificate(rsa_key)
        signed = rsa_key.sign(
            message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()
        )
        self.assertEqual(holder._verify_detached(cert, signed, message), "RSA-PSS-SHA256")
        wrong_salt = rsa_key.sign(
            message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=20), hashes.SHA256()
        )
        with self.assertRaises(holder.BridgeError):
            holder._verify_detached(cert, wrong_salt, message)


@override_settings(ALLOWED_HOSTS=["127.0.0.1"], SECURE_SSL_REDIRECT=False)
class HolderHTTPSRoundTripTests(TransactionTestCase):
    def test_detached_signature_crosses_real_tls_and_keeps_private_material_local(self):
        actor = get_user_model().objects.create_superuser("holder-admin")
        org = Organization.objects.create(key="holder", name="Holder fixture")
        for module in ("identity", "access", "connectors"):
            ModuleActivation.objects.create(
                organization=org, module_key=module, version="0.2.0", enabled=True
            )
        key = ed25519.Ed25519PrivateKey.generate()
        cert = certificate(key)
        with organization_context(org):
            source, token = create_source("TLS test holder", actor=actor, organization=org)
            machine = Identity.objects.create(organization=org, name="Machine", kind="machine")
            credential = Credential.objects.create(
                organization=org,
                identity=machine,
                name="Fixture",
                kind="certificate",
                fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
            )
            event, _ = ingest_event(
                {
                    "external_id": "actual-tls-holder",
                    "occurred_at": timezone.now(),
                    "credential": credential,
                    "domain": "certificate",
                    "method": "TLS",
                    "action": "connect",
                },
                organization=org,
                source=source,
            )

        seen = []
        redirect = False
        app = get_wsgi_application()

        def wsgi(environ, respond):
            seen.append(environ["PATH_INFO"])
            if redirect:
                respond("307 Temporary Redirect", [("Location", "/never-follow")])
                return [b""]
            return app(environ, respond)

        with TemporaryDirectory(prefix="pamolive-holder-tls-") as directory:
            root = Path(directory)
            context, ca = tls_material(directory)
            server = make_server(
                "127.0.0.1", 0, wsgi, server_class=ThreadedWSGI, handler_class=TLSHandler
            )
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            scope = holder.target(
                {
                    "origin": f"https://127.0.0.1:{server.server_port}",
                    "organization_id": str(org.pk),
                    "source_id": str(source.pk),
                    "event_id": str(event.pk),
                    "credential_id": str(credential.pk),
                }
            )
            der, bundle, detached = root / "public.der", root / "challenge", root / "signature.bin"
            der.write_bytes(cert.public_bytes(serialization.Encoding.DER))
            env = {holder.TOKEN_ENV: token}
            try:
                with self.assertRaises(holder.BridgeError):
                    holder.fetch(holder.DirectTLS(), scope, der, bundle, environ=env)
                self.assertFalse(seen)
                keylog = root / "must-not-log"
                with patch.dict("os.environ", {"SSLKEYLOGFILE": str(keylog)}):
                    client = holder.DirectTLS(ca)
                    redirect = True
                    with self.assertRaisesMessage(holder.BridgeError, "Redirection refusée"):
                        holder.fetch(client, scope, der, bundle, environ=env)
                    self.assertEqual(len(seen), 1)
                    self.assertNotIn("/never-follow", seen)
                    redirect = False
                    foreign = {**scope, "source_id": "12345678-1234-1234-1234-123456789abc"}
                    with self.assertRaisesMessage(holder.BridgeError, "hors du périmètre"):
                        holder.fetch(client, foreign, der, bundle, environ=env)
                    self.assertFalse(bundle.exists())
                    holder.fetch(client, scope, der, bundle, environ=env)
                    self.assertFalse(keylog.exists())
                self.assertEqual(len(seen), 3)
                self.assertNotIn(token.encode(), (bundle / "challenge.json").read_bytes())
                self.assertNotIn(token.encode(), (bundle / "message.bin").read_bytes())
                with self.assertRaisesMessage(holder.BridgeError, "existe déjà"):
                    holder.fetch(client, scope, der, bundle, environ=env)
                key_file = root / "not-a-certificate.der"
                key_file.write_bytes(
                    key.private_bytes(
                        serialization.Encoding.DER,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                )
                with self.assertRaisesMessage(holder.BridgeError, "certificat public"):
                    holder.fetch(client, scope, key_file, root / "reject", environ=env)
                message = (bundle / "message.bin").read_bytes()
                detached.write_bytes(ed25519.Ed25519PrivateKey.generate().sign(message))
                with self.assertRaisesMessage(holder.BridgeError, "aucun fichier envoyé"):
                    holder.submit(client, scope, der, bundle, detached, environ=env)
                self.assertEqual(len(seen), 3)
                self.assertFalse(AuditEvent.objects.filter(action=proof.ACTION).exists())
                detached.write_bytes(key.sign(message))
                (bundle / "message.bin").write_bytes(message + b"x")
                with self.assertRaisesMessage(holder.BridgeError, "ont été modifiés"):
                    holder.submit(client, scope, der, bundle, detached, environ=env)
                (bundle / "message.bin").write_bytes(message)
                result = holder.submit(client, scope, der, bundle, detached, environ=env)
                self.assertEqual(result["status"], "verified")
                self.assertEqual(result["algorithm"], "Ed25519")
                self.assertEqual(len(seen), 4)
                self.assertEqual(proof.verify_restored_proofs(), 1)
                with self.assertRaisesMessage(holder.BridgeError, "existe déjà"):
                    holder.submit(client, scope, der, bundle, detached, environ=env)
                self.assertEqual(AuditEvent.objects.filter(action=proof.ACTION).count(), 1)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
