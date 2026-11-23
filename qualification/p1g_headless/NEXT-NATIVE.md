# P1-G native browser acceptance

Les parcours natifs SSH et RDP du commit `8ed3f88` ont vérifié les votes,
le lancement WebAuthn, l'ouverture et la fermeture du transport, et la
lecture autorisée de la capture partielle. Le banc a tourné sur le runner
Linux isolé de la PR #95. [Reçus](https://github.com/pamolive/PamOlive-Platform/actions/runs/45247882731/artifacts/14856749904)

Le parcours étendu part de la même demande. Il soumet une observation
synthétique via l'API du collecteur, vérifie le reçu V8 et l'évaluation qui
référence la demande, puis révoque le mandat depuis la fiche du parcours.
Le test attend la fermeture WSS et celle du transport de la cible synthétique.
Il vérifie la capture et l'événement d'audit, ainsi que la disparition du
bouton d'ouverture pour ce mandat. La validation du parcours étendu dépend
de sa propre CI.

Le demandeur peut renoncer à son mandat depuis sa session. La révocation
du mandat d'un autre utilisateur est réservée à un administrateur de
l'organisation sous MFA récente. Le service révoque les baux liés et
retire l'autorité des relais sous le verrou de l'organisation. Le broker
ferme les transports actifs et scelle les captures. Le journal décrit le
retrait local et la demande de fermeture. Le collecteur rapporte les faits
synthétiques et le rapprochement décrit leur concordance avec la demande.

Le démonstrateur historique PC-483/PC-991 et la révocation du droit IAM de
fixture restent des cas distincts. Le parcours natif s'exécute uniquement
sur des cibles dédiées de laboratoire.

The next native case can reuse P1GBrowser.login/enroll/request/votes and override
only after_approval and install_websocket_policy plus the server/endpoint
fixture. No product authentication or synthetic assertion generator is needed.

1. Reuse `tests.fixtures.ssh.SSHFixture`, which owns the loopback listener and
   accepts only generated test credentials. It reports shell opening, a fixed
   round trip and closure of the transport that owns that shell. Fixture cleanup
   cannot supply the closure signal. RelayHarness already uses this peer and
   still owns guacd and Uvicorn. In the browser lab, set up and probe the target
   before the test authority snapshot is frozen. Keep the private target
   credential on the server side. The browser must create its own request, two
   votes and launch through the shipped forms and pam-trust.js.
2. Reuse `tests.fixtures.asgi.TLSASGIServer` in the separate browser native case.
   It owns a TLS listener on a kernel-selected loopback port and serves the
   static wrapper and the real `config.asgi` application. The synthetic SSH
   and RDP test clients use certificate verification for their WSS connection.
   Pass the browser lab leaf and key to this listener. Keep the private NSS
   trust database and use the exact DNS name and port for the HTTPS origin and
   synthetic RP ID. The browser case must allow only the actual same-origin
   `/ws/pam/<connection-id>/` socket and observe its closure.
3. Use the delivered native-test image for guacd/FreeRDP and its ABI closure;
   do not extract Debian-native ELF onto the Ubuntu host and assume ABI equality.
   A test-only derivative with browser tooling is one concrete execution context.
   Its nonroot Chromium sandbox must actually work with the admitted namespace
   seccomp profile; no SYS_ADMIN/hostIPC/unconfined/no-sandbox workaround. This is
   a separate image/profile prerequisite, not provided or silently approved here.
   The current cheap host-browser job needs neither that build nor Docker exec.
4. In after_approval: open pam-home, select the existing pam-launch POST form,
   click it and confirm the WebAuthn ceremony. The real session JS must establish
   WSS; correlate the resulting RelayConnection with that intention and browser
   session, verify connected_at and the actual SSH server's accepted connection,
   then exercise the fixed keyboard/output sentinel already used by RelayHarness.
   Target passwords/private keys never enter the page; the ordinary short-lived
   application session capability must not be retained in artifacts.
5. Keep the player open. Open the relay detail and its pam-stop form in a second
   tab of the same browser context, since navigating the player away would close
   the client socket on pagehide. Submit the form, then independently await WSS
   closure, native SSH connection closure, stop_requested_at, ended_at and
   end_reason=stop_requested.
   Reuse backend verification of RecordingChunk/recording_page from
   RelayHarness.exercise: bounded sequence/hash chain, byte totals, completion
   and absence of fixture-secret/PRIVATE KEY/4.argv. Do not infer closure from a
   click, local grant revocation, timeout or VM destruction. A denied/failed DB
   observation remains unknown, like the delivered database-failure native test.
6. Add real-clock lease expiry (bounded TTL) and actual endpoint/person-binding
   revocation through the existing HTTP/UI controls. In particular,
   identity-binding-revoke targets the login/person link; grant-review targets a
   frozen Review ID and revokes a local Grant. They are different controls.
   Never equate the current local-grant UI test with revoking a live PAM lease.
   Existing native test names cover expiry, disabled endpoint, binding_revoked,
   logout, quota and database_failure; keep their expected distinctions.
7. For Observe, no automatic PAM-to-AccessEvent producer was established by the
   inspected sessions/broker code. Use the existing authenticated collector
   ingestion API only if the synthetic observer actually observes that native
   fixture; keep its token in the fixture process, never the browser. Verify the
   existing V8 provenance and evaluation, and report reference association rather
   than causal proof. Do not fabricate a PAM observation because a lease exists.
8. RDP follows the same browser path with tests/test_pam_rdp_e2e.py and the actual
   CredSSP fixture tests/fixtures/rdp.py plus rdp_fixture.c. Preserve its TLS/NLA/
   server pin, protocol restrictions and encrypted recording oracle. Start with
   SSH to obtain a small real closure receipt; do not transfer that success to RDP.

The existing Platform native-test build continues to exercise SSH and RDP.
The browser job needs its own admitted Linux context at the same source head.
Its native receipt requires actual opening, keyboard input, administrative
stop, both transport closures and verified partial capture playback. Local
configuration and fixture tests exercise the synthetic target and key exchange.
The browser and native engine have yet to run together in that job.
