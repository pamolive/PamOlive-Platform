# Concrete next raccord — full P1-G remains the objective

The present test is one increment, not a substitute for full P1-G. It has two
separate subjects: a browser-created PAM intention with two genuine UI votes;
and a seeded Observe demonstration plus a new, independently reviewed local
fixture grant revoked through the existing UI. It never claims those are one
end-to-end intention or that the in-memory provider is a real target.

The next native case can reuse P1GBrowser.login/enroll/request/votes and override
only after_approval and install_websocket_policy plus the server/endpoint
fixture. No product authentication or synthetic assertion generator is needed.

1. Reuse the owned native environment from tests/test_pam_relay_e2e.py:
   RelayHarness.setUp owns guacd, Uvicorn and their termination; exercise creates
   an actual AsyncSSH server and awaits server.close/wait_closed. Extract a
   **test-fixture-only** context around that lifetime, leaving its existing tests
   unchanged. Expose the assigned loopback port, generated host key and synthetic
   target credential to the SERVER fixture only. Do not reuse its pre-authorized
   lease/assurance as a browser action: the new driver must create its own request,
   two votes and launch through the shipped forms and pam-trust.js.
2. Replace the initial WSGI TLS thread with TLS Uvicorn serving config.asgi plus
   Django's ASGI static-files wrapper. Reuse the same private CA/server-key/NSS
   trust handling; configure the exact HTTPS/WSS origin and synthetic RP ID.
   The current WSGI thread cannot serve WebSockets. Do not treat a mocked socket
   or driver WebSocket interception as the real transport. The native follow-up
   disables the current fail-on-any-WebSocket test policy only inside its owned
   fixture network, permits the actual same-origin /ws/pam/<connection-id>/ path,
   and observes native browser socket closure.
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
5. Exercise actual UI stop through the existing pam-stop form, then independently
   await WSS closure, native SSH connection closure and ended_at/end_reason.
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

Run shape after independent source/profile review: the existing Platform
native-test build and gates remain mandatory; add the native browser case to a
separate test-only target/job at the exact same source head. The scoped P1-G job
must return a new artifact with actual start/transport/end/recording facts.
No such case, image allocation, native process, browser, SQL or artifact was run
in this preparation. The next prerequisite is the explicit execution-context/
sandbox decision above, followed by this narrow fixture-lifetime extraction;
there is no new product route or new service/ADR required to invent authority.
