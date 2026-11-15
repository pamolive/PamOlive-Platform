-- Explicit V-side laboratory extension, owned by its existing NOLOGIN owner.
-- Does not alter ADR024 tables, runtime modules or callers.
BEGIN;
SET LOCAL ROLE vault_n0_owner;
CREATE TABLE vault_reservation.usage_mirrors (
 reservation_id uuid PRIMARY KEY REFERENCES vault_reservation.reservations,
 operation_id uuid NOT NULL UNIQUE, body_hash text NOT NULL,
 bound_response bytea NOT NULL CHECK(octet_length(bound_response) BETWEEN 1 AND 196608),
 terminal_response bytea CHECK(octet_length(terminal_response) BETWEEN 1 AND 4096),
 state text NOT NULL CHECK(state IN ('bound','uncertain','consumed_no_release','refused_no_release'))
);
REVOKE ALL ON vault_reservation.usage_mirrors FROM PUBLIC;
GRANT SELECT,INSERT ON vault_reservation.usage_mirrors TO vault_n0_runtime;
GRANT UPDATE(state,terminal_response) ON vault_reservation.usage_mirrors TO vault_n0_runtime;
COMMIT;
