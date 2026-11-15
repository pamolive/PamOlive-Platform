-- ADR024 LAB ONLY. Execute explicitly as a dedicated schema owner after review.
-- Database/roles are provisioned separately; never run from the runtime process.
-- Required NOLOGIN owner: vault_n0_owner. Runtime login: vault_n0_runtime.
-- Runtime must have NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS,
-- no privileged memberships, no owner membership, no PUBLIC/default DDL rights.
BEGIN;
CREATE SCHEMA vault_reservation AUTHORIZATION vault_n0_owner;
REVOKE ALL ON SCHEMA vault_reservation FROM PUBLIC;
SET LOCAL ROLE vault_n0_owner;
ALTER DEFAULT PRIVILEGES IN SCHEMA vault_reservation REVOKE ALL ON TABLES FROM PUBLIC;

CREATE TABLE vault_reservation.commissioned_state (
    slot_id uuid PRIMARY KEY,
    singleton boolean NOT NULL DEFAULT true CHECK (singleton),
    incarnation uuid NOT NULL,
    slot_sha256 text NOT NULL CHECK (slot_sha256 ~ '^[0-9a-f]{64}$'),
    serving_state text NOT NULL CHECK (serving_state IN ('closed', 'open')),
    lock_marker boolean NOT NULL DEFAULT false,
    UNIQUE (singleton)
);
-- No seed/default open state. Admin explicitly inserts the reviewed incarnation/slot.

CREATE TABLE vault_reservation.reservations (
    reservation_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    service_id text NOT NULL CHECK (length(service_id) BETWEEN 1 AND 64),
    operation text NOT NULL CHECK (operation = 'technical-credential.release.prepare'),
    idempotency_key uuid NOT NULL,
    certificate_sha256 text NOT NULL CHECK (certificate_sha256 ~ '^[0-9a-f]{64}$'),
    draft_sha256 text NOT NULL CHECK (draft_sha256 ~ '^[0-9a-f]{64}$'),
    canonical_draft bytea NOT NULL CHECK (octet_length(canonical_draft) BETWEEN 1 AND 16384),
    slot_sha256 text NOT NULL CHECK (slot_sha256 ~ '^[0-9a-f]{64}$'),
    incarnation uuid NOT NULL,
    broker_instance_id uuid NOT NULL,
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 32),
    issued_at bigint NOT NULL CHECK (issued_at > 0),
    expires_at bigint NOT NULL CHECK (issued_at < expires_at AND expires_at <= issued_at + 30),
    state text NOT NULL CHECK (state = 'pending_proofs'),
    UNIQUE (tenant_id, installation_id, service_id, operation, idempotency_key)
);
CREATE INDEX pending_quota ON vault_reservation.reservations (tenant_id, installation_id, service_id, expires_at);
CREATE TABLE vault_reservation.audit (
    reservation_id uuid PRIMARY KEY REFERENCES vault_reservation.reservations,
    event text NOT NULL CHECK (event = 'reserved_pending_proofs'),
    issued_at bigint NOT NULL CHECK (issued_at > 0),
    slot_sha256 text NOT NULL CHECK (slot_sha256 ~ '^[0-9a-f]{64}$')
);
REVOKE ALL ON ALL TABLES IN SCHEMA vault_reservation FROM PUBLIC;
GRANT USAGE ON SCHEMA vault_reservation TO vault_n0_runtime;
GRANT SELECT ON vault_reservation.commissioned_state TO vault_n0_runtime;
-- PostgreSQL SELECT FOR UPDATE requires UPDATE on at least one column.
-- This semantically unused marker grants no ability to alter commissioned context.
GRANT UPDATE (lock_marker) ON vault_reservation.commissioned_state TO vault_n0_runtime;
GRANT SELECT, INSERT ON vault_reservation.reservations, vault_reservation.audit TO vault_n0_runtime;
COMMIT;
