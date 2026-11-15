-- W1 isolated laboratory only. Run explicitly as migration identity, never runtime.
-- Roles/database provisioning is external. Owner usage_anchor_owner must be NOLOGIN.
-- Runtime usage_anchor_runtime: NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
-- NOBYPASSRLS, no memberships, no database/schema CREATE or server-file privileges.
BEGIN;
CREATE SCHEMA pam_usage_anchor AUTHORIZATION usage_anchor_owner;
REVOKE ALL ON SCHEMA pam_usage_anchor FROM PUBLIC;
SET LOCAL ROLE usage_anchor_owner;
ALTER DEFAULT PRIVILEGES IN SCHEMA pam_usage_anchor REVOKE ALL ON TABLES FROM PUBLIC;
CREATE TABLE pam_usage_anchor.contexts (
 context_id uuid PRIMARY KEY, installation_id uuid NOT NULL, tenant_id uuid NOT NULL,
 witness_incarnation uuid NOT NULL, slot_sha256 text NOT NULL CHECK(slot_sha256 ~ '^[0-9a-f]{64}$'),
 serving_state text NOT NULL CHECK(serving_state IN ('open','closed')),
 lock_marker boolean NOT NULL DEFAULT false, UNIQUE(installation_id,tenant_id)
);
CREATE TABLE pam_usage_anchor.quotas (
 context_id uuid NOT NULL REFERENCES pam_usage_anchor.contexts,
 service_id text COLLATE "C" NOT NULL CHECK(length(service_id) BETWEEN 1 AND 64),
 lock_marker boolean NOT NULL DEFAULT false, PRIMARY KEY(context_id,service_id)
);
CREATE TABLE pam_usage_anchor.leases (
 context_id uuid NOT NULL REFERENCES pam_usage_anchor.contexts,
 service_id text COLLATE "C" NOT NULL, incarnation uuid NOT NULL, owner_der text NOT NULL,
 epoch bigint NOT NULL CHECK(epoch>0), issued_at bigint NOT NULL CHECK(issued_at>0),
 expires_at bigint NOT NULL CHECK(expires_at>issued_at AND expires_at<=issued_at+30),
 serving_state text NOT NULL CHECK(serving_state IN ('open','closed')),
 lock_marker boolean NOT NULL DEFAULT false, PRIMARY KEY(context_id,service_id)
);
CREATE TABLE pam_usage_anchor.operations (
 operation_id uuid PRIMARY KEY, context_id uuid NOT NULL REFERENCES pam_usage_anchor.contexts,
 broker_service text COLLATE "C" NOT NULL, operation text NOT NULL
 CHECK(operation='technical-credential.release.prepare'), idempotency_key uuid NOT NULL,
 vault_service text NOT NULL, vault_instance uuid NOT NULL, vault_der text NOT NULL,
 reservation_id uuid NOT NULL, lease_epoch bigint NOT NULL, slot_sha256 text NOT NULL,
 binding bytea NOT NULL CHECK(octet_length(binding) BETWEEN 1 AND 32768),
 baseline bytea CHECK(octet_length(baseline) BETWEEN 1 AND 65536),
 transcript bytea CHECK(octet_length(transcript) BETWEEN 1 AND 32768),
 body_hash text CHECK(body_hash ~ '^[0-9a-f]{64}$'),
 bound_response bytea CHECK(octet_length(bound_response) BETWEEN 1 AND 196608),
 issued_at bigint NOT NULL, expires_at bigint NOT NULL
 CHECK(issued_at>0 AND expires_at>issued_at AND expires_at<=issued_at+30),
 state text NOT NULL CHECK(state IN ('binding','pending_proofs','consumed_no_release','refused_no_release')),
 CHECK(state='binding' OR (baseline IS NOT NULL AND transcript IS NOT NULL
 AND body_hash IS NOT NULL AND bound_response IS NOT NULL)),
 final_bundle bytea CHECK(octet_length(final_bundle) BETWEEN 1 AND 2097152),
 final_digest text, terminal_response bytea,
 CHECK((state IN ('binding','pending_proofs') AND final_bundle IS NULL AND final_digest IS NULL AND terminal_response IS NULL)
 OR (state IN ('consumed_no_release','refused_no_release') AND final_bundle IS NOT NULL
 AND final_digest IS NOT NULL AND terminal_response IS NOT NULL
 AND final_digest ~ '^[0-9a-f]{64}$' AND octet_length(terminal_response) BETWEEN 1 AND 4096)),
 UNIQUE(context_id,broker_service,operation,idempotency_key)
);
CREATE TABLE pam_usage_anchor.activations (
 context_id uuid NOT NULL REFERENCES pam_usage_anchor.contexts,
 credential_id text COLLATE "C" NOT NULL, person_id uuid NOT NULL,
 spki_sha256 text NOT NULL, enrollment_id uuid NOT NULL, rp_id text NOT NULL, origin text NOT NULL,
 activation_version bigint NOT NULL CHECK(activation_version>0),
 sign_count bigint NOT NULL CHECK(sign_count BETWEEN 0 AND 4294967295),
 state_version bigint NOT NULL CHECK(state_version>0),
 status text NOT NULL CHECK(status IN ('commissioned','active','revoked')),
 -- Historical credentials remain for the same person after rotation. The RO
 -- slot selects exactly one credential per person; old rows are never rebound.
 PRIMARY KEY(context_id,credential_id), UNIQUE(context_id,spki_sha256)
);
-- No FK to activations/operations from these tables: it could acquire a lower-rank
-- lock during audit/INSERT. The single context lock and explicit checks enforce scope.
CREATE TABLE pam_usage_anchor.activation_challenges (
 challenge_id uuid PRIMARY KEY, context_id uuid NOT NULL REFERENCES pam_usage_anchor.contexts,
 service_id text NOT NULL, certificate_sha256 text NOT NULL, credential_id text NOT NULL,
 binding bytea NOT NULL CHECK(octet_length(binding) BETWEEN 1 AND 8192),
 challenge bytea NOT NULL CHECK(octet_length(challenge)=32), expires_at bigint NOT NULL,
 used_at bigint
);
CREATE TABLE pam_usage_anchor.proof_uses (
 context_id uuid NOT NULL REFERENCES pam_usage_anchor.contexts, operation_id uuid NOT NULL,
 person_id uuid NOT NULL, role text NOT NULL CHECK(role IN ('requester','reviewer','sponsor')),
 decision text NOT NULL, credential_id text NOT NULL, challenge_sha256 text NOT NULL,
 assertion_sha256 text NOT NULL, sign_count bigint NOT NULL CHECK(sign_count BETWEEN 0 AND 4294967295),
 PRIMARY KEY(operation_id,person_id,role), UNIQUE(context_id,credential_id,challenge_sha256)
);
CREATE TABLE pam_usage_anchor.audit_heads (
 context_id uuid PRIMARY KEY REFERENCES pam_usage_anchor.contexts,
 seq bigint NOT NULL CHECK(seq>=0), head_sha256 text NOT NULL
);
CREATE TABLE pam_usage_anchor.audit_events (
 context_id uuid NOT NULL REFERENCES pam_usage_anchor.contexts, seq bigint NOT NULL,
 event_bytes bytea NOT NULL CHECK(octet_length(event_bytes) BETWEEN 1 AND 4096),
 previous_sha256 text NOT NULL, event_sha256 text NOT NULL, PRIMARY KEY(context_id,seq)
);
-- Invoker triggers examine OLD/NEW only: no SQL reads, advisory locks or hidden
-- lower-rank acquisitions. They enforce monotonicity, never grant authority.
CREATE FUNCTION pam_usage_anchor.operation_transition() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
 IF OLD.state IN ('consumed_no_release','refused_no_release') THEN
   RAISE EXCEPTION 'terminal operation is immutable';
 END IF;
 IF (to_jsonb(NEW)-ARRAY['state','baseline','transcript','body_hash','bound_response','expires_at',
     'final_bundle','final_digest','terminal_response']) <>
    (to_jsonb(OLD)-ARRAY['state','baseline','transcript','body_hash','bound_response','expires_at',
     'final_bundle','final_digest','terminal_response']) THEN
   RAISE EXCEPTION 'immutable operation metadata';
 END IF;
 IF OLD.state='binding' THEN
   IF NEW.state<>'pending_proofs' OR NEW.expires_at>OLD.expires_at THEN
     RAISE EXCEPTION 'invalid bind transition';
   END IF;
 ELSE
   IF NEW.state NOT IN ('consumed_no_release','refused_no_release') OR
     ROW(NEW.baseline,NEW.transcript,NEW.body_hash,NEW.bound_response,NEW.expires_at) IS DISTINCT FROM
     ROW(OLD.baseline,OLD.transcript,OLD.body_hash,OLD.bound_response,OLD.expires_at) THEN
     RAISE EXCEPTION 'invalid terminal transition';
   END IF;
 END IF;
 RETURN NEW;
 END $$;
CREATE TRIGGER operation_transition BEFORE UPDATE ON pam_usage_anchor.operations
 FOR EACH ROW EXECUTE FUNCTION pam_usage_anchor.operation_transition();
CREATE FUNCTION pam_usage_anchor.activation_transition() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.sign_count<OLD.sign_count OR NEW.state_version<>OLD.state_version+1 OR
   (OLD.status='revoked' AND NEW.status<>'revoked') OR
   (OLD.status='active' AND NEW.status='commissioned') THEN
   RAISE EXCEPTION 'non-monotone activation';
 END IF;
 IF (to_jsonb(NEW)-ARRAY['sign_count','state_version','status']) <>
    (to_jsonb(OLD)-ARRAY['sign_count','state_version','status']) THEN
   RAISE EXCEPTION 'immutable activation metadata';
 END IF;
 RETURN NEW;
 END $$;
CREATE TRIGGER activation_transition BEFORE UPDATE ON pam_usage_anchor.activations
 FOR EACH ROW EXECUTE FUNCTION pam_usage_anchor.activation_transition();
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pam_usage_anchor FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pam_usage_anchor.operation_transition(),pam_usage_anchor.activation_transition()
 TO usage_anchor_runtime;
REVOKE ALL ON ALL TABLES IN SCHEMA pam_usage_anchor FROM PUBLIC;
GRANT USAGE ON SCHEMA pam_usage_anchor TO usage_anchor_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA pam_usage_anchor TO usage_anchor_runtime;
GRANT UPDATE(lock_marker) ON pam_usage_anchor.contexts,pam_usage_anchor.quotas,pam_usage_anchor.leases TO usage_anchor_runtime;
GRANT INSERT ON pam_usage_anchor.operations,pam_usage_anchor.activation_challenges,
 pam_usage_anchor.proof_uses,pam_usage_anchor.audit_events TO usage_anchor_runtime;
GRANT UPDATE(state,baseline,transcript,body_hash,bound_response,expires_at,
 final_bundle,final_digest,terminal_response) ON pam_usage_anchor.operations TO usage_anchor_runtime;
GRANT UPDATE(sign_count,state_version,status) ON pam_usage_anchor.activations TO usage_anchor_runtime;
GRANT UPDATE(used_at) ON pam_usage_anchor.activation_challenges TO usage_anchor_runtime;
GRANT UPDATE(seq,head_sha256) ON pam_usage_anchor.audit_heads TO usage_anchor_runtime;
COMMIT;
