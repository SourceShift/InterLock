-- interlock cloud control plane, migration 001.
--
-- The application connects as a role that is NOT the table owner and has no
-- BYPASSRLS. Row-level security is therefore enforced for it. Every tenant
-- table carries org_id and gets a fail-closed org_isolation policy; the
-- request sets `interlock.org_id` for its transaction, and an unset value
-- compares equal to nothing, so a query returns no rows.
--
-- Nothing is granted to PUBLIC. The app role is provisioned separately.
--
-- Time columns are timestamptz, ids are text, and structured payloads
-- (masked previews, receipt bodies, signed documents) are jsonb. Secrets are
-- stored hashed or encrypted; no column holds a plaintext password or secret.

CREATE TABLE orgs (
    id text primary key,
    slug text not null unique,
    name text not null,
    sso_issuer text,
    sso_client_id text,
    step_up_policy text not null default 'webauthn',
    retention_days integer not null default 365
        check (retention_days between 30 and 2555)
);

CREATE TABLE org_domains (
    org_id text not null references orgs(id) on delete cascade,
    domain text not null,
    verified_at timestamptz,
    primary key (org_id, domain)
);

CREATE TABLE users (
    org_id text not null references orgs(id) on delete cascade,
    id text not null,
    issuer text not null,
    subject text not null,
    -- C1: the address an invited member was provisioned with and the address
    -- an OIDC claim carries. Accounts are never merged by email (FR-048):
    -- it is a display and invite attribute only.
    email text,
    -- No default: every user is assigned an explicit role from the fixed
    -- model (FR-054), so no account is created with an implied privilege.
    role text not null
        check (role in ('owner', 'admin', 'reviewer', 'auditor')),
    status text not null default 'active',
    primary key (org_id, id),
    unique (org_id, issuer, subject)
);

CREATE TABLE sessions (
    org_id text not null references orgs(id) on delete cascade,
    id text not null,
    user_id text not null,
    token_hash text not null unique,
    csrf_hash text not null,
    step_up_at timestamptz,
    step_up_method text,
    expires timestamptz not null,
    -- C1 session bookkeeping: the absolute deadline is derived from created,
    -- and last_seen drives the 30-minute idle timeout (FR-049). Touches are
    -- throttled by the session manager, not by a trigger.
    created timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    ip text,
    user_agent text,
    primary key (org_id, id),
    foreign key (org_id, user_id) references users(org_id, id) on delete cascade
);

CREATE TABLE webauthn_credentials (
    org_id text not null references orgs(id) on delete cascade,
    id text not null,
    user_id text not null,
    public_key text not null,
    sign_count bigint not null default 0,
    last_used timestamptz,
    primary key (org_id, id),
    foreign key (org_id, user_id) references users(org_id, id) on delete cascade
);

CREATE TABLE totp_secrets (
    org_id text not null references orgs(id) on delete cascade,
    user_id text not null,
    secret_enc text not null,
    confirmed_at timestamptz,
    primary key (org_id, user_id),
    foreign key (org_id, user_id) references users(org_id, id) on delete cascade
);

CREATE TABLE enrollment_tokens (
    org_id text not null references orgs(id) on delete cascade,
    id text not null,
    token_hash text not null unique,
    host_name text,
    expires timestamptz not null,
    used_at timestamptz,
    primary key (org_id, id)
);

CREATE TABLE hosts (
    org_id text not null references orgs(id) on delete cascade,
    id text not null,
    name text not null,
    owner_subject text not null,
    public_keys jsonb not null default '[]'::jsonb,
    state text not null default 'active',
    last_seen timestamptz,
    primary key (org_id, id)
);

CREATE TABLE agent_keys (
    org_id text not null references orgs(id) on delete cascade,
    id text not null,
    prefix text not null,
    secret_hash text not null,
    host_id text not null,
    scopes jsonb not null default '[]'::jsonb,
    expires timestamptz,
    revoked_at timestamptz,
    primary key (org_id, id),
    foreign key (org_id, host_id) references hosts(org_id, id) on delete cascade
);

CREATE TABLE reviews (
    org_id text not null references orgs(id) on delete cascade,
    host_id text not null,
    id text not null,
    status text not null default 'pending',
    masked_preview jsonb,
    metadata jsonb not null default '{}'::jsonb,
    decided timestamptz,
    decided_by text,
    approval_until timestamptz,
    approvers jsonb not null default '[]'::jsonb,
    created timestamptz not null default now(),
    primary key (org_id, host_id, id),
    unique (org_id, id),
    foreign key (org_id, host_id) references hosts(org_id, id) on delete cascade
);

CREATE TABLE decisions (
    org_id text not null references orgs(id) on delete cascade,
    id text not null,
    review_id text not null,
    reviewer text not null,
    step_up_method text not null,
    step_up_at timestamptz not null,
    decision text not null,
    grant_id text,
    grant_seq bigint,
    primary key (org_id, id),
    foreign key (org_id, review_id) references reviews(org_id, id) on delete cascade
);

CREATE TABLE receipts (
    org_id text not null references orgs(id) on delete cascade,
    host_id text not null,
    mac text not null,
    body jsonb not null,
    verification text not null default 'unverified',
    created timestamptz not null default now(),
    primary key (org_id, host_id, mac),
    foreign key (org_id, host_id) references hosts(org_id, id) on delete cascade
);

CREATE TABLE receipt_heads (
    org_id text not null references orgs(id) on delete cascade,
    host_id text not null,
    head_mac text,
    count bigint not null default 0,
    checkpoint timestamptz,
    primary key (org_id, host_id),
    foreign key (org_id, host_id) references hosts(org_id, id) on delete cascade
);

CREATE TABLE policy_artifacts (
    org_id text not null references orgs(id) on delete cascade,
    sha256 text not null,
    storage_ref text not null,
    format text not null,
    -- PolicyEngine.epoch is the 16-character hex identity of the compiled
    -- rule set, not a counter (interlock/policy/engine.py).
    epoch text not null check (epoch ~ '^[0-9a-f]{16}$'),
    compiler_version text not null,
    primary key (org_id, sha256)
);

-- FR-043's additional manifest fields -- mode, issued-at, artifact size -- and
-- the artifact envelope's typed format are additive columns for the next
-- migration; 001 stores the data-model row exactly as documented.
CREATE TABLE policy_manifests (
    org_id text not null references orgs(id) on delete cascade,
    version integer not null,
    -- Epoch of the compiled rule set; 16 hex characters (PolicyEngine.epoch).
    epoch text not null check (epoch ~ '^[0-9a-f]{16}$'),
    target_kind text not null,
    target_id text not null,
    artifact_sha256 text not null,
    expires timestamptz,
    key_id text not null,
    signature text not null,
    author text,
    primary key (org_id, version),
    foreign key (org_id, artifact_sha256)
        references policy_artifacts(org_id, sha256)
);

CREATE TABLE policy_rollouts (
    org_id text not null references orgs(id) on delete cascade,
    id text not null,
    manifest_version integer not null,
    ring text not null,
    state text not null,
    health text,
    promoted_at timestamptz,
    rolled_back_at timestamptz,
    primary key (org_id, id),
    foreign key (org_id, manifest_version)
        references policy_manifests(org_id, version)
);

CREATE TABLE policy_kills (
    org_id text not null references orgs(id) on delete cascade,
    id text not null,
    scope text not null,
    reason text not null,
    document jsonb not null,
    author text not null,
    issued_at timestamptz not null,
    primary key (org_id, id)
);

CREATE TABLE audit_log (
    org_id text not null references orgs(id) on delete cascade,
    id text not null,
    event text not null,
    actor text,
    detail jsonb not null default '{}'::jsonb,
    created timestamptz not null default now(),
    primary key (org_id, id)
);

CREATE TABLE webhook_endpoints (
    org_id text not null references orgs(id) on delete cascade,
    id text not null,
    url text not null,
    active boolean not null default true,
    primary key (org_id, id)
);

CREATE TABLE webhook_deliveries (
    org_id text not null references orgs(id) on delete cascade,
    id text not null,
    endpoint_id text not null,
    event text not null,
    payload jsonb not null default '{}'::jsonb,
    status text not null default 'pending',
    attempts integer not null default 0,
    last_error text,
    next_attempt timestamptz,
    delivered_at timestamptz,
    primary key (org_id, id),
    foreign key (org_id, endpoint_id)
        references webhook_endpoints(org_id, id) on delete cascade
);

-- Documented access paths.
CREATE INDEX reviews_org_status_created_idx ON reviews (org_id, status, created);
CREATE INDEX receipts_org_host_created_idx ON receipts (org_id, host_id, created);
CREATE INDEX sessions_token_hash_idx ON sessions (token_hash);
CREATE INDEX agent_keys_prefix_idx ON agent_keys (prefix);
CREATE INDEX policy_manifests_target_idx
    ON policy_manifests (org_id, target_kind, target_id, version);

-- Row-level isolation for every table that carries org_id. orgs itself is not
-- org-scoped: its id is the setting, so it gets no policy.
ALTER TABLE org_domains ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON org_domains USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON users USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON sessions USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE webauthn_credentials ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON webauthn_credentials USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE totp_secrets ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON totp_secrets USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE enrollment_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON enrollment_tokens USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE hosts ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON hosts USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE agent_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON agent_keys USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE reviews ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON reviews USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE decisions ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON decisions USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE receipts ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON receipts USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE receipt_heads ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON receipt_heads USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE policy_artifacts ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON policy_artifacts USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE policy_manifests ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON policy_manifests USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE policy_rollouts ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON policy_rollouts USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE policy_kills ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON policy_kills USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON audit_log USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON webhook_endpoints USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON webhook_deliveries USING (org_id = current_setting('interlock.org_id', true));
