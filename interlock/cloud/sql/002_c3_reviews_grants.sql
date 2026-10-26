-- interlock cloud control plane, migration 002 (C3: reviews and grants).
--
-- 001 already carries the review/decision rows the data model documents. C3
-- needs the fields a remote decision actually reads and writes: the binding a
-- grant proves, the argument digest and mask counts that ship in place of the
-- preview, the sealed preview ciphertext, the decision clocks, and the
-- four-eyes policy copied from the host's review. Additive only: every column
-- has a default, so an existing pending review stays readable.
--
-- The grant delivery state is plane-side: a signed envelope per host, ordered
-- by a per-host sequence, plus the acknowledgement cursor the connector
-- advances. The plane never dials a host; `GET /v1/grants` is a poll.
--
-- Every tenant table carries org_id and gets the same fail-closed
-- org_isolation policy migration 001 uses. Nothing is granted to PUBLIC.

ALTER TABLE reviews ADD COLUMN IF NOT EXISTS binding text NOT NULL DEFAULT '';
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS action text NOT NULL DEFAULT '';
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS phase text NOT NULL DEFAULT 'call';
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS principal text;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS requester text;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS policy_id text;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS reason text;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS args_digest text;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS preview_enc bytea;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS mask_counts jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS pending_until timestamptz;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS min_approvals integer NOT NULL DEFAULT 1;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS allow_self_approval boolean NOT NULL DEFAULT true;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS approval_ttl double precision NOT NULL DEFAULT 900;

ALTER TABLE decisions ADD COLUMN IF NOT EXISTS approve_anyway boolean NOT NULL DEFAULT false;
ALTER TABLE decisions ADD COLUMN IF NOT EXISTS reason text;

CREATE TABLE IF NOT EXISTS cloud_grants (
    org_id text not null references orgs(id) on delete cascade,
    id text not null,
    host_id text not null,
    review_id text not null,
    seq bigint not null,
    envelope jsonb not null,
    delivered_at timestamptz not null default now(),
    acked_at timestamptz,
    primary key (org_id, id),
    foreign key (org_id, host_id) references hosts(org_id, id) on delete cascade,
    unique (org_id, host_id, seq)
);

CREATE TABLE IF NOT EXISTS grant_heads (
    org_id text not null references orgs(id) on delete cascade,
    host_id text not null,
    last_seq bigint not null default 0,
    last_sig text not null default 'GENESIS',
    updated_at timestamptz not null default now(),
    primary key (org_id, host_id),
    foreign key (org_id, host_id) references hosts(org_id, id) on delete cascade
);

CREATE INDEX IF NOT EXISTS cloud_grants_host_seq_idx
    ON cloud_grants (org_id, host_id, seq);
CREATE INDEX IF NOT EXISTS reviews_org_host_idx ON reviews (org_id, host_id);

ALTER TABLE cloud_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON cloud_grants USING (org_id = current_setting('interlock.org_id', true));
ALTER TABLE grant_heads ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON grant_heads USING (org_id = current_setting('interlock.org_id', true));
