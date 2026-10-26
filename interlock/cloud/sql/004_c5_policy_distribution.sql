-- interlock cloud control plane, migration 004 (C5: policy distribution).
--
-- 001 reserved the four policy tables. C5 fills the envelope the signed
-- manifest carries and adds the authored source a plane compiles from:
--
--   * `policy_sources` is the plane's authored policy input (documents, the
--     scope bindings and the rules-module reference). It is versioned per org
--     so a rollout rollback can recompile the source it replaced instead of
--     reusing a manifest body;
--   * `policy_artifacts.artifact` stores the exact canonical bytes behind the
--     sha256, so a host fetches what the manifest names even after a restart;
--   * `policy_manifests` gains the full signed envelope (manifest id, mode,
--     issue time, minimum agent, rules digest, artifact size and the signed
--     document itself). The existing `expires`, `key_id` and `signature`
--     columns stay authoritative;
--   * `policy_kills` gains a strictly increasing per-org `kill_epoch` and the
--     target columns the signed kill carries;
--   * `policy_rollouts` gains the percentage stage and an updated timestamp.
--
-- Every change is additive: an older plane keeps reading the columns it knew.
-- Every tenant table keeps the same fail-closed org_isolation policy.

ALTER TABLE policy_artifacts ADD COLUMN IF NOT EXISTS artifact bytea;
ALTER TABLE policy_artifacts ADD COLUMN IF NOT EXISTS artifact_size integer;
ALTER TABLE policy_artifacts ADD COLUMN IF NOT EXISTS created timestamptz
    NOT NULL DEFAULT now();

ALTER TABLE policy_manifests ADD COLUMN IF NOT EXISTS manifest_id text;
ALTER TABLE policy_manifests ADD COLUMN IF NOT EXISTS mode text;
ALTER TABLE policy_manifests ADD COLUMN IF NOT EXISTS issued_at timestamptz;
ALTER TABLE policy_manifests ADD COLUMN IF NOT EXISTS minimum_agent text;
ALTER TABLE policy_manifests ADD COLUMN IF NOT EXISTS rules_digest text;
ALTER TABLE policy_manifests ADD COLUMN IF NOT EXISTS artifact_size integer;
ALTER TABLE policy_manifests ADD COLUMN IF NOT EXISTS document jsonb;
ALTER TABLE policy_manifests ADD COLUMN IF NOT EXISTS created timestamptz
    NOT NULL DEFAULT now();

-- Cross-org lookups must miss even when the sha is known; the composite key
-- above already does that, and this index makes "manifest for host" cheap.
CREATE INDEX IF NOT EXISTS policy_manifests_org_version_idx
    ON policy_manifests (org_id, version DESC);

ALTER TABLE policy_kills ADD COLUMN IF NOT EXISTS kill_epoch bigint;
ALTER TABLE policy_kills ADD COLUMN IF NOT EXISTS target_kind text;
ALTER TABLE policy_kills ADD COLUMN IF NOT EXISTS target_id text;

-- Number existing kills once, in issue order, so the unique index below can
-- be created and a host's "since" cursor stays meaningful.
UPDATE policy_kills AS k
SET kill_epoch = numbered.rn
FROM (
    SELECT org_id, id,
           row_number() OVER (PARTITION BY org_id ORDER BY issued_at, id) AS rn
    FROM policy_kills
    WHERE kill_epoch IS NULL
) AS numbered
WHERE k.org_id = numbered.org_id
  AND k.id = numbered.id
  AND k.kill_epoch IS NULL;

ALTER TABLE policy_kills ALTER COLUMN kill_epoch SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS policy_kills_org_epoch_idx
    ON policy_kills (org_id, kill_epoch);

ALTER TABLE policy_rollouts ADD COLUMN IF NOT EXISTS percent integer
    NOT NULL DEFAULT 0;
ALTER TABLE policy_rollouts ADD COLUMN IF NOT EXISTS reason text;
ALTER TABLE policy_rollouts ADD COLUMN IF NOT EXISTS updated_at timestamptz
    NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS policy_sources (
    org_id text not null references orgs(id) on delete cascade,
    source_version integer not null,
    documents jsonb not null,
    scope jsonb not null,
    rules_module text,
    sha256 text,
    updated_at timestamptz not null default now(),
    primary key (org_id, source_version)
);

CREATE INDEX IF NOT EXISTS policy_sources_org_version_idx
    ON policy_sources (org_id, source_version DESC);

CREATE INDEX IF NOT EXISTS policy_sources_org_sha_idx
    ON policy_sources (org_id, sha256);

ALTER TABLE policy_sources ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON policy_sources
    USING (org_id = current_setting('interlock.org_id', true));
