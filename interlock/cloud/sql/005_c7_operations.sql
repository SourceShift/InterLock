-- interlock cloud control plane, migration 005 (C7: operations).
--
-- 001 reserved `webhook_endpoints` and `webhook_deliveries`. C7 turns them
-- into a signed, retrying outbox and adds the operational state the admin
-- surfaces need:
--
--   * `orgs.deleted_at` is the tombstone. Org deletion keeps receipts and
--     audit rows for the retention period, so a cascading delete would lose
--     exactly the evidence an operator must retain;
--   * webhook endpoints gain their event subscriptions, the hashed and the
--     sealed signing secret, and a disable timestamp; deliveries gain the
--     response metadata the admin view shows (never a response body);
--   * `version_floor` records the highest manifest version ever published per
--     org. A publish may only advance it, so a restore or a rollback can never
--     silently hand hosts an older policy than one already issued.
--
-- Every change is additive and every tenant table keeps the same fail-closed
-- org_isolation policy. `version_floor` is a tenant table and gets one too.

ALTER TABLE orgs ADD COLUMN IF NOT EXISTS deleted_at timestamptz;

ALTER TABLE webhook_endpoints ADD COLUMN IF NOT EXISTS events jsonb
    NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE webhook_endpoints ADD COLUMN IF NOT EXISTS secret_hash text;
ALTER TABLE webhook_endpoints ADD COLUMN IF NOT EXISTS secret_enc bytea;
ALTER TABLE webhook_endpoints ADD COLUMN IF NOT EXISTS created timestamptz
    NOT NULL DEFAULT now();
ALTER TABLE webhook_endpoints ADD COLUMN IF NOT EXISTS disabled_at timestamptz;

ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS duration_ms integer;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS response_status integer;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS body_digest text;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS created timestamptz
    NOT NULL DEFAULT now();

-- The worker asks for due pending rows on every tick; without this index the
-- scan grows with the whole delivery history.
CREATE INDEX IF NOT EXISTS webhook_deliveries_org_due_idx
    ON webhook_deliveries (org_id, next_attempt)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS webhook_deliveries_org_endpoint_idx
    ON webhook_deliveries (org_id, endpoint_id, created DESC);

CREATE TABLE IF NOT EXISTS version_floor (
    org_id text primary key references orgs(id) on delete cascade,
    highest_version integer not null default 0,
    updated_at timestamptz not null default now()
);

ALTER TABLE version_floor ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON version_floor
    USING (org_id = current_setting('interlock.org_id', true));
