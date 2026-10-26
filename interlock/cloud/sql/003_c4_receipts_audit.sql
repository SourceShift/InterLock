-- interlock cloud control plane, migration 003 (C4: receipts and audit).
--
-- 001 already carries `receipts` and `receipt_heads`. C4 adds what chain
-- verification and audit search need, additively:
--
--   * `receipts.seq` orders a host's chain for cursor paging and retention
--     without relying on `created` (which can collide inside one batch);
--   * `receipt_heads.head_prev`, `last_checkpoint_at`, `verification` and
--     `updated_at` let the plane show a verification level and detect a
--     stale linkage-only chain (FR-035);
--   * `receipt_checkpoints` stores the signed attestation an HMAC host sends.
--
-- Every tenant table carries org_id and the same fail-closed org_isolation
-- policy migration 001 uses. Nothing is granted to PUBLIC.

ALTER TABLE receipts ADD COLUMN IF NOT EXISTS seq bigint;

-- Existing rows predate the counter: number each host's chain once, in the
-- order the plane received it, so the unique index below can be created.
UPDATE receipts AS r
SET seq = numbered.rn
FROM (
    SELECT org_id, host_id, mac,
           row_number() OVER (PARTITION BY org_id, host_id
                              ORDER BY created, mac) AS rn
    FROM receipts
    WHERE seq IS NULL
) AS numbered
WHERE r.org_id = numbered.org_id
  AND r.host_id = numbered.host_id
  AND r.mac = numbered.mac
  AND r.seq IS NULL;

ALTER TABLE receipts ALTER COLUMN seq SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS receipts_org_host_seq_idx
    ON receipts (org_id, host_id, seq);

ALTER TABLE receipt_heads ADD COLUMN IF NOT EXISTS head_prev text;
ALTER TABLE receipt_heads ADD COLUMN IF NOT EXISTS last_checkpoint_at timestamptz;
ALTER TABLE receipt_heads ADD COLUMN IF NOT EXISTS verification text
    NOT NULL DEFAULT 'receipts_unverified';
ALTER TABLE receipt_heads ADD COLUMN IF NOT EXISTS updated_at timestamptz
    NOT NULL DEFAULT now();

-- 001's `checkpoint` column held the last attested time; keep it authoritative
-- for existing rows and carry it forward.
UPDATE receipt_heads
SET last_checkpoint_at = checkpoint
WHERE last_checkpoint_at IS NULL AND checkpoint IS NOT NULL;

CREATE TABLE IF NOT EXISTS receipt_checkpoints (
    org_id text not null references orgs(id) on delete cascade,
    host_id text not null,
    head_mac text not null,
    count bigint not null default 0,
    issued_at timestamptz not null,
    document jsonb not null,
    primary key (org_id, host_id, head_mac, count),
    foreign key (org_id, host_id) references hosts(org_id, id) on delete cascade
);

CREATE INDEX IF NOT EXISTS receipt_checkpoints_host_issued_idx
    ON receipt_checkpoints (org_id, host_id, issued_at);

ALTER TABLE receipt_checkpoints ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON receipt_checkpoints
    USING (org_id = current_setting('interlock.org_id', true));
