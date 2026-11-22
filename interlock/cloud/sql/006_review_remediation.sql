-- interlock cloud control plane, migration 006 (review remediation).
--
-- The host already stores the policy's one-line hint at what would be allowed
-- instead with an escalated review, and the local surfaces show it. The plane
-- kept only `reason`, so a remote reviewer saw what was refused but not the
-- alternative the policy offered.
--
-- Additive and nullable: an upload from a host that predates the field stores
-- NULL, which every reader treats as "the rule gave no hint".
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS remediation text;
