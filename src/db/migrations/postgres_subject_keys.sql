-- Apply once as schema owner before upgrading all Vectis nodes.
BEGIN;
ALTER TABLE tokens ADD COLUMN subject VARCHAR(128);
CREATE TABLE subjects (
    kid VARCHAR(128) NOT NULL,
    subject VARCHAR(128) NOT NULL,
    seed TEXT NOT NULL,
    PRIMARY KEY (kid, subject)
);
COMMIT;
-- Separately grant SELECT, INSERT, DELETE on public.subjects to the runtime role.
