-- Apply once to an existing installation before running the updated binary.
BEGIN;
ALTER TABLE tokens ADD COLUMN subject VARCHAR(128);
CREATE TABLE subjects (
    kid VARCHAR(128) NOT NULL,
    subject VARCHAR(128) NOT NULL,
    seed TEXT NOT NULL,
    PRIMARY KEY (kid, subject)
);
COMMIT;
