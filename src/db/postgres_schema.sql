CREATE TABLE opskeys (
    kid VARCHAR(128) PRIMARY KEY,
    keys TEXT NOT NULL,
    properties TEXT NOT NULL
);

CREATE TABLE tokens (
    kid VARCHAR(128) NOT NULL,
    hashid VARCHAR(128) NOT NULL,
    data TEXT NOT NULL,
    subject VARCHAR(128),
    PRIMARY KEY (kid, hashid)
);

CREATE TABLE indexes (
    kid VARCHAR(128) NOT NULL,
    digest VARCHAR(128) NOT NULL,
    PRIMARY KEY (kid, digest)
);

CREATE TABLE subjects (
    kid VARCHAR(128) NOT NULL,
    subject VARCHAR(128) NOT NULL,
    seed TEXT NOT NULL,
    PRIMARY KEY (kid, subject)
);
