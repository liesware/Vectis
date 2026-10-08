CREATE TABLE IF NOT EXISTS opskeys (
    kid VARCHAR(128) PRIMARY KEY,
    keys VARCHAR(10240) NOT NULL,
    properties VARCHAR(10240) NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    kid VARCHAR(128) NOT NULL,
    hashid VARCHAR(128) NOT NULL,
    data VARCHAR(10240) NOT NULL,
    subject VARCHAR(128),
    PRIMARY KEY (kid, hashid)
);

CREATE TABLE IF NOT EXISTS indexes (
    kid VARCHAR(128) NOT NULL,
    digest VARCHAR(128) NOT NULL,
    PRIMARY KEY (kid, digest)
);

CREATE TABLE IF NOT EXISTS subjects (
    kid VARCHAR(128) NOT NULL,
    subject VARCHAR(128) NOT NULL,
    seed TEXT NOT NULL,
    PRIMARY KEY (kid, subject)
);
