CREATE TABLE users (
    id              INTEGER         NOT NULL PRIMARY KEY,
    email           VARCHAR(255)    UNIQUE NOT NULL,
    password_hash   VARCHAR(255)    NOT NULL,
    role            VARCHAR(255)    NOT NULL DEFAULT 'user',
    totp_secret     VARCHAR(255)    NULL
);