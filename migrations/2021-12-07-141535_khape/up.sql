DROP TABLE users;
CREATE TABLE users (
    id                      INTEGER         PRIMARY KEY NOT NULL,
    email                   VARCHAR(255)    UNIQUE NOT NULL,
    file_entry              VARCHAR(255)    NULL,
    pre_register_secrets    VARCHAR(255)    NULL,
    ephemeral_keys          VARCHAR(255)    NULL,
    role                    VARCHAR(255)    NOT NULL DEFAULT 'user',
    totp_secret             VARCHAR(255)    NULL
);