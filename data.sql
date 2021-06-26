PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE __diesel_schema_migrations (version VARCHAR(50) PRIMARY KEY NOT NULL,run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
INSERT INTO __diesel_schema_migrations VALUES('20210603095530','2021-06-11 12:05:27');
INSERT INTO __diesel_schema_migrations VALUES('20210611115119','2021-06-11 12:05:27');
CREATE TABLE users (
    id              INTEGER         PRIMARY KEY NOT NULL,
    email           VARCHAR(255)    UNIQUE NOT NULL,
    password_hash   VARCHAR(255)    NOT NULL,
    role            VARCHAR(255)    NOT NULL DEFAULT 'user',
    totp_secret     VARCHAR(255)    NULL
);
INSERT INTO users VALUES(1,'gil@demo.ch','wYN1dH00o2Go3mVMQMFo7qosokh0IfUiJqEJ670WsQA','user','abcdabcdabcdabcdabcdabcdabcdabcd');
CREATE TABLE tokens (
    token           VARCHAR(255)    NOT NULL PRIMARY KEY,
    expire_at       DATETIME        NOT NULL,
    user_id         INTEGER         NOT NULL,
    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);
INSERT INTO tokens VALUES('HQelWYqp/jEPm7aAu1mdhriuyp8iayiq','2021-06-11 13:35:09.406859233',1);
INSERT INTO tokens VALUES('FCRl7vIluHW3Gt7wXDi1mohbc5xVw4nM','2021-06-11 13:41:00.744430681',1);
COMMIT;
