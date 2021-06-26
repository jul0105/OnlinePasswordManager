CREATE TABLE tokens (
    token           VARCHAR(255)    NOT NULL PRIMARY KEY,
    validity_start  DATETIME        NOT NULL,
    validity_end    DATETIME        NOT NULL,
    user_id         INTEGER         NOT NULL,
    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);