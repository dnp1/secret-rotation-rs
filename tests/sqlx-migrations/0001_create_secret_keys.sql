CREATE TABLE IF NOT EXISTS secret_keys
(
    id                     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_group              UUID        NOT NULL,
    version                SMALLINT    NOT NULL,
    key_bytes              BYTEA       NOT NULL,
    nonce                  BYTEA,
    encryption_key_version SMALLINT    NOT NULL DEFAULT 0,
    activated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_secret_keys_group_version UNIQUE (key_group, version)
);
CREATE INDEX IF NOT EXISTS idx_secret_keys_group_activation ON secret_keys (key_group, activated_at ASC);
