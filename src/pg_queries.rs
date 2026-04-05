//! Shared PostgreSQL queries for both Diesel and SQLx backends.

pub const LOAD_ALL_QUERY: &str = "SELECT id, version, key_bytes, nonce, encryption_key_version, activated_at \
     FROM secret_keys \
     WHERE key_group = $1 \
     ORDER BY activated_at ASC, id ASC";

pub const POLL_NEW_QUERY: &str = "SELECT id, version, key_bytes, nonce, encryption_key_version, activated_at \
     FROM secret_keys \
     WHERE key_group = $1 AND (activated_at, id) > ($2, $3) \
     ORDER BY activated_at ASC, id ASC";

pub const LATEST_KEY_INFO_QUERY: &str = "SELECT version, activated_at \
     FROM secret_keys \
     WHERE key_group = $1 \
     ORDER BY activated_at DESC \
     LIMIT 1";

pub const ADVISORY_LOCK_QUERY: &str = "SELECT pg_advisory_xact_lock(hashtext($1::text)::bigint)";

pub const INSERT_KEY_QUERY: &str = "INSERT INTO secret_keys \
     (key_group, version, key_bytes, nonce, encryption_key_version, activated_at) \
     VALUES ($1, $2, $3, $4, $5, $6) \
     ON CONFLICT (key_group, version) DO UPDATE SET \
        key_bytes = EXCLUDED.key_bytes, \
        nonce = EXCLUDED.nonce, \
        encryption_key_version = EXCLUDED.encryption_key_version, \
        activated_at = EXCLUDED.activated_at";
