use async_trait::async_trait;
use std::time::SystemTime;

pub(super) const EPOCH_CURSOR: SystemTime = SystemTime::UNIX_EPOCH;

/// A versioned secret key record as returned by a [`SecretBackend`].
///
/// The ciphertext in `key_bytes` must be decrypted with the matching [`KeyEncryptor`](crate::KeyEncryptor)
/// before being placed into an [`InMemorySecretGroup`](crate::InMemorySecretGroup).
#[derive(Clone)]
pub struct KeyRecord {
    /// Monotonic database ID, used as a tie-breaker for polling cursors.
    pub id: i64,
    /// Ring-buffer slot index (fits in `u8` for the default 256-slot ring).
    pub version: u8,
    /// Encrypted key bytes (ciphertext). Decryption is the caller's responsibility.
    pub key_bytes: Vec<u8>,
    /// Nonce used during encryption, or `None` for KMS / no-op.
    pub nonce: Option<Vec<u8>>,
    /// Version of the key-encryption key used (0 = no-op/plaintext).
    pub encryption_key_version: u8,
    /// When this key became (or will become) active.
    pub activated_at: SystemTime,
}

/// Read-side storage contract used by [`SecretSyncer`](crate::SecretSyncer).
///
/// Implement this trait (alongside [`SecretRotationBackend`](crate::SecretRotationBackend) if
/// the same backend serves both roles) to connect `SecretSyncer` to your storage layer.
/// Built-in implementations are available behind feature flags:
/// `DieselPgSecretBackend` (`pg-diesel-async`) and `SqlxPgSecretBackend` (`pg-sqlx`).
#[async_trait]
pub trait SecretBackend: Send + Sync + 'static {
    /// The error type returned on backend failures.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load **all** keys for `group_id`, ordered by `activated_at` ascending.
    ///
    /// Called once at startup by [`SecretSyncer::initial_load`](crate::SecretSyncer::initial_load).
    async fn load_all(&self, group_id: &str) -> Result<Vec<KeyRecord>, Self::Error>;

    /// Return keys inserted after `(since_time, since_id)`, ordered by `activated_at` ascending.
    ///
    /// The cursor is a `(SystemTime, i64)` pair — both components must be strictly greater
    /// than the cursor for a record to be returned, ensuring no record is delivered twice
    /// even when multiple records share the same `activated_at`.
    async fn poll_new(
        &self,
        group_id: &str,
        since_time: SystemTime,
        since_id: i64,
    ) -> Result<Vec<KeyRecord>, Self::Error>;
}
