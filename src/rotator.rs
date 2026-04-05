use crate::encryptor::{Encrypted, KeyEncryptor};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Back-off on backend errors before retrying the full loop.
const ERROR_RETRY_DELAY: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// SecretRotationBackend — write-side trait
// ---------------------------------------------------------------------------

/// Write-side storage contract required by [`KeyRotator`].
///
/// Implement this trait (together with [`SecretBackend`](crate::SecretBackend) if you also need
/// reading) to bring your own backend.  The two methods together form an optimistic-locking
/// protocol: read the latest version, then attempt a conditional insert.
#[async_trait]
pub trait SecretRotationBackend: Send + Sync + 'static {
    /// The error type returned on backend failures.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns `(version, activated_at)` of the most recently **inserted** key for `group_id`,
    /// or `None` when no key exists yet.
    async fn latest_key_info(
        &self,
        group_id: &str,
    ) -> Result<Option<(u8, SystemTime)>, Self::Error>;

    /// Atomically inserts a new key only when the current version still equals
    /// `expected_version` (use `None` when no key exists yet).
    ///
    /// Returns `true` if the key was inserted, `false` if another instance raced ahead and
    /// the version no longer matches.  Implementations should acquire an advisory lock or use
    /// a compare-and-swap so that concurrent rotators converge safely.
    async fn try_insert_key(
        &self,
        group_id: &str,
        expected_version: Option<u8>,
        new_version: u8,
        encrypted: &Encrypted,
        activated_at: SystemTime,
    ) -> Result<bool, Self::Error>;
}

// ---------------------------------------------------------------------------
// KeyRotator
// ---------------------------------------------------------------------------

/// Background task that periodically generates and persists a new encryption key.
///
/// `KeyRotator` is the **write side** of the key-management system.  It runs a single
/// perpetual loop: sleep until the current key is due for rotation, generate a new key,
/// encrypt it, and attempt a conditional insert via [`SecretRotationBackend::try_insert_key`].
/// If another instance raced ahead the insert is skipped and the loop simply sleeps until the
/// *new* key expires.
///
/// Multiple `KeyRotator` instances for the same `group_id` can run concurrently (e.g. for
/// high availability); the optimistic-locking protocol in `try_insert_key` ensures only one
/// insert succeeds per rotation cycle.
///
/// # Type parameters
///
/// - `B` — backend that implements [`SecretRotationBackend`]
/// - `E` — encryptor that implements [`KeyEncryptor`]
/// - `V` — ring buffer size (number of key slots, **must be ≤ 256**, default 256).
///   Must match the `V` of any [`InMemorySecretGroup`](crate::InMemorySecretGroup) consuming
///   the keys.
/// - `S` — key size in bytes (default 32)
///
/// # Standalone use
///
/// `KeyRotator` can be used without a [`SecretSyncer`](crate::SecretSyncer) or
/// [`SecretManager`](crate::SecretManager).  This is useful when you want a dedicated
/// rotation service that writes to shared storage while other nodes only read:
///
/// ```rust,no_run
/// # use secret_manager::*;
/// # use async_trait::async_trait;
/// # use std::time::{Duration, SystemTime};
/// # use tokio_util::sync::CancellationToken;
/// # struct MyBackend;
/// # #[async_trait]
/// # impl SecretRotationBackend for MyBackend {
/// #     type Error = std::convert::Infallible;
/// #     async fn latest_key_info(&self, _: &str) -> Result<Option<(u8, SystemTime)>, Self::Error> { Ok(None) }
/// #     async fn try_insert_key(&self, _: &str, _: Option<u8>, _: u8, _: &Encrypted, _: SystemTime) -> Result<bool, Self::Error> { Ok(true) }
/// # }
/// # async fn example() {
/// # let (backend, encryptor) = (MyBackend, NoOpEncryptor);
/// let rotator: KeyRotator<_, _, 256, 32> = KeyRotator::new(
///     "session-tokens",
///     backend,
///     Duration::from_secs(3600),
///     Duration::from_secs(30),
///     encryptor,
///     || [0u8; 32],
/// );
/// rotator.run(CancellationToken::new()).await;
/// # }
/// ```
pub struct KeyRotator<B: SecretRotationBackend, E: KeyEncryptor + Clone, const V: usize = 256, const S: usize = 32> {
    group_id: String,
    backend: B,
    encryptor: E,
    rotation_interval: Duration,
    propagation_delay: Duration,
    generate_key: Arc<dyn Fn() -> [u8; S] + Send + Sync + 'static>,
}

impl<B: SecretRotationBackend, E: KeyEncryptor + Clone, const V: usize, const S: usize> KeyRotator<B, E, V, S> {
    /// Create a new `KeyRotator`.
    ///
    /// # Arguments
    ///
    /// - `group_id` — identifies the logical key group in storage
    /// - `backend` — implements [`SecretRotationBackend`]
    /// - `rotation_interval` — how long a key is valid before a new one is generated
    /// - `propagation_delay` — added to `SystemTime::now()` to compute `activated_at` for the
    ///   new key, giving syncers time to pull the key before it becomes active
    /// - `encryptor` — wraps key bytes before storage
    /// - `generate_key` — produces fresh key material; defaults in [`SecretManager`](crate::SecretManager)
    ///   to a CSPRNG fill
    ///
    /// # Panics
    ///
    /// Panics at compile time if `V > 256` (versions are stored as `u8`).
    pub fn new(
        group_id: impl Into<String>,
        backend: B,
        rotation_interval: Duration,
        propagation_delay: Duration,
        encryptor: E,
        generate_key: impl Fn() -> [u8; S] + Send + Sync + 'static,
    ) -> Self {
        const { assert!(V <= 256, "ring buffer size V must be ≤ 256; versions are u8") };
        Self {
            group_id: group_id.into(),
            backend,
            encryptor,
            rotation_interval,
            propagation_delay,
            generate_key: Arc::new(generate_key),
        }
    }

    /// Run the rotation loop until `token` is cancelled.
    ///
    /// This method consumes `self` and runs forever, sleeping between rotations.  Pass the
    /// returned future to [`tokio::spawn`] or run it directly.  Cancel `token` for a clean
    /// shutdown; the loop exits after the current sleep or retry delay completes.
    ///
    /// On backend or encryption errors the rotator backs off for 30 seconds before retrying,
    /// so transient failures do not cause a tight error loop.
    pub async fn run(self, token: CancellationToken) {
        info!(group_id = %self.group_id, "KeyRotator starting");

        loop {
            let pre_info = match self.backend.latest_key_info(&self.group_id).await {
                Ok(info) => info,
                Err(e) => {
                    error!(group_id = %self.group_id, error = %e, "KeyRotator: backend error");
                    if sleep_or_cancel(ERROR_RETRY_DELAY, &token).await {
                        break;
                    }
                    continue;
                }
            };

            let sleep_dur = match pre_info {
                Some((_, last_activated_at)) => last_activated_at
                    .checked_add(self.rotation_interval)
                    .and_then(|next| next.duration_since(SystemTime::now()).ok())
                    .unwrap_or(Duration::ZERO),
                None => Duration::ZERO,
            };

            if sleep_or_cancel(sleep_dur, &token).await {
                break;
            }

            let expected_version = pre_info.map(|(v, _)| v);
            let new_version = expected_version
                .map(|v| ((v as usize + 1) % V) as u8)
                .unwrap_or(0);
            let key_bytes = (self.generate_key)();
            let activated_at = SystemTime::now() + self.propagation_delay;

            let encrypted = match self.encryptor.encrypt(&key_bytes).await {
                Ok(enc) => enc,
                Err(e) => {
                    error!(group_id = %self.group_id, error = %e, "KeyRotator: encryption failed");
                    if sleep_or_cancel(ERROR_RETRY_DELAY, &token).await {
                        break;
                    }
                    continue;
                }
            };

            match self
                .backend
                .try_insert_key(
                    &self.group_id,
                    expected_version,
                    new_version,
                    &encrypted,
                    activated_at,
                )
                .await
            {
                Ok(true) => {
                    info!(group_id = %self.group_id, version = new_version, "KeyRotator: new key inserted")
                }
                Ok(false) => {
                    info!(group_id = %self.group_id, "KeyRotator: another instance rotated")
                }
                Err(e) => {
                    error!(group_id = %self.group_id, error = %e, "KeyRotator: try_insert_key failed");
                    if sleep_or_cancel(ERROR_RETRY_DELAY, &token).await {
                        break;
                    }
                }
            }
        }
        info!(group_id = %self.group_id, "KeyRotator: shutting down");
    }
}

async fn sleep_or_cancel(duration: Duration, token: &CancellationToken) -> bool {
    tokio::select! {
        biased;
        _ = token.cancelled() => true,
        _ = tokio::time::sleep(duration) => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryptor::Encrypted;
    use crate::no_op_encryptor::NoOpEncryptor;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Debug, PartialEq)]
    struct MockError;
    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "mock error")
        }
    }
    impl std::error::Error for MockError {}

    struct TryInsertCall {
        expected_version: Option<u8>,
        new_version: u8,
        ciphertext: Vec<u8>,
        activated_at: SystemTime,
    }

    struct MockRotationBackend {
        latest_queue: Mutex<VecDeque<Option<(u8, SystemTime)>>>,
        insert_results: Mutex<VecDeque<Result<bool, MockError>>>,
        inserted: Arc<Mutex<Vec<TryInsertCall>>>,
    }

    impl MockRotationBackend {
        fn new(inserted: Arc<Mutex<Vec<TryInsertCall>>>) -> Self {
            Self {
                latest_queue: Mutex::new(VecDeque::new()),
                insert_results: Mutex::new(VecDeque::new()),
                inserted,
            }
        }
        fn push_latest(&self, v: Option<(u8, SystemTime)>) {
            self.latest_queue.lock().unwrap().push_back(v);
        }
    }

    #[async_trait]
    impl SecretRotationBackend for MockRotationBackend {
        type Error = MockError;

        async fn latest_key_info(
            &self,
            _group_id: &str,
        ) -> Result<Option<(u8, SystemTime)>, MockError> {
            Ok(self.latest_queue.lock().unwrap().pop_front().flatten())
        }

        async fn try_insert_key(
            &self,
            _group_id: &str,
            expected_version: Option<u8>,
            new_version: u8,
            encrypted: &Encrypted,
            activated_at: SystemTime,
        ) -> Result<bool, MockError> {
            let result = self
                .insert_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(true));
            if result == Ok(true) {
                self.inserted.lock().unwrap().push(TryInsertCall {
                    expected_version,
                    new_version,
                    ciphertext: encrypted.ciphertext.clone(),
                    activated_at,
                });
            }
            result
        }
    }

    #[tokio::test]
    async fn rotates_immediately_when_no_key_exists() {
        let inserted = Arc::new(Mutex::new(vec![]));
        let backend = MockRotationBackend::new(Arc::clone(&inserted));
        backend.push_latest(None);
        backend.push_latest(Some((0, SystemTime::now())));

        let rotator: KeyRotator<_, _, 256> = KeyRotator::new(
            "test-rotator",
            backend,
            Duration::from_secs(3600),
            Duration::from_secs(120),
            NoOpEncryptor,
            || [42u8; 32],
        );
        let token = CancellationToken::new();
        let tc = token.clone();
        let handle = tokio::spawn(async move { rotator.run(tc).await });

        tokio::time::sleep(Duration::from_millis(100)).await;
        token.cancel();
        handle.await.unwrap();

        let calls = inserted.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].expected_version, None);
        assert_eq!(calls[0].new_version, 0);
        // NoOpEncryptor passes bytes through as-is
        assert_eq!(calls[0].ciphertext, vec![42u8; 32]);
        assert!(calls[0].activated_at > SystemTime::now() + Duration::from_secs(100));
    }
}
