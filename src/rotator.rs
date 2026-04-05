use crate::encryptor::{Encrypted, KeyEncryptor};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Back-off on backend errors before retrying the full loop.
const ERROR_RETRY_DELAY: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// SecretRotationBackend — write-side trait
// ---------------------------------------------------------------------------

/// Write-side storage contract for key rotation.
#[async_trait]
pub trait SecretRotationBackend: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns `(version, activated_at)` of the most recently **inserted** key.
    async fn latest_key_info(
        &self,
        group_id: Uuid,
    ) -> Result<Option<(u8, SystemTime)>, Self::Error>;

    /// Acquires a lock and inserts only if the current version still matches `expected_version`.
    async fn try_insert_key(
        &self,
        group_id: Uuid,
        expected_version: Option<u8>,
        new_version: u8,
        encrypted: &Encrypted,
        activated_at: SystemTime,
    ) -> Result<bool, Self::Error>;
}

// ---------------------------------------------------------------------------
// KeyRotator
// ---------------------------------------------------------------------------

pub struct KeyRotator<B: SecretRotationBackend, E: KeyEncryptor + Clone, const V: usize = 256, const S: usize = 32> {
    group_id: Uuid,
    backend: B,
    encryptor: E,
    rotation_interval: Duration,
    propagation_delay: Duration,
    generate_key: Arc<dyn Fn() -> [u8; S] + Send + Sync + 'static>,
}

impl<B: SecretRotationBackend, E: KeyEncryptor + Clone, const V: usize, const S: usize> KeyRotator<B, E, V, S> {
    pub fn new(
        group_id: Uuid,
        backend: B,
        rotation_interval: Duration,
        propagation_delay: Duration,
        encryptor: E,
        generate_key: impl Fn() -> [u8; S] + Send + Sync + 'static,
    ) -> Self {
        const { assert!(V <= 256, "ring buffer size V must be ≤ 256; versions are u8") };
        Self {
            group_id,
            backend,
            encryptor,
            rotation_interval,
            propagation_delay,
            generate_key: Arc::new(generate_key),
        }
    }

    pub async fn run(self, token: CancellationToken) {
        info!(group_id = %self.group_id, "KeyRotator starting");

        loop {
            let pre_info = match self.backend.latest_key_info(self.group_id).await {
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
                    self.group_id,
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
            _group_id: Uuid,
        ) -> Result<Option<(u8, SystemTime)>, MockError> {
            Ok(self.latest_queue.lock().unwrap().pop_front().flatten())
        }

        async fn try_insert_key(
            &self,
            _group_id: Uuid,
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
            Uuid::new_v4(),
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
