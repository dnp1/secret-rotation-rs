use crate::backend::SecretBackend;
use crate::encryptor::KeyEncryptor;
use crate::rotator::{KeyRotator, SecretRotationBackend};
use crate::secret_rotation::{InMemorySecretGroup, SecretGroup};
use crate::syncer::SecretSyncer;

use crate::util::generate_secret;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Returned by [`SecretManager::start`]. Call [`wait`](SecretManagerHandle::wait) after
/// cancelling the [`CancellationToken`] to ensure both background tasks have fully stopped.
pub struct SecretManagerHandle {
    syncer: JoinHandle<()>,
    rotator: JoinHandle<()>,
}

impl SecretManagerHandle {
    /// Waits for both background tasks to finish.
    pub async fn wait(self) {
        let _ = tokio::join!(self.syncer, self.rotator);
    }
}

/// Convenience facade that runs a [`SecretSyncer`] and a [`KeyRotator`] together.
///
/// `SecretManager` is the right choice when a single service instance should **both** rotate
/// keys **and** consume them.  Internally it:
///
/// 1. Calls [`SecretSyncer::initial_load`] synchronously so the ring is hydrated before
///    `start` returns (any failure is propagated as the `Err` variant).
/// 2. Spawns the syncer and rotator as independent `tokio` tasks that run until the
///    [`CancellationToken`] is cancelled.
///
/// The [`SecretGroup`] trait is forwarded to the inner [`InMemorySecretGroup`] so you can
/// call [`current`](SecretGroup::current) and [`resolve`](SecretGroup::resolve) directly on the
/// manager.
///
/// For split deployments — a dedicated rotation service plus many reader nodes — use
/// [`KeyRotator`] and [`SecretSyncer`] independently instead.
///
/// # Type parameters
///
/// - `B` — backend that implements both [`SecretBackend`] and [`SecretRotationBackend`]
/// - `E` — encryptor that implements [`KeyEncryptor`]
/// - `V` — ring buffer size (default 256, must be ≤ 256)
/// - `S` — key size in bytes (default 32)
pub struct SecretManager<B, E, const V: usize = 256, const S: usize = 32>
where
    B: SecretBackend + SecretRotationBackend + Clone,
    E: KeyEncryptor + Clone,
{
    group_id: String,
    group: Arc<InMemorySecretGroup<V, S>>,
    backend: B,
    encryptor: E,
    rotation_interval: Duration,
    propagation_delay: Duration,
    poll_interval: Option<Duration>,
    generate_key: Arc<dyn Fn() -> [u8; S] + Send + Sync + 'static>,
}

impl<B, E, const V: usize, const S: usize> SecretManager<B, E, V, S>
where
    B: SecretBackend + SecretRotationBackend + Clone,
    E: KeyEncryptor + Clone,
{
    /// Create a new `SecretManager`.
    ///
    /// # Arguments
    ///
    /// - `group_id` — identifies the logical key group in storage
    /// - `group` — the ring buffer that will be kept hydrated; typically wrapped in `Arc` so
    ///   application code can read it concurrently
    /// - `backend` — implements both [`SecretBackend`] (read) and [`SecretRotationBackend`] (write)
    /// - `encryptor` — encrypts keys on write, decrypts on read
    /// - `rotation_interval` — how long a key lives before a new one is generated
    /// - `propagation_delay` — head-start given to syncers before a new key becomes `current`;
    ///   set to at least your maximum expected poll latency
    /// - `poll_interval` — how often the syncer polls for new keys; `None` uses 5 seconds
    /// - `generate_key` — custom key-material generator; `None` uses a CSPRNG fill
    pub fn new(
        group_id: impl Into<String>,
        group: Arc<InMemorySecretGroup<V, S>>,
        backend: B,
        encryptor: E,
        rotation_interval: Duration,
        propagation_delay: Duration,
        poll_interval: Option<Duration>,
        generate_key: Option<fn() -> [u8; S]>,
    ) -> Self {
        let generate_key = generate_key.unwrap_or(generate_secret::<S>);
        Self {
            group_id: group_id.into(),
            group,
            backend,
            encryptor,
            rotation_interval,
            propagation_delay,
            poll_interval,
            generate_key: Arc::new(generate_key),
        }
    }

    /// Hydrate the ring buffer and spawn background tasks.
    ///
    /// Performs the initial load synchronously — if it fails the error is returned and no
    /// tasks are spawned.  On success, the syncer and rotator are launched and a
    /// [`SecretManagerHandle`] is returned.
    ///
    /// # Graceful shutdown
    ///
    /// ```rust,no_run
    /// # use secret_manager::*;
    /// # use async_trait::async_trait;
    /// # use std::{sync::Arc, time::{Duration, SystemTime}};
    /// # use tokio_util::sync::CancellationToken;
    /// # #[derive(Clone)]
    /// # struct MyBackend;
    /// # #[async_trait]
    /// # impl SecretBackend for MyBackend {
    /// #     type Error = std::convert::Infallible;
    /// #     async fn load_all(&self, _: &str) -> Result<Vec<KeyRecord>, Self::Error> { Ok(vec![]) }
    /// #     async fn poll_new(&self, _: &str, _: SystemTime, _: i64) -> Result<Vec<KeyRecord>, Self::Error> { Ok(vec![]) }
    /// # }
    /// # #[async_trait]
    /// # impl SecretRotationBackend for MyBackend {
    /// #     type Error = std::convert::Infallible;
    /// #     async fn latest_key_info(&self, _: &str) -> Result<Option<(u8, SystemTime)>, Self::Error> { Ok(None) }
    /// #     async fn try_insert_key(&self, _: &str, _: Option<u8>, _: u8, _: &Encrypted, _: SystemTime) -> Result<bool, Self::Error> { Ok(true) }
    /// # }
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let (backend, encryptor) = (MyBackend, NoOpEncryptor);
    /// # let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0u8; 32]));
    /// let token = CancellationToken::new();
    /// let handle = SecretManager::new("payments-signing", group, backend, encryptor,
    ///     Duration::from_secs(3600), Duration::from_secs(30), None, None)
    ///     .start(token.clone()).await?;
    ///
    /// // … serve traffic …
    ///
    /// token.cancel();      // signal tasks to stop
    /// handle.wait().await; // block until both tasks have exited
    /// # Ok(()) }
    /// ```
    pub async fn start(self, token: CancellationToken) -> Result<SecretManagerHandle, <B as SecretBackend>::Error> {
        let generate_key = Arc::clone(&self.generate_key);

        let mut syncer = SecretSyncer::new(
            self.group_id.clone(),
            Arc::clone(&self.group),
            self.backend.clone(),
            self.encryptor.clone(),
            self.rotation_interval,
            self.poll_interval,
        );

        let cursor = syncer.initial_load(&token).await?;

        let rotator: KeyRotator<B, E, V, S> = KeyRotator::new(
            self.group_id,
            self.backend,
            self.rotation_interval,
            self.propagation_delay,
            self.encryptor,
            move || (generate_key)(),
        );

        Ok(SecretManagerHandle {
            syncer: tokio::spawn(syncer.run(token.clone(), cursor)),
            rotator: tokio::spawn(rotator.run(token)),
        })
    }
}

impl<B, E, const V: usize, const S: usize> SecretGroup<V, S> for SecretManager<B, E, V, S>
where
    B: SecretBackend + SecretRotationBackend + Clone,
    E: KeyEncryptor + Clone,
{
    fn current(&self) -> (u8, [u8; S]) {
        self.group.current()
    }

    fn resolve(&self, version: u8) -> Option<[u8; S]> {
        self.group.resolve(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::KeyRecord;
    use crate::encryptor::Encrypted;
    use crate::no_op_encryptor::NoOpEncryptor;
    use crate::rotator::SecretRotationBackend;
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::SystemTime;

    #[derive(Debug)]
    struct MockError;
    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "mock error")
        }
    }
    impl std::error::Error for MockError {}

    #[derive(Clone)]
    struct MockBackend {
        load_response: Vec<KeyRecord>,
        poll_responses: Arc<Mutex<VecDeque<Vec<KeyRecord>>>>,
        latest_responses: Arc<Mutex<VecDeque<Option<(u8, SystemTime)>>>>,
    }

    #[async_trait]
    impl SecretBackend for MockBackend {
        type Error = MockError;
        async fn load_all(&self, _group_id: &str) -> Result<Vec<KeyRecord>, MockError> {
            Ok(self.load_response.clone())
        }
        async fn poll_new(
            &self,
            _group_id: &str,
            _since_time: SystemTime,
            _since_id: i64,
        ) -> Result<Vec<KeyRecord>, MockError> {
            Ok(self
                .poll_responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_default())
        }
    }

    #[async_trait]
    impl SecretRotationBackend for MockBackend {
        type Error = MockError;
        async fn latest_key_info(
            &self,
            _group_id: &str,
        ) -> Result<Option<(u8, SystemTime)>, MockError> {
            Ok(self
                .latest_responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(None))
        }
        async fn try_insert_key(
            &self,
            _group_id: &str,
            _expected_version: Option<u8>,
            _new_version: u8,
            _encrypted: &Encrypted,
            _activated_at: SystemTime,
        ) -> Result<bool, MockError> {
            Ok(false)
        }
    }

    #[tokio::test]
    async fn start_hydrates_group_and_returns_ok() {
        let backend = MockBackend {
            load_response: vec![KeyRecord {
                id: 1,
                version: 0,
                key_bytes: vec![0xAA; 32],
                nonce: None,
                encryption_key_version: 0,
                activated_at: SystemTime::now() - Duration::from_secs(300),
            }],
            poll_responses: Arc::new(Mutex::new(VecDeque::new())),
            latest_responses: Arc::new(Mutex::new(VecDeque::new())),
        };
        let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0u8; 32]));
        let manager = SecretManager::new(
            "test-manager",
            Arc::clone(&group),
            backend,
            NoOpEncryptor,
            Duration::from_secs(3600),
            Duration::from_secs(10),
            None,
            Some(|| [0xFFu8; 32]),
        );
        let token = CancellationToken::new();
        let handle = manager.start(token.clone()).await.expect("start should succeed");
        let (v, _) = group.current();
        assert_eq!(v, 0);
        token.cancel();
        handle.wait().await;
    }

    #[test]
    fn manager_implements_secret_group() {
        let backend = MockBackend {
            load_response: vec![],
            poll_responses: Arc::new(Mutex::new(VecDeque::new())),
            latest_responses: Arc::new(Mutex::new(VecDeque::new())),
        };
        let group = Arc::new(InMemorySecretGroup::<256, 32>::new(42, [0xEEu8; 32]));
        let manager = SecretManager::new(
            "test-manager",
            group,
            backend,
            NoOpEncryptor,
            Duration::from_secs(3600),
            Duration::from_secs(10),
            None,
            Some(|| [0u8; 32]),
        );

        let sg: &dyn SecretGroup<256, 32> = &manager;
        let (v, k) = sg.current();
        assert_eq!(v, 42);
        assert_eq!(k, [0xEEu8; 32]);
    }
}
