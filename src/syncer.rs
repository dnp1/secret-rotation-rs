use crate::backend::{EPOCH_CURSOR, SecretBackend};
use crate::encryptor::{Encrypted, KeyEncryptor};
use crate::secret_rotation::InMemorySecretGroup;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
const ROTATION_POLL_BUFFER: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Converts a DB-sourced nonce `Vec` into a fixed-size array.
/// Returns `None` for both absent nonces and malformed ones (wrong length triggers
/// a "missing nonce" error at decryption time, surfacing the invariant violation).
fn to_nonce(v: Option<Vec<u8>>) -> Option<[u8; 12]> {
    v.and_then(|b| b.try_into().ok())
}

fn payload_hash(enc: &Encrypted) -> u64 {
    let mut h = DefaultHasher::new();
    enc.ciphertext.hash(&mut h);
    enc.nonce.hash(&mut h);
    enc.key_version.hash(&mut h);
    h.finish()
}

// ---------------------------------------------------------------------------
// SecretSyncer
// ---------------------------------------------------------------------------

/// Background task that keeps an [`InMemorySecretGroup`] up-to-date by polling storage.
///
/// `SecretSyncer` is the **read side** of the key-management system.  It:
///
/// 1. **Initial load** — calls [`SecretBackend::load_all`] once at startup to hydrate the
///    ring buffer and promote the most-recently-activated key as `current`.
/// 2. **Poll loop** — periodically calls [`SecretBackend::poll_new`] to pick up keys added
///    after the cursor.  Keys with `activated_at` in the future are stored in the ring but
///    only promoted to `current` once their activation time arrives (via a spawned timer task).
///
/// A hash-based dedup cache prevents redundant [`KeyEncryptor::decrypt`] calls when the same
/// ciphertext is seen again (e.g. after a service restart or a backend re-delivery).
///
/// The poll interval is adaptive: if a rotation is expected soon (based on `rotation_interval`),
/// the syncer wakes earlier so it picks up the new key promptly; otherwise it sleeps for the
/// configured `poll_interval`.
///
/// # Type parameters
///
/// - `B` — backend that implements [`SecretBackend`]
/// - `E` — encryptor that implements [`KeyEncryptor`]
/// - `V` — ring buffer size (must match the [`InMemorySecretGroup`] passed in, default 256)
/// - `S` — key size in bytes (default 32)
///
/// # Standalone use
///
/// Use `SecretSyncer` directly when your instances should only **read** keys, not rotate them:
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
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let (backend, encryptor) = (MyBackend, NoOpEncryptor);
/// let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0u8; 32]));
/// let mut syncer: SecretSyncer<_, _, 256, 32> = SecretSyncer::new(
///     "session-tokens",
///     Arc::clone(&group),
///     backend,
///     encryptor,
///     Duration::from_secs(3600),
///     None,
/// );
/// let token = CancellationToken::new();
/// let cursor = syncer.initial_load(&token).await?;
/// tokio::spawn(syncer.run(token, cursor));
/// # Ok(()) }
/// ```
pub struct SecretSyncer<B: SecretBackend, E: KeyEncryptor + Clone, const V: usize = 256, const S: usize = 32> {
    group_id: String,
    secret: Arc<InMemorySecretGroup<V, S>>,
    backend: B,
    encryptor: E,
    rotation_interval: Duration,
    poll_interval: Duration,
    seen_hashes: HashMap<u8, u64>,
}

impl<B: SecretBackend, E: KeyEncryptor + Clone, const V: usize, const S: usize> SecretSyncer<B, E, V, S> {
    /// Create a new `SecretSyncer`.
    ///
    /// # Arguments
    ///
    /// - `group_id` — identifies the logical key group in storage
    /// - `secret` — the in-memory ring buffer to keep populated
    /// - `backend` — implements [`SecretBackend`]
    /// - `encryptor` — used to decrypt ciphertext from storage before placing keys in the ring
    /// - `rotation_interval` — expected time between rotations; used to compute a smart early
    ///   wake-up before the next key is due, reducing promotion latency
    /// - `poll_interval` — base polling cadence; `None` uses the 5-second default
    pub fn new(
        group_id: impl Into<String>,
        secret: Arc<InMemorySecretGroup<V, S>>,
        backend: B,
        encryptor: E,
        rotation_interval: Duration,
        poll_interval: Option<Duration>,
    ) -> Self {
        Self {
            group_id: group_id.into(),
            secret,
            backend,
            encryptor,
            rotation_interval,
            poll_interval: poll_interval.unwrap_or(DEFAULT_POLL_INTERVAL),
            seen_hashes: HashMap::new(),
        }
    }

    /// Load all existing keys from storage and hydrate the ring buffer.
    ///
    /// Must be called once before [`run`](Self::run).  Returns a cursor
    /// `(max_activated_at, max_id)` that marks the newest record seen; pass this directly to
    /// `run` so the poll loop starts from where the initial load left off.
    ///
    /// Keys already present in the ring are not re-decrypted (hash dedup).  Keys with
    /// `activated_at` in the future are stored but not yet promoted; a timer task is spawned
    /// for each to promote them at the right moment.
    ///
    /// The `token` parameter is threaded through only for future cancellability of long-running
    /// initial loads; it is not yet acted upon inside the method body.
    pub async fn initial_load(
        &mut self,
        token: &CancellationToken,
    ) -> Result<(SystemTime, i64), B::Error> {
        let records = self.backend.load_all(&self.group_id).await?;
        let count = records.len();
        let mut max_time = EPOCH_CURSOR;
        let mut max_id = 0i64;
        let mut latest_active_version: Option<u8> = None;
        let mut latest_active_at = EPOCH_CURSOR;

        let now = SystemTime::now();

        for record in records {
            if (record.activated_at, record.id) > (max_time, max_id) {
                max_time = record.activated_at;
                max_id = record.id;
            }

            if (record.version as usize) >= V {
                error!(
                    group_id = %self.group_id,
                    version = record.version,
                    ring_size = V,
                    "SecretSyncer: version exceeds ring buffer size, skipping"
                );
                continue;
            }

            let enc = Encrypted {
                ciphertext: record.key_bytes,
                nonce: to_nonce(record.nonce),
                key_version: record.encryption_key_version,
            };
            let hash = payload_hash(&enc);

            if self.seen_hashes.get(&record.version) == Some(&hash) {
                // payload unchanged — key is already in the ring, skip decryption
                if record.activated_at <= now {
                    if record.activated_at >= latest_active_at {
                        latest_active_at = record.activated_at;
                        latest_active_version = Some(record.version);
                    }
                }
                continue;
            }

            match self.encryptor.decrypt(&enc).await {
                Ok(bytes) => {
                    if let Ok(key) = <[u8; S]>::try_from(bytes) {
                        self.secret.store_key(record.version, key);
                        self.seen_hashes.insert(record.version, hash);
                        if record.activated_at <= now {
                            if record.activated_at >= latest_active_at {
                                latest_active_at = record.activated_at;
                                latest_active_version = Some(record.version);
                            }
                        } else {
                            self.schedule_promotion(record.version, record.activated_at, token.clone());
                        }
                    }
                }
                Err(e) => {
                    error!(
                        group_id = %self.group_id,
                        version = record.version,
                        error = %e,
                        "SecretSyncer: decryption failed during initial load"
                    );
                }
            }
        }

        if let Some(v) = latest_active_version {
            self.secret.promote(v);
        }

        info!(group_id = %self.group_id, count, "SecretSyncer initial load complete");
        Ok((max_time, max_id))
    }

    /// Run the poll loop until `token` is cancelled.
    ///
    /// Consumes `self`; pass to [`tokio::spawn`] after calling [`initial_load`](Self::initial_load).
    ///
    /// On backend errors the syncer backs off for 30 seconds before retrying.  Decryption
    /// errors for individual records are logged and skipped; the loop continues.
    pub async fn run(mut self, token: CancellationToken, mut cursor: (SystemTime, i64)) {
        loop {
            let now = SystemTime::now();
            let next_expected = cursor.0.checked_add(self.rotation_interval).unwrap_or(now);

            let sleep_dur = next_expected
                .duration_since(now)
                .ok()
                .map(|d| d + ROTATION_POLL_BUFFER)
                .filter(|&smart| smart < self.poll_interval)
                .unwrap_or(self.poll_interval);

            tokio::select! {
                biased;
                _ = token.cancelled() => {
                    info!(group_id = %self.group_id, "SecretSyncer shutting down");
                    break;
                }
                _ = tokio::time::sleep(sleep_dur) => {
                    match self.backend.poll_new(&self.group_id, cursor.0, cursor.1).await {
                        Ok(records) => {
                            for record in records {
                                if (record.activated_at, record.id) > cursor {
                                    cursor = (record.activated_at, record.id);
                                }
                                if (record.version as usize) >= V {
                                    error!(
                                        group_id = %self.group_id,
                                        version = record.version,
                                        ring_size = V,
                                        "SecretSyncer: version exceeds ring buffer size, skipping"
                                    );
                                    continue;
                                }
                                let enc = Encrypted {
                                    ciphertext: record.key_bytes,
                                    nonce: to_nonce(record.nonce),
                                    key_version: record.encryption_key_version,
                                };
                                let hash = payload_hash(&enc);
                                if self.seen_hashes.get(&record.version) == Some(&hash) {
                                    continue;
                                }
                                match self.encryptor.decrypt(&enc).await {
                                    Ok(bytes) => {
                                        if let Ok(key) = <[u8; S]>::try_from(bytes) {
                                            self.secret.store_key(record.version, key);
                                            self.seen_hashes.insert(record.version, hash);
                                            let now = SystemTime::now();
                                            if record.activated_at <= now {
                                                self.secret.promote(record.version);
                                            } else {
                                                self.schedule_promotion(record.version, record.activated_at, token.clone());
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            group_id = %self.group_id,
                                            version = record.version,
                                            error = %e,
                                            "SecretSyncer: decryption failed during poll"
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!(group_id = %self.group_id, error = %e, "SecretSyncer poll failed");
                            if self.sleep_or_cancel(Duration::from_secs(30), &token).await { break; }
                        }
                    }
                }
            }
        }
    }

    fn schedule_promotion(&self, version: u8, activated_at: SystemTime, token: CancellationToken) {
        let secret = Arc::clone(&self.secret);
        tokio::spawn(async move {
            if let Ok(sleep_dur) = activated_at.duration_since(SystemTime::now()) {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => return,
                    _ = tokio::time::sleep(sleep_dur) => {}
                }
            }
            secret.promote(version);
        });
    }

    async fn sleep_or_cancel(&self, duration: Duration, token: &CancellationToken) -> bool {
        tokio::select! {
            biased;
            _ = token.cancelled() => true,
            _ = tokio::time::sleep(duration) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::KeyRecord;
    use crate::encryptor::Encrypted;
    use crate::no_op_encryptor::NoOpEncryptor;
    use crate::secret_rotation::SecretGroup;
    use anyhow::Result as AnyResult;
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    // -----------------------------------------------------------------------
    // Shared test infrastructure
    // -----------------------------------------------------------------------

    #[derive(Debug)]
    struct MockError;
    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "mock error")
        }
    }
    impl std::error::Error for MockError {}

    /// Cloneable mock backend. Clones share the same poll queue via `Arc`.
    #[derive(Clone)]
    struct MockBackend {
        load_response: Vec<KeyRecord>,
        poll_responses: Arc<Mutex<VecDeque<Result<Vec<KeyRecord>, MockError>>>>,
    }

    impl MockBackend {
        fn with_load(records: Vec<KeyRecord>) -> Self {
            Self {
                load_response: records,
                poll_responses: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn push_poll(&self, records: Vec<KeyRecord>) {
            self.poll_responses.lock().unwrap().push_back(Ok(records));
        }

        fn push_poll_err(&self) {
            self.poll_responses.lock().unwrap().push_back(Err(MockError));
        }
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
            self.poll_responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(vec![]))
        }
    }

    /// Encryptor that counts how many times `decrypt` has been called.
    #[derive(Clone)]
    struct CountingEncryptor {
        decrypt_calls: Arc<Mutex<usize>>,
    }

    impl CountingEncryptor {
        fn new() -> Self {
            Self { decrypt_calls: Arc::new(Mutex::new(0)) }
        }
        fn decrypt_calls(&self) -> usize {
            *self.decrypt_calls.lock().unwrap()
        }
    }

    #[async_trait]
    impl KeyEncryptor for CountingEncryptor {
        async fn encrypt(&self, plaintext: &[u8]) -> AnyResult<Encrypted> {
            Ok(Encrypted { ciphertext: plaintext.to_vec(), nonce: None, key_version: 0 })
        }
        async fn decrypt(&self, enc: &Encrypted) -> AnyResult<Vec<u8>> {
            *self.decrypt_calls.lock().unwrap() += 1;
            Ok(enc.ciphertext.clone())
        }
    }

    fn rec(id: i64, version: u8, fill: u8, activated_at: SystemTime) -> KeyRecord {
        KeyRecord {
            id,
            version,
            key_bytes: vec![fill; 32],
            nonce: None,
            encryption_key_version: 0,
            activated_at,
        }
    }

    fn make_syncer<E: KeyEncryptor + Clone>(
        backend: MockBackend,
        group: Arc<InMemorySecretGroup<256, 32>>,
        enc: E,
    ) -> SecretSyncer<MockBackend, E, 256, 32> {
        SecretSyncer::new(
            "test-syncer",
            group,
            backend,
            enc,
            Duration::from_secs(3600),
            Some(Duration::from_millis(10)),
        )
    }

    // -----------------------------------------------------------------------
    // initial_load
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn initial_load_applies_all_keys_and_promotes_latest_active() {
        let now = SystemTime::now();
        let backend = MockBackend::with_load(vec![
            rec(1, 0, 0xAA, now - Duration::from_secs(600)),
            rec(2, 1, 0xBB, now - Duration::from_secs(300)),
        ]);
        let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0u8; 32]));
        let mut syncer = make_syncer(backend, Arc::clone(&group), NoOpEncryptor);
        syncer.initial_load(&CancellationToken::new()).await.unwrap();
        let (v, _) = group.current();
        assert_eq!(v, 1);
    }

    #[tokio::test]
    async fn initial_load_empty_returns_epoch_cursor() {
        let backend = MockBackend::with_load(vec![]);
        let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0u8; 32]));
        let mut syncer = make_syncer(backend, Arc::clone(&group), NoOpEncryptor);
        let (t, id) = syncer.initial_load(&CancellationToken::new()).await.unwrap();
        assert_eq!(t, EPOCH_CURSOR);
        assert_eq!(id, 0);
    }

    #[tokio::test]
    async fn initial_load_returns_max_cursor() {
        let t0 = SystemTime::now() - Duration::from_secs(60);
        let t1 = SystemTime::now();
        let backend = MockBackend::with_load(vec![
            rec(10, 0, 0xAA, t0),
            rec(20, 1, 0xBB, t1), // highest (t1, id=20)
        ]);
        let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0u8; 32]));
        let mut syncer = make_syncer(backend, Arc::clone(&group), NoOpEncryptor);
        let (t, id) = syncer.initial_load(&CancellationToken::new()).await.unwrap();
        assert_eq!(id, 20);
        assert!(t.duration_since(t1).unwrap_or_default().as_millis() < 5);
    }

    #[tokio::test]
    async fn initial_load_stores_future_key_but_does_not_promote_it() {
        tokio::time::pause();
        let future_at = SystemTime::now() + Duration::from_secs(30);
        let backend = MockBackend::with_load(vec![rec(1, 1, 0xCC, future_at)]);
        let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0xFFu8; 32]));
        let mut syncer = make_syncer(backend, Arc::clone(&group), NoOpEncryptor);
        syncer.initial_load(&CancellationToken::new()).await.unwrap();

        // Key is stored in the ring but not promoted yet.
        assert_eq!(group.resolve(1), Some([0xCC; 32]));
        assert_eq!(group.current().0, 0, "current must still be the initial version");
    }

    #[tokio::test]
    async fn initial_load_future_key_promoted_after_activation_time() {
        tokio::time::pause();
        let future_at = SystemTime::now() + Duration::from_secs(10);
        let backend = MockBackend::with_load(vec![rec(1, 1, 0xCC, future_at)]);
        let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0xFFu8; 32]));
        let token = CancellationToken::new();
        let mut syncer = make_syncer(backend, Arc::clone(&group), NoOpEncryptor);
        syncer.initial_load(&token).await.unwrap();

        // Yield first so the spawned promotion task can register its sleep
        // with the mock clock before we advance it.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(11)).await;
        tokio::task::yield_now().await;

        assert_eq!(group.current().0, 1, "key must be promoted after activation time elapses");
    }

    #[tokio::test]
    async fn initial_load_skips_version_out_of_ring_range() {
        let now = SystemTime::now() - Duration::from_secs(1);
        // Ring size is 4; version 4 is out of range.
        let backend = MockBackend::with_load(vec![
            rec(1, 0, 0xAA, now),
            rec(2, 4, 0xBB, now), // out of range — should be silently skipped
        ]);
        let group = Arc::new(InMemorySecretGroup::<4, 32>::new(0, [0u8; 32]));
        let mut syncer: SecretSyncer<MockBackend, NoOpEncryptor, 4, 32> = SecretSyncer::new(
            "test-syncer",
            Arc::clone(&group),
            backend,
            NoOpEncryptor,
            Duration::from_secs(3600),
            None,
        );
        syncer.initial_load(&CancellationToken::new()).await.unwrap();

        assert_eq!(group.current().0, 0);
        assert!(group.resolve(0).is_some());
        // version 4 was skipped — only 4 slots (0-3), so slot 4 doesn't exist
    }

    #[tokio::test]
    async fn initial_load_dedup_skips_decrypt_on_repeated_load() {
        let now = SystemTime::now() - Duration::from_secs(60);
        let backend = MockBackend::with_load(vec![rec(1, 0, 0xAA, now)]);
        let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0u8; 32]));
        let enc = CountingEncryptor::new();
        let mut syncer = make_syncer(backend, Arc::clone(&group), enc.clone());

        syncer.initial_load(&CancellationToken::new()).await.unwrap();
        assert_eq!(enc.decrypt_calls(), 1);

        // Second load with identical payload — dedup must suppress the decrypt call.
        syncer.initial_load(&CancellationToken::new()).await.unwrap();
        assert_eq!(enc.decrypt_calls(), 1, "dedup should skip decrypt for unchanged payload");
    }

    // -----------------------------------------------------------------------
    // run
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn run_exits_on_cancellation() {
        let backend = MockBackend::with_load(vec![]);
        let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0u8; 32]));
        let mut syncer = make_syncer(backend, Arc::clone(&group), NoOpEncryptor);
        let cursor = syncer.initial_load(&CancellationToken::new()).await.unwrap();

        let token = CancellationToken::new();
        let handle = tokio::spawn(syncer.run(token.clone(), cursor));
        token.cancel();
        tokio::time::timeout(Duration::from_millis(200), handle)
            .await
            .expect("run must exit promptly after cancellation")
            .unwrap();
    }

    #[tokio::test]
    async fn run_applies_polled_keys_and_promotes() {
        tokio::time::pause();
        let backend = MockBackend::with_load(vec![]);
        let poll_handle = backend.clone();
        let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0u8; 32]));
        let mut syncer = make_syncer(backend, Arc::clone(&group), NoOpEncryptor);
        let cursor = syncer.initial_load(&CancellationToken::new()).await.unwrap();

        let past = SystemTime::now() - Duration::from_secs(5);
        poll_handle.push_poll(vec![rec(1, 1, 0xBB, past)]);

        let token = CancellationToken::new();
        let handle = tokio::spawn(syncer.run(token.clone(), cursor));

        // Yield so the run task registers its sleep before we advance.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(20)).await;
        tokio::task::yield_now().await;

        assert_eq!(group.current().0, 1);
        assert_eq!(group.resolve(1), Some([0xBB; 32]));

        token.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn run_poll_error_retries_and_eventually_recovers() {
        tokio::time::pause();
        let backend = MockBackend::with_load(vec![]);
        let poll_handle = backend.clone();
        let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0u8; 32]));
        let mut syncer = make_syncer(backend, Arc::clone(&group), NoOpEncryptor);
        let cursor = syncer.initial_load(&CancellationToken::new()).await.unwrap();

        // First poll errors; second poll succeeds with a new key.
        let past = SystemTime::now() - Duration::from_secs(5);
        poll_handle.push_poll_err();
        poll_handle.push_poll(vec![rec(1, 1, 0xBB, past)]);

        let token = CancellationToken::new();
        let handle = tokio::spawn(syncer.run(token.clone(), cursor));

        // Step 1: let the task register its first sleep (10ms poll interval), then fire it.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(15)).await;
        // Step 2: yield so the task runs poll_new (errors) and registers the 30s backoff timer.
        tokio::task::yield_now().await;
        // Step 3: advance past 30s error backoff.
        tokio::time::advance(Duration::from_secs(31)).await;
        // Step 4: yield so the task wakes from backoff, loops, and registers a new 10ms poll timer.
        tokio::task::yield_now().await;
        // Step 5: advance past the second 10ms poll timer.
        tokio::time::advance(Duration::from_millis(15)).await;
        // Step 6: yield so the task runs the successful poll_new and applies the key.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert_eq!(group.current().0, 1, "must recover and apply key after error back-off");

        token.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn run_dedup_skips_repeated_poll_records() {
        tokio::time::pause();
        let backend = MockBackend::with_load(vec![]);
        let poll_handle = backend.clone();
        let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0u8; 32]));
        let enc = CountingEncryptor::new();
        let mut syncer = make_syncer(backend, Arc::clone(&group), enc.clone());
        let cursor = syncer.initial_load(&CancellationToken::new()).await.unwrap();

        let past = SystemTime::now() - Duration::from_secs(5);
        // Push the same record twice — the second should be skipped by dedup.
        poll_handle.push_poll(vec![rec(1, 1, 0xBB, past)]);
        poll_handle.push_poll(vec![rec(1, 1, 0xBB, past)]);

        let token = CancellationToken::new();
        let handle = tokio::spawn(syncer.run(token.clone(), cursor));

        tokio::task::yield_now().await;
        // Two poll intervals to trigger both polls.
        tokio::time::advance(Duration::from_millis(25)).await;
        tokio::task::yield_now().await;

        assert_eq!(enc.decrypt_calls(), 1, "second identical poll record must be deduped");

        token.cancel();
        handle.await.unwrap();
    }
}
