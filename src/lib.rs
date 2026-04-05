//! Distributed secret-key rotation and in-process caching.
//!
//! # Overview
//!
//! `secret-manager` manages a *ring buffer* of versioned encryption keys shared across a
//! cluster.  Keys are generated, encrypted, and persisted by a **rotator**; they are fetched,
//! decrypted, and cached in memory by a **syncer**.  The two roles are intentionally
//! decoupled so you can deploy them in whatever topology fits your system.
//!
//! ## Core concepts
//!
//! | Concept | Type | Purpose |
//! |---------|------|---------|
//! | Key group | [`GroupId`] | Logical namespace for a set of rotating keys |
//! | Ring buffer | [`InMemorySecretGroup<V, S>`] | In-process cache; `V` slots, each key `S` bytes |
//! | Version | `u8` | Slot index (0 … V-1); wraps modulo V, **not** at 255 |
//! | Rotator | [`KeyRotator`] | Background task — generates and stores new keys |
//! | Syncer | [`SecretSyncer`] | Background task — polls storage and updates the ring |
//! | Manager | [`SecretManager`] | Convenience facade that runs both together |
//!
//! # Usage patterns
//!
//! ## All-in-one: `SecretManager`
//!
//! Use this when a single service instance should both rotate **and** consume keys:
//!
//! ```rust,no_run
//! # use secret_manager::*;
//! # use async_trait::async_trait;
//! # use std::{sync::Arc, time::{Duration, SystemTime}};
//! # use tokio_util::sync::CancellationToken;
//! # #[derive(Clone)]
//! # struct MyBackend;
//! # #[async_trait]
//! # impl SecretBackend for MyBackend {
//! #     type Error = std::convert::Infallible;
//! #     async fn load_all(&self, _: &str) -> Result<Vec<KeyRecord>, Self::Error> { Ok(vec![]) }
//! #     async fn poll_new(&self, _: &str, _: SystemTime, _: i64) -> Result<Vec<KeyRecord>, Self::Error> { Ok(vec![]) }
//! # }
//! # #[async_trait]
//! # impl SecretRotationBackend for MyBackend {
//! #     type Error = std::convert::Infallible;
//! #     async fn latest_key_info(&self, _: &str) -> Result<Option<(u8, SystemTime)>, Self::Error> { Ok(None) }
//! #     async fn try_insert_key(&self, _: &str, _: Option<u8>, _: u8, _: &Encrypted, _: SystemTime) -> Result<bool, Self::Error> { Ok(true) }
//! # }
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let (backend, encryptor) = (MyBackend, NoOpEncryptor);
//! let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0u8; 32]));
//!
//! // `backend` implements both `SecretBackend` and `SecretRotationBackend`.
//! // `encryptor` implements `KeyEncryptor` (e.g. `LocalEncryptor`).
//! let manager = SecretManager::new(
//!     "payments-signing",
//!     Arc::clone(&group),
//!     backend,
//!     encryptor,
//!     Duration::from_secs(3600), // rotate every hour
//!     Duration::from_secs(30),   // propagation delay before activating a new key
//!     None,                      // poll interval (default: 5 s)
//!     None,                      // key generator (default: CSPRNG)
//! );
//!
//! let token = CancellationToken::new();
//! let handle = manager.start(token.clone()).await?;
//!
//! // Use `group.current()` to get the active signing key.
//! // Use `group.resolve(version)` to verify tokens issued with an older key.
//!
//! token.cancel();
//! handle.wait().await; // wait for background tasks to stop cleanly
//! # Ok(()) }
//! ```
//!
//! ## Rotation-only: `KeyRotator`
//!
//! Deploy a single dedicated rotation service that writes keys to storage while the rest of
//! your fleet only reads them via syncers:
//!
//! ```rust,no_run
//! # use secret_manager::*;
//! # use async_trait::async_trait;
//! # use std::{time::{Duration, SystemTime}};
//! # use tokio_util::sync::CancellationToken;
//! # struct MyBackend;
//! # #[async_trait]
//! # impl SecretRotationBackend for MyBackend {
//! #     type Error = std::convert::Infallible;
//! #     async fn latest_key_info(&self, _: &str) -> Result<Option<(u8, SystemTime)>, Self::Error> { Ok(None) }
//! #     async fn try_insert_key(&self, _: &str, _: Option<u8>, _: u8, _: &Encrypted, _: SystemTime) -> Result<bool, Self::Error> { Ok(true) }
//! # }
//! # async fn example() {
//! # let (backend, encryptor) = (MyBackend, NoOpEncryptor);
//! let rotator: KeyRotator<_, _, 256, 32> = KeyRotator::new(
//!     "session-tokens",
//!     backend,                   // implements `SecretRotationBackend`
//!     Duration::from_secs(3600),
//!     Duration::from_secs(30),
//!     encryptor,
//!     || [0u8; 32],
//! );
//! rotator.run(CancellationToken::new()).await;
//! # }
//! ```
//!
//! ## Read-only: `SecretSyncer`
//!
//! Reader instances that never rotate — they only follow the key stream from storage:
//!
//! ```rust,no_run
//! # use secret_manager::*;
//! # use async_trait::async_trait;
//! # use std::{sync::Arc, time::{Duration, SystemTime}};
//! # use tokio_util::sync::CancellationToken;
//! # #[derive(Clone)]
//! # struct MyBackend;
//! # #[async_trait]
//! # impl SecretBackend for MyBackend {
//! #     type Error = std::convert::Infallible;
//! #     async fn load_all(&self, _: &str) -> Result<Vec<KeyRecord>, Self::Error> { Ok(vec![]) }
//! #     async fn poll_new(&self, _: &str, _: SystemTime, _: i64) -> Result<Vec<KeyRecord>, Self::Error> { Ok(vec![]) }
//! # }
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let (backend, encryptor) = (MyBackend, NoOpEncryptor);
//! let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0u8; 32]));
//! let mut syncer: SecretSyncer<_, _, 256, 32> = SecretSyncer::new(
//!     "api-tokens",
//!     Arc::clone(&group),
//!     backend,   // implements `SecretBackend`
//!     encryptor,
//!     Duration::from_secs(3600), // used to compute smart poll intervals
//!     None,                      // poll interval override
//! );
//!
//! let token = CancellationToken::new();
//! let cursor = syncer.initial_load(&token).await?;
//! tokio::spawn(syncer.run(token, cursor));
//! # Ok(()) }
//! ```
//!
//! # Encryptors
//!
//! | Type | Crate feature | Notes |
//! |------|--------------|-------|
//! | [`NoOpEncryptor`] | *(always)* | Plaintext — testing / storage-layer encryption |
//! | [`LocalEncryptor`] | *(always)* | AES-256-GCM-SIV with a local 32-byte key |
//! | `KmsEncryptor` | `aws-kms` | AWS KMS — KMS manages the IV; requires network |
//!
//! # Backends
//!
//! | Type | Crate feature |
//! |------|--------------|
//! | `DieselPgSecretBackend` | `pg-diesel-async` |
//! | `SqlxPgSecretBackend` | `pg-sqlx` |
//!
//! Implement [`SecretBackend`] + [`SecretRotationBackend`] together to bring your own backend.

mod backend;
#[cfg(feature = "pg-diesel-async")]
mod diesel_pg_backend;
mod encryptor;
mod local_encryptor;
#[cfg(feature = "aws-kms")]
mod aws_kms_encryptor;
mod no_op_encryptor;
mod manager;
#[cfg(any(feature = "pg-diesel-async", feature = "pg-sqlx"))]
mod pg_queries;
mod rotator;
mod secret_rotation;
#[cfg(feature = "pg-sqlx")]
mod sqlx_pg_backend;
mod syncer;
mod util;

/// Identifies a logical group of rotating keys.
///
/// A group ID is a human-readable label stored as `VARCHAR(32)` in the database.
/// Keep it short, lowercase, and slug-style (e.g. `"payments-signing"`, `"session-tokens"`).
/// Values longer than 32 characters will be rejected by the storage backend.
pub type GroupId = String;



pub use backend::{KeyRecord, SecretBackend};
pub use encryptor::{Encrypted, KeyEncryptor};
pub use local_encryptor::LocalEncryptor;
pub use manager::{SecretManager, SecretManagerHandle};
pub use no_op_encryptor::NoOpEncryptor;
pub use rotator::{KeyRotator, SecretRotationBackend};
pub use secret_rotation::{InMemorySecretGroup, SecretGroup};
pub use syncer::SecretSyncer;

#[cfg(any(test, feature = "aws-kms"))]
pub use aws_kms_encryptor::KmsEncryptor;
#[cfg(any(test, feature = "pg-diesel-async"))]
pub use diesel_pg_backend::{DieselPgSecretBackend, DieselPgSecretBackendError};
#[cfg(any(test, feature = "pg-sqlx"))]
pub use sqlx_pg_backend::{SqlxPgSecretBackend, SqlxPgSecretBackendError};
