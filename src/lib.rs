mod backend;
#[cfg(feature = "pg-diesel-async")]
mod diesel_pg_backend;
mod encryptor;
mod local_encryptor;
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

pub use backend::{KeyRecord, SecretBackend};
pub use encryptor::{Encrypted, KeyEncryptor};
pub use local_encryptor::LocalEncryptor;
pub use manager::SecretManager;
pub use no_op_encryptor::NoOpEncryptor;
pub use rotator::{KeyRotator, SecretRotationBackend};
pub use secret_rotation::{InMemorySecretGroup, SecretGroup};
pub use syncer::SecretSyncer;
#[cfg(any(test, feature = "pg-diesel-async"))]
pub use diesel_pg_backend::{DieselPgSecretBackend, DieselPgSecretBackendError};
#[cfg(any(test, feature = "pg-sqlx"))]
pub use sqlx_pg_backend::{SqlxPgSecretBackend, SqlxPgSecretBackendError};
