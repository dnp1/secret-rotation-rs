//! PostgreSQL-backed `SecretBackend` implementation using Diesel.

use crate::backend::{KeyRecord, SecretBackend};
use crate::encryptor::Encrypted;
use crate::pg_queries::*;
use crate::rotator::SecretRotationBackend;
use async_trait::async_trait;
use diesel::sql_types::{Bytea, Nullable, SmallInt, Timestamptz};
use diesel::{QueryableByName, sql_query};
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use jiff::Timestamp;
use jiff_diesel::{Timestamp as DieselTimestamp, ToDiesel};
use std::time::SystemTime;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum DieselPgSecretBackendError {
    #[error("connection pool error: {0}")]
    Pool(String),
    #[error("query error: {0}")]
    Query(#[from] diesel::result::Error),
}

#[derive(QueryableByName)]
struct KeyRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    id: i64,
    #[diesel(sql_type = SmallInt)]
    version: i16,
    #[diesel(sql_type = Bytea)]
    key_bytes: Vec<u8>,
    #[diesel(sql_type = Nullable<Bytea>)]
    nonce: Option<Vec<u8>>,
    #[diesel(sql_type = SmallInt)]
    encryption_key_version: i16,
    #[diesel(sql_type = Timestamptz)]
    activated_at: DieselTimestamp,
}

impl From<KeyRow> for KeyRecord {
    fn from(r: KeyRow) -> Self {
        KeyRecord {
            id: r.id,
            version: r.version as u8,
            key_bytes: r.key_bytes,
            nonce: r.nonce,
            encryption_key_version: r.encryption_key_version as u8,
            activated_at: r.activated_at.to_jiff().into(),
        }
    }
}

#[derive(Clone)]
pub struct DieselPgSecretBackend {
    pool: Pool<AsyncPgConnection>,
}

impl DieselPgSecretBackend {
    pub fn new(pool: Pool<AsyncPgConnection>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SecretBackend for DieselPgSecretBackend {
    type Error = DieselPgSecretBackendError;

    async fn load_all(&self, group_id: Uuid) -> Result<Vec<KeyRecord>, Self::Error> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| DieselPgSecretBackendError::Pool(e.to_string()))?;
        let rows: Vec<KeyRow> = sql_query(LOAD_ALL_QUERY)
            .bind::<diesel::sql_types::Uuid, _>(group_id)
            .get_results(&mut conn)
            .await?;
        Ok(rows.into_iter().map(KeyRecord::from).collect())
    }

    async fn poll_new(
        &self,
        group_id: Uuid,
        since_time: SystemTime,
        since_id: i64,
    ) -> Result<Vec<KeyRecord>, Self::Error> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| DieselPgSecretBackendError::Pool(e.to_string()))?;
        let since_jiff = Timestamp::try_from(since_time)
            .map_err(|e| diesel::result::Error::SerializationError(Box::new(e)))?;
        let rows: Vec<KeyRow> = sql_query(POLL_NEW_QUERY)
            .bind::<diesel::sql_types::Uuid, _>(group_id)
            .bind::<Timestamptz, _>(since_jiff.to_diesel())
            .bind::<diesel::sql_types::BigInt, _>(since_id)
            .get_results(&mut conn)
            .await?;
        Ok(rows.into_iter().map(KeyRecord::from).collect())
    }
}

#[derive(QueryableByName)]
struct KeyInfoRow {
    #[diesel(sql_type = SmallInt)]
    version: i16,
    #[diesel(sql_type = Timestamptz)]
    activated_at: DieselTimestamp,
}

#[async_trait]
impl SecretRotationBackend for DieselPgSecretBackend {
    type Error = DieselPgSecretBackendError;

    async fn latest_key_info(
        &self,
        group_id: Uuid,
    ) -> Result<Option<(u8, SystemTime)>, Self::Error> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| DieselPgSecretBackendError::Pool(e.to_string()))?;
        let rows: Vec<KeyInfoRow> = sql_query(LATEST_KEY_INFO_QUERY)
            .bind::<diesel::sql_types::Uuid, _>(group_id)
            .get_results(&mut conn)
            .await?;
        Ok(rows
            .into_iter()
            .next()
            .map(|r| (r.version as u8, r.activated_at.to_jiff().into())))
    }

    async fn try_insert_key(
        &self,
        group_id: Uuid,
        expected_version: Option<u8>,
        new_version: u8,
        encrypted: &Encrypted,
        activated_at: SystemTime,
    ) -> Result<bool, Self::Error> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| DieselPgSecretBackendError::Pool(e.to_string()))?;
        let ciphertext = encrypted.ciphertext.clone();
        let nonce = encrypted.nonce.clone();
        let enc_version = encrypted.key_version as i16;
        let activated_at_jiff = Timestamp::try_from(activated_at)
            .map_err(|e| diesel::result::Error::SerializationError(Box::new(e)))?;
        let activated_at_diesel = activated_at_jiff.to_diesel();

        let inserted = conn
            .transaction(|conn| {
                Box::pin(async move {
                    sql_query(ADVISORY_LOCK_QUERY)
                        .bind::<diesel::sql_types::Uuid, _>(group_id)
                        .execute(conn)
                        .await?;
                    let rows: Vec<KeyInfoRow> = sql_query(LATEST_KEY_INFO_QUERY)
                        .bind::<diesel::sql_types::Uuid, _>(group_id)
                        .get_results(conn)
                        .await?;
                    let current_version = rows.into_iter().next().map(|r| r.version as u8);
                    if current_version != expected_version {
                        return Ok::<bool, diesel::result::Error>(false);
                    }
                    let rows_affected = sql_query(INSERT_KEY_QUERY)
                        .bind::<diesel::sql_types::Uuid, _>(group_id)
                        .bind::<SmallInt, _>(new_version as i16)
                        .bind::<Bytea, _>(ciphertext.as_slice())
                        .bind::<Nullable<Bytea>, _>(nonce.as_ref().map(|n| n as &[u8]))
                        .bind::<SmallInt, _>(enc_version)
                        .bind::<Timestamptz, _>(activated_at_diesel)
                        .execute(conn)
                        .await?;
                    Ok(rows_affected > 0)
                })
            })
            .await?;
        Ok(inserted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::SecretBackend;
    use crate::encryptor::Encrypted;
    use crate::rotator::SecretRotationBackend;
    use diesel::sql_types::{Bytea, SmallInt};
    use diesel_async::RunQueryDsl;
    use diesel_migrations::{EmbeddedMigrations, embed_migrations};
    use std::time::{Duration, SystemTime};
    use test_containers_util::diesel_pg::PostgresTestDb;
    use uuid::Uuid;

    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("tests/diesel-migrations");

    async fn make_backend() -> (PostgresTestDb, DieselPgSecretBackend) {
        let db = PostgresTestDb::create("secret-rotation-diesel", MIGRATIONS, None, None).await;
        let backend = DieselPgSecretBackend::new(db.pool());
        (db, backend)
    }

    fn no_op_encrypted(bytes: &[u8]) -> Encrypted {
        Encrypted { ciphertext: bytes.to_vec(), nonce: None, key_version: 0 }
    }

    async fn insert_key(
        backend: &DieselPgSecretBackend,
        group_id: Uuid,
        version: i16,
        bytes: &[u8],
    ) {
        let mut conn = backend.pool.get().await.unwrap();
        diesel::sql_query(
            "INSERT INTO secret_keys (key_group, version, key_bytes) VALUES ($1, $2, $3)",
        )
        .bind::<diesel::sql_types::Uuid, _>(group_id)
        .bind::<SmallInt, _>(version)
        .bind::<Bytea, _>(bytes)
        .execute(&mut conn)
        .await
        .unwrap();
    }

    fn abs_diff(a: SystemTime, b: SystemTime) -> Duration {
        a.duration_since(b)
            .or_else(|_| b.duration_since(a))
            .unwrap_or(Duration::ZERO)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn load_all_returns_empty_for_unknown_group() {
        let (_db, backend) = make_backend().await;
        let records = backend.load_all(Uuid::new_v4()).await.unwrap();
        assert!(records.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn load_all_returns_rows_ordered_by_activated_at() {
        let (_db, backend) = make_backend().await;
        let gid = Uuid::new_v4();
        let t0 = SystemTime::now() - Duration::from_secs(120);
        let t1 = SystemTime::now() - Duration::from_secs(60);
        let t2 = SystemTime::now();

        backend.try_insert_key(gid, None, 2, &no_op_encrypted(&[2u8; 32]), t0).await.unwrap();
        backend.try_insert_key(gid, Some(2), 0, &no_op_encrypted(&[0u8; 32]), t1).await.unwrap();
        backend.try_insert_key(gid, Some(0), 1, &no_op_encrypted(&[1u8; 32]), t2).await.unwrap();

        let records = backend.load_all(gid).await.unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].version, 2);
        assert_eq!(records[1].version, 0);
        assert_eq!(records[2].version, 1);
        assert_eq!(records[0].key_bytes, vec![2u8; 32]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn poll_new_returns_empty_when_no_newer_key() {
        let (_db, backend) = make_backend().await;
        let gid = Uuid::new_v4();
        let t = SystemTime::now();
        backend.try_insert_key(gid, None, 5, &no_op_encrypted(&[5u8; 32]), t).await.unwrap();

        let inserted = backend.load_all(gid).await.unwrap();
        let id = inserted[0].id;

        let result = backend.poll_new(gid, t, id).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn poll_new_returns_keys_newer_than_cursor() {
        let (_db, backend) = make_backend().await;
        let gid = Uuid::new_v4();
        let t0 = SystemTime::now() - Duration::from_secs(180);
        let t1 = SystemTime::now() - Duration::from_secs(120);
        let t2 = SystemTime::now() - Duration::from_secs(60);

        backend.try_insert_key(gid, None, 3, &no_op_encrypted(&[3u8; 32]), t0).await.unwrap();
        backend.try_insert_key(gid, Some(3), 7, &no_op_encrypted(&[7u8; 32]), t1).await.unwrap();
        backend.try_insert_key(gid, Some(7), 5, &no_op_encrypted(&[5u8; 32]), t2).await.unwrap();

        let all = backend.load_all(gid).await.unwrap();
        let id0 = all[0].id;

        let records = backend.poll_new(gid, t0, id0).await.unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].version, 7);
        assert_eq!(records[1].version, 5);
        assert!(abs_diff(t1, records[0].activated_at).as_millis() < 5);
        assert!(abs_diff(t2, records[1].activated_at).as_millis() < 5);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn load_all_isolates_groups() {
        let (_db, backend) = make_backend().await;
        let gid_a = Uuid::new_v4();
        let gid_b = Uuid::new_v4();
        insert_key(&backend, gid_a, 0, &[10u8; 32]).await;
        insert_key(&backend, gid_b, 0, &[20u8; 32]).await;

        let a = backend.load_all(gid_a).await.unwrap();
        let b = backend.load_all(gid_b).await.unwrap();

        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_eq!(a[0].key_bytes, vec![10u8; 32]);
        assert_eq!(b[0].key_bytes, vec![20u8; 32]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn latest_key_info_returns_none_for_empty_group() {
        let (_db, backend) = make_backend().await;
        let result = backend.latest_key_info(Uuid::new_v4()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn try_insert_key_inserts_first_key() {
        let (_db, backend) = make_backend().await;
        let gid = Uuid::new_v4();
        let activated_at = SystemTime::now() + Duration::from_secs(120);

        let inserted = backend
            .try_insert_key(gid, None, 0, &no_op_encrypted(&[0u8; 32]), activated_at)
            .await
            .unwrap();
        assert!(inserted);

        let info = backend.latest_key_info(gid).await.unwrap().expect("expected Some");
        assert_eq!(info.0, 0);
        assert!(abs_diff(info.1, activated_at).as_millis() < 5);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn try_insert_key_returns_false_when_version_already_changed() {
        let (_db, backend) = make_backend().await;
        let gid = Uuid::new_v4();
        let t = SystemTime::now() + Duration::from_secs(60);

        insert_key(&backend, gid, 0, &[0u8; 32]).await;

        let inserted = backend
            .try_insert_key(gid, None, 1, &no_op_encrypted(&[1u8; 32]), t)
            .await
            .unwrap();
        assert!(!inserted, "must return false when version already changed");

        let records = backend.load_all(gid).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].version, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn try_insert_key_sequential_rotations_succeed() {
        let (_db, backend) = make_backend().await;
        let gid = Uuid::new_v4();
        let t0 = SystemTime::now() + Duration::from_secs(60);
        let t1 = SystemTime::now() + Duration::from_secs(120);

        let ok0 = backend.try_insert_key(gid, None, 0, &no_op_encrypted(&[0u8; 32]), t0).await.unwrap();
        assert!(ok0);

        let ok1 = backend.try_insert_key(gid, Some(0), 1, &no_op_encrypted(&[1u8; 32]), t1).await.unwrap();
        assert!(ok1);

        let records = backend.load_all(gid).await.unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].version, 0);
        assert_eq!(records[1].version, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn latest_key_info_returns_most_recently_activated() {
        let (_db, backend) = make_backend().await;
        let gid = Uuid::new_v4();
        let t2 = SystemTime::now() + Duration::from_secs(120);

        insert_key(&backend, gid, 10, &[10u8; 32]).await;
        let ok = backend
            .try_insert_key(gid, Some(10), 2, &no_op_encrypted(&[2u8; 32]), t2)
            .await
            .unwrap();
        assert!(ok);

        let info = backend.latest_key_info(gid).await.unwrap().expect("expected Some");
        assert_eq!(info.0, 2, "must return most recently activated, not highest version number");
    }
}
