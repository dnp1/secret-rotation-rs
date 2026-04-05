use async_trait::async_trait;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::primitives::Blob;
use crate::encryptor::{Encrypted, KeyEncryptor};
use anyhow::Result;

#[derive(Clone)]
pub struct KmsEncryptor {
    client: KmsClient,
    key_id: String,
    version: u8,
}

impl KmsEncryptor {
    pub fn new(client: KmsClient, key_id: impl Into<String>, version: u8) -> Self {
        Self { client, key_id: key_id.into(), version }
    }
}

#[async_trait]
impl KeyEncryptor for KmsEncryptor {
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Encrypted> {
        let resp = self.client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(Blob::new(plaintext))
            .send()
            .await?;

        Ok(Encrypted {
            ciphertext: resp.ciphertext_blob.unwrap().into_inner(),
            nonce: None, // KMS manages its own IVs internally
            key_version: self.version,
        })
    }

    async fn decrypt(&self, encrypted: &Encrypted) -> Result<Vec<u8>> {
        let resp = self.client
            .decrypt()
            .ciphertext_blob(Blob::new(encrypted.ciphertext.clone()))
            .send()
            .await?;

        Ok(resp.plaintext.unwrap().into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_kms::types::KeyUsageType;
    use test_containers_util::moto_container::get_aws_config;

    async fn make_encryptor(version: u8) -> KmsEncryptor {
        let config = get_aws_config("moto-kms").await;
        let client = KmsClient::new(&config);
        let key_id = client
            .create_key()
            .key_usage(KeyUsageType::EncryptDecrypt)
            .send()
            .await
            .expect("create_key failed")
            .key_metadata()
            .unwrap()
            .key_id()
            .to_string();
        KmsEncryptor::new(client, key_id, version)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn encrypt_decrypt_roundtrip() {
        let enc = make_encryptor(1).await;
        let plaintext = b"my secret key bytes";
        let encrypted = enc.encrypt(plaintext).await.unwrap();
        let decrypted = enc.decrypt(&encrypted).await.unwrap();
        assert_eq!(decrypted, plaintext.as_ref());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn encrypted_payload_has_no_nonce() {
        let enc = make_encryptor(42).await;
        let encrypted = enc.encrypt(b"some bytes").await.unwrap();
        assert!(encrypted.nonce.is_none(), "KMS manages its own IV — nonce must be None");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn encrypted_payload_carries_correct_key_version() {
        let enc = make_encryptor(7).await;
        let encrypted = enc.encrypt(b"some bytes").await.unwrap();
        assert_eq!(encrypted.key_version, 7);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn same_plaintext_produces_different_ciphertext() {
        let enc = make_encryptor(1).await;
        let plaintext = b"determinism test";
        let a = enc.encrypt(plaintext).await.unwrap();
        let b = enc.encrypt(plaintext).await.unwrap();
        assert_ne!(a.ciphertext, b.ciphertext, "KMS should produce different ciphertext per call");
    }
}
