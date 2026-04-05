use crate::encryptor::{Encrypted, KeyEncryptor};
use aes_gcm_siv::aead::{Aead, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use rand::{Rng, rng};

#[derive(Clone, Copy)]
pub struct LocalEncryptor {
    key: [u8; 32],
    version: u8,
}

impl LocalEncryptor {
    pub fn new(key: &[u8; 32], version: u8) -> Self {
        Self { key: *key, version }
    }

    fn cipher(&self) -> Aes256GcmSiv {
        Aes256GcmSiv::new_from_slice(&self.key).expect("key is exactly 32 bytes")
    }
}

#[async_trait]
impl KeyEncryptor for LocalEncryptor {
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Encrypted> {
        let mut nonce_bytes = [0u8; 12];
        rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = self
            .cipher()
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("local encryption failed: {:?}", e))?;

        Ok(Encrypted {
            ciphertext,
            nonce: Some(nonce_bytes),
            key_version: self.version,
        })
    }

    async fn decrypt(&self, encrypted: &Encrypted) -> Result<Vec<u8>> {
        let nonce_bytes = encrypted
            .nonce
            .ok_or_else(|| anyhow!("missing nonce for local decryption"))?;

        let nonce = Nonce::from(nonce_bytes);

        self.cipher()
            .decrypt(&nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| anyhow!("local decryption failed: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 32] = [0x42; 32];
    const TEST_VERSION: u8 = 1;

    #[tokio::test]
    async fn test_local_encrypt_decrypt() {
        let encryptor = LocalEncryptor::new(&TEST_KEY, TEST_VERSION);
        let plaintext = b"local-secret-key-material";

        let encrypted = encryptor.encrypt(plaintext).await.unwrap();
        assert_ne!(encrypted.ciphertext, plaintext);
        assert_eq!(encrypted.key_version, TEST_VERSION);
        assert!(encrypted.nonce.is_some());
        assert_eq!(encrypted.nonce.as_ref().unwrap().len(), 12);

        let decrypted = encryptor.decrypt(&encrypted).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_local_unique_nonces() {
        let encryptor = LocalEncryptor::new(&TEST_KEY, TEST_VERSION);
        let plaintext = b"same-plaintext";

        let encrypted1 = encryptor.encrypt(plaintext).await.unwrap();
        let encrypted2 = encryptor.encrypt(plaintext).await.unwrap();

        assert_ne!(encrypted1.nonce, encrypted2.nonce);
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    #[tokio::test]
    async fn test_local_decrypt_wrong_key() {
        let encryptor1 = LocalEncryptor::new(&TEST_KEY, TEST_VERSION);
        let mut wrong_key = TEST_KEY;
        wrong_key[0] ^= 1;
        let encryptor2 = LocalEncryptor::new(&wrong_key, TEST_VERSION);

        let plaintext = b"secret-stuff";
        let encrypted = encryptor1.encrypt(plaintext).await.unwrap();

        let result = encryptor2.decrypt(&encrypted).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_local_decrypt_missing_nonce() {
        let encryptor = LocalEncryptor::new(&TEST_KEY, TEST_VERSION);
        let mut encrypted = encryptor.encrypt(b"data").await.unwrap();
        encrypted.nonce = None;

        let result = encryptor.decrypt(&encrypted).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing nonce"));
    }

    #[tokio::test]
    async fn test_local_decrypt_tampered_ciphertext() {
        let encryptor = LocalEncryptor::new(&TEST_KEY, TEST_VERSION);
        let mut encrypted = encryptor.encrypt(b"sensitive-data").await.unwrap();
        encrypted.ciphertext[0] ^= 1;

        let result = encryptor.decrypt(&encrypted).await;
        assert!(result.is_err());
    }
}
