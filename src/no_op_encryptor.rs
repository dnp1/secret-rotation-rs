use crate::encryptor::{Encrypted, KeyEncryptor};
use anyhow::{Result, anyhow};
use async_trait::async_trait;

/// A passthrough [`KeyEncryptor`] that stores key bytes as-is (no encryption).
///
/// Intended for development, testing, or deployments where at-rest encryption
/// is handled by the storage layer itself.
#[derive(Clone)]
pub struct NoOpEncryptor;

#[async_trait]
impl KeyEncryptor for NoOpEncryptor {
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Encrypted> {
        Ok(Encrypted {
            ciphertext: plaintext.to_vec(),
            nonce: None,
            key_version: 0, // 0 = plaintext / no-op
        })
    }

    async fn decrypt(&self, encrypted: &Encrypted) -> Result<Vec<u8>> {
        if encrypted.key_version != 0 {
            return Err(anyhow!(
                "NoOpEncryptor cannot decrypt key_version {}",
                encrypted.key_version
            ));
        }
        Ok(encrypted.ciphertext.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_noop_encrypt_decrypt() {
        let encryptor = NoOpEncryptor;
        let plaintext = b"secret-key-material";

        let encrypted = encryptor.encrypt(plaintext).await.unwrap();
        assert_eq!(encrypted.ciphertext, plaintext);
        assert!(encrypted.nonce.is_none());
        assert_eq!(encrypted.key_version, 0);

        let decrypted = encryptor.decrypt(&encrypted).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_noop_invalid_version() {
        let encryptor = NoOpEncryptor;
        let encrypted = Encrypted {
            ciphertext: b"some data".to_vec(),
            nonce: None,
            key_version: 1,
        };

        let result = encryptor.decrypt(&encrypted).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("NoOpEncryptor cannot decrypt key_version 1"));
    }
}
