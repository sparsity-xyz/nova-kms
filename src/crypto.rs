use ring::{
    aead::{self, LessSafeKey, UnboundKey, Nonce},
    hkdf, hmac,
    rand::{SecureRandom, SystemRandom},
};
use tokio::sync::RwLock;
use zeroize::Zeroize;
use crate::error::KmsError;

#[derive(Clone)]
pub struct MasterSecret {
    pub bytes: [u8; 32],
}

impl Drop for MasterSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

pub struct MasterSecretManager {
    secret: RwLock<Option<MasterSecret>>,
}

impl MasterSecretManager {
    pub fn new() -> Self {
        Self { secret: RwLock::new(None) }
    }

    pub async fn initialize(&self, secret_bytes: [u8; 32]) {
        let mut w = self.secret.write().await;
        *w = Some(MasterSecret { bytes: secret_bytes });
    }

    pub async fn get_secret(&self) -> Result<MasterSecret, KmsError> {
        let r = self.secret.read().await;
        r.as_ref().cloned().ok_or_else(|| KmsError::ServiceUnavailable("Master secret not initialized".to_string()))
    }
}

pub fn derive_app_key(master_secret: &MasterSecret, app_id: u64, path: &str) -> [u8; 32] {
    let salt_str = format!("nova-kms:app:{}", app_id);
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt_str.as_bytes());
    
    let prk = salt.extract(&master_secret.bytes);
    
    let info = [path.as_bytes()];
    let okm = prk.expand(&info, hkdf::HKDF_SHA256).unwrap();
    
    let mut out = [0u8; 32];
    okm.fill(&mut out).unwrap();
    out
}

pub fn derive_data_key(master_secret: &MasterSecret, app_id: u64) -> [u8; 32] {
    derive_app_key(master_secret, app_id, "data_key")
}

pub fn derive_sync_key(master_secret: &MasterSecret) -> [u8; 32] {
    derive_app_key(master_secret, 0, "sync_hmac_key")
}

fn rand_bytes(len: usize) -> Vec<u8> {
    let rng = SystemRandom::new();
    let mut v = vec![0u8; len];
    rng.fill(&mut v).unwrap();
    v
}

pub fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, KmsError> {
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| KmsError::InternalError("Failed to create sealing key".to_string()))?;
    let less_safe = LessSafeKey::new(unbound_key);
    
    let nonce_bytes = rand_bytes(12);
    let mut in_out = data.to_vec();
    
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| KmsError::InternalError("Failed nonce".to_string()))?;

    less_safe.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| KmsError::InternalError("Sealing failed".to_string()))?;

    let mut res = nonce_bytes.to_vec();
    res.extend(in_out);
    Ok(res)
}

pub fn decrypt_data(encrypted: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, KmsError> {
    if encrypted.len() < 12 + 16 { // nonce + tag
        return Err(KmsError::ValidationError("Ciphertext too short".to_string()));
    }
    let (nonce_bytes, ciphertext) = encrypted.split_at(12);

    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| KmsError::InternalError("Failed to create opening key".to_string()))?;
    let less_safe = LessSafeKey::new(unbound_key);
    
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| KmsError::InternalError("Failed nonce".to_string()))?;

    let mut in_out = ciphertext.to_vec();
    let plaintext = less_safe.open_in_place(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| KmsError::ValidationError("Decryption failed".to_string()))?;

    Ok(plaintext.to_vec())
}

pub fn generate_hmac_sha256(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let s_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&s_key, data).as_ref().to_vec()
}

pub fn verify_hmac_sha256(key: &[u8; 32], data: &[u8], sig: &[u8]) -> Result<(), KmsError> {
    let s_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&s_key, data, sig)
        .map_err(|_| KmsError::Unauthorized("Invalid HMAC signature".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_master_secret_manager() {
        let mgr = MasterSecretManager::new();
        assert!(mgr.get_secret().await.is_err());
        
        let secret = [42u8; 32];
        mgr.initialize(secret).await;
        
        let retrieved = mgr.get_secret().await.unwrap();
        assert_eq!(retrieved.bytes, secret);
    }

    #[test]
    fn test_hkdf_derivation() {
        let secret = MasterSecret { bytes: [1u8; 32] };
        
        let app_key1 = derive_app_key(&secret, 49, "test_path");
        let app_key2 = derive_app_key(&secret, 49, "test_path");
        assert_eq!(app_key1, app_key2, "Derived app keys should be deterministic");
        
        let data_key = derive_data_key(&secret, 49);
        let sync_key = derive_sync_key(&secret);
        assert_ne!(data_key, sync_key, "Data and sync keys must be strictly separated");
        assert_ne!(data_key, app_key1);
    }

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let key = [2u8; 32];
        let plaintext = b"Hello Nova KMS Protocol";
        
        let encrypted = encrypt_data(plaintext, &key).expect("Encryption failed");
        assert!(encrypted.len() > plaintext.len());
        assert_ne!(encrypted, plaintext);
        
        // Ensure nonce is included (12 bytes) + tag (16 bytes)
        assert_eq!(encrypted.len(), plaintext.len() + 12 + 16);
        
        let decrypted = decrypt_data(&encrypted, &key).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
        
        // Test failure with wrong key
        let wrong_key = [3u8; 32];
        assert!(decrypt_data(&encrypted, &wrong_key).is_err());
        
        // Test failure with tampered ciphertext
        let mut tampered = encrypted.clone();
        let last_idx = tampered.len() - 1;
        tampered[last_idx] ^= 1;
        assert!(decrypt_data(&tampered, &key).is_err());
    }

    #[test]
    fn test_hmac_signing() {
        let key = [5u8; 32];
        let data = b"sync-payload-12345";
        
        let signature = generate_hmac_sha256(&key, data);
        assert_eq!(signature.len(), 32);
        
        assert!(verify_hmac_sha256(&key, data, &signature).is_ok());
        
        let wrong_data = b"sync-payload-12346";
        assert!(verify_hmac_sha256(&key, wrong_data, &signature).is_err());
    }
}


