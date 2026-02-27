use crate::error::KmsError;
use p384::{
    PublicKey, SecretKey,
    ecdh::diffie_hellman,
    elliptic_curve::rand_core::OsRng,
    pkcs8::{DecodePublicKey, EncodePublicKey},
};
use ring::{
    aead::{self, LessSafeKey, Nonce, UnboundKey},
    hkdf, hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use zeroize::Zeroize;

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
    init_state: RwLock<String>,
    synced_from: RwLock<Option<String>>,
}

impl Default for MasterSecretManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MasterSecretManager {
    pub fn new() -> Self {
        Self {
            secret: RwLock::new(None),
            init_state: RwLock::new("uninitialized".to_string()),
            synced_from: RwLock::new(None),
        }
    }

    pub async fn initialize_generated(&self, secret_bytes: [u8; 32]) {
        {
            let mut w = self.secret.write().await;
            *w = Some(MasterSecret {
                bytes: secret_bytes,
            });
        }
        {
            let mut s = self.init_state.write().await;
            *s = "generated".to_string();
        }
        {
            let mut synced_from = self.synced_from.write().await;
            *synced_from = None;
        }
    }

    pub async fn initialize_synced(&self, secret_bytes: [u8; 32], peer_url: Option<String>) {
        {
            let mut w = self.secret.write().await;
            *w = Some(MasterSecret {
                bytes: secret_bytes,
            });
        }
        {
            let mut s = self.init_state.write().await;
            *s = "synced".to_string();
        }
        {
            let mut synced_from = self.synced_from.write().await;
            *synced_from = peer_url;
        }
    }

    pub async fn get_secret(&self) -> Result<MasterSecret, KmsError> {
        let r = self.secret.read().await;
        r.as_ref().cloned().ok_or_else(|| {
            KmsError::ServiceUnavailable("Master secret not initialized".to_string())
        })
    }

    pub async fn is_initialized(&self) -> bool {
        self.secret.read().await.is_some()
    }

    pub async fn init_state(&self) -> String {
        self.init_state.read().await.clone()
    }

    pub async fn synced_from(&self) -> Option<String> {
        self.synced_from.read().await.clone()
    }

    pub async fn get_sync_key(&self) -> Result<[u8; 32], KmsError> {
        let secret = self.get_secret().await?;
        Ok(derive_sync_key(&secret))
    }
}

pub fn derive_app_key_extended(
    master_secret: &MasterSecret,
    app_id: u64,
    path: &str,
    context: &str,
    length: usize,
) -> Result<Vec<u8>, KmsError> {
    if path.trim().is_empty() {
        return Err(KmsError::ValidationError(
            "Derive path must not be empty".to_string(),
        ));
    }
    if !(1..=1024).contains(&length) {
        return Err(KmsError::ValidationError(
            "Derive length must be in range 1..1024".to_string(),
        ));
    }

    let salt_str = format!("nova-kms:app:{}", app_id);
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt_str.as_bytes());
    let prk = salt.extract(&master_secret.bytes);

    let info_string = if context.is_empty() {
        path.to_string()
    } else {
        format!("{}:{}", path, context)
    };
    let info = [info_string.as_bytes()];
    struct DynamicLen(usize);
    impl hkdf::KeyType for DynamicLen {
        fn len(&self) -> usize {
            self.0
        }
    }

    let okm = prk
        .expand(&info, DynamicLen(length))
        .map_err(|_| KmsError::InternalError("HKDF expand failed".to_string()))?;

    let mut out = vec![0u8; length];
    okm.fill(&mut out)
        .map_err(|_| KmsError::InternalError("HKDF output fill failed".to_string()))?;
    Ok(out)
}

pub fn derive_app_key(master_secret: &MasterSecret, app_id: u64, path: &str) -> [u8; 32] {
    let derived = derive_app_key_extended(master_secret, app_id, path, "", 32)
        .expect("derive_app_key() fixed-length derivation cannot fail");
    let mut out = [0u8; 32];
    out.copy_from_slice(&derived);
    out
}

pub fn derive_data_key(master_secret: &MasterSecret, app_id: u64) -> [u8; 32] {
    derive_app_key(master_secret, app_id, "data_key")
}

pub fn derive_sync_key(master_secret: &MasterSecret) -> [u8; 32] {
    derive_app_key(master_secret, 0, "sync_hmac_key")
}

fn rand_bytes(len: usize) -> Result<Vec<u8>, KmsError> {
    let rng = SystemRandom::new();
    let mut v = vec![0u8; len];
    rng.fill(&mut v)
        .map_err(|_| KmsError::InternalError("Secure RNG failed".to_string()))?;
    Ok(v)
}

pub fn random_secret_32() -> Result<[u8; 32], KmsError> {
    let mut out = [0u8; 32];
    out.copy_from_slice(&rand_bytes(32)?);
    Ok(out)
}

pub fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, KmsError> {
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| KmsError::InternalError("Failed to create sealing key".to_string()))?;
    let less_safe = LessSafeKey::new(unbound_key);

    let nonce_bytes = rand_bytes(12)?;
    let mut in_out = data.to_vec();

    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| KmsError::InternalError("Invalid nonce".to_string()))?;

    less_safe
        .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| KmsError::InternalError("Sealing failed".to_string()))?;

    let mut res = nonce_bytes.to_vec();
    res.extend(in_out);
    Ok(res)
}

pub fn decrypt_data(encrypted: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, KmsError> {
    if encrypted.len() < 12 + 16 {
        return Err(KmsError::ValidationError(
            "Ciphertext too short".to_string(),
        ));
    }
    let (nonce_bytes, ciphertext) = encrypted.split_at(12);

    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| KmsError::InternalError("Failed to create opening key".to_string()))?;
    let less_safe = LessSafeKey::new(unbound_key);

    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| KmsError::InternalError("Invalid nonce".to_string()))?;

    let mut in_out = ciphertext.to_vec();
    let plaintext = less_safe
        .open_in_place(nonce, aead::Aad::empty(), &mut in_out)
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedMasterSecretEnvelope {
    pub ephemeral_pubkey: String,
    pub encrypted_data: String,
    pub nonce: String,
}

fn parse_p384_public_key(peer_pubkey_bytes: &[u8]) -> Result<PublicKey, KmsError> {
    if let Ok(pk) = PublicKey::from_public_key_der(peer_pubkey_bytes) {
        return Ok(pk);
    }
    PublicKey::from_sec1_bytes(peer_pubkey_bytes)
        .map_err(|_| KmsError::ValidationError("Invalid peer ECDH public key".to_string()))
}

fn derive_sealed_exchange_key(shared_secret: &[u8]) -> Result<[u8; 32], KmsError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"nova-kms:sealed-master-secret");
    let prk = salt.extract(shared_secret);
    let info = [b"aes-gcm-key".as_slice()];
    let okm = prk
        .expand(&info, hkdf::HKDF_SHA256)
        .map_err(|_| KmsError::InternalError("HKDF expand failed".to_string()))?;
    let mut out = [0u8; 32];
    okm.fill(&mut out)
        .map_err(|_| KmsError::InternalError("HKDF output fill failed".to_string()))?;
    Ok(out)
}

pub fn seal_master_secret(
    master_secret: &[u8; 32],
    peer_pubkey_bytes: &[u8],
) -> Result<SealedMasterSecretEnvelope, KmsError> {
    let peer_pubkey = parse_p384_public_key(peer_pubkey_bytes)?;
    let ephemeral_secret = SecretKey::random(&mut OsRng);
    let ephemeral_public = ephemeral_secret.public_key();

    let shared = diffie_hellman(
        ephemeral_secret.to_nonzero_scalar(),
        peer_pubkey.as_affine(),
    );
    let exchange_key = derive_sealed_exchange_key(shared.raw_secret_bytes())?;

    let nonce = rand_bytes(12)?;
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &exchange_key)
        .map_err(|_| KmsError::InternalError("Failed to create sealing key".to_string()))?;
    let less_safe = LessSafeKey::new(unbound_key);

    let nonce_obj = Nonce::try_assume_unique_for_key(&nonce)
        .map_err(|_| KmsError::InternalError("Invalid nonce".to_string()))?;
    let mut in_out = master_secret.to_vec();
    less_safe
        .seal_in_place_append_tag(nonce_obj, aead::Aad::empty(), &mut in_out)
        .map_err(|_| KmsError::InternalError("Sealing failed".to_string()))?;

    let ephemeral_der = ephemeral_public
        .to_public_key_der()
        .map_err(|_| KmsError::InternalError("Failed to encode ECDH key".to_string()))?;

    Ok(SealedMasterSecretEnvelope {
        ephemeral_pubkey: hex::encode(ephemeral_der.as_ref()),
        encrypted_data: hex::encode(in_out),
        nonce: hex::encode(nonce),
    })
}

pub fn unseal_master_secret(
    envelope: &SealedMasterSecretEnvelope,
    local_secret: &SecretKey,
) -> Result<[u8; 32], KmsError> {
    let peer_pubkey_bytes = hex::decode(&envelope.ephemeral_pubkey)
        .map_err(|_| KmsError::ValidationError("Invalid ephemeral_pubkey hex".to_string()))?;
    let ciphertext = hex::decode(&envelope.encrypted_data)
        .map_err(|_| KmsError::ValidationError("Invalid encrypted_data hex".to_string()))?;
    let nonce = hex::decode(&envelope.nonce)
        .map_err(|_| KmsError::ValidationError("Invalid nonce hex".to_string()))?;
    if nonce.len() != 12 {
        return Err(KmsError::ValidationError(
            "Invalid sealed envelope nonce length".to_string(),
        ));
    }

    let peer_pubkey = parse_p384_public_key(&peer_pubkey_bytes)?;
    let shared = diffie_hellman(local_secret.to_nonzero_scalar(), peer_pubkey.as_affine());
    let exchange_key = derive_sealed_exchange_key(shared.raw_secret_bytes())?;

    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &exchange_key)
        .map_err(|_| KmsError::InternalError("Failed to create opening key".to_string()))?;
    let less_safe = LessSafeKey::new(unbound_key);
    let nonce_obj = Nonce::try_assume_unique_for_key(&nonce)
        .map_err(|_| KmsError::InternalError("Invalid nonce".to_string()))?;

    let mut in_out = ciphertext;
    let plaintext = less_safe
        .open_in_place(nonce_obj, aead::Aad::empty(), &mut in_out)
        .map_err(|_| KmsError::ValidationError("Failed to unseal master secret".to_string()))?;
    if plaintext.len() < 32 {
        return Err(KmsError::ValidationError(
            "Sealed master secret payload too short".to_string(),
        ));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&plaintext[..32]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_master_secret_manager_status() {
        let mgr = MasterSecretManager::new();
        assert!(!mgr.is_initialized().await);
        assert!(mgr.get_secret().await.is_err());

        let secret = [42u8; 32];
        mgr.initialize_generated(secret).await;

        assert!(mgr.is_initialized().await);
        assert_eq!(mgr.init_state().await, "generated");
        assert_eq!(mgr.synced_from().await, None);
        let retrieved = mgr.get_secret().await.unwrap();
        assert_eq!(retrieved.bytes, secret);
    }

    #[test]
    fn test_hkdf_derivation_matches_info_layout() {
        let secret = MasterSecret { bytes: [1u8; 32] };
        let k1 = derive_app_key_extended(&secret, 49, "foo", "", 32).unwrap();
        let k2 = derive_app_key_extended(&secret, 49, "foo", "bar", 32).unwrap();
        assert_ne!(k1, k2);
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let key = [2u8; 32];
        let plaintext = b"Hello Nova KMS Protocol";

        let encrypted = encrypt_data(plaintext, &key).expect("Encryption failed");
        assert!(encrypted.len() > plaintext.len());
        assert_ne!(encrypted, plaintext);
        assert_eq!(encrypted.len(), plaintext.len() + 12 + 16);

        let decrypted = decrypt_data(&encrypted, &key).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hmac_signing() {
        let key = [5u8; 32];
        let data = b"sync-payload-12345";
        let signature = generate_hmac_sha256(&key, data);
        assert_eq!(signature.len(), 32);
        assert!(verify_hmac_sha256(&key, data, &signature).is_ok());
    }

    #[test]
    fn test_sealed_master_secret_roundtrip() {
        let mut master = [0u8; 32];
        master.copy_from_slice(b"0123456789abcdef0123456789abcdef");

        let peer_secret = SecretKey::random(&mut OsRng);
        let peer_public_der = peer_secret
            .public_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();

        let sealed = seal_master_secret(&master, &peer_public_der).unwrap();
        let unsealed = unseal_master_secret(&sealed, &peer_secret).unwrap();
        assert_eq!(unsealed, master);
    }
}
