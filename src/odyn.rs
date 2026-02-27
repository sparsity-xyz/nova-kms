use crate::error::KmsError;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};

const LOCAL_ODYN_TIMEOUT_SECS: u64 = 3;

#[derive(Clone)]
pub struct OdynClient {
    endpoint: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
pub struct EthAddressRes {
    pub address: String,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct SignMessageRes {
    pub signature: String,
    pub address: String,
    pub attestation: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EncryptionPubKeyRes {
    pub public_key_der: String,
    pub public_key_pem: String,
}

#[derive(Debug, Deserialize)]
pub struct EncryptRes {
    pub encrypted_data: String,
    pub enclave_public_key: String,
    pub nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct DecryptRes {
    pub plaintext: String,
}

impl OdynClient {
    pub fn new(in_enclave: bool) -> Self {
        let endpoint = if in_enclave {
            "http://127.0.0.1:18000".to_string()
        } else {
            "http://odyn.sparsity.cloud:18000".to_string()
        };
        Self {
            endpoint,
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(LOCAL_ODYN_TIMEOUT_SECS))
                .build()
                .unwrap_or_default(),
        }
    }

    async fn post<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: Value,
    ) -> Result<T, KmsError> {
        let url = format!("{}{}", self.endpoint, path);
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| KmsError::InternalError(format!("Odyn POST {:?} err: {}", path, e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(KmsError::InternalError(format!(
                "Odyn POST {:?} Http {}: {}",
                path, status, text
            )));
        }

        resp.json::<T>().await.map_err(|e| {
            KmsError::InternalError(format!("Odyn POST {:?} JSON decode err: {}", path, e))
        })
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, KmsError> {
        let url = format!("{}{}", self.endpoint, path);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| KmsError::InternalError(format!("Odyn GET {:?} err: {}", path, e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(KmsError::InternalError(format!(
                "Odyn GET {:?} Http {}: {}",
                path, status, text
            )));
        }

        resp.json::<T>().await.map_err(|e| {
            KmsError::InternalError(format!("Odyn GET {:?} JSON decode err: {}", path, e))
        })
    }

    pub async fn eth_address(&self) -> Result<String, KmsError> {
        let res: EthAddressRes = self.get("/v1/eth/address").await?;
        Ok(res.address)
    }

    pub async fn sign_message(
        &self,
        message: &str,
        include_attestation: bool,
    ) -> Result<SignMessageRes, KmsError> {
        self.post(
            "/v1/eth/sign",
            json!({
                "message": message,
                "include_attestation": include_attestation
            }),
        )
        .await
    }

    pub async fn get_random_bytes(&self) -> Result<Vec<u8>, KmsError> {
        #[derive(Deserialize)]
        struct RandomBytesRes {
            random_bytes: String,
        }

        let res: RandomBytesRes = self.get("/v1/random").await?;
        let hex_str = res.random_bytes.trim_start_matches("0x");
        hex::decode(hex_str).map_err(|e| KmsError::InternalError(format!("Failed to parse: {}", e)))
    }

    pub async fn get_encryption_public_key(&self) -> Result<EncryptionPubKeyRes, KmsError> {
        self.get("/v1/encryption/public_key").await
    }

    pub async fn get_encryption_public_key_der(&self) -> Result<Vec<u8>, KmsError> {
        let res = self.get_encryption_public_key().await?;
        let hex_str = res.public_key_der.trim_start_matches("0x");
        hex::decode(hex_str).map_err(|e| {
            KmsError::InternalError(format!("Failed to parse Odyn public key der hex: {}", e))
        })
    }

    pub async fn encrypt(
        &self,
        plaintext: &str,
        client_public_key: &str,
    ) -> Result<EncryptRes, KmsError> {
        let pk = if !client_public_key.starts_with("0x") {
            format!("0x{}", client_public_key)
        } else {
            client_public_key.to_string()
        };
        self.post(
            "/v1/encryption/encrypt",
            json!({
                "plaintext": plaintext,
                "client_public_key": pk
            }),
        )
        .await
    }

    pub async fn decrypt(
        &self,
        nonce: &str,
        client_public_key: &str,
        encrypted_data: &str,
    ) -> Result<String, KmsError> {
        let n = if !nonce.starts_with("0x") {
            format!("0x{}", nonce)
        } else {
            nonce.to_string()
        };
        let pk = if !client_public_key.starts_with("0x") {
            format!("0x{}", client_public_key)
        } else {
            client_public_key.to_string()
        };
        let enc_data = if !encrypted_data.starts_with("0x") {
            format!("0x{}", encrypted_data)
        } else {
            encrypted_data.to_string()
        };

        let res: DecryptRes = self
            .post(
                "/v1/encryption/decrypt",
                json!({
                    "nonce": n,
                    "client_public_key": pk,
                    "encrypted_data": enc_data
                }),
            )
            .await?;
        Ok(res.plaintext)
    }

    pub async fn sign_tx(&self, tx: Value) -> Result<Value, KmsError> {
        self.post("/v1/eth/sign-tx", json!({ "payload": tx })).await
    }
}
