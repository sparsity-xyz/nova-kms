use nova_kms_rust::crypto::{MasterSecret, derive_app_key, derive_data_key, derive_sync_key, encrypt_data};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Input {
    master_secret: String, // hex
    app_id: u64,
    plaintext: String, // string
}

#[derive(Serialize)]
struct Output {
    app_key: String, // hex
    data_key: String, // hex
    sync_key: String, // hex
    ciphertext: String, // hex
}

fn main() {
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    
    let parsed: Input = serde_json::from_str(&input).unwrap();
    let secret_bytes = hex::decode(&parsed.master_secret).unwrap();
    let mut ms_arr = [0u8; 32];
    ms_arr.copy_from_slice(&secret_bytes);
    
    let ms = MasterSecret { bytes: ms_arr };
    let app_key = derive_app_key(&ms, parsed.app_id, "default_test_path");
    let data_key = derive_data_key(&ms, parsed.app_id);
    let sync_key = derive_sync_key(&ms);
    
    let ciphertext = encrypt_data(parsed.plaintext.as_bytes(), &data_key).unwrap();
    
    let out = Output {
        app_key: hex::encode(app_key),
        data_key: hex::encode(data_key),
        sync_key: hex::encode(sync_key),
        ciphertext: hex::encode(ciphertext),
    };
    
    println!("{}", serde_json::to_string(&out).unwrap());
}
