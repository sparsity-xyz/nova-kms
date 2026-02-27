import os
import sys
import json
import subprocess
import binascii

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def derive_app_key(master_secret: bytes, app_id: int, path: str, *, length: int = 32, context: str = "") -> bytes:
    salt = f"nova-kms:app:{app_id}".encode("utf-8")
    info = f"{path}:{context}".encode("utf-8") if context else path.encode("utf-8")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(master_secret)


def derive_data_key(master_secret: bytes, app_id: int) -> bytes:
    return derive_app_key(master_secret, app_id, "data_key")


def derive_sync_key(master_secret: bytes) -> bytes:
    return derive_app_key(master_secret, 0, "sync_hmac_key")

def run_tests():
    print("=== Nova KMS Behavior Comparison (Python vs Rust) ===")
    
    master_secret_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    master_secret = bytes.fromhex(master_secret_hex)
    app_id = 49
    plaintext = "Hello Nova KMS!"
    
    # Python Evaluation
    print("Evaluating Python implementation...")
    py_data_key = derive_data_key(master_secret, app_id)
    py_sync_key = derive_sync_key(master_secret)
    
    rust_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    print("Compiling Rust comparison binary...")
    subprocess.run(["cargo", "build", "--bin", "compare_rust"], check=True, cwd=rust_dir)
    
    rust_bin = os.path.join(rust_dir, "target", "debug", "compare_rust")
    print("Evaluating Rust implementation...")
    rust_process = subprocess.Popen(
        [rust_bin],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True
    )
    
    in_data = json.dumps({
        "master_secret": master_secret_hex,
        "app_id": app_id,
        "plaintext": plaintext
    })
    
    out, _ = rust_process.communicate(input=in_data + "\n")
    rust_out = json.loads(out)
    
    print(f"\n--- HKDF Results ---")
    print(f"Data Key Match:    {rust_out['data_key'] == py_data_key.hex()}")
    print(f"Sync Key Match:    {rust_out['sync_key'] == py_sync_key.hex()}")
    
    assert rust_out['data_key'] == py_data_key.hex(), "Data Key Mismatch!"
    assert rust_out['sync_key'] == py_sync_key.hex(), "Sync Key Mismatch!"
    print("HKDF behavior is exactly identical.")
    
    print(f"\n--- AES-GCM Results ---")
    rust_ciphertext = bytes.fromhex(rust_out['ciphertext'])
    
    # We must be able to decrypt the Rust ciphertext using the Python decrypt method!
    # Rust Prepends the 12-byte nonce to the ciphertext
    nonce = rust_ciphertext[:12]
    actual_ct = rust_ciphertext[12:]
    
    # Decrypt via standard AESGCM
    aesgcm = AESGCM(py_data_key)
    py_decrypted = aesgcm.decrypt(nonce, actual_ct, None)
    
    print(f"Cross-Language Decryption Success: {py_decrypted.decode() == plaintext}")
    assert py_decrypted.decode() == plaintext, "Cross-language AES-GCM decryption failed!"
    print("AES-GCM encryption behavior is strictly compatible.")
    
    print("\n✅ All behavior comparisons passed successfully!")

if __name__ == "__main__":
    run_tests()
