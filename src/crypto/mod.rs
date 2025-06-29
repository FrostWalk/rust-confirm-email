use crate::error::Error;
use crate::error::Error::Other;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

// Derive key from password using Argon2id
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 16], Error> {
    let argon2 = Argon2::default();
    let salt_string = SaltString::encode_b64(salt).map_err(|e| Other(format!("{e:#?}")))?;
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| Other(format!("{e:#?}")))?;
    let hash_bytes = password_hash
        .hash
        .ok_or(Other("Failed to generate the hash".to_string()))?;

    let mut key = [0u8; 16];
    key.copy_from_slice(&hash_bytes.as_bytes()[..16]);
    Ok(key)
}

// Encrypt string with password
pub fn encrypt(enc_key: &str, plaintext: &str) -> Result<String, Error> {
    // Generate random salt and nonce
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    // Derive key from password
    let key_bytes = derive_key(enc_key, &salt).map_err(|e| Other(format!("{e:#?}")))?;
    let key = Key::<Aes128Gcm>::from_slice(&key_bytes);
    let cipher = Aes128Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the plaintext
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| Other(format!("{e:#?}")))?;

    // Combine salt + nonce + ciphertext and encode as base64
    let mut result = Vec::new();
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(URL_SAFE_NO_PAD.encode(result))
}

// Decrypt string with password
pub fn decrypt(enc_key: &str, encrypted_data: &str) -> Result<String, Error> {
    // Decode from base64
    let data = URL_SAFE_NO_PAD
        .decode(encrypted_data)
        .map_err(|e| Other(format!("{e:#?}")))?;

    if data.len() < 28 {
        return Err(Other("Invalid encrypted data".to_string()));
    }

    // Extract salt, nonce, and ciphertext
    let salt = &data[0..16];
    let nonce_bytes = &data[16..28];
    let ciphertext = &data[28..];

    // Derive key from password
    let key_bytes = derive_key(enc_key, salt).map_err(|e| Other(format!("{e:#?}")))?;
    let key = Key::<Aes128Gcm>::from_slice(&key_bytes);
    let cipher = Aes128Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt the ciphertext
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| Other(format!("{e:#?}")))?;
    String::from_utf8(plaintext).map_err(|e| Other(format!("{e:#?}")))
}
