use crate::crypto::decrypt;
use crate::error::Error;
use crate::{generate_token, generate_token_with_expiration, validate_token};
use aes_gcm::aead::OsRng;
use argon2::password_hash::rand_core::RngCore;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::thread::sleep;

const KEY: &str = "encryption_Key";
const EMAIL: &str = "user@example.com";

#[test]
fn generate_default_expiration_test() {
    let token = generate_token(EMAIL.to_string(), KEY.to_string());
    assert!(token.is_ok(), "should generate with default expiration");

    let email = validate_token(token.unwrap(), KEY.to_string());
    assert!(email.is_ok(), "should validate default‐exp token");
    assert_eq!(EMAIL, email.unwrap());
}

#[test]
fn generate_custom_expiration_test() {
    let token = generate_token_with_expiration(EMAIL.to_string(), KEY.to_string(), 3600);
    assert!(token.is_ok(), "should generate with 1h expiration");

    let email = validate_token(token.unwrap(), KEY.to_string());
    assert!(email.is_ok(), "should validate custom‐exp token");
    assert_eq!(EMAIL, email.unwrap());
}

#[test]
fn expired_token_test() {
    let token = generate_token_with_expiration(EMAIL.to_string(), KEY.to_string(), 2).unwrap();

    sleep(std::time::Duration::from_secs(3));

    let result = validate_token(token, KEY.to_string());
    assert!(
        matches!(result, Err(Error::Expired(_))),
        "expected Expired(_), got {result:?}",
    );
}

#[test]
fn invalid_key_test() {
    let token = generate_token(EMAIL.to_string(), KEY.to_string()).unwrap();

    let result = validate_token(token, "wrong_key".to_string());
    assert!(
        matches!(result, Err(Error::AesGcm(_))),
        "expected AesGcm(_), got {result:?}",
    );
}

#[test]
fn invalid_token_test() {
    let mut bytes = vec![0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    let bogus = URL_SAFE_NO_PAD.encode(&bytes);

    let result = validate_token(bogus, KEY.to_string());
    assert!(
        matches!(result, Err(Error::AesGcm(_))),
        "expected AesGcm(_), got {result:?}",
    );
}

#[test]
fn too_short_decoded_test() {
    let short = URL_SAFE_NO_PAD.encode([0u8; 10]);
    let result = decrypt(KEY, &short);
    assert!(
        matches!(result, Err(Error::InvalidDataLength(len)) if len < 28),
        "expected InvalidDataLength(_ < 28), got {result:?}",
    );
}
