use crate::error::Error;
use crate::{generate_token, generate_token_with_expiration, validate_token};
use aes_gcm::aead::OsRng;
use argon2::password_hash::rand_core::RngCore;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::thread;
use std::time::Duration;

const KEY: &str = "encryption_Key";
const EMAIL: &str = "user@example.com";

#[test]
fn generate_default_expiration_test() {
    let token = generate_token(EMAIL.to_string(), KEY.to_string());
    assert!(token.is_ok());

    let email = validate_token(token.unwrap(), KEY.to_string());
    assert!(email.is_ok());

    assert_eq!(EMAIL, email.unwrap())
}

#[test]
fn generate_custom_expiration_test() {
    let token = generate_token_with_expiration(EMAIL.to_string(), KEY.to_string(), 3600);
    assert!(token.is_ok());

    let email = validate_token(token.unwrap(), KEY.to_string());
    assert!(email.is_ok());

    assert_eq!(EMAIL, email.unwrap())
}

#[test]
fn expired_token_test() {
    let token = generate_token_with_expiration(EMAIL.to_string(), KEY.to_string(), 2);
    assert!(token.is_ok());

    thread::sleep(Duration::from_secs(3));

    let expired = validate_token(token.unwrap(), KEY.to_string());
    assert!(matches!(expired, Err(Error::Expired(_))))

    // assert_matches!(expired, Err(Error::Expired(_))); // unstable
}

#[test]
fn invalid_key_test() {
    let token = generate_token(EMAIL.to_string(), KEY.to_string());
    assert!(token.is_ok());

    let error = validate_token(token.unwrap(), "wrong_key".to_string());
    assert!(error.is_err())
}

#[test]
fn invalid_token_test() {
    let mut bytes = vec![0u8; 64];
    OsRng.fill_bytes(&mut bytes);

    let invalid_token = URL_SAFE_NO_PAD.encode(&bytes);
    let error = validate_token(invalid_token, "wrong_key".to_string());
    assert!(error.is_err())
}
