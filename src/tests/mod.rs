use crate::error::Error;
use crate::{generate_token, generate_token_with_expiration, validate_token};
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
    assert!(matches!(expired, Err(Error::Expired(_))));

    // assert_matches!(expired, Err(Error::Expired(_))); // unstable
}
