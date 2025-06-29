use crate::error::Error;
use crate::{generate_token, generate_token_with_expiration, validate_token};
use aes_gcm::aead::OsRng;
use argon2::password_hash::rand_core::RngCore;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::thread;
use std::time::Duration;

const KEY: &str = "encryption_Key";
const LONG_KEY: &str = "this_is_a_very_long_encryption_key_for_testing_purposes_1234567890";
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

// New comprehensive tests
#[test]
fn test_invalid_email_formats() {
    let invalid_emails = vec![
        "invalid-email",
        "@domain.com",
        "user@",
        "user@@domain.com",
        "user@domain",
        "",
        "user space@domain.com",
        "user@domain..com",
    ];

    for email in invalid_emails {
        let result = generate_token(email.to_string(), KEY.to_string());
        assert!(matches!(result, Err(Error::InvalidEmail(_))), 
                "Email '{}' should be invalid", email);
    }
}

#[test]
fn test_valid_email_formats() {
    let valid_emails = vec![
        "user@example.com",
        "test.email@domain.org",
        "user+tag@example.co.uk",
        "firstname.lastname@company.com",
        "user123@test-domain.net",
    ];

    for email in valid_emails {
        let result = generate_token(email.to_string(), KEY.to_string());
        assert!(result.is_ok(), "Email '{}' should be valid", email);
    }
}

#[test]
fn test_short_encryption_key() {
    let short_keys = vec!["", "1", "12", "1234567"]; // All less than 8 chars

    for key in short_keys {
        let result = generate_token(EMAIL.to_string(), key.to_string());
        assert!(result.is_err(), "Key '{}' should be rejected", key);
        
        let result = validate_token("dummy_token".to_string(), key.to_string());
        assert!(result.is_err(), "Key '{}' should be rejected in validation", key);
    }
}

#[test]
fn test_long_encryption_key() {
    let result = generate_token(EMAIL.to_string(), LONG_KEY.to_string());
    assert!(result.is_ok());

    let token = result.unwrap();
    let email = validate_token(token, LONG_KEY.to_string());
    assert!(email.is_ok());
    assert_eq!(EMAIL, email.unwrap());
}

#[test]
fn test_expiration_edge_cases() {
    // Test minimum invalid expiration
    let result = generate_token_with_expiration(EMAIL.to_string(), KEY.to_string(), 0);
    assert!(matches!(result, Err(Error::InvalidExpiration(_))));

    let result = generate_token_with_expiration(EMAIL.to_string(), KEY.to_string(), 1);
    assert!(matches!(result, Err(Error::InvalidExpiration(_))));

    // Test minimum valid expiration
    let result = generate_token_with_expiration(EMAIL.to_string(), KEY.to_string(), 2);
    assert!(result.is_ok());

    // Test maximum valid expiration (1 year)
    let result = generate_token_with_expiration(EMAIL.to_string(), KEY.to_string(), 365 * 24 * 3600);
    assert!(result.is_ok());

    // Test expiration too large (more than 1 year)
    let result = generate_token_with_expiration(EMAIL.to_string(), KEY.to_string(), 365 * 24 * 3600 + 1);
    assert!(matches!(result, Err(Error::InvalidExpiration(_))));
}

#[test]
fn test_unicode_email() {
    // Test with unicode characters in email (should be rejected by our simple validator)
    let unicode_email = "用户@例子.测试";
    let result = generate_token(unicode_email.to_string(), KEY.to_string());
    assert!(matches!(result, Err(Error::InvalidEmail(_))));
}

#[test]
fn test_empty_inputs() {
    // Empty email
    let result = generate_token("".to_string(), KEY.to_string());
    assert!(matches!(result, Err(Error::InvalidEmail(_))));

    // Empty key
    let result = generate_token(EMAIL.to_string(), "".to_string());
    assert!(result.is_err());
}

#[test]
fn test_malformed_tokens() {
    let malformed_tokens = vec![
        "",
        "invalid",
        "not-base64-!@#$%",
        "dGVzdA==", // Valid base64 but too short
        "YWJjZGVmZ2hpamtsbW5vcA==", // Valid base64 but wrong length
    ];

    for token in malformed_tokens {
        let result = validate_token(token.to_string(), KEY.to_string());
        assert!(result.is_err(), "Token '{}' should be invalid", token);
    }
}

#[test]
fn test_token_uniqueness() {
    // Generate multiple tokens for the same email and verify they're different
    let mut tokens = Vec::new();
    for _ in 0..10 {
        let token = generate_token(EMAIL.to_string(), KEY.to_string()).unwrap();
        tokens.push(token);
    }

    // All tokens should be unique due to random salt and nonce
    for (i, token1) in tokens.iter().enumerate() {
        for (j, token2) in tokens.iter().enumerate() {
            if i != j {
                assert_ne!(token1, token2, "Tokens should be unique");
            }
        }
    }

    // All tokens should validate to the same email
    for token in tokens {
        let email = validate_token(token, KEY.to_string()).unwrap();
        assert_eq!(email, EMAIL);
    }
}

#[test]
fn test_different_emails_same_key() {
    let emails = vec![
        "user1@example.com",
        "user2@example.com", 
        "admin@company.org",
        "test@test.net",
    ];

    for email in &emails {
        let token = generate_token(email.to_string(), KEY.to_string()).unwrap();
        let validated_email = validate_token(token, KEY.to_string()).unwrap();
        assert_eq!(&validated_email, email);
    }
}

#[test]
fn test_same_email_different_keys() {
    let keys = vec![
        "key1_12345",
        "key2_67890", 
        "different_key_123",
        "another_secret_key",
    ];

    let mut tokens = Vec::new();
    
    // Generate tokens with different keys
    for key in &keys {
        let token = generate_token(EMAIL.to_string(), key.to_string()).unwrap();
        tokens.push((token, key));
    }

    // Validate with correct keys
    for (token, key) in &tokens {
        let email = validate_token(token.clone(), key.to_string()).unwrap();
        assert_eq!(email, EMAIL);
    }

    // Cross-validate with wrong keys (should fail)
    for (i, (token, _)) in tokens.iter().enumerate() {
        for (j, (_, wrong_key)) in tokens.iter().enumerate() {
            if i != j {
                let result = validate_token(token.clone(), wrong_key.to_string());
                assert!(result.is_err(), "Token should not validate with wrong key");
            }
        }
    }
}

#[test]
fn test_concurrent_token_generation() {
    use std::thread;

    let handles: Vec<_> = (0..10).map(|i| {
        let email = format!("user{}@example.com", i);
        thread::spawn(move || {
            generate_token(email, KEY.to_string())
        })
    }).collect();

    // All concurrent generations should succeed
    for handle in handles {
        let result = handle.join().unwrap();
        assert!(result.is_ok());
    }
}

#[test]
fn test_very_long_email() {
    // Test with a very long but valid email
    let long_email = format!("{}@example.com", "a".repeat(100));
    let result = generate_token(long_email.clone(), KEY.to_string());
    assert!(result.is_ok());

    let token = result.unwrap();
    let validated_email = validate_token(token, KEY.to_string()).unwrap();
    assert_eq!(validated_email, long_email);
}

#[test] 
fn test_boundary_expiration_times() {
    // Test various boundary conditions for expiration
    let test_cases = vec![
        (2, true),      // minimum valid
        (60, true),     // 1 minute
        (3600, true),   // 1 hour  
        (86400, true),  // 1 day
        (604800, true), // 1 week
        (2592000, true), // 30 days
        (365 * 24 * 3600, true), // 1 year (maximum)
    ];

    for (exp_seconds, should_succeed) in test_cases {
        let result = generate_token_with_expiration(EMAIL.to_string(), KEY.to_string(), exp_seconds);
        if should_succeed {
            assert!(result.is_ok(), "Expiration {} seconds should be valid", exp_seconds);
            let token = result.unwrap();
            
            // Only validate tokens that have reasonable expiration times (> 5 seconds)
            // to avoid timing issues in tests
            if exp_seconds > 5 {
                let email = validate_token(token, KEY.to_string()).unwrap();
                assert_eq!(email, EMAIL);
            }
        } else {
            assert!(result.is_err(), "Expiration {} seconds should be invalid", exp_seconds);
        }
    }
}
