//! Utility functions for common email confirmation workflows
//! 
//! This module provides convenience functions and helpers that make it easier
//! to integrate the email confirmation system into web applications.

use crate::error::Error;
use crate::{generate_token, generate_token_with_expiration, validate_token};
use std::collections::HashMap;

/// Convenience function to generate a token with human-readable time units
/// 
/// # Examples
/// 
/// ```
/// use confirm_email::utils::generate_token_with_duration;
/// 
/// // Generate a token that expires in 2 hours
/// let token = generate_token_with_duration(
///     "user@example.com", 
///     "secret_key", 
///     2, 
///     "hours"
/// ).unwrap();
/// ```
pub fn generate_token_with_duration(
    email: &str,
    key: &str,
    amount: u32,
    unit: &str,
) -> Result<String, Error> {
    let seconds = match unit.to_lowercase().as_str() {
        "second" | "seconds" | "s" => amount as i64,
        "minute" | "minutes" | "m" => amount as i64 * 60,
        "hour" | "hours" | "h" => amount as i64 * 3600,
        "day" | "days" | "d" => amount as i64 * 86400,
        "week" | "weeks" | "w" => amount as i64 * 604800,
        _ => return Err(Error::Other(format!("Invalid time unit: {}", unit))),
    };

    generate_token_with_expiration(email.to_string(), key.to_string(), seconds)
}

/// Generate multiple tokens for different emails in batch
/// 
/// # Examples
/// 
/// ```
/// use confirm_email::utils::generate_batch_tokens;
/// 
/// let emails = vec!["user1@example.com", "user2@example.com"];
/// let results = generate_batch_tokens(&emails, "secret_key");
/// ```
pub fn generate_batch_tokens(
    emails: &[&str],
    key: &str,
) -> HashMap<String, Result<String, Error>> {
    let mut results = HashMap::new();
    
    for email in emails {
        let result = generate_token(email.to_string(), key.to_string());
        results.insert(email.to_string(), result);
    }
    
    results
}

/// Validate multiple tokens and return their corresponding emails
/// 
/// # Examples
/// 
/// ```
/// use confirm_email::utils::validate_batch_tokens;
/// use std::collections::HashMap;
/// 
/// let mut tokens = HashMap::new();
/// tokens.insert("token1".to_string(), "key1".to_string());
/// tokens.insert("token2".to_string(), "key2".to_string());
/// 
/// let results = validate_batch_tokens(&tokens);
/// ```
pub fn validate_batch_tokens(
    token_key_pairs: &HashMap<String, String>,
) -> HashMap<String, Result<String, Error>> {
    let mut results = HashMap::new();
    
    for (token, key) in token_key_pairs {
        let result = validate_token(token.clone(), key.clone());
        results.insert(token.clone(), result);
    }
    
    results
}

/// Check if a token is expired without fully validating it
/// 
/// This is useful for providing specific "expired" vs "invalid" error messages
/// without revealing whether the token format is correct.
/// 
/// Note: This function still requires the correct key to decrypt the token.
pub fn is_token_expired(token: &str, key: &str) -> Result<bool, Error> {
    match validate_token(token.to_string(), key.to_string()) {
        Ok(_) => Ok(false), // Valid, not expired
        Err(Error::Expired(_)) => Ok(true), // Expired
        Err(e) => Err(e), // Other error (invalid format, wrong key, etc.)
    }
}

/// Extract expiration timestamp from a token without validating the email
/// 
/// Returns the Unix timestamp when the token expires.
/// Useful for displaying "expires at" information to users.
pub fn get_token_expiration(token: &str, key: &str) -> Result<i64, Error> {
    use crate::crypto::decrypt;
    use crate::payload::Payload;
    
    let decrypted = decrypt(key, token)?;
    let payload: Payload = serde_json::from_str(&decrypted)
        .map_err(|_| Error::JsonError)?;
    
    Ok(payload.expiration)
}

/// Generate a secure random key for encryption
/// 
/// This is useful for applications that need to generate encryption keys
/// programmatically. The generated key will be URL-safe and of appropriate length.
/// 
/// # Examples
/// 
/// ```
/// use confirm_email::utils::generate_secure_key;
/// 
/// let key = generate_secure_key(32); // Generate a 32-character key
/// ```
pub fn generate_secure_key(length: usize) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use aes_gcm::aead::rand_core::{OsRng, RngCore};
    
    if length < 8 {
        panic!("Key length must be at least 8 characters");
    }
    
    // Generate random bytes (3/4 of desired length since base64 encoding increases size)
    let byte_count = (length * 3) / 4;
    let mut bytes = vec![0u8; byte_count];
    OsRng.fill_bytes(&mut bytes);
    
    let key = URL_SAFE_NO_PAD.encode(&bytes);
    
    // Truncate to desired length
    key.chars().take(length).collect()
}

/// Predefined expiration durations for common use cases
pub mod durations {
    /// 5 minutes - for very short-lived tokens
    pub const FIVE_MINUTES: i64 = 300;
    
    /// 15 minutes - for quick confirmations
    pub const FIFTEEN_MINUTES: i64 = 900;
    
    /// 1 hour - for same-session confirmations
    pub const ONE_HOUR: i64 = 3600;
    
    /// 24 hours - default duration
    pub const ONE_DAY: i64 = 86400;
    
    /// 3 days - for delayed confirmations
    pub const THREE_DAYS: i64 = 259200;
    
    /// 1 week - for long-term confirmations
    pub const ONE_WEEK: i64 = 604800;
}

/// Token validation result with more detailed information
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub email: String,
    pub is_expired: bool,
    pub expires_at: i64,
    pub time_remaining: Option<i64>, // Seconds remaining, None if expired
}

/// Enhanced validation that provides detailed information about the token
pub fn validate_token_detailed(token: &str, key: &str) -> Result<ValidationResult, Error> {
    use chrono::Utc;
    
    let email = validate_token(token.to_string(), key.to_string())?;
    let expires_at = get_token_expiration(token, key)?;
    let now = Utc::now().timestamp();
    
    let (is_expired, time_remaining) = if now > expires_at {
        (true, None)
    } else {
        (false, Some(expires_at - now))
    };
    
    Ok(ValidationResult {
        email,
        is_expired,
        expires_at,
        time_remaining,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token_with_duration() {
        let token = generate_token_with_duration("test@example.com", "test_key_123", 1, "hour");
        assert!(token.is_ok());
        
        let token = generate_token_with_duration("test@example.com", "test_key_123", 30, "minutes");
        assert!(token.is_ok());
        
        let token = generate_token_with_duration("test@example.com", "test_key_123", 5, "days");
        assert!(token.is_ok());
        
        // Invalid unit
        let token = generate_token_with_duration("test@example.com", "test_key_123", 1, "invalid");
        assert!(token.is_err());
    }

    #[test]
    fn test_generate_secure_key() {
        let key = generate_secure_key(16);
        assert_eq!(key.len(), 16);
        
        let key32 = generate_secure_key(32);
        assert_eq!(key32.len(), 32);
        
        // Keys should be different
        assert_ne!(key, key32);
        
        // Multiple generations should produce different keys
        let key_a = generate_secure_key(20);
        let key_b = generate_secure_key(20);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn test_batch_operations() {
        let emails = vec!["user1@example.com", "user2@example.com", "user3@example.com"];
        let key = "batch_test_key";
        
        let results = generate_batch_tokens(&emails, key);
        assert_eq!(results.len(), 3);
        
        // All should succeed
        for (email, result) in &results {
            assert!(result.is_ok(), "Failed for email: {}", email);
        }
        
        // Test validation
        let mut token_key_pairs = HashMap::new();
        for (_email, result) in results {
            if let Ok(token) = result {
                token_key_pairs.insert(token, key.to_string());
            }
        }
        
        let validation_results = validate_batch_tokens(&token_key_pairs);
        assert_eq!(validation_results.len(), 3);
        
        for (_, result) in validation_results {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_token_expiration_check() {
        let key = "expiration_test_key";
        
        // Valid token
        let token = generate_token("test@example.com".to_string(), key.to_string()).unwrap();
        let is_expired = is_token_expired(&token, key).unwrap();
        assert!(!is_expired);
        
        // Expired token (use 2 seconds as minimum, then wait 3 seconds)
        let expired_token = generate_token_with_expiration(
            "test@example.com".to_string(), 
            key.to_string(), 
            2
        ).unwrap();
        
        std::thread::sleep(std::time::Duration::from_secs(3));
        
        let is_expired = is_token_expired(&expired_token, key).unwrap();
        assert!(is_expired);
    }
} 