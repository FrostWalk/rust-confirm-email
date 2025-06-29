//! # confirm_email
//!
//! `confirm_email` is a lightweight Rust crate for generating and validating
//! URL-safe, encrypted email confirmation tokens with configurable expiry.
//!
//! ## Purpose
//! The `confirm_email` crate addresses a common requirement in user registration systems: verifying that users have access to the email addresses they provide. When users register for an account, the system needs to confirm their email address before fully activating their account or granting access to certain features.
//!
//! This library generates secure, encrypted tokens that can be embedded in confirmation emails sent to users. When users click the confirmation link, the application validates the token to verify the email address and complete the registration process. The tokens contain the user's email address and an expiration timestamp, ensuring that confirmation links remain valid only for a specified period.
//!
//! The crate is designed for applications that need reliable email verification without the complexity of managing token storage in databases or external services. All token information is self-contained and cryptographically protected, making the system both secure and stateless.
//! ## Features
//!
//! - Generate a token containing an email address and expiration timestamp, encrypted
//!   and encoded as a compact string.
//! - Configure token validity duration (default: 1 day).
//! - Validate and decrypt a token, returning the original email or a descriptive error
//!   if the token is invalid or expired.
//!
//! ## Quickstart
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! confirm_email = "0.1"
//! ```
//!
//! ## Usage
//!
//! ```rust
//! use confirm_email::{generate_token, generate_token_with_expiration, validate_token};
//! use confirm_email::error::Error;
//!
//! // 1. Generate a token with default expiry (1 day):
//! let token = generate_token(
//!     "user@example.com".to_string(),
//!     "super_secret_key".to_string(),
//! ).expect("Error generating token with default validity");
//!
//! // 2. Generate a token with custom expiry (e.g., 3600 seconds = 1 hour):
//! let hour_token = generate_token_with_expiration(
//!     "user@example.com".to_string(),
//!     "super_secret_key".to_string(),
//!     3600,
//! ).expect("Error generating token with custom validity");
//!
//! // 3. Validate and decrypt the token:
//! match validate_token(token.clone(), "super_secret_key".to_string()) {
//!     Ok(email) => println!("Confirmed email: {}", email),
//!     Err(Error::Expired(ts)) => eprintln!("Token expired at {}", ts),
//!     Err(e) => eprintln!("Invalid token: {}", e),
//! }
//! ```
//!
//! ## API
//!
//! - [`generate_token(email, key)`]
//!   Generate a token for `email` using `key`, valid for the default duration (1 day).
//!
//! - [`generate_token_with_expiration(email, key, exp_seconds)`]
//!   Generate a token for `email` using `key`, valid for `exp_seconds` seconds.
//!
//! - [`validate(token, key)`]
//!   Decrypt and verify `token` with `key`. Returns the original email on success or
//!   an [`Other`] on failure (`Expired`, `Invalid`, etc.).
//!
//! ## License
//!
//! MIT
use crate::crypto::{decrypt, encrypt};
use crate::error::Error;
use crate::error::Error::{Expired, InvalidEmail, InvalidExpiration, JsonError, Other};
use crate::payload::Payload;
use chrono::{Duration, TimeZone, Utc};
use regex;

/// Contains helper functions for encryption and decryption
mod crypto;
/// Contains definitions for the possible errors
pub mod error;
/// Contains the definition of the token's payload
mod payload;
/// Contains tests
#[cfg(test)]
mod tests;
/// Contains benchmarks
#[cfg(test)]
mod benchmarks;
/// Contains utility functions
pub mod utils;

const DEFAULT_VALIDITY_DAYS: i64 = 1;

/// Validates email format using a simple regex pattern
fn validate_email_format(email: &str) -> bool {
    // More strict email validation - rejects consecutive dots and other invalid patterns
    let email_regex = regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    
    // Additional checks for edge cases
    if email.contains("..") || // No consecutive dots
       email.starts_with('.') || email.ends_with('.') || // No leading/trailing dots
       email.contains("@.") || email.contains(".@") || // No dots adjacent to @
       email.chars().filter(|&c| c == '@').count() != 1 { // Exactly one @
        return false;
    }
    
    email_regex.is_match(email)
}

fn generate(email: String, key: String, exp: Duration) -> Result<String, Error> {
    // Validate email format
    if !validate_email_format(&email) {
        return Err(InvalidEmail(email));
    }

    // Validate key length
    if key.len() < 8 {
        return Err(Other("encryption key must be at least 8 characters".to_string()));
    }

    let expiration = (Utc::now() + exp).timestamp();

    let payload = Payload { email, expiration };

    let json = serde_json::to_string(&payload).map_err(|_| JsonError)?;
    let data = encrypt(key.as_str(), json.as_str())?;

    Ok(data)
}

#[inline]
/// Generates a token with a specified expiration time in seconds.
///
/// This function creates a token that expires after the specified number of seconds. It uses
/// the provided email and key to generate the token.
///
/// # Arguments
///
/// * `email` - A `String` representing the user's email address.
/// * `key` - A `String` representing the encryption key.
/// * `exp_seconds` - An `i64` representing the number of seconds until the token expires. **Must be greater than 1**
///
/// # Returns
///
/// A `Result<String, Error>` that contains the generated token if successful, or an error otherwise.
///
/// # Examples
///
/// ```
/// // Example of generating a token with custom expiration (e.g., 3600 seconds = 1 hour)
/// use confirm_email::{generate_token_with_expiration, validate_token};
///
/// let token = generate_token_with_expiration("user@example.com".to_string(), "secret_key".to_string(), 3600).unwrap();
/// assert!(validate_token(token, "secret_key".to_string()).is_ok());
/// ```
pub fn generate_token_with_expiration(
    email: String,
    key: String,
    exp_seconds: i64,
) -> Result<String, Error> {
    if exp_seconds <= 1 {
        return Err(InvalidExpiration(
            "expiration must be greater than 1 second".to_string(),
        ));
    }
    if exp_seconds > 365 * 24 * 3600 {
        return Err(InvalidExpiration(
            "expiration cannot be more than 1 year".to_string(),
        ));
    }
    generate(email, key, Duration::seconds(exp_seconds))
}

#[inline]
/// Generates a token with the default expiration time.
///
/// This function creates a token that expires after the default number of days (1 day). It uses
/// the provided email and key to generate the token.
///
/// # Arguments
///
/// * `email` - A `String` representing the user's email address.
/// * `key` - A `String` representing the encryption key.
///
/// # Returns
///
/// A `Result<String, Error>` that contains the generated token if successful, or an error otherwise.
///
/// # Examples
///
/// ```
/// // Example of generating a token with default validity (1 day)
/// use confirm_email::{generate_token, validate_token};
///
/// let token = generate_token("user@example.com".to_string(), "secret_key".to_string()).unwrap();
/// assert!(validate_token(token, "secret_key".to_string()).is_ok());
/// ```
pub fn generate_token(email: String, key: String) -> Result<String, Error> {
    generate(email, key, Duration::days(DEFAULT_VALIDITY_DAYS))
}

/// Parse the token and if valid returns the corresponding email.
///
/// This function takes an encrypted token and decryption key, decrypts the token,
/// verifies its expiration time, and returns the associated email address if valid.
///
/// # Arguments
///
/// * `token` - A `String` containing the encrypted token to validate.
/// * `key` - A `String` representing the decryption key.
///
/// # Returns
///
/// A `Result<String, Error>` that contains the user's email address if validation succeeds,
/// or an error if validation fails due to invalid token format, expiration, or decryption issues.
///
/// # Examples
///
/// ```
/// // Example of successful validation
/// use confirm_email::{generate_token, generate_token_with_expiration, validate_token};
///
/// let token = generate_token("user@example.com".to_string(), "secret_key".to_string()).unwrap();
/// assert_eq!(validate_token(token, "secret_key".to_string()).unwrap(), "user@example.com");
/// ```
pub fn validate_token(token: String, key: String) -> Result<String, Error> {
    // Validate key length
    if key.len() < 8 {
        return Err(Other("encryption key must be at least 8 characters".to_string()));
    }

    let decrypted = decrypt(key.as_str(), token.as_str())?;

    let payload: Payload =
        serde_json::from_str(decrypted.as_str()).map_err(|_| JsonError)?;

    let exp = match Utc.timestamp_opt(payload.expiration, 0).single() {
        None => {
            return Err(InvalidExpiration(
                "out-of-range number of seconds in expiration".to_string(),
            ));
        }
        Some(d) => d,
    };

    if Utc::now() > exp {
        return Err(Expired(exp));
    }

    Ok(payload.email)
}
