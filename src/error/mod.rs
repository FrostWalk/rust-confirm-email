use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Error, Debug)]
/// Defines possible errors
pub enum Error {
    /// The Token is expired at the date
    #[error("token expired at `{0}`")]
    Expired(DateTime<Utc>),
    /// Invalid token format or corrupted data
    #[error("invalid token format")]
    InvalidFormat,
    /// Decryption failed - likely wrong key or corrupted data
    #[error("decryption failed")]
    DecryptionFailed,
    /// Invalid email format
    #[error("invalid email format: `{0}`")]
    InvalidEmail(String),
    /// Encryption failed
    #[error("encryption failed")]
    EncryptionFailed,
    /// Invalid expiration time
    #[error("invalid expiration time: `{0}`")]
    InvalidExpiration(String),
    /// JSON serialization/deserialization error
    #[error("JSON processing error")]
    JsonError,
    /// Key derivation error
    #[error("key derivation failed")]
    KeyDerivationFailed,
    /// Unknown error
    #[error("error occurred: {0:?}")]
    Other(String),
}
