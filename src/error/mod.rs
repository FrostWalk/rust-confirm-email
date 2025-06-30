use aes_gcm::Error as AesGcmError;
use argon2::password_hash::Error as PwhError;
use base64::DecodeError as Base64DecodeError;
use chrono::{DateTime, Utc};
use serde_json::Error as JsonError;
use std::string::FromUtf8Error;
use std::{error::Error as StdError, fmt};

/// Defines possible errors
#[derive(Debug)]
pub enum Error {
    /// The Token is expired at the date time
    Expired(DateTime<Utc>),

    /// JSON serialization failed
    JsonSerialize(JsonError),
    /// JSON deserialization failed
    JsonDeserialize(JsonError),

    /// The requested expiration was invalid (<= 1s)
    InvalidExpirationSeconds(i64),

    /// Expiration timestamp was out of range for `Utc.timestamp_opt`
    ExpirationOutOfRange(i64),

    /// Something went wrong with password hashing (salt‐encode or hash_password)
    PasswordHash(PwhError),

    /// We got a PHC string back, but it had no `.hash` component
    MissingHash,

    /// AES‐GCM encryption/decryption error
    AesGcm(AesGcmError),

    /// Base64 decoding failed
    Base64Decode(Base64DecodeError),

    /// UTF‑8 decoding (after decryption) failed
    Utf8(FromUtf8Error),

    /// Encrypted blob was too short to contain salt and nonce
    InvalidDataLength(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Expired(dt) => write!(f, "token expired at `{dt:#?}`"),

            Error::JsonSerialize(e) => write!(f, "failed to serialize payload to JSON: {e}"),

            Error::JsonDeserialize(e) => write!(f, "failed to parse JSON payload: {e}"),

            Error::InvalidExpirationSeconds(secs) => write!(
                f,
                "invalid expiration {secs}s: must be greater than 1 second"
            ),

            Error::ExpirationOutOfRange(ts) => write!(
                f,
                "expiration timestamp {ts} is out of range for a UTC DateTime"
            ),

            Error::PasswordHash(e) => write!(f, "password hashing failed: {e}"),

            Error::MissingHash => write!(f, "failed to extract raw hash bytes from PHC string"),

            Error::AesGcm(e) => write!(f, "AES‑GCM error: {e}"),

            Error::Base64Decode(e) => write!(f, "Base64 decode error: {e:#?}"),

            Error::Utf8(e) => write!(f, "UTF‑8 conversion error: {e:#?}"),

            Error::InvalidDataLength(got) => {
                let needed = 16 + 12;
                write!(
                    f,
                    "invalid encrypted data length: expected at least {needed} bytes but got {got}"
                )
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::PasswordHash(e) => Some(e),
            Error::AesGcm(e) => Some(e),
            Error::Base64Decode(e) => Some(e),
            Error::Utf8(e) => Some(e),
            _ => None,
        }
    }
}

// allow `?` on password-hash results
impl From<PwhError> for Error {
    fn from(e: PwhError) -> Error {
        Error::PasswordHash(e)
    }
}

impl From<AesGcmError> for Error {
    fn from(e: AesGcmError) -> Error {
        Error::AesGcm(e)
    }
}

impl From<Base64DecodeError> for Error {
    fn from(e: Base64DecodeError) -> Error {
        Error::Base64Decode(e)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Error {
        Error::Utf8(e)
    }
}
impl From<JsonError> for Error {
    fn from(e: JsonError) -> Self {
        Error::JsonSerialize(e)
    }
}
