use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
/// Defines the data to be encoded in the token
pub(super) struct Payload {
    #[serde(rename = "m")]
    /// Email address to verify
    pub(super) email: String,
    #[serde(rename = "e")]
    /// Timestamp in unix epoch after which the token is considered expired
    pub(super) expiration: i64,
}
