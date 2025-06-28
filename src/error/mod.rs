use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Error, Debug)]
/// Defines possible errors
pub enum Error {
    /// The Token is expired at the date
    #[error("token expired at `{0}`")]
    Expired(DateTime<Utc>),
    /// Unknown error
    #[error("error occurred: {0:?}")]
    Other(String),
}
