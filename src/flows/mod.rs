//! What the API does, over the encrypted state ([`crate::storage`]). Every change is read, made
//! and written under the lock of the state, and journaled; the log tells only what happened.

mod ca;
mod certs;
mod error;
mod files_key;
mod journal;
mod network_key;
mod proxy;

pub use ca::*;
pub use certs::*;
pub use error::*;
pub use files_key::*;
pub use journal::*;
pub use network_key::*;
pub use proxy::*;

pub use crate::pem::PemCertInfo;


/// Run `job` — RSA key generation, signing — off the async workers.
async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, FlowError> {
    tokio::task::spawn_blocking(job)
        .await
        .map_err(|e| FlowError::SomethingWentWrong(e.to_string()))?
        .map_err(FlowError::SomethingWentWrong)
}

/// A CA name or a CN for something new: 1 to 256 characters, no control characters, no spaces
/// around.
fn validate_name(what: &str, value: &str) -> Result<(), FlowError> {
    let valid = !value.is_empty()
        && value.trim() == value
        && value.chars().count() <= 256
        && !value.chars().any(char::is_control);
    if valid {
        Ok(())
    } else {
        Err(FlowError::ValidationError(format!(
            "{what} must be 1 to 256 characters, with no control characters and no spaces around"
        )))
    }
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
