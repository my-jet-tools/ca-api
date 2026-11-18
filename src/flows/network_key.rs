use crate::app::AppContext;
use crate::crypto::envelope::{decode_key, encode_key};
use crate::storage::journal::{unix_now, JournalEvent, JournalRecord};

use super::FlowError;

/// What setting the network key did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKeySet {
    /// There was none: my-reverse-proxy can be served from now on.
    New,
    /// Another one is replaced: a rotation.
    Replaced,
    /// It already was this one.
    Unchanged,
}

/// Keep `raw` (base64 of 32 bytes) in the state as the network key: what the answers to
/// my-reverse-proxy are encrypted with. Never the files key: my-reverse-proxy holds the network
/// key, and with the files key it would hold everything.
pub async fn set_network_key(app: &AppContext, raw: &str) -> Result<NetworkKeySet, FlowError> {
    let key = decode_key(raw).map_err(|e| FlowError::ValidationError(format!("networkKey: {e}")))?;
    let mut opened = app.storage.lock().await?;
    if opened.is_files_key(&key) {
        return Err(FlowError::ValidationError(
            "networkKey must not be the files key: my-reverse-proxy holds the network key".to_string(),
        ));
    }
    let result = match opened.state().network_key.as_deref().map(decode_key) {
        Some(Ok(current)) if current == key => return Ok(NetworkKeySet::Unchanged),
        Some(_) => NetworkKeySet::Replaced,
        None => NetworkKeySet::New,
    };
    let mut state = opened.state().clone();
    state.network_key = Some(encode_key(&key));
    opened
        .commit(state)
        .map_err(FlowError::SomethingWentWrong)?;
    let mut record = JournalRecord::new(JournalEvent::NetworkKeySet, unix_now());
    record.by = Some(
        match result {
            NetworkKeySet::Replaced => "replaced",
            _ => "new",
        }
        .to_string(),
    );
    opened.journal(record);
    crate::log::info(match result {
        NetworkKeySet::Replaced => "The network key is replaced",
        _ => "The network key is set",
    });
    Ok(result)
}
