//! Changing the encryption key, and rolling it back. Both come under the current encryption key,
//! and hand the key that becomes the encryption key in the body.
//!
//! A change archives the data folder as it is — under the old key, in
//! `archive/<YYYYMMDDhhmmss>` — and a snapshot of it under the new key takes its place. A rollback
//! opens an archive with the key it is handed: when the key fits, the archive is put back and the
//! key becomes the encryption key. What a rollback replaces is archived too, so it is undone the
//! same way. Either way, from the next request on my-http-server takes the new key alone.

use crate::app::AppContext;
use crate::crypto::envelope::{decode_key, Key};
use crate::storage::journal::{JournalEvent, JournalRecord};
use crate::storage::{KeyChange, RollBackError};

use super::FlowError;

/// What changing the encryption key did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChanged {
    /// `false` — it already was this key, and nothing was done.
    pub changed: bool,
    /// Where the data folder as it was is kept, under the old key.
    pub archive: Option<String>,
    /// Journal lines carried into the snapshot.
    pub journal_records: usize,
    /// Journal lines that did not open with the old key: carried as they were.
    pub journal_unreadable: usize,
}

/// Make `raw` (base64 of 32 bytes) the encryption key: archive the data folder, take its place
/// with a snapshot encrypted with the new key, and open the calls with it.
pub async fn change_encryption_key(app: &AppContext, raw: &str) -> Result<KeyChanged, FlowError> {
    let key = decode_key(raw).map_err(|e| FlowError::ValidationError(format!("newKey: {e}")))?;
    let mut opened = app.storage.lock().await?;
    if opened.network_key() == Some(key) {
        return Err(FlowError::ValidationError(
            "newKey must not be the network key: my-reverse-proxy holds the network key"
                .to_string(),
        ));
    }
    let (archive, rekeyed) = match opened
        .change_key(&key)
        .map_err(FlowError::SomethingWentWrong)?
    {
        KeyChange::Unchanged => {
            return Ok(KeyChanged {
                changed: false,
                archive: None,
                journal_records: 0,
                journal_unreadable: 0,
            })
        }
        KeyChange::Changed { archive, rekeyed } => (archive, rekeyed),
    };
    // Still under the lock of the state: no call is let in with the old key once the folder has
    // the new one.
    app.refresh_call_keys(&opened);
    warn_pending(rekeyed.pending.as_deref());
    opened.journal(JournalRecord::of_archive(
        JournalEvent::KeyChanged,
        &archive,
    ));
    crate::log::info("The encryption key is changed: the data folder is archived and re-encrypted");
    Ok(KeyChanged {
        changed: true,
        archive: Some(archive),
        journal_records: rekeyed.records,
        journal_unreadable: rekeyed.unreadable,
    })
}

/// What a rollback did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRolledBack {
    /// The archive that was put back.
    pub restored: String,
    /// Where what was in place went, under the key it had.
    pub archive: String,
    /// Whether the state put back has a network key.
    pub network_key: bool,
}

/// Open the archive `archive` — with none named, the newest one — with `raw`, the key it was
/// encrypted with; when the key fits, put it back, and `raw` becomes the encryption key.
pub async fn roll_back_encryption_key(
    app: &AppContext,
    raw: &str,
    archive: Option<&str>,
) -> Result<KeyRolledBack, FlowError> {
    let key: Key = decode_key(raw).map_err(|e| FlowError::ValidationError(format!("key: {e}")))?;
    let archive = archive.map(str::trim).filter(|archive| !archive.is_empty());
    let mut opened = app.storage.lock().await?;
    let rolled_back = opened.roll_back(&key, archive).map_err(|e| match e {
        RollBackError::NoSuchArchive => FlowError::ArchiveNotFound,
        RollBackError::NoArchiveOpens => {
            FlowError::ValidationError("the key opens no archive".to_string())
        }
        RollBackError::Failed(e) => FlowError::SomethingWentWrong(e),
    })?;
    // The keys of the state put back: the archive's encryption key, its network key.
    app.refresh_call_keys(&opened);
    warn_pending(rolled_back.pending.as_deref());
    let mut record = JournalRecord::of_archive(JournalEvent::RolledBack, &rolled_back.archive);
    record.restored = Some(rolled_back.restored.clone());
    opened.journal(record);
    crate::log::info("The data folder is rolled back to an archive, with its encryption key");
    Ok(KeyRolledBack {
        restored: rolled_back.restored,
        archive: rolled_back.archive,
        network_key: opened.network_key().is_some(),
    })
}

fn warn_pending(pending: Option<&str>) {
    if let Some(e) = pending {
        crate::log::warn(format!(
            "The journal of the data folder is not in place yet; the next start puts it there: {e}"
        ));
    }
}
