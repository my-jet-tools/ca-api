//! Changing the files key. Under the hood the data folder is archived as it is — encrypted with the
//! old key, in `archive/<YYYYMMDDhhmmss>` — and a snapshot of it with the new key takes its
//! place; from then on only the new key opens the folder and the encrypted calls. A rollback puts
//! an archive back with its key, and archives what it replaces, so it is undone the same way.

use my_http_server::BodyEncryptionKey;

use crate::app::{AppContext, FILES_KEY_ID};
use crate::crypto::envelope::{decode_key, Key};
use crate::storage::journal::{JournalEvent, JournalRecord};
use crate::storage::{FilesKeyChange, RollBackError};

use super::FlowError;

/// What changing the files key did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesKeyChanged {
    /// `false` — it already was this key, and nothing was done.
    pub changed: bool,
    /// Where the data folder as it was is kept, with the old key.
    pub archive: Option<String>,
    /// Journal lines carried into the snapshot.
    pub journal_records: usize,
    /// Journal lines that did not open with the old key: carried as they were.
    pub journal_unreadable: usize,
}

/// Make `raw` (base64 of 32 bytes) the files key: archive the data folder, take its place with a
/// snapshot encrypted with the new key, and open the encrypted calls with it alone.
pub async fn change_files_key(app: &AppContext, raw: &str) -> Result<FilesKeyChanged, FlowError> {
    let key = decode_key(raw).map_err(|e| FlowError::ValidationError(format!("newKey: {e}")))?;
    let body_key = calls_key(&key)?;
    let mut opened = app.storage.lock().await?;
    if network_key_is(opened.state().network_key.as_deref(), &key) {
        return Err(FlowError::ValidationError(
            "newKey must not be the network key: my-reverse-proxy holds the network key"
                .to_string(),
        ));
    }
    let (archive, rekeyed) = match opened
        .change_key(&key)
        .map_err(FlowError::SomethingWentWrong)?
    {
        FilesKeyChange::Unchanged => {
            return Ok(FilesKeyChanged {
                changed: false,
                archive: None,
                journal_records: 0,
                journal_unreadable: 0,
            })
        }
        FilesKeyChange::Changed { archive, rekeyed } => (archive, rekeyed),
    };
    // Still under the lock of the state: no call is let in with the old key once the folder has
    // the new one.
    app.body_encryption_keys.set(vec![body_key]);
    warn_pending(rekeyed.pending.as_deref());
    opened.journal(JournalRecord::of_archive(
        JournalEvent::FilesKeyChanged,
        &archive,
    ));
    crate::log::info("The files key is changed: the data folder is archived and re-encrypted");
    Ok(FilesKeyChanged {
        changed: true,
        archive: Some(archive),
        journal_records: rekeyed.records,
        journal_unreadable: rekeyed.unreadable,
    })
}

/// What a rollback did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesKeyRolledBack {
    /// The archive that was put back.
    pub restored: String,
    /// Where what it replaced is kept, with the key of before.
    pub archive: String,
}

/// Put the archive `archive` back — the newest one when `None` — with `raw`, the key it is
/// encrypted with, as the files key from now on.
pub async fn roll_back_files_key(
    app: &AppContext,
    raw: &str,
    archive: Option<&str>,
) -> Result<FilesKeyRolledBack, FlowError> {
    let key = decode_key(raw).map_err(|e| FlowError::ValidationError(format!("key: {e}")))?;
    let body_key = calls_key(&key)?;
    let archive = archive.map(str::trim).filter(|archive| !archive.is_empty());
    let mut opened = app.storage.lock().await?;
    let rolled_back = opened.roll_back(archive, &key).map_err(|e| match e {
        RollBackError::NotFound => FlowError::ArchiveNotFound,
        RollBackError::WrongKey => {
            FlowError::ValidationError("the key does not open this archive".to_string())
        }
        RollBackError::Failed(e) => FlowError::SomethingWentWrong(e),
    })?;
    app.body_encryption_keys.set(vec![body_key]);
    warn_pending(rolled_back.pending.as_deref());
    let mut record =
        JournalRecord::of_archive(JournalEvent::FilesKeyRolledBack, &rolled_back.archive);
    record.restored = Some(rolled_back.restored.clone());
    opened.journal(record);
    crate::log::info("The data folder is rolled back to an archive, with its files key");
    Ok(FilesKeyRolledBack {
        restored: rolled_back.restored,
        archive: rolled_back.archive,
    })
}

/// The ids of the archives, newest first.
pub async fn files_key_archives(app: &AppContext) -> Result<Vec<String>, FlowError> {
    let opened = app.storage.lock().await?;
    opened.archives().map_err(FlowError::SomethingWentWrong)
}

/// Delete the archive `archive`: once it is gone, the key it was encrypted with opens nothing on
/// this disk any more.
pub async fn delete_files_key_archive(app: &AppContext, archive: &str) -> Result<(), FlowError> {
    let opened = app.storage.lock().await?;
    let archive = archive.trim();
    if !opened
        .delete_archive(archive)
        .map_err(FlowError::SomethingWentWrong)?
    {
        return Err(FlowError::ArchiveNotFound);
    }
    opened.journal(JournalRecord::of_archive(
        JournalEvent::ArchiveDeleted,
        archive,
    ));
    crate::log::info("An archive of the data folder is deleted");
    Ok(())
}

/// The key the encrypted calls are opened with: made before anything changes, so that when it
/// cannot be, nothing does.
fn calls_key(key: &Key) -> Result<BodyEncryptionKey, FlowError> {
    BodyEncryptionKey::from_bytes(FILES_KEY_ID, key)
        .map_err(|e| FlowError::SomethingWentWrong(format!("the files key for the calls: {e}")))
}

fn network_key_is(network_key: Option<&str>, key: &Key) -> bool {
    network_key.map(decode_key) == Some(Ok(*key))
}

fn warn_pending(pending: Option<&str>) {
    if let Some(e) = pending {
        crate::log::warn(format!(
            "The journal of the data folder is not in place yet; the next start puts it there: {e}"
        ));
    }
}
