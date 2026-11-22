//! The lock on everything ca-api knows.
//!
//! The service starts knowing nothing: the state is in the data folder, encrypted with a key that
//! is never on the disk. It is handed the key once per start (`POST /api/initialize`, over the
//! unix socket only), and the key that opens `state.enc` is the right one. Until then there are no
//! CAs, nothing is served and nothing is written.
//!
//! A data folder with no state yet is created by the first key — with the CAs of the plaintext
//! folder of ca-api 0.2 (`config_path`), when the settings name one ([`super::legacy`]).

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard};

use super::data_folder::{ArchiveError, DataFolder, Rekeyed, UnlockError};
use super::journal::{unix_now, JournalEvent, JournalPage, JournalQuery, JournalRecord};
use super::legacy::read_legacy_pki;
use super::state_model::StateModel;
use crate::crypto::envelope::{self, Key};

/// What an initialization did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Initialized {
    /// `true` — the data folder was created now (it had no state), `false` — the key opened it.
    pub created: bool,
    /// The key the service made, base64 — only when it was asked to create the data folder
    /// without one. A key that was handed to it is never told back.
    pub generated_key: Option<String>,
    pub cas: usize,
    pub certificates: usize,
    /// What came from the plaintext folder of 0.2: CAs and certificate records. Only when the
    /// state was created now and the folder had any.
    pub imported: Option<(usize, usize)>,
    /// Whether the state has a network key: the answers to my-reverse-proxy can be served.
    pub network_key: bool,
    /// What was deleted from the data folder: everything that was not the encrypted data.
    pub deleted: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitializeError {
    AlreadyInitialized,
    /// The key is not base64 of 32 bytes, or there is none where one is needed.
    BadKey(String),
    /// The key does not open the state in the data folder.
    WrongKey,
    Failed(String),
}

impl std::fmt::Display for InitializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyInitialized => write!(f, "the service is already initialized"),
            Self::WrongKey => write!(f, "the key does not open the state in the data folder"),
            Self::BadKey(e) | Self::Failed(e) => write!(f, "{e}"),
        }
    }
}

/// The service has no key yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotInitialized;

/// What [`Opened::change_key`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyChange {
    /// It already was this key: nothing was done.
    Unchanged,
    /// Everything is encrypted with the new key now; what it was, with the old key, is in
    /// `archive`.
    Changed { archive: String, rekeyed: Rekeyed },
}

/// What [`Opened::roll_back`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolledBack {
    /// The archive that was put back.
    pub restored: String,
    /// Where what was in place went, under its key.
    pub archive: String,
    /// Why the journal put back is not in place yet, if it is not: the next start puts it there.
    pub pending: Option<String>,
}

/// Why [`Opened::roll_back`] did nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollBackError {
    /// There is no archive with this name.
    NoSuchArchive,
    /// The key opens no archive — or not the one named.
    NoArchiveOpens,
    Failed(String),
}

/// The opened data folder and the state it holds.
pub struct Opened {
    folder: DataFolder,
    key: Key,
    state: StateModel,
}

impl Opened {
    pub fn state(&self) -> &StateModel {
        &self.state
    }

    /// Write `state` and make it the state. When it cannot be written, nothing changes: neither
    /// the disk nor what the service serves.
    pub fn commit(&mut self, state: StateModel) -> Result<(), String> {
        self.folder.save_state(&state)?;
        self.state = state;
        Ok(())
    }

    /// Append `record` to the journal. A record that cannot be written is a warning in the log:
    /// what it records is done already.
    pub fn journal(&self, record: JournalRecord) {
        if let Err(e) = self.folder.append(&record) {
            crate::log::warn(format!("A journal record is lost: {e}"));
        }
    }

    pub fn read_journal(&self, query: &JournalQuery) -> Result<JournalPage, String> {
        self.folder.read_journal(query)
    }

    /// The encryption key: what the data folder is encrypted with.
    pub fn encryption_key(&self) -> &Key {
        &self.key
    }

    /// The network key of the state, when it has one.
    pub fn network_key(&self) -> Option<Key> {
        let network_key = self.state.network_key.as_deref()?;
        envelope::decode_key(network_key).ok()
    }

    /// Archive what the data folder holds, under the key it has, and take its place with a
    /// snapshot encrypted with `new_key` — the state and every journal line — which becomes the
    /// encryption key: after a restart only it opens the folder. An error means nothing changed:
    /// the folder keeps the key it had.
    pub fn change_key(&mut self, new_key: &Key) -> Result<KeyChange, String> {
        if self.key == *new_key {
            return Ok(KeyChange::Unchanged);
        }
        let archive = self.folder.archive()?;
        let rekeyed = self.folder.rekey(new_key, &self.state)?;
        self.key = *new_key;
        Ok(KeyChange::Changed { archive, rekeyed })
    }

    /// Put the archive `archive` back — with none named, the newest archive `key` opens — and
    /// make `key` the encryption key. What is in place is archived first, under its key, so a
    /// rollback loses nothing and is rolled back the same way. An error means nothing changed.
    pub fn roll_back(
        &mut self,
        key: &Key,
        archive: Option<&str>,
    ) -> Result<RolledBack, RollBackError> {
        let rolled = self.folder.roll_back(key, archive).map_err(|e| match e {
            ArchiveError::NotFound => RollBackError::NoSuchArchive,
            ArchiveError::WrongKey | ArchiveError::NoneOpens => RollBackError::NoArchiveOpens,
            ArchiveError::Failed(e) => RollBackError::Failed(e),
        })?;
        self.key = *key;
        self.state = rolled.state;
        Ok(RolledBack {
            restored: rolled.restored,
            archive: rolled.archive,
            pending: rolled.pending,
        })
    }
}

/// A data folder opened, about to become [`Opened`].
struct Opening {
    folder: DataFolder,
    key: Key,
    state: StateModel,
    created: bool,
    generated_key: Option<String>,
    imported: Option<(usize, usize)>,
}

pub struct SecureStorage {
    data_folder: String,
    /// The plaintext folder of 0.2 to import from when the state is created.
    legacy_pki: Option<String>,
    opened: Mutex<Option<Opened>>,
    initialized: AtomicBool,
}

impl SecureStorage {
    pub fn new(data_folder: String, legacy_pki: Option<String>) -> Self {
        Self {
            data_folder,
            legacy_pki,
            opened: Mutex::new(None),
            initialized: AtomicBool::new(false),
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// The opened state — held until the guard is dropped, so a change is read, made and written
    /// as one step.
    pub async fn lock(&self) -> Result<MappedMutexGuard<'_, Opened>, NotInitialized> {
        MutexGuard::try_map(self.opened.lock().await, |opened| opened.as_mut())
            .map_err(|_| NotInitialized)
    }

    /// Hand the service its encryption key (base64 of 32 bytes), once per start. Returns what was
    /// done, and the key.
    ///
    /// - A data folder with a state: `key` must open it.
    /// - Without one: the state is created, encrypted with `key` — or with a key made now when
    ///   there is none, told back once — holding the CAs of the plaintext folder, if any.
    pub async fn initialize(
        &self,
        key: Option<&str>,
    ) -> Result<(Initialized, Key), InitializeError> {
        let mut opened = self.opened.lock().await;
        if opened.is_some() {
            return Err(InitializeError::AlreadyInitialized);
        }
        let folder = self.data_folder.as_str();
        let key_text = key.map(str::trim).filter(|key| !key.is_empty());

        let opening = if DataFolder::has_state(folder) {
            let Some(key_text) = key_text else {
                return Err(InitializeError::BadKey(
                    "the data folder has a state: the key that opens it is needed".to_string(),
                ));
            };
            let key = envelope::decode_key(key_text).map_err(InitializeError::BadKey)?;
            let (data_folder, state) = DataFolder::unlock(folder, &key).map_err(|e| match e {
                UnlockError::WrongKey => InitializeError::WrongKey,
                UnlockError::Failed(e) => InitializeError::Failed(e),
            })?;
            // A change of the key the process did not live to finish: finished, or dropped.
            if let Err(e) = data_folder.finish_rekey() {
                crate::log::warn(format!(
                    "The journal written again with the new encryption key is not in place yet: {e}"
                ));
            }
            data_folder.append_or_warn(JournalRecord::new(JournalEvent::Unlocked, unix_now()));
            Opening {
                folder: data_folder,
                key,
                state,
                created: false,
                generated_key: None,
                imported: None,
            }
        } else {
            let (key, generated_key) = match key_text {
                Some(key_text) => (
                    envelope::decode_key(key_text).map_err(InitializeError::BadKey)?,
                    None,
                ),
                None => {
                    let key = envelope::generate_key().map_err(InitializeError::Failed)?;
                    (key, Some(envelope::encode_key(&key)))
                }
            };
            let mut state = StateModel::default();
            if let Some(legacy) = self.legacy_pki.as_deref() {
                state.cas = read_legacy_pki(legacy).map_err(|e| {
                    InitializeError::Failed(format!(
                        "the plaintext PKI folder cannot be imported: {e}"
                    ))
                })?;
            }
            let data_folder =
                DataFolder::create(folder, &key, &state).map_err(InitializeError::Failed)?;
            let now = unix_now();
            data_folder.append_or_warn(JournalRecord::new(JournalEvent::Initialized, now));
            let mut imported = None;
            if !state.cas.is_empty() {
                let mut certificates = 0;
                for (name, ca) in &state.cas {
                    let mut record = JournalRecord::new(JournalEvent::CaImported, now);
                    record.ca = Some(name.clone());
                    record.by = Some("legacy".to_string());
                    record.certificates = Some(ca.certificates.len());
                    data_folder.append_or_warn(record);
                    certificates += ca.certificates.len();
                }
                imported = Some((state.cas.len(), certificates));
            }
            Opening {
                folder: data_folder,
                key,
                state,
                created: true,
                generated_key,
                imported,
            }
        };
        let key = opening.key;
        Ok((self.open(&mut opened, opening), key))
    }

    /// Sweep the folder `opening` opened and make it the opened one.
    fn open(&self, slot: &mut Option<Opened>, opening: Opening) -> Initialized {
        let sweep = opening.folder.sweep();
        for failed in &sweep.failed {
            crate::log::warn(format!(
                "Not deleted from the data folder, as not encrypted: {failed}"
            ));
        }
        let state = &opening.state;
        let done = Initialized {
            created: opening.created,
            generated_key: opening.generated_key,
            cas: state.cas.len(),
            certificates: state.cas.values().map(|ca| ca.certificates.len()).sum(),
            imported: opening.imported,
            network_key: state.network_key.is_some(),
            deleted: sweep.deleted,
        };
        *slot = Some(Opened {
            folder: opening.folder,
            key: opening.key,
            state: opening.state,
        });
        self.initialized.store(true, Ordering::SeqCst);
        done
    }

    /// Whether the plaintext folder of 0.2 still holds a CA: then its keys are still readable on
    /// the disk, and it is to be deleted once the import is checked.
    pub fn legacy_plaintext_left(&self) -> bool {
        let Some(folder) = self.legacy_pki.as_deref() else {
            return false;
        };
        let Ok(entries) = std::fs::read_dir(folder) else {
            return false;
        };
        entries
            .filter_map(|entry| entry.ok())
            .any(|entry| entry.path().join("ca_cert.pem").exists())
    }
}

impl DataFolder {
    fn append_or_warn(&self, record: JournalRecord) {
        if let Err(e) = self.append(&record) {
            crate::log::warn(format!("A journal record is lost: {e}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{InitializeError, KeyChange, RollBackError, SecureStorage};
    use crate::crypto::envelope::{encode_key, generate_key};
    use crate::storage::data_folder::tests::Folder;
    use crate::storage::journal::{JournalEvent, JournalQuery};
    use crate::storage::legacy::tests::write_legacy_ca;

    #[tokio::test]
    async fn the_first_key_creates_the_state_and_only_it_opens_it_after_a_restart() {
        let data = Folder::new();
        let key = encode_key(&generate_key().unwrap());

        let storage = SecureStorage::new(data.0.clone(), None);
        assert!(!storage.is_initialized());
        assert!(storage.lock().await.is_err());
        let (done, _) = storage.initialize(Some(&key)).await.unwrap();
        assert!(done.created && done.generated_key.is_none());
        assert_eq!((done.cas, done.imported), (0, None));
        assert!(storage.is_initialized() && storage.lock().await.is_ok());
        assert_eq!(
            storage.initialize(Some(&key)).await.unwrap_err(),
            InitializeError::AlreadyInitialized
        );

        // A restart: a new process knows nothing.
        let storage = SecureStorage::new(data.0.clone(), None);
        let other = encode_key(&generate_key().unwrap());
        assert_eq!(
            storage.initialize(Some(&other)).await.unwrap_err(),
            InitializeError::WrongKey
        );
        assert!(matches!(
            storage.initialize(None).await.unwrap_err(),
            InitializeError::BadKey(_)
        ));
        assert!(matches!(
            storage.initialize(Some("short")).await.unwrap_err(),
            InitializeError::BadKey(_)
        ));
        assert!(!storage.is_initialized());
        let (done, _) = storage.initialize(Some(&key)).await.unwrap();
        assert!(!done.created);

        let opened = storage.lock().await.unwrap();
        let events: Vec<JournalEvent> = opened
            .read_journal(&JournalQuery::default())
            .unwrap()
            .records
            .iter()
            .map(|r| r.event)
            .collect();
        assert_eq!(events, [JournalEvent::Unlocked, JournalEvent::Initialized]);
    }

    #[tokio::test]
    async fn the_encryption_key_is_changed_and_rolled_back_and_the_rollback_is_undone() {
        let data = Folder::new();
        let (old, new) = (generate_key().unwrap(), generate_key().unwrap());
        let (old_text, new_text) = (encode_key(&old), encode_key(&new));

        let storage = SecureStorage::new(data.0.clone(), None);
        storage.initialize(Some(&old_text)).await.unwrap();
        let mut opened = storage.lock().await.unwrap();
        let KeyChange::Changed { archive, rekeyed } = opened.change_key(&new).unwrap() else {
            panic!("not changed");
        };
        assert_eq!((rekeyed.records, rekeyed.pending), (1, None));
        assert_eq!(opened.encryption_key(), &new);
        assert_eq!(opened.change_key(&new).unwrap(), KeyChange::Unchanged);
        drop(opened);

        // After a restart only the new key opens the folder.
        let storage = SecureStorage::new(data.0.clone(), None);
        assert_eq!(
            storage.initialize(Some(&old_text)).await.unwrap_err(),
            InitializeError::WrongKey
        );
        storage.initialize(Some(&new_text)).await.unwrap();

        let mut opened = storage.lock().await.unwrap();
        assert_eq!(
            opened.roll_back(&new, None).unwrap_err(),
            RollBackError::NoArchiveOpens
        );
        assert_eq!(
            opened.roll_back(&old, Some("20000101000000")).unwrap_err(),
            RollBackError::NoSuchArchive
        );
        let rolled_back = opened.roll_back(&old, None).unwrap();
        assert_eq!(rolled_back.restored, archive);
        assert_eq!(opened.encryption_key(), &old);
        drop(opened);

        let storage = SecureStorage::new(data.0.clone(), None);
        assert_eq!(
            storage.initialize(Some(&new_text)).await.unwrap_err(),
            InitializeError::WrongKey
        );
        storage.initialize(Some(&old_text)).await.unwrap();

        // The rollback is undone the same way: its archive, with the new key.
        let mut opened = storage.lock().await.unwrap();
        let undone = opened.roll_back(&new, None).unwrap();
        assert_eq!(undone.restored, rolled_back.archive);
        assert_eq!(opened.encryption_key(), &new);
        let events: Vec<JournalEvent> = opened
            .read_journal(&JournalQuery::default())
            .unwrap()
            .records
            .iter()
            .map(|r| r.event)
            .collect();
        // The journal of the archive of the rollback: as it was then — created, and unlocked once
        // with the new key. The unlock with the old key since is in the folder it replaced.
        assert_eq!(events, [JournalEvent::Unlocked, JournalEvent::Initialized]);
    }

    #[tokio::test]
    async fn without_a_key_the_service_makes_one_and_tells_it_once() {
        let data = Folder::new();
        let storage = SecureStorage::new(data.0.clone(), None);
        let (done, key) = storage.initialize(None).await.unwrap();
        assert_eq!(done.generated_key, Some(encode_key(&key)));
        let again = SecureStorage::new(data.0.clone(), None);
        let (done, _) = again.initialize(done.generated_key.as_deref()).await.unwrap();
        assert!(!done.created && done.generated_key.is_none());
    }

    #[tokio::test]
    async fn the_plaintext_folder_is_imported_once_and_left_as_it_is() {
        let data = Folder::new();
        let legacy = Folder::new();
        write_legacy_ca(&legacy.0, "xfin-ca");
        let key = encode_key(&generate_key().unwrap());

        let storage = SecureStorage::new(data.0.clone(), Some(legacy.0.clone()));
        let (done, _) = storage.initialize(Some(&key)).await.unwrap();
        assert_eq!(done.imported, Some((1, 2)));
        assert_eq!((done.cas, done.certificates), (1, 2));
        assert!(storage.legacy_plaintext_left());
        let opened = storage.lock().await.unwrap();
        assert!(opened.state().cas["xfin-ca"].newest_active("alice@example.com").is_some());
        drop(opened);

        // Changed after the import: the state is not created again, so nothing is imported again.
        std::fs::remove_dir_all(format!("{}/xfin-ca", legacy.0)).unwrap();
        assert!(!storage.legacy_plaintext_left());
        let storage = SecureStorage::new(data.0.clone(), Some(legacy.0.clone()));
        let (done, _) = storage.initialize(Some(&key)).await.unwrap();
        assert_eq!((done.imported, done.cas), (None, 1));
    }

    #[tokio::test]
    async fn a_broken_plaintext_folder_creates_nothing() {
        let data = Folder::new();
        let legacy = Folder::new();
        write_legacy_ca(&legacy.0, "xfin-ca");
        std::fs::write(format!("{}/xfin-ca/index.json", legacy.0), "broken").unwrap();
        let storage = SecureStorage::new(data.0.clone(), Some(legacy.0.clone()));
        let key = encode_key(&generate_key().unwrap());
        assert!(matches!(
            storage.initialize(Some(&key)).await.unwrap_err(),
            InitializeError::Failed(_)
        ));
        assert!(!storage.is_initialized());
        assert!(!crate::storage::data_folder::DataFolder::has_state(&data.0));
    }
}
