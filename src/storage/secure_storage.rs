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

use super::data_folder::{DataFolder, UnlockError};
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

    /// Whether `key` is the key the data folder is encrypted with.
    pub fn is_files_key(&self, key: &Key) -> bool {
        self.key == *key
    }
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

    /// Hand the service its key (base64 of 32 bytes), once per start. Returns what was done, and
    /// the key — for the encrypted calls.
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

        let (data_folder, state, key, created, generated_key, imported) =
            if DataFolder::has_state(folder) {
                let Some(key_text) = key_text else {
                    return Err(InitializeError::BadKey(
                        "the data folder has a state: the key that opens it is needed".to_string(),
                    ));
                };
                let key = envelope::decode_key(key_text).map_err(InitializeError::BadKey)?;
                let (data_folder, state) =
                    DataFolder::unlock(folder, &key).map_err(|e| match e {
                        UnlockError::WrongKey => InitializeError::WrongKey,
                        UnlockError::Failed(e) => InitializeError::Failed(e),
                    })?;
                data_folder.append_or_warn(JournalRecord::new(JournalEvent::Unlocked, unix_now()));
                (data_folder, state, key, false, None, None)
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
                (data_folder, state, key, true, generated_key, imported)
            };

        let sweep = data_folder.sweep();
        for failed in &sweep.failed {
            crate::log::warn(format!(
                "Not deleted from the data folder, as not encrypted: {failed}"
            ));
        }

        let done = Initialized {
            created,
            generated_key,
            cas: state.cas.len(),
            certificates: state.cas.values().map(|ca| ca.certificates.len()).sum(),
            imported,
            network_key: state.network_key.is_some(),
            deleted: sweep.deleted,
        };
        *opened = Some(Opened {
            folder: data_folder,
            key,
            state,
        });
        self.initialized.store(true, Ordering::SeqCst);
        Ok((done, key))
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
    use super::{InitializeError, SecureStorage};
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
