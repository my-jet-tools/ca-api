//! The data folder (`data_folder` of the settings) — the only place ca-api keeps anything, and all
//! of it encrypted with the key ([`crate::crypto::envelope`]):
//!
//! - `state.enc` — the state ([`super::StateModel`]) as JSON in one envelope with the AAD `state`;
//! - `journal/<yyyy-mm>.log` — the journal ([`super::journal`]) of a UTC month: one envelope per
//!   line, each one record as JSON, with the AAD `journal`.
//!
//! The key is never written anywhere: it is handed to the service by `POST /api/initialize` and
//! lives in its memory. A key is the right one when it opens `state.enc`. Once it has, everything
//! else in the folder is deleted ([`DataFolder::sweep`]), so nothing readable stays on the disk.
//!
//! Every file is readable by its owner only (`0600`); the state is written atomically, journal
//! lines are appended.

use std::io::Write;
use std::path::{Path, PathBuf};

use super::journal::{year_month, JournalPage, JournalQuery, JournalRecord};
use super::state_model::{write_atomic, StateModel};
use crate::crypto::envelope::{Cipher, Key};

const STATE_FILE: &str = "state.enc";
const JOURNAL_DIR: &str = "journal";
const JOURNAL_EXT: &str = ".log";
const STATE_AAD: &str = "state";
const JOURNAL_AAD: &str = "journal";

/// Why a key did not open the data folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockError {
    /// The key does not open the state: another key — or the file was changed.
    WrongKey,
    Failed(String),
}

/// An opened data folder: its path and the key, in memory.
pub struct DataFolder {
    folder: PathBuf,
    cipher: Cipher,
}

impl DataFolder {
    /// Whether the data folder at `folder` has a state — then only the key that opens it opens
    /// the folder.
    pub fn has_state(folder: &str) -> bool {
        Path::new(folder).join(STATE_FILE).exists()
    }

    /// The data folder at `folder` and its state — when `key` opens the state.
    pub fn unlock(folder: &str, key: &Key) -> Result<(Self, StateModel), UnlockError> {
        let data_folder = Self::with_key(folder, key);
        let path = data_folder.folder.join(STATE_FILE);
        let envelope = std::fs::read_to_string(&path).map_err(|e| {
            UnlockError::Failed(format!("the state {} cannot be read: {e}", path.display()))
        })?;
        let opened = data_folder
            .cipher
            .open(&envelope, STATE_AAD)
            .map_err(|_| UnlockError::WrongKey)?;
        let state = serde_json::from_slice(&opened).map_err(|e| {
            UnlockError::Failed(format!("the state {} is invalid: {e}", path.display()))
        })?;
        Ok((data_folder, state))
    }

    /// A new data folder at `folder`, with `state` encrypted with `key`. A folder that has a state
    /// already is an error: it is opened with its key, never replaced.
    pub fn create(folder: &str, key: &Key, state: &StateModel) -> Result<Self, String> {
        if Self::has_state(folder) {
            return Err(format!("the data folder {folder} has a state already"));
        }
        std::fs::create_dir_all(folder)
            .map_err(|e| format!("the data folder {folder} cannot be created: {e}"))?;
        let data_folder = Self::with_key(folder, key);
        data_folder.save_state(state)?;
        Ok(data_folder)
    }

    fn with_key(folder: &str, key: &Key) -> Self {
        Self {
            folder: PathBuf::from(folder),
            cipher: Cipher::new(key),
        }
    }

    pub fn save_state(&self, state: &StateModel) -> Result<(), String> {
        let json =
            serde_json::to_vec(state).map_err(|e| format!("the state cannot be written: {e}"))?;
        let envelope = self.cipher.seal(&json, STATE_AAD)?;
        write_atomic(&path_str(&self.folder.join(STATE_FILE)), envelope.as_bytes())
    }

    /// Delete everything in the folder that is not the encrypted data: anything but `state.enc`
    /// and `journal/<yyyy-mm>.log` — a leftover temporary file, a plaintext copy, a key file.
    /// Symbolic links are deleted, never followed. Returns what was deleted, and what could not be.
    pub fn sweep(&self) -> Sweep {
        let mut sweep = Sweep::default();
        sweep_dir(&self.folder, &mut sweep, |name, is_dir| {
            name == STATE_FILE || (is_dir && name == JOURNAL_DIR)
        });
        sweep_dir(&self.folder.join(JOURNAL_DIR), &mut sweep, |name, is_dir| {
            !is_dir && name.strip_suffix(JOURNAL_EXT).is_some_and(is_month)
        });
        sweep
    }

    /// Append `record` to the journal of its month.
    pub fn append(&self, record: &JournalRecord) -> Result<(), String> {
        let dir = self.folder.join(JOURNAL_DIR);
        std::fs::create_dir_all(&dir).map_err(|e| {
            format!("the journal folder {} cannot be created: {e}", dir.display())
        })?;
        let path = dir.join(format!("{}{JOURNAL_EXT}", year_month(record.at)));
        let json = serde_json::to_vec(record)
            .map_err(|e| format!("a journal record cannot be written: {e}"))?;
        let mut line = self.cipher.seal(&json, JOURNAL_AAD)?;
        line.push('\n');
        append_private(&path, line.as_bytes())
            .map_err(|e| format!("the journal {} cannot be written: {e}", path.display()))
    }

    /// The records `query` asks for, newest first.
    pub fn read_journal(&self, query: &JournalQuery) -> Result<JournalPage, String> {
        let limit = query.limit();
        let from_month = query.from.map(year_month);
        // `to` is not included: the month of the second before it is the last one.
        let to_month = query.to.map(|to| year_month(to.saturating_sub(1)));
        let mut page = JournalPage::default();
        for month in self.journal_months()? {
            if to_month.as_ref().is_some_and(|to| month > *to) {
                continue;
            }
            if from_month.as_ref().is_some_and(|from| month < *from) {
                break;
            }
            let path = self
                .folder
                .join(JOURNAL_DIR)
                .join(format!("{month}{JOURNAL_EXT}"));
            let content = std::fs::read_to_string(&path)
                .map_err(|e| format!("the journal {} cannot be read: {e}", path.display()))?;
            for line in content.lines().rev().filter(|line| !line.trim().is_empty()) {
                let record = self
                    .cipher
                    .open(line, JOURNAL_AAD)
                    .ok()
                    .and_then(|opened| serde_json::from_slice::<JournalRecord>(&opened).ok());
                let Some(record) = record else {
                    page.unreadable += 1;
                    continue;
                };
                if record.matches(query) {
                    page.records.push(record);
                    if page.records.len() >= limit {
                        return Ok(page);
                    }
                }
            }
        }
        Ok(page)
    }

    /// The months there are journal files of, newest first.
    fn journal_months(&self) -> Result<Vec<String>, String> {
        let dir = self.folder.join(JOURNAL_DIR);
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(format!(
                    "the journal folder {} cannot be read: {e}",
                    dir.display()
                ))
            }
        };
        let mut months: Vec<String> = entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().to_string();
                let month = name.strip_suffix(JOURNAL_EXT)?;
                is_month(month).then(|| month.to_string())
            })
            .collect();
        months.sort_unstable_by(|a, b| b.cmp(a));
        Ok(months)
    }
}

/// What [`DataFolder::sweep`] did: the paths it deleted, and those it could not, with why.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Sweep {
    pub deleted: Vec<String>,
    pub failed: Vec<String>,
}

/// Delete every entry of `dir` that `keep(name, is_dir)` does not keep. A missing `dir` is
/// nothing to do.
fn sweep_dir(dir: &Path, sweep: &mut Sweep, keep: impl Fn(&str, bool) -> bool) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(|entry| entry.ok()) {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        // Not following a symbolic link: the link is what is deleted.
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if keep(&name, metadata.is_dir()) {
            continue;
        }
        let removed = if metadata.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match removed {
            Ok(()) => sweep.deleted.push(path_str(&path)),
            Err(e) => sweep.failed.push(format!("{}: {e}", path.display())),
        }
    }
}

/// `yyyy-mm`.
fn is_month(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.len() == 7
        && bytes[4] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || b.is_ascii_digit())
}

fn path_str(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn append_private(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(content)?;
    file.sync_data()
}

#[cfg(test)]
pub mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{DataFolder, UnlockError};
    use crate::crypto::envelope::generate_key;
    use crate::storage::journal::{JournalEvent, JournalQuery, JournalRecord};
    use crate::storage::state_model::{CaModel, StateModel};

    /// A folder in the temp directory no other test uses; not created.
    pub fn temp_folder() -> String {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir()
            .join(format!("ca-api-test-data-{}-{n}", std::process::id()))
            .to_string_lossy()
            .to_string()
    }

    /// Deletes the folder when dropped.
    pub struct Folder(pub String);

    impl Folder {
        pub fn new() -> Self {
            Self(temp_folder())
        }
    }

    impl Drop for Folder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn state() -> StateModel {
        let mut state = StateModel::default();
        state.cas.insert(
            "xfin-ca".to_string(),
            CaModel::new("CERTIFICATE-PEM".to_string(), "PRIVATE-KEY-PEM".to_string()),
        );
        state
    }

    #[test]
    fn the_key_that_opens_the_state_opens_the_folder_and_is_never_written() {
        let folder = Folder::new();
        assert!(!DataFolder::has_state(&folder.0));
        let key = generate_key().unwrap();
        let created = DataFolder::create(&folder.0, &key, &StateModel::default()).unwrap();
        assert!(DataFolder::has_state(&folder.0));
        let again = DataFolder::create(&folder.0, &key, &StateModel::default())
            .err()
            .unwrap();
        assert!(again.contains("has a state already"), "{again}");
        created.save_state(&state()).unwrap();

        let (_, loaded) = DataFolder::unlock(&folder.0, &key).unwrap();
        assert_eq!(loaded, state());
        assert_eq!(
            DataFolder::unlock(&folder.0, &generate_key().unwrap()).err(),
            Some(UnlockError::WrongKey)
        );

        // Nothing but the encrypted state is on the disk: no key, no plain text.
        let names: Vec<String> = std::fs::read_dir(&folder.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, ["state.enc"]);
        let on_disk = std::fs::read_to_string(format!("{}/state.enc", folder.0)).unwrap();
        assert!(
            !on_disk.contains("xfin-ca") && !on_disk.contains("PRIVATE-KEY"),
            "{on_disk}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(format!("{}/state.enc", folder.0))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn the_sweep_leaves_only_the_encrypted_data() {
        let folder = Folder::new();
        let data =
            DataFolder::create(&folder.0, &generate_key().unwrap(), &StateModel::default())
                .unwrap();
        data.append(&JournalRecord::new(JournalEvent::Initialized, 1_763_200_800))
            .unwrap();
        let f = &folder.0;
        std::fs::write(format!("{f}/state.enc.tmp"), "x").unwrap();
        std::fs::create_dir_all(format!("{f}/xfin-ca/certs")).unwrap();
        std::fs::write(format!("{f}/xfin-ca/ca_private_key.pem"), "x").unwrap();
        std::fs::write(format!("{f}/journal/notes.txt"), "x").unwrap();
        // A link to something outside: the link goes, what it points at stays.
        let outside = Folder::new();
        std::fs::create_dir_all(&outside.0).unwrap();
        std::fs::write(format!("{}/keep.txt", outside.0), "x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside.0, format!("{f}/link")).unwrap();

        let sweep = data.sweep();
        assert!(sweep.failed.is_empty(), "{:?}", sweep.failed);
        let mut left = walk(f);
        left.sort();
        assert_eq!(left, ["journal/2025-11.log", "state.enc"]);
        assert!(std::path::Path::new(&format!("{}/keep.txt", outside.0)).exists());
        assert!(data.sweep().deleted.is_empty());
    }

    /// The files under `root`, relative to it.
    fn walk(root: &str) -> Vec<String> {
        let mut files = Vec::new();
        let mut dirs = vec![std::path::PathBuf::from(root)];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                } else {
                    files.push(path.strip_prefix(root).unwrap().to_string_lossy().to_string());
                }
            }
        }
        files
    }

    #[test]
    fn the_journal_is_read_newest_first_across_months() {
        let folder = Folder::new();
        let data =
            DataFolder::create(&folder.0, &generate_key().unwrap(), &StateModel::default())
                .unwrap();
        // 2025-10-31 23:00, 2025-11-15 10:00, 2025-11-15 11:00, 2025-12-01 00:00.
        let times = [1_761_951_600u64, 1_763_200_800, 1_763_204_400, 1_764_547_200];
        for (i, at) in times.iter().enumerate() {
            let mut record = JournalRecord::new(JournalEvent::CertIssued, *at);
            record.ca = Some(if i % 2 == 0 { "a" } else { "b" }.to_string());
            data.append(&record).unwrap();
        }
        let at = |page: crate::storage::journal::JournalPage| {
            page.records.iter().map(|r| r.at).collect::<Vec<_>>()
        };
        let all = JournalQuery::default();
        assert_eq!(
            at(data.read_journal(&all).unwrap()),
            [times[3], times[2], times[1], times[0]]
        );
        assert_eq!(
            at(data
                .read_journal(&JournalQuery { limit: Some(2), ..all.clone() })
                .unwrap()),
            [times[3], times[2]]
        );
        let november = JournalQuery {
            from: Some(times[1]),
            to: Some(times[3]),
            ..all.clone()
        };
        assert_eq!(at(data.read_journal(&november).unwrap()), [times[2], times[1]]);
        let of_a = JournalQuery {
            ca: Some("a".to_string()),
            ..all.clone()
        };
        assert_eq!(at(data.read_journal(&of_a).unwrap()), [times[2], times[0]]);

        // A line that does not open is passed over and counted.
        let path = format!("{}/journal/2025-11.log", folder.0);
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str("garbage\n");
        std::fs::write(&path, content).unwrap();
        let page = data.read_journal(&all).unwrap();
        assert_eq!(page.records.len(), 4);
        assert_eq!(page.unreadable, 1);
    }
}
