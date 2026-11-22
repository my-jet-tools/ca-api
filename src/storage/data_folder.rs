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
//!
//! - `archive/<YYYYMMDDhhmmss>/` — a copy of `state.enc` and the journal as they were before the
//!   key changed or a rollback replaced them ([`DataFolder::archive`]): still encrypted, with the
//!   key of that time, which alone opens it. A rollback puts one back ([`DataFolder::install`]).
//!
//! A new key re-encrypts everything ([`DataFolder::rekey`]); a rollback puts an archive back. Both
//! replace what is in the folder so that a crash at any moment loses nothing. The new journal is
//! first written next to the old one, as `journal.new`. Then `state.enc` is replaced atomically,
//! and that is the moment the key changes: the key that opens `state.enc` is the key. Last,
//! `journal.new` takes the place of `journal`. What a crash leaves halfway is finished — or
//! dropped — at the next unlock ([`DataFolder::finish_rekey`]), by whether `journal.new` opens
//! with the key that opened the state.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::journal::{year_month, JournalPage, JournalQuery, JournalRecord};
use super::state_model::{write_atomic, StateModel};
use crate::crypto::envelope::{Cipher, Key};

const STATE_FILE: &str = "state.enc";
const JOURNAL_DIR: &str = "journal";
/// The journal written again with a new key, until it takes the place of `journal`.
const JOURNAL_STAGED_DIR: &str = "journal.new";
/// The journal `journal.new` replaced, until it is deleted.
const JOURNAL_REPLACED_DIR: &str = "journal.old";
/// The copies of what the data folder held before the key changed or a rollback.
const ARCHIVE_DIR: &str = "archive";
const JOURNAL_EXT: &str = ".log";
const STATE_AAD: &str = "state";
const JOURNAL_AAD: &str = "journal";

/// What [`DataFolder::rekey`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Rekeyed {
    /// Journal lines encrypted again with the new key.
    pub records: usize,
    /// Journal lines that did not open with the old key: carried over as they were.
    pub unreadable: usize,
    /// Why `journal.new` could not take the place of the journal yet. The key is changed all the
    /// same; the next unlock puts it in place.
    pub pending: Option<String>,
}

/// Why an archive cannot be put back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    /// There is no archive with this id.
    NotFound,
    /// The key does not open the archive.
    WrongKey,
    /// None was named, and the key opens none of the archives.
    NoneOpens,
    Failed(String),
}

/// An archive the key opened, ready to be put back with [`DataFolder::install`].
pub struct OpenedArchive {
    id: String,
    dir: PathBuf,
    /// Its `state.enc`, as it is.
    envelope: String,
    state: StateModel,
    cipher: Cipher,
}

/// What [`DataFolder::roll_back`] did.
pub struct RolledBackFolder {
    /// The state of the archive put back.
    pub state: StateModel,
    /// The archive put back.
    pub restored: String,
    /// Where what was in place went.
    pub archive: String,
    /// Why the journal put back is not in place yet, if it is not.
    pub pending: Option<String>,
}

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
        save_state_with(&self.folder, &self.cipher, state)
    }

    /// A snapshot of everything with `new_key` — `state` and every line of the journal — that
    /// takes the place of what the folder held, and the key of the folder becomes `new_key`. An
    /// error means nothing changed: the folder keeps its key. A crash halfway loses nothing either
    /// (see the module). Archive first ([`Self::archive`]) to be able to roll back.
    pub fn rekey(&mut self, new_key: &Key, state: &StateModel) -> Result<Rekeyed, String> {
        let new_cipher = Cipher::new(new_key);
        let mut rekeyed =
            self.stage_journal(|staged| self.write_rekeyed_journal(staged, &new_cipher))?;
        if let Err(e) = save_state_with(&self.folder, &new_cipher, state) {
            let _ = remove_dir_if_exists(&self.folder.join(JOURNAL_STAGED_DIR));
            return Err(e);
        }
        // From here on the new key is the key: it is the one that opens `state.enc`.
        self.cipher = new_cipher;
        rekeyed.pending = self.put_staged_in_place().err();
        Ok(rekeyed)
    }

    /// Copy what the folder holds — `state.enc` and the journal, as they are, encrypted with the
    /// key — into `archive/<id>`, and return the id: the UTC time, `YYYYMMDDhhmmss` (and `-2`,
    /// `-3`… within one second). An archive is written whole or not at all.
    pub fn archive(&self) -> Result<String, String> {
        if self.folder.join(JOURNAL_STAGED_DIR).is_dir() {
            self.finish_rekey().map_err(|e| {
                format!("the journal of the last change is not in place yet, so it cannot be archived: {e}")
            })?;
        }
        let root = self.folder.join(ARCHIVE_DIR);
        std::fs::create_dir_all(&root)
            .map_err(|e| format!("{} cannot be created: {e}", root.display()))?;
        let id = new_archive_id(&root);
        let tmp = root.join(format!("{id}.tmp"));
        remove_dir_if_exists(&tmp)?;
        let result = self.write_archive(&tmp).and_then(|()| {
            std::fs::rename(&tmp, root.join(&id))
                .map_err(|e| format!("{} cannot be moved: {e}", tmp.display()))
        });
        if let Err(e) = result {
            let _ = remove_dir_if_exists(&tmp);
            return Err(e);
        }
        sync_dir(&root);
        Ok(id)
    }

    fn write_archive(&self, dir: &Path) -> Result<(), String> {
        let journal = dir.join(JOURNAL_DIR);
        std::fs::create_dir_all(&journal)
            .map_err(|e| format!("{} cannot be created: {e}", journal.display()))?;
        let state_path = self.folder.join(STATE_FILE);
        let state = std::fs::read(&state_path)
            .map_err(|e| format!("the state {} cannot be read: {e}", state_path.display()))?;
        write_atomic(&path_str(&dir.join(STATE_FILE)), &state)?;
        copy_journal(&self.folder.join(JOURNAL_DIR), &journal)?;
        sync_dir(&journal);
        sync_dir(dir);
        Ok(())
    }

    /// The ids of the archives, newest first.
    fn archives(&self) -> Result<Vec<String>, String> {
        let root = self.folder.join(ARCHIVE_DIR);
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("{} cannot be read: {e}", root.display())),
        };
        let mut ids: Vec<String> = entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_dir())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| is_archive_id(name))
            .collect();
        ids.sort_unstable_by(|a, b| archive_order(b).cmp(&archive_order(a)));
        Ok(ids)
    }

    /// The archive `id`, when `key` opens its state.
    pub fn open_archive(&self, id: &str, key: &Key) -> Result<OpenedArchive, ArchiveError> {
        let dir = self.archive_dir(id).ok_or(ArchiveError::NotFound)?;
        let path = dir.join(STATE_FILE);
        let envelope = std::fs::read_to_string(&path).map_err(|e| {
            ArchiveError::Failed(format!("the state {} cannot be read: {e}", path.display()))
        })?;
        let cipher = Cipher::new(key);
        let opened = cipher
            .open(&envelope, STATE_AAD)
            .map_err(|_| ArchiveError::WrongKey)?;
        let state = serde_json::from_slice(&opened).map_err(|e| {
            ArchiveError::Failed(format!("the state {} is invalid: {e}", path.display()))
        })?;
        Ok(OpenedArchive {
            id: id.to_string(),
            dir,
            envelope,
            state,
            cipher,
        })
    }

    /// Put `archived` back in the place of what the folder holds; its key becomes the key of the
    /// folder. Returns its state, and why its journal is not in place yet, if it is not (the next
    /// unlock puts it there). An error means nothing changed. Archive first to keep what is
    /// replaced.
    pub fn install(
        &mut self,
        archived: OpenedArchive,
    ) -> Result<(StateModel, Option<String>), String> {
        let source = archived.dir.join(JOURNAL_DIR);
        self.stage_journal(|staged| copy_journal(&source, staged))?;
        if let Err(e) = write_atomic(
            &path_str(&self.folder.join(STATE_FILE)),
            archived.envelope.as_bytes(),
        ) {
            let _ = remove_dir_if_exists(&self.folder.join(JOURNAL_STAGED_DIR));
            return Err(e);
        }
        // From here on the archive's key is the key: it is the one that opens `state.enc`.
        self.cipher = archived.cipher;
        let pending = self.put_staged_in_place().err();
        Ok((archived.state, pending))
    }

    /// Put the archive `archive` back — with none named, the newest archive `key` opens — after
    /// archiving what is in place under the key it has. `key` is the key of the folder from then
    /// on. An error means nothing changed.
    pub fn roll_back(
        &mut self,
        key: &Key,
        archive: Option<&str>,
    ) -> Result<RolledBackFolder, ArchiveError> {
        let archived = match archive {
            Some(id) => self.open_archive(id, key)?,
            None => self.newest_archive_opening(key)?,
        };
        let restored = archived.id.clone();
        let archive = self.archive().map_err(ArchiveError::Failed)?;
        let (state, pending) = self.install(archived).map_err(ArchiveError::Failed)?;
        Ok(RolledBackFolder {
            state,
            restored,
            archive,
            pending,
        })
    }

    fn newest_archive_opening(&self, key: &Key) -> Result<OpenedArchive, ArchiveError> {
        for id in self.archives().map_err(ArchiveError::Failed)? {
            match self.open_archive(&id, key) {
                Ok(archived) => return Ok(archived),
                Err(ArchiveError::WrongKey | ArchiveError::NotFound | ArchiveError::NoneOpens) => {}
                Err(failed @ ArchiveError::Failed(_)) => return Err(failed),
            }
        }
        Err(ArchiveError::NoneOpens)
    }

    fn archive_dir(&self, id: &str) -> Option<PathBuf> {
        if !is_archive_id(id) {
            return None;
        }
        let dir = self.folder.join(ARCHIVE_DIR).join(id);
        dir.is_dir().then_some(dir)
    }

    /// `journal.new`, written by `write`. On an error it is deleted.
    fn stage_journal<T>(
        &self,
        write: impl FnOnce(&Path) -> Result<T, String>,
    ) -> Result<T, String> {
        let staged = self.folder.join(JOURNAL_STAGED_DIR);
        remove_dir_if_exists(&staged)?;
        let result = std::fs::create_dir_all(&staged)
            .map_err(|e| format!("{} cannot be created: {e}", staged.display()))
            .and_then(|()| write(&staged));
        match result {
            Ok(done) => {
                sync_dir(&staged);
                Ok(done)
            }
            Err(e) => {
                let _ = remove_dir_if_exists(&staged);
                Err(e)
            }
        }
    }

    /// The journal written again into `staged` with `new`: every line that opens with the key,
    /// sealed again with `new`; a line that does not open is carried over as it is.
    fn write_rekeyed_journal(&self, staged: &Path, new: &Cipher) -> Result<Rekeyed, String> {
        let journal = self.folder.join(JOURNAL_DIR);
        let mut rekeyed = Rekeyed::default();
        for month in months_in(&journal)? {
            let file = format!("{month}{JOURNAL_EXT}");
            let content = read_journal_file(&journal.join(&file))?;
            let mut out = String::with_capacity(content.len());
            for line in content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
            {
                match self.cipher.open(line, JOURNAL_AAD) {
                    Ok(plain) => {
                        out.push_str(&new.seal(&plain, JOURNAL_AAD)?);
                        rekeyed.records += 1;
                    }
                    Err(_) => {
                        out.push_str(line);
                        rekeyed.unreadable += 1;
                    }
                }
                out.push('\n');
            }
            write_atomic(&path_str(&staged.join(&file)), out.as_bytes())?;
        }
        Ok(rekeyed)
    }

    /// What a change of the key left halfway, at an unlock: `journal.new` is put in the place of
    /// the journal when it opens with the key — then the state was committed with that key, and
    /// `journal.new` is the journal. When it does not open with the key, it is what is left of a
    /// change that never happened, and it is deleted. Doing it again changes nothing. Runs at
    /// every unlock, before the sweep.
    pub fn finish_rekey(&self) -> Result<(), String> {
        let staged = self.folder.join(JOURNAL_STAGED_DIR);
        if !staged.is_dir() {
            return Ok(());
        }
        if !self.any_line_opens(&staged)? {
            return remove_dir_if_exists(&staged);
        }
        self.put_staged_in_place()
    }

    /// Put `journal.new` in the place of the journal, once the state is committed with the key.
    /// The lines of the journal that open with the key — written after that commit — are carried
    /// into it first; a line it has already is not carried twice.
    fn put_staged_in_place(&self) -> Result<(), String> {
        let staged = self.folder.join(JOURNAL_STAGED_DIR);
        let journal = self.folder.join(JOURNAL_DIR);
        for month in months_in(&journal)? {
            let file = format!("{month}{JOURNAL_EXT}");
            let content = read_journal_file(&journal.join(&file))?;
            let written_after: Vec<&str> = content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && self.cipher.open(line, JOURNAL_AAD).is_ok())
                .collect();
            if written_after.is_empty() {
                continue;
            }
            let staged_file = staged.join(&file);
            let has: HashSet<String> = match std::fs::read_to_string(&staged_file) {
                Ok(content) => content
                    .lines()
                    .map(|line| line.trim().to_string())
                    .collect(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashSet::new(),
                Err(e) => return Err(format!("{} cannot be read: {e}", staged_file.display())),
            };
            let mut carried = String::new();
            for line in written_after
                .into_iter()
                .filter(|line| !has.contains(*line))
            {
                carried.push_str(line);
                carried.push('\n');
            }
            if !carried.is_empty() {
                append_private(&staged_file, carried.as_bytes())
                    .map_err(|e| format!("{} cannot be written: {e}", staged_file.display()))?;
            }
        }
        let replaced = self.folder.join(JOURNAL_REPLACED_DIR);
        remove_dir_if_exists(&replaced)?;
        if journal.exists() {
            std::fs::rename(&journal, &replaced)
                .map_err(|e| format!("{} cannot be moved: {e}", journal.display()))?;
        }
        std::fs::rename(&staged, &journal)
            .map_err(|e| format!("{} cannot be moved: {e}", staged.display()))?;
        sync_dir(&self.folder);
        // What it replaced is in it already; when it cannot be deleted now, the sweep does.
        let _ = remove_dir_if_exists(&replaced);
        Ok(())
    }

    /// Whether a line of the journal files in `dir` opens with the key.
    fn any_line_opens(&self, dir: &Path) -> Result<bool, String> {
        for month in months_in(dir)? {
            let content = read_journal_file(&dir.join(format!("{month}{JOURNAL_EXT}")))?;
            let opens = content
                .lines()
                .map(str::trim)
                .any(|line| !line.is_empty() && self.cipher.open(line, JOURNAL_AAD).is_ok());
            if opens {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Delete everything in the folder that is not the encrypted data: anything but `state.enc`,
    /// `journal/<yyyy-mm>.log`, `journal.new` (a journal of a change, which
    /// [`Self::finish_rekey`] could not put in place) and `archive/<id>/` — a leftover temporary
    /// file, a half-written archive, a plaintext copy, a key file. Symbolic links are deleted,
    /// never followed. Returns what was deleted, and what could not be.
    pub fn sweep(&self) -> Sweep {
        let mut sweep = Sweep::default();
        sweep_dir(&self.folder, &mut sweep, |name, is_dir| {
            name == STATE_FILE
                || (is_dir
                    && (name == JOURNAL_DIR || name == JOURNAL_STAGED_DIR || name == ARCHIVE_DIR))
        });
        sweep_dir(
            &self.folder.join(ARCHIVE_DIR),
            &mut sweep,
            |name, is_dir| is_dir && is_archive_id(name),
        );
        sweep_dir(
            &self.folder.join(JOURNAL_DIR),
            &mut sweep,
            |name, is_dir| !is_dir && name.strip_suffix(JOURNAL_EXT).is_some_and(is_month),
        );
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
        months_in(&self.folder.join(JOURNAL_DIR))
    }
}

/// The months there are journal files of in `dir`, newest first. A missing `dir` has none.
fn months_in(dir: &Path) -> Result<Vec<String>, String> {
    let entries = match std::fs::read_dir(dir) {
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

fn read_journal_file(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|e| format!("the journal {} cannot be read: {e}", path.display()))
}

fn save_state_with(folder: &Path, cipher: &Cipher, state: &StateModel) -> Result<(), String> {
    let json =
        serde_json::to_vec(state).map_err(|e| format!("the state cannot be written: {e}"))?;
    let envelope = cipher.seal(&json, STATE_AAD)?;
    write_atomic(&path_str(&folder.join(STATE_FILE)), envelope.as_bytes())
}

/// The journal files of `from` copied, as they are, into `to`.
fn copy_journal(from: &Path, to: &Path) -> Result<(), String> {
    for month in months_in(from)? {
        let file = format!("{month}{JOURNAL_EXT}");
        let content = std::fs::read(from.join(&file)).map_err(|e| {
            format!(
                "the journal {} cannot be read: {e}",
                from.join(&file).display()
            )
        })?;
        write_atomic(&path_str(&to.join(&file)), &content)?;
    }
    Ok(())
}

/// The length of an archive id without its `-<n>`: `YYYYMMDDhhmmss`.
const ARCHIVE_STAMP_LEN: usize = 14;

/// A new archive id in `root`: the UTC time, `YYYYMMDDhhmmss`, and `-2`, `-3`… when taken.
fn new_archive_id(root: &Path) -> String {
    let now = time::OffsetDateTime::now_utc();
    let stamp = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let taken = |id: &str| root.join(id).exists() || root.join(format!("{id}.tmp")).exists();
    let mut id = stamp.clone();
    let mut n = 2u32;
    while taken(&id) {
        id = format!("{stamp}-{n}");
        n += 1;
    }
    id
}

/// `YYYYMMDDhhmmss`, or that and `-<n>`.
fn is_archive_id(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    if bytes.len() < ARCHIVE_STAMP_LEN || !bytes[..ARCHIVE_STAMP_LEN].iter().all(u8::is_ascii_digit)
    {
        return false;
    }
    let rest = &bytes[ARCHIVE_STAMP_LEN..];
    rest.is_empty()
        || (rest.len() >= 2 && rest[0] == b'-' && rest[1..].iter().all(u8::is_ascii_digit))
}

/// What archive ids are ordered by: the time, then the `-<n>` of the same second.
fn archive_order(id: &str) -> (&str, u64) {
    let (stamp, n) = id.split_at(ARCHIVE_STAMP_LEN);
    (stamp, n.trim_start_matches('-').parse().unwrap_or(1))
}

fn remove_dir_if_exists(dir: &Path) -> Result<(), String> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{} cannot be deleted: {e}", dir.display())),
    }
}

/// Make the files written and moved in `dir` stay after a power cut, as far as the system lets.
fn sync_dir(dir: &Path) {
    if let Ok(dir) = std::fs::File::open(dir) {
        let _ = dir.sync_all();
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

    use super::{append_private, save_state_with, ArchiveError, DataFolder, UnlockError};
    use crate::crypto::envelope::{generate_key, Cipher};
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

    fn record(at: u64) -> JournalRecord {
        let mut record = JournalRecord::new(JournalEvent::CertIssued, at);
        record.ca = Some("xfin-ca".to_string());
        record
    }

    fn journal_ats(data: &DataFolder) -> (Vec<u64>, usize) {
        let page = data.read_journal(&JournalQuery::default()).unwrap();
        (page.records.iter().map(|r| r.at).collect(), page.unreadable)
    }

    // 2025-10-31 23:00, 2025-11-15 10:00, 2025-11-15 11:00 UTC.
    const OCT: u64 = 1_761_951_600;
    const NOV: u64 = 1_763_200_800;
    const NOV_LATER: u64 = 1_763_204_400;

    #[test]
    fn a_new_key_archives_the_folder_and_takes_its_place_with_a_snapshot() {
        let folder = Folder::new();
        let (old, new) = (generate_key().unwrap(), generate_key().unwrap());
        let mut data = DataFolder::create(&folder.0, &old, &state()).unwrap();
        for at in [OCT, NOV, NOV_LATER] {
            data.append(&record(at)).unwrap();
        }
        let november = format!("{}/journal/2025-11.log", folder.0);
        let mut content = std::fs::read_to_string(&november).unwrap();
        content.push_str("garbage\n");
        std::fs::write(&november, content).unwrap();

        let archive = data.archive().unwrap();
        assert!(
            archive.len() == 14 && archive.bytes().all(|b| b.is_ascii_digit()),
            "{archive}"
        );
        let done = data.rekey(&new, &state()).unwrap();
        assert_eq!((done.records, done.unreadable, done.pending), (3, 1, None));

        // The folder: only the new key opens it, with everything in it.
        assert_eq!(
            DataFolder::unlock(&folder.0, &old).err(),
            Some(UnlockError::WrongKey)
        );
        let (unlocked, loaded) = DataFolder::unlock(&folder.0, &new).unwrap();
        assert_eq!(loaded, state());
        assert_eq!(journal_ats(&unlocked), (vec![NOV_LATER, NOV, OCT], 1));
        data.append(&record(NOV_LATER + 1)).unwrap();
        assert_eq!(journal_ats(&unlocked).0.len(), 4);

        // The archive: what it was, with the old key only.
        assert_eq!(data.open_archive(&archive, &old).unwrap().state, state());
        assert!(matches!(
            data.open_archive(&archive, &new),
            Err(ArchiveError::WrongKey)
        ));
        for unknown in ["20000101000000", "../journal", "", "archive"] {
            assert!(
                matches!(
                    data.open_archive(unknown, &old),
                    Err(ArchiveError::NotFound)
                ),
                "{unknown}"
            );
        }

        let mut left = walk(&folder.0);
        left.sort();
        let a = format!("archive/{archive}");
        assert_eq!(
            left,
            [
                format!("{a}/journal/2025-10.log"),
                format!("{a}/journal/2025-11.log"),
                format!("{a}/state.enc"),
                "journal/2025-10.log".to_string(),
                "journal/2025-11.log".to_string(),
                "state.enc".to_string(),
            ]
        );
        // The sweep keeps the archives, and drops a half-written one.
        std::fs::create_dir_all(format!("{}/archive/{archive}-9.tmp", folder.0)).unwrap();
        let sweep = data.sweep();
        assert_eq!(sweep.deleted.len(), 1, "{:?}", sweep.deleted);
        assert_eq!(walk(&folder.0).len(), 6);

        // Archives: newest first, a second one within the second is `-2`.
        let second = data.archive().unwrap();
        assert!(
            second == format!("{archive}-2") || second > archive,
            "{second}"
        );
        assert_eq!(data.archives().unwrap(), [second, archive]);
    }

    #[test]
    fn a_rollback_puts_back_the_archive_its_key_opens() {
        let folder = Folder::new();
        let (first, second, third) = (
            generate_key().unwrap(),
            generate_key().unwrap(),
            generate_key().unwrap(),
        );
        let mut data = DataFolder::create(&folder.0, &first, &state()).unwrap();
        data.append(&record(OCT)).unwrap();
        let under_first = data.archive().unwrap();
        data.rekey(&second, &StateModel::default()).unwrap();
        data.append(&record(NOV)).unwrap();
        let under_second = data.archive().unwrap();
        data.rekey(&third, &StateModel::default()).unwrap();

        assert!(matches!(
            data.roll_back(&first, Some("20000101000000")),
            Err(ArchiveError::NotFound)
        ));
        assert!(matches!(
            data.roll_back(&first, Some(&under_second)),
            Err(ArchiveError::WrongKey)
        ));
        assert!(matches!(
            data.roll_back(&generate_key().unwrap(), None),
            Err(ArchiveError::NoneOpens)
        ));

        // None named: the newest archive the key opens — under_first, though under_second is
        // newer.
        let rolled = data.roll_back(&first, None).unwrap();
        assert_eq!(
            (rolled.restored.as_str(), rolled.state, rolled.pending),
            (under_first.as_str(), state(), None)
        );
        let (unlocked, _) = DataFolder::unlock(&folder.0, &first).unwrap();
        assert_eq!(journal_ats(&unlocked), (vec![OCT], 0));
        // What was in place is archived under the key it had: the third.
        assert!(data.open_archive(&rolled.archive, &third).is_ok());
        assert!(data.open_archive(&rolled.archive, &first).is_err());
    }

    #[test]
    fn an_archive_put_back_brings_back_its_key_and_its_journal() {
        let folder = Folder::new();
        let (old, new) = (generate_key().unwrap(), generate_key().unwrap());
        let mut data = DataFolder::create(&folder.0, &old, &state()).unwrap();
        data.append(&record(OCT)).unwrap();
        let archive = data.archive().unwrap();
        data.rekey(&new, &StateModel::default()).unwrap();
        data.append(&record(NOV)).unwrap();

        let archived = data.open_archive(&archive, &old).unwrap();
        let (restored, pending) = data.install(archived).unwrap();
        assert_eq!((restored, pending), (state(), None));
        assert_eq!(
            DataFolder::unlock(&folder.0, &new).err(),
            Some(UnlockError::WrongKey)
        );
        let (unlocked, loaded) = DataFolder::unlock(&folder.0, &old).unwrap();
        assert_eq!(loaded, state());
        assert_eq!(journal_ats(&unlocked), (vec![OCT], 0));
        // The folder writes with the archive's key from now on.
        data.append(&record(NOV_LATER)).unwrap();
        assert_eq!(journal_ats(&unlocked), (vec![NOV_LATER, OCT], 0));
    }

    #[test]
    fn a_change_that_never_committed_is_dropped_at_unlock() {
        let folder = Folder::new();
        let (old, new) = (generate_key().unwrap(), generate_key().unwrap());
        let data = DataFolder::create(&folder.0, &old, &state()).unwrap();
        data.append(&record(OCT)).unwrap();
        data.append(&record(NOV)).unwrap();
        // The process stops after writing journal.new, before `state.enc`.
        let new_cipher = Cipher::new(&new);
        data.stage_journal(|staged| data.write_rekeyed_journal(staged, &new_cipher))
            .unwrap();
        assert!(std::path::Path::new(&format!("{}/journal.new", folder.0)).is_dir());

        let (unlocked, _) = DataFolder::unlock(&folder.0, &old).unwrap();
        unlocked.finish_rekey().unwrap();
        assert!(!std::path::Path::new(&format!("{}/journal.new", folder.0)).exists());
        assert_eq!(journal_ats(&unlocked), (vec![NOV, OCT], 0));
    }

    #[test]
    fn a_change_that_committed_is_finished_at_unlock_losing_and_doubling_nothing() {
        let folder = Folder::new();
        let (old, new) = (generate_key().unwrap(), generate_key().unwrap());
        let data = DataFolder::create(&folder.0, &old, &state()).unwrap();
        data.append(&record(OCT)).unwrap();
        data.append(&record(NOV)).unwrap();
        let new_cipher = Cipher::new(&new);
        data.stage_journal(|staged| data.write_rekeyed_journal(staged, &new_cipher))
            .unwrap();
        save_state_with(&data.folder, &new_cipher, &state()).unwrap();
        // The new key is the key now, but journal.new is not in place: a record written since
        // went to the old journal folder — and one of them was carried already.
        DataFolder::with_key(&folder.0, &new)
            .append(&record(NOV_LATER))
            .unwrap();
        let november =
            std::fs::read_to_string(format!("{}/journal/2025-11.log", folder.0)).unwrap();
        let written_after = november.lines().last().unwrap();
        append_private(
            std::path::Path::new(&format!("{}/journal.new/2025-11.log", folder.0)),
            format!("{written_after}\n").as_bytes(),
        )
        .unwrap();

        let (unlocked, _) = DataFolder::unlock(&folder.0, &new).unwrap();
        unlocked.finish_rekey().unwrap();
        assert_eq!(journal_ats(&unlocked), (vec![NOV_LATER, NOV, OCT], 0));
        unlocked.finish_rekey().unwrap();
        assert_eq!(journal_ats(&unlocked), (vec![NOV_LATER, NOV, OCT], 0));
        let mut left = walk(&folder.0);
        left.sort();
        assert_eq!(
            left,
            ["journal/2025-10.log", "journal/2025-11.log", "state.enc"]
        );
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
