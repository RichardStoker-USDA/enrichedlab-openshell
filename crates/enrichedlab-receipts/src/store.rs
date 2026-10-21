// SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
// SPDX-License-Identifier: Apache-2.0

//! The receipt store: one owner-only directory on a persistent volume, every file named by the
//! gateway's immutable sandbox id.
//!
//! ```text
//! <state>/starts/<sandbox id>.json             what the gateway committed; the first record is kept
//! <state>/observed/<sandbox id>.json           what Kubernetes showed, replaced atomically
//! <state>/receipts/<sandbox id>.json           the receipt, written once
//! <state>/receipts/<sandbox id>.json.sha256    its SHA-256
//! ```
//!
//! A sandbox id names a file only when it is 1 to 128 letters, digits, `-`, `_` or `.` and does not
//! start with a dot. At most 4,096 start and 4,096 observed records are kept at once, so a flood of
//! sandboxes cannot fill the volume through working records; receipts are the evidence and are kept.
//! Every file is mode 0600, every directory 0700, and every write is flushed and its directory synced
//! before it is reported.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

/// Working records of one kind kept at once.
pub const MAX_TRACKED: usize = 4096;
/// The largest record read back (a bounded receipt is far smaller).
const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;
/// The suffix of temporary files.
const TEMPORARY: &str = ".tmp";

/// Where a receipt is and the SHA-256 of its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenReceipt {
    pub path: PathBuf,
    pub sha256: String,
    /// False when the receipt already existed and was left as it was.
    pub new: bool,
}

/// Errors from the store. Paths are shown; contents never are.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("{0} is open to other users; the store needs mode 0700")]
    Permissions(PathBuf),
    #[error("sandbox id {0:?} cannot name a record")]
    SandboxId(String),
    #[error("{0} is in use by another instance of the service")]
    Locked(PathBuf),
    #[error("{0} records are kept already")]
    Full(&'static str),
    #[error("{0} cannot be read as a record")]
    Unreadable(PathBuf),
    #[error("{0} does not match its recorded SHA-256")]
    Digest(PathBuf),
    #[error("record cannot be encoded: {0}")]
    Encode(serde_json::Error),
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> StoreError + '_ {
    move |source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// A sandbox id names a file only when it is 1 to 128 characters of letters, digits, `-`, `_` and
/// `.` and does not start with a dot.
pub fn valid_sandbox_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('.')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// The receipt store rooted at one directory.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
    /// Held open, exclusively locked, for the life of every clone: one service instance per store.
    _lock: std::sync::Arc<File>,
}

impl Store {
    /// Opens (creating when absent) the store and its subdirectories, refusing a root that others can
    /// read or write.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        ensure_private_dir(&root)?;
        let lock = lock_store(&root)?;
        for sub in ["starts", "observed", "receipts"] {
            ensure_private_dir(&root.join(sub))?;
            remove_temporaries(&root.join(sub))?;
        }
        Ok(Self {
            root,
            _lock: std::sync::Arc::new(lock),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, kind: &str, id: &str) -> Result<PathBuf, StoreError> {
        if !valid_sandbox_id(id) {
            return Err(StoreError::SandboxId(id.to_string()));
        }
        Ok(self.root.join(kind).join(format!("{id}.json")))
    }

    fn count(&self, kind: &str) -> Result<usize, StoreError> {
        let dir = self.root.join(kind);
        Ok(fs::read_dir(&dir)
            .map_err(io_error(&dir))?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".json"))
            .count())
    }

    /// Keeps the first start record of a sandbox; false when one exists already.
    pub fn write_start<T: Serialize>(&self, id: &str, record: &T) -> Result<bool, StoreError> {
        let path = self.path("starts", id)?;
        if path.exists() {
            return Ok(false);
        }
        if self.count("starts")? >= MAX_TRACKED {
            return Err(StoreError::Full("start"));
        }
        let bytes = serde_json::to_vec_pretty(record).map_err(StoreError::Encode)?;
        publish_new(&path, &format!("{id}.json"), &bytes)
    }

    pub fn read_start<T: DeserializeOwned>(&self, id: &str) -> Result<Option<T>, StoreError> {
        read_record(&self.path("starts", id)?)
    }

    /// The sandbox ids with a start record, and when each was written.
    pub fn starts(&self) -> Result<Vec<(String, SystemTime)>, StoreError> {
        let dir = self.root.join("starts");
        let mut found = Vec::new();
        for entry in fs::read_dir(&dir)
            .map_err(io_error(&dir))?
            .filter_map(Result::ok)
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_suffix(".json")
                && valid_sandbox_id(id)
            {
                let modified = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                found.push((id.to_string(), modified));
            }
        }
        found.sort();
        Ok(found)
    }

    /// Replaces what was observed of a sandbox.
    pub fn write_observed<T: Serialize>(&self, id: &str, record: &T) -> Result<(), StoreError> {
        let path = self.path("observed", id)?;
        if !path.exists() && self.count("observed")? >= MAX_TRACKED {
            return Err(StoreError::Full("observed"));
        }
        let bytes = serde_json::to_vec_pretty(record).map_err(StoreError::Encode)?;
        replace_file(&path, &bytes)
    }

    pub fn read_observed<T: DeserializeOwned>(&self, id: &str) -> Result<Option<T>, StoreError> {
        read_record(&self.path("observed", id)?)
    }

    /// The sandbox ids with an observed record.
    pub fn observed(&self) -> Result<Vec<String>, StoreError> {
        let dir = self.root.join("observed");
        let mut ids: Vec<String> = fs::read_dir(&dir)
            .map_err(io_error(&dir))?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                name.strip_suffix(".json")
                    .filter(|id| valid_sandbox_id(id))
                    .map(str::to_string)
            })
            .collect();
        ids.sort();
        Ok(ids)
    }

    pub fn has_receipt(&self, id: &str) -> Result<bool, StoreError> {
        Ok(self.path("receipts", id)?.exists())
    }

    /// Writes the receipt of a sandbox once, with its SHA-256 beside it.
    ///
    /// The bytes go to a temporary file that is flushed first and then hard-linked to the receipt's
    /// name, so the name only ever holds a complete receipt and an existing one is never replaced. When
    /// the receipt exists already, it is checked (it parses, and its digest file, when present, matches)
    /// and its digest returned; a digest file missing after a crash between the two writes is written
    /// again from the receipt.
    pub fn write_receipt(&self, id: &str, bytes: &[u8]) -> Result<WrittenReceipt, StoreError> {
        let path = self.path("receipts", id)?;
        let sidecar = path.with_extension("json.sha256");
        if path.exists() {
            return existing_receipt(id, path, &sidecar);
        }
        if !publish_new(&path, &format!("{id}.json"), bytes)? {
            return existing_receipt(id, path, &sidecar);
        }
        let sha256 = hex(&Sha256::digest(bytes));
        replace_file(&sidecar, digest_line(&sha256, id).as_bytes())?;
        Ok(WrittenReceipt {
            path,
            sha256,
            new: true,
        })
    }

    /// Removes a sandbox's working records once its receipt holds them.
    pub fn retire(&self, id: &str) -> Result<(), StoreError> {
        for kind in ["starts", "observed"] {
            let path = self.path(kind, id)?;
            match fs::remove_file(&path) {
                Ok(()) => sync_dir(path.parent().unwrap_or(&self.root))?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(StoreError::Io {
                        path,
                        source: error,
                    });
                }
            }
        }
        Ok(())
    }
}

fn digest_line(sha256: &str, id: &str) -> String {
    format!("{sha256}  {id}.json\n")
}

/// Checks a receipt that already exists and returns its digest.
fn existing_receipt(id: &str, path: PathBuf, sidecar: &Path) -> Result<WrittenReceipt, StoreError> {
    let bytes = read_bounded(&path)?.ok_or_else(|| StoreError::Unreadable(path.clone()))?;
    if serde_json::from_slice::<serde::de::IgnoredAny>(&bytes).is_err() {
        return Err(StoreError::Unreadable(path));
    }
    let sha256 = hex(&Sha256::digest(&bytes));
    match fs::read_to_string(sidecar) {
        Ok(recorded) => {
            if recorded.split_whitespace().next() != Some(sha256.as_str()) {
                return Err(StoreError::Digest(path));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            replace_file(sidecar, digest_line(&sha256, id).as_bytes())?;
        }
        Err(error) => {
            return Err(StoreError::Io {
                path: sidecar.to_path_buf(),
                source: error,
            });
        }
    }
    Ok(WrittenReceipt {
        path,
        sha256,
        new: false,
    })
}

/// Reads a file of at most 4 MiB; `None` when it does not exist.
fn read_bounded(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(StoreError::Io {
                path: path.to_path_buf(),
                source: error,
            });
        }
    };
    let length = file.metadata().map_err(io_error(path))?.len();
    if length > MAX_RECORD_BYTES {
        return Err(StoreError::Unreadable(path.to_path_buf()));
    }
    fs::read(path).map(Some).map_err(io_error(path))
}

fn read_record<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, StoreError> {
    let Some(bytes) = read_bounded(path)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| StoreError::Unreadable(path.to_path_buf()))
}

fn ensure_private_dir(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() {
                return Err(StoreError::Io {
                    path: path.to_path_buf(),
                    source: io::Error::new(io::ErrorKind::InvalidInput, "not a directory"),
                });
            }
            let mode = metadata.permissions().mode();
            if mode & 0o007 != 0 {
                return Err(StoreError::Permissions(path.to_path_buf()));
            }
            // Kubernetes' fsGroup handling gives the Pod's own group access when it mounts the volume
            // again; take the directory back to owner-only.
            if mode & 0o7077 != 0 {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .map_err(io_error(path))?;
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(io_error(path))?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error(path))?;
            if let Some(parent) = path.parent() {
                sync_dir(parent)?;
            }
            Ok(())
        }
        Err(error) => Err(StoreError::Io {
            path: path.to_path_buf(),
            source: error,
        }),
    }
}

/// Writes `bytes` to a new file at `path` and flushes it; false when `path` already exists.
fn create_new_file(path: &Path, bytes: &[u8]) -> Result<bool, StoreError> {
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => {
            return Err(StoreError::Io {
                path: path.to_path_buf(),
                source: error,
            });
        }
    };
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(StoreError::Io {
            path: path.to_path_buf(),
            source: error,
        });
    }
    sync_dir(path.parent().unwrap_or_else(|| Path::new(".")))?;
    Ok(true)
}

/// Writes `bytes` to a new, flushed temporary file in `dir` named after `name`.
fn write_temporary(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, StoreError> {
    for attempt in 0..100u32 {
        let temp = dir.join(format!(
            ".{name}.{}.{attempt}{TEMPORARY}",
            std::process::id()
        ));
        if create_new_file(&temp, bytes)? {
            return Ok(temp);
        }
    }
    Err(StoreError::Io {
        path: dir.join(name),
        source: io::Error::new(io::ErrorKind::AlreadyExists, "no free temporary name"),
    })
}

/// Publishes `bytes` at `path` only when nothing is there: a flushed temporary file is hard-linked
/// to the name, so the name never holds a partial file. False when `path` exists.
fn publish_new(path: &Path, name: &str, bytes: &[u8]) -> Result<bool, StoreError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let temp = write_temporary(dir, name, bytes)?;
    let linked = fs::hard_link(&temp, path);
    let _ = fs::remove_file(&temp);
    match linked {
        Ok(()) => {
            sync_dir(dir)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(StoreError::Io {
            path: path.to_path_buf(),
            source: error,
        }),
    }
}

/// Replaces `path` with `bytes` through a new temporary file in the same directory.
fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = write_temporary(dir, &name, bytes)?;
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(StoreError::Io {
            path: path.to_path_buf(),
            source: error,
        });
    }
    sync_dir(dir)
}

/// Takes the store's exclusive lock, so a second instance (an overlapping replacement or a second
/// replica) refuses to start instead of racing this one's transitions.
fn lock_store(root: &Path) -> Result<File, StoreError> {
    let path = root.join(".lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(io_error(&path))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => Err(StoreError::Locked(root.to_path_buf())),
        Err(fs::TryLockError::Error(error)) => Err(StoreError::Io {
            path,
            source: error,
        }),
    }
}

/// Removes temporary files a crash left behind.
fn remove_temporaries(dir: &Path) -> Result<(), StoreError> {
    for entry in fs::read_dir(dir)
        .map_err(io_error(dir))?
        .filter_map(Result::ok)
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') && name.ends_with(TEMPORARY) {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    File::open(dir)
        .and_then(|file| file.sync_all())
        .map_err(io_error(dir))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde::Deserialize;

    pub fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "enrichedlab-receipts-test-{}",
            uuid::Uuid::new_v4()
        ))
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Record {
        n: u32,
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn creates_private_directories_and_refuses_an_open_root() {
        let root = temp_root();
        let store = Store::open(&root).unwrap();
        for sub in ["", "starts", "observed", "receipts"] {
            assert_eq!(mode(&store.root().join(sub)), 0o700, "{sub}");
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            Store::open(&root),
            Err(StoreError::Permissions(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn group_access_added_by_a_remount_is_taken_back() {
        let root = temp_root();
        drop(Store::open(&root).unwrap());
        for sub in ["", "starts", "observed", "receipts"] {
            fs::set_permissions(root.join(sub), fs::Permissions::from_mode(0o2770)).unwrap();
        }
        let store = Store::open(&root).unwrap();
        for sub in ["", "starts", "observed", "receipts"] {
            assert_eq!(mode(&store.root().join(sub)), 0o700, "{sub}");
        }
        drop(store);
        fs::set_permissions(root.join("receipts"), fs::Permissions::from_mode(0o705)).unwrap();
        assert!(
            matches!(Store::open(&root), Err(StoreError::Permissions(_))),
            "access for others is refused"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_second_instance_is_refused_until_the_first_is_gone() {
        let root = temp_root();
        let first = Store::open(&root).unwrap();
        let clone = first.clone();
        assert!(matches!(Store::open(&root), Err(StoreError::Locked(_))));
        drop(first);
        assert!(
            matches!(Store::open(&root), Err(StoreError::Locked(_))),
            "a clone still holds the lock"
        );
        drop(clone);
        Store::open(&root).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_first_start_is_kept() {
        let root = temp_root();
        let store = Store::open(&root).unwrap();
        assert!(store.write_start("a", &Record { n: 1 }).unwrap());
        assert!(!store.write_start("a", &Record { n: 2 }).unwrap());
        assert_eq!(
            store.read_start::<Record>("a").unwrap(),
            Some(Record { n: 1 })
        );
        assert_eq!(store.starts().unwrap().len(), 1);
        assert_eq!(mode(&root.join("starts/a.json")), 0o600);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn observed_records_replace_list_and_retire() {
        let root = temp_root();
        let store = Store::open(&root).unwrap();
        store.write_observed("a", &Record { n: 1 }).unwrap();
        store.write_observed("a", &Record { n: 2 }).unwrap();
        store.write_observed("b", &Record { n: 3 }).unwrap();
        assert_eq!(
            store.read_observed::<Record>("a").unwrap(),
            Some(Record { n: 2 })
        );
        assert_eq!(store.observed().unwrap(), vec!["a", "b"]);
        assert_eq!(
            fs::read_dir(root.join("observed")).unwrap().count(),
            2,
            "no temporary file left"
        );
        store.write_start("a", &Record { n: 9 }).unwrap();
        store.retire("a").unwrap();
        assert_eq!(store.read_observed::<Record>("a").unwrap(), None);
        assert_eq!(store.read_start::<Record>("a").unwrap(), None);
        store.retire("a").unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_unreadable_record_is_reported_not_parsed() {
        let root = temp_root();
        let store = Store::open(&root).unwrap();
        fs::write(root.join("observed/a.json"), b"not json").unwrap();
        assert!(matches!(
            store.read_observed::<Record>("a"),
            Err(StoreError::Unreadable(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_receipt_is_written_once_with_its_digest() {
        let root = temp_root();
        let store = Store::open(&root).unwrap();
        let first = store.write_receipt("a", b"{\"a\":1}").unwrap();
        assert!(first.new);
        assert_eq!(first.sha256, hex(&Sha256::digest(b"{\"a\":1}")));
        let again = store.write_receipt("a", b"{\"a\":2}").unwrap();
        assert!(!again.new);
        assert_eq!(again.sha256, first.sha256);
        assert_eq!(fs::read(&first.path).unwrap(), b"{\"a\":1}");
        assert!(store.has_receipt("a").unwrap());
        assert_eq!(mode(&first.path), 0o600);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_digest_missing_after_a_crash_is_rewritten_and_a_changed_receipt_is_refused() {
        let root = temp_root();
        let store = Store::open(&root).unwrap();
        let first = store.write_receipt("a", b"{\"a\":1}").unwrap();
        fs::remove_file(root.join("receipts/a.json.sha256")).unwrap();
        let again = store.write_receipt("a", b"{\"a\":2}").unwrap();
        assert_eq!(again.sha256, first.sha256);
        assert!(root.join("receipts/a.json.sha256").exists());
        fs::write(root.join("receipts/a.json.sha256"), "0000  a.json\n").unwrap();
        assert!(matches!(
            store.write_receipt("a", b"{}"),
            Err(StoreError::Digest(_))
        ));
        fs::write(root.join("receipts/b.json"), b"{\"partial").unwrap();
        assert!(matches!(
            store.write_receipt("b", b"{}"),
            Err(StoreError::Unreadable(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn temporaries_left_by_a_crash_are_removed_on_open() {
        let root = temp_root();
        Store::open(&root).unwrap();
        fs::write(root.join("receipts/.a.json.1.0.tmp"), b"{").unwrap();
        fs::write(root.join("starts/.a.json.1.0.tmp"), b"{").unwrap();
        let store = Store::open(&root).unwrap();
        assert_eq!(fs::read_dir(root.join("receipts")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(root.join("starts")).unwrap().count(), 0);
        assert!(store.starts().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn working_records_are_capped() {
        let root = temp_root();
        let store = Store::open(&root).unwrap();
        for i in 0..MAX_TRACKED {
            fs::write(root.join(format!("observed/x{i}.json")), b"{}").unwrap();
        }
        assert!(matches!(
            store.write_observed("new", &Record { n: 1 }),
            Err(StoreError::Full(_))
        ));
        store.write_observed("x0", &Record { n: 1 }).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sandbox_ids_cannot_escape_the_store() {
        let root = temp_root();
        let store = Store::open(&root).unwrap();
        for id in ["", "..", "../x", "a/b", ".hidden", &"x".repeat(129)] {
            assert!(
                matches!(
                    store.write_receipt(id, b"{}"),
                    Err(StoreError::SandboxId(_))
                ),
                "{id}"
            );
            assert!(
                matches!(
                    store.write_start(id, &Record { n: 1 }),
                    Err(StoreError::SandboxId(_))
                ),
                "{id}"
            );
        }
        assert!(valid_sandbox_id("4b1d2c3e-0000-4000-8000-000000000001"));
        fs::remove_dir_all(root).unwrap();
    }
}
