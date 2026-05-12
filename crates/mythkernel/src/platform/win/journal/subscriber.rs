//! `JournalSubscriber` — vendored from Sourcerer.
//!
//! `open()` queries the volume's USN journal and loads a persisted cursor.
//! `bootstrap()` walks the entire MFT once via `FSCTL_ENUM_USN_DATA` and emits
//! synthetic `Create` events. `subscribe()` loops `FSCTL_READ_USN_JOURNAL`
//! and emits classified, settled events.
//!
//! Both streams resolve every event's full path via the FRN cache populated
//! during bootstrap and refreshed on Create.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use futures::Stream;
use futures::channel::mpsc;

use super::cursor::VolumeCursor;
use super::event::{JournalError, JournalEvent};
use super::ffi::{
    JournalState, ParsedUsnRecord, UsnRecordIter, VolumeHandle, enum_usn_data, query_usn_journal,
    read_usn_journal, resolve_path_by_frn, volume_info,
};
use super::reasons::{ReasonKind, classify};

/// Per-volume subscriber. Cheap to hold; expensive operations only happen
/// when the caller asks for a stream.
pub struct JournalSubscriber {
    volume_root: PathBuf,
    journal: JournalState,
    cursor_root: PathBuf,
    cursor: Arc<Mutex<VolumeCursor>>,
    cache: PathCache,
}

impl JournalSubscriber {
    pub fn volume_root(&self) -> &Path {
        &self.volume_root
    }

    pub fn journal_state(&self) -> JournalState {
        self.journal
    }

    pub fn cursor(&self) -> VolumeCursor {
        self.cursor.lock().expect("cursor mutex poisoned").clone()
    }
}

/// Opens the USN journal on `volume`. The path must be a Windows drive root
/// like `C:\` or `D:\`.
pub fn open(volume: &Path) -> Result<JournalSubscriber, JournalError> {
    open_with_cursor_root(volume, &VolumeCursor::default_root())
}

/// `open()` variant that lets tests redirect cursor persistence to a
/// scratch directory.
pub fn open_with_cursor_root(
    volume: &Path,
    cursor_root: &Path,
) -> Result<JournalSubscriber, JournalError> {
    let info =
        volume_info(volume).map_err(|e| JournalError::OpenVolume(volume.to_path_buf(), e))?;
    let handle = VolumeHandle::open(volume)
        .map_err(|e| JournalError::OpenVolume(volume.to_path_buf(), e))?;
    let journal = query_usn_journal(&handle).map_err(JournalError::QueryJournal)?;

    let persisted = VolumeCursor::load(cursor_root, info.serial)?;
    let cursor = match persisted {
        Some(c) if c.journal_id == journal.journal_id => c,
        Some(stale) => {
            tracing::info!(
                volume = %volume.display(),
                old_journal = stale.journal_id,
                new_journal = journal.journal_id,
                "persisted USN cursor is stale (journal recreated); resetting to NextUsn (now)"
            );
            VolumeCursor {
                volume_serial: info.serial,
                journal_id: journal.journal_id,
                next_usn: journal.next_usn,
                fs_name: info.fs_name.clone(),
            }
        }
        None => VolumeCursor {
            volume_serial: info.serial,
            journal_id: journal.journal_id,
            next_usn: journal.next_usn,
            fs_name: info.fs_name.clone(),
        },
    };
    cursor.save(cursor_root)?;

    Ok(JournalSubscriber {
        volume_root: volume.to_path_buf(),
        journal,
        cursor_root: cursor_root.to_path_buf(),
        cursor: Arc::new(Mutex::new(cursor)),
        cache: PathCache::default(),
    })
}

/// FRN -> last-known-path cache. Shared between bootstrap and subscribe so
/// renames/deletes can be resolved against paths we observed during the MFT
/// walk or earlier creates.
type PathCache = Arc<Mutex<HashMap<u64, PathBuf>>>;

/// Pending half of a rename pair, keyed by FRN.
type RenameTable = Arc<Mutex<HashMap<u64, PathBuf>>>;

const READ_BUFFER_BYTES: usize = 64 * 1024;
const ENUM_BUFFER_BYTES: usize = 64 * 1024;
/// 100ns ticks; 100ms wakeup so we can check shutdown without blocking
/// indefinitely on a quiet volume.
const READ_TIMEOUT_100NS: u64 = 1_000_000;

impl JournalSubscriber {
    /// One-shot stream of synthetic `Create` events for every file currently
    /// in the volume's MFT. Skips reserved system entries (FRN < 24). After
    /// the walk, advances the persisted cursor to the journal snapshot's
    /// `next_usn` so a follow-up `subscribe()` doesn't replay every event
    /// the MFT walk already covered.
    pub fn bootstrap(&self) -> impl Stream<Item = JournalEvent> + Send + 'static {
        let (tx, rx) = mpsc::unbounded::<JournalEvent>();
        let volume_root = self.volume_root.clone();
        let journal = self.journal;
        let cache = self.cache.clone();
        let cursor = self.cursor.clone();
        let cursor_root = self.cursor_root.clone();

        std::thread::Builder::new()
            .name("mythkernel-journal/bootstrap".into())
            .spawn(move || {
                if let Err(err) = bootstrap_thread(&volume_root, &journal, &cache, &tx) {
                    tracing::warn!(error = %err, "bootstrap MFT walk failed");
                    return;
                }
                if let Ok(mut c) = cursor.lock()
                    && c.next_usn < journal.next_usn
                {
                    c.next_usn = journal.next_usn;
                    let _ = c.save(&cursor_root);
                }
            })
            .expect("spawn bootstrap thread");

        rx
    }

    /// **Bounded** stream of incremental events from the persisted cursor up
    /// to `end_usn` (inclusive of any record whose USN is < `end_usn`). Used
    /// by [`crate::walker::incremental::IncrementalWalker`] (TASK-051) to
    /// turn an unbounded journal subscription into a single-pass walk that
    /// closes when the snapshot point is reached. Persists the advanced
    /// cursor on completion.
    ///
    /// Returns `None` if the journal has rotated or wrapped since the cursor
    /// was minted — the caller MUST fall back to a full MFT walk.
    pub fn drain_until(
        &self,
        end_usn: i64,
    ) -> Option<impl Stream<Item = JournalEvent> + Send + 'static> {
        let (tx, rx) = mpsc::unbounded::<JournalEvent>();
        let volume_root = self.volume_root.clone();
        let cursor_root = self.cursor_root.clone();
        let cache = self.cache.clone();
        let renames = RenameTable::default();
        let cursor = self.cursor.clone();

        // Rotation gate: read the cursor under a short lock; if the cursor's
        // journal_id is older than the live journal we already loaded in
        // open(), the caller must do a full MFT walk instead.
        {
            let snap = self.cursor.lock().expect("cursor mutex poisoned");
            if snap.journal_id != self.journal.journal_id || snap.next_usn < self.journal.first_usn
            {
                tracing::info!(
                    cursor_journal = snap.journal_id,
                    live_journal = self.journal.journal_id,
                    "USN journal rotated since cursor minted; bounded drain refuses"
                );
                return None;
            }
        }

        std::thread::Builder::new()
            .name("mythkernel-journal/drain-until".into())
            .spawn(move || {
                if let Err(err) = drain_until_thread(
                    &volume_root,
                    cursor,
                    &cursor_root,
                    &cache,
                    &renames,
                    end_usn,
                    &tx,
                ) {
                    tracing::warn!(error = %err, "drain_until exited with error");
                }
            })
            .expect("spawn drain-until thread");

        Some(rx)
    }

    /// Long-running stream of incremental events. Drops the receiver to stop.
    pub fn subscribe(&self) -> impl Stream<Item = JournalEvent> + Send + 'static {
        let (tx, rx) = mpsc::unbounded::<JournalEvent>();
        let volume_root = self.volume_root.clone();
        let journal = self.journal;
        let cursor_root = self.cursor_root.clone();
        let cache = self.cache.clone();
        let renames = RenameTable::default();
        let cursor = self.cursor.clone();

        std::thread::Builder::new()
            .name("mythkernel-journal/subscribe".into())
            .spawn(move || {
                if let Err(err) = subscribe_thread(
                    &volume_root,
                    &journal,
                    cursor,
                    &cursor_root,
                    &cache,
                    &renames,
                    &tx,
                ) {
                    tracing::warn!(error = %err, "subscribe loop exited");
                }
            })
            .expect("spawn subscribe thread");

        rx
    }
}

fn bootstrap_thread(
    volume_root: &Path,
    journal: &JournalState,
    cache: &PathCache,
    tx: &mpsc::UnboundedSender<JournalEvent>,
) -> Result<(), JournalError> {
    let handle = VolumeHandle::open(volume_root)
        .map_err(|e| JournalError::OpenVolume(volume_root.to_path_buf(), e))?;
    let mut buf = vec![0u8; ENUM_BUFFER_BYTES];
    let mut next_frn: u64 = 0;

    loop {
        let res =
            enum_usn_data(&handle, next_frn, journal, &mut buf).map_err(JournalError::EnumMft)?;
        let (advance_frn, byte_count) = match res {
            Some(v) => v,
            None => break,
        };
        if byte_count <= std::mem::size_of::<u64>() {
            if advance_frn == 0 {
                break;
            }
            next_frn = advance_frn;
            continue;
        }

        for rec in UsnRecordIter::after_initial_frn(&buf[..byte_count]) {
            // Skip NTFS reserved entries.
            let frn_low = rec.file_ref & 0x0000_FFFF_FFFF_FFFF;
            if frn_low < 24 {
                continue;
            }

            let parent = match resolve_dir_path(&handle, rec.parent_file_ref, cache) {
                Some(p) => p,
                None => continue,
            };
            let full = parent.join(&rec.file_name);

            cache
                .lock()
                .expect("path cache mutex poisoned")
                .insert(rec.file_ref, full.clone());

            // USN records carry attrs + a single timestamp but NOT file
            // size. For correctness (Size column / Modified column in
            // the UI), pull `len` + `modified` + `created` via the
            // standard metadata syscall. This costs one stat() per
            // file but populates the columns properly.
            let (size, mtime_ns, ctime_ns) = match std::fs::metadata(&full) {
                Ok(m) => {
                    let mtime = m
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_nanos() as i128)
                        .unwrap_or_else(|| filetime_to_unix_ns(rec.timestamp_filetime));
                    let ctime = m
                        .created()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_nanos() as i128)
                        .unwrap_or(mtime);
                    (m.len(), mtime, ctime)
                }
                Err(_) => {
                    let t = filetime_to_unix_ns(rec.timestamp_filetime);
                    (0, t, t)
                }
            };
            let event = JournalEvent::Create {
                path: full,
                size,
                mtime_ns,
                ctime_ns,
                attrs: rec.file_attributes,
            };
            if tx.unbounded_send(event).is_err() {
                return Ok(());
            }
        }

        if advance_frn == 0 {
            break;
        }
        next_frn = advance_frn;
    }
    Ok(())
}

fn drain_until_thread(
    volume_root: &Path,
    cursor: Arc<Mutex<VolumeCursor>>,
    cursor_root: &Path,
    cache: &PathCache,
    renames: &RenameTable,
    end_usn: i64,
    tx: &mpsc::UnboundedSender<JournalEvent>,
) -> Result<(), JournalError> {
    let handle = VolumeHandle::open(volume_root)
        .map_err(|e| JournalError::OpenVolume(volume_root.to_path_buf(), e))?;
    let mut buf = vec![0u8; READ_BUFFER_BYTES];
    let mut local = cursor.lock().expect("cursor mutex poisoned").clone();

    while local.next_usn < end_usn {
        if tx.is_closed() {
            return Ok(());
        }
        let (next_usn, bytes) = read_usn_journal(
            &handle,
            local.journal_id,
            local.next_usn,
            &mut buf,
            READ_TIMEOUT_100NS,
        )
        .map_err(JournalError::ReadJournal)?;

        if bytes <= std::mem::size_of::<i64>() {
            // Idle round-trip — journal has nothing new in this window.
            // The bounded drain doesn't busy-loop; if next_usn is still
            // behind end_usn but the journal is quiet, just advance and
            // continue. The volume's NextUsn is monotonic so we're
            // guaranteed to converge.
            if next_usn <= local.next_usn {
                break;
            }
            local.next_usn = next_usn;
            continue;
        }

        for rec in UsnRecordIter::after_initial_frn(&buf[..bytes]) {
            // The DRAIN must respect the snapshot boundary — any record
            // emitted after we observed `end_usn` belongs to a future
            // scan. Skip them; the next IncrementalWalker call will see
            // them in its own bounded window.
            if rec.usn >= end_usn {
                continue;
            }
            if let Some(event) = handle_record(
                &handle,
                &rec,
                cache,
                renames,
                &JournalState {
                    journal_id: local.journal_id,
                    first_usn: 0,
                    next_usn: end_usn,
                    lowest_valid_usn: 0,
                    max_usn: 0,
                },
            ) && tx.unbounded_send(event).is_err()
            {
                return Ok(());
            }
        }

        local.next_usn = next_usn;
        persist(&local, &cursor, cursor_root);
    }

    // Final cursor advancement to the snapshot point so the next IncrementalWalker
    // call doesn't replay the same records.
    if local.next_usn < end_usn {
        local.next_usn = end_usn;
        persist(&local, &cursor, cursor_root);
    }
    Ok(())
}

fn subscribe_thread(
    volume_root: &Path,
    journal: &JournalState,
    cursor: Arc<Mutex<VolumeCursor>>,
    cursor_root: &Path,
    cache: &PathCache,
    renames: &RenameTable,
    tx: &mpsc::UnboundedSender<JournalEvent>,
) -> Result<(), JournalError> {
    let mut buf = vec![0u8; READ_BUFFER_BYTES];
    let mut backoff_attempts: u32 = 0;
    // Local snapshot of the live cursor; written back to the shared mutex
    // every time we persist. Avoids holding the lock while doing I/O.
    let mut local = cursor.lock().expect("cursor mutex poisoned").clone();

    loop {
        let handle = match VolumeHandle::open(volume_root) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, attempts = backoff_attempts,
                    "volume open failed; retrying");
                if !sleep_with_drop_check(&mut backoff_attempts, tx) {
                    return Ok(());
                }
                continue;
            }
        };

        // If the journal was recreated since our cursor was minted, reset.
        let live = match query_usn_journal(&handle) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(error = %e, "query_usn_journal failed during subscribe; retrying");
                if !sleep_with_drop_check(&mut backoff_attempts, tx) {
                    return Ok(());
                }
                continue;
            }
        };
        if live.journal_id != local.journal_id || local.next_usn < live.first_usn {
            tracing::info!(
                old = local.journal_id,
                new = live.journal_id,
                "USN journal recreated or wrapped; reseating cursor to FirstUsn"
            );
            local.journal_id = live.journal_id;
            local.next_usn = live.first_usn;
            persist(&local, &cursor, cursor_root);
        }

        backoff_attempts = 0;

        loop {
            if tx.is_closed() {
                return Ok(());
            }

            let (next_usn, bytes) = match read_usn_journal(
                &handle,
                local.journal_id,
                local.next_usn,
                &mut buf,
                READ_TIMEOUT_100NS,
            ) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e,
                            "FSCTL_READ_USN_JOURNAL failed; reopening volume");
                    break;
                }
            };

            if bytes <= std::mem::size_of::<i64>() {
                local.next_usn = next_usn;
                continue;
            }

            for rec in UsnRecordIter::after_initial_frn(&buf[..bytes]) {
                if let Some(event) = handle_record(&handle, &rec, cache, renames, journal)
                    && tx.unbounded_send(event).is_err()
                {
                    return Ok(());
                }
            }

            local.next_usn = next_usn;
            persist(&local, &cursor, cursor_root);
        }
    }
}

fn persist(local: &VolumeCursor, shared: &Arc<Mutex<VolumeCursor>>, root: &Path) {
    if let Ok(mut guard) = shared.lock() {
        *guard = local.clone();
    }
    let _ = local.save(root);
}

fn sleep_with_drop_check(attempts: &mut u32, tx: &mpsc::UnboundedSender<JournalEvent>) -> bool {
    *attempts = (*attempts + 1).min(8);
    let backoff_ms = 50_u64
        .saturating_mul(1 << (*attempts - 1).min(7))
        .min(5_000);
    let step = std::time::Duration::from_millis(50);
    let total = std::time::Duration::from_millis(backoff_ms);
    let mut elapsed = std::time::Duration::ZERO;
    while elapsed < total {
        if tx.is_closed() {
            return false;
        }
        std::thread::sleep(step);
        elapsed += step;
    }
    true
}

fn handle_record(
    handle: &VolumeHandle,
    rec: &ParsedUsnRecord,
    cache: &PathCache,
    renames: &RenameTable,
    _journal: &JournalState,
) -> Option<JournalEvent> {
    // Skip NTFS reserved entries.
    let frn_low = rec.file_ref & 0x0000_FFFF_FFFF_FFFF;
    if frn_low < 24 {
        return None;
    }

    let kind = classify(rec.reason);
    let path = build_path(handle, rec, cache);

    match kind {
        ReasonKind::Pending | ReasonKind::Ignore => None,
        ReasonKind::Create => {
            let path = path?;
            cache
                .lock()
                .expect("path cache mutex poisoned")
                .insert(rec.file_ref, path.clone());
            if rec.is_directory() {
                return None;
            }
            Some(JournalEvent::Create {
                path,
                size: 0,
                mtime_ns: filetime_to_unix_ns(rec.timestamp_filetime),
                ctime_ns: filetime_to_unix_ns(rec.timestamp_filetime),
                attrs: rec.file_attributes,
            })
        }
        ReasonKind::Modify => {
            if rec.is_directory() {
                return None;
            }
            let path = path?;
            Some(JournalEvent::Modify {
                path,
                size: 0,
                mtime_ns: filetime_to_unix_ns(rec.timestamp_filetime),
                attrs: rec.file_attributes,
            })
        }
        ReasonKind::Delete => {
            // POSIX-style deletes on Windows produce RENAME_OLD_NAME
            // (original path) → RENAME_NEW_NAME (temp `$.dF{guid}`-style
            // path) → FILE_DELETE (temp path). Step 3's `build_path`
            // returns the temp name; if our pairing table holds a
            // RenameOld for this FRN (set in step 1), use that ORIGINAL
            // path for the Delete event.
            let renamed_old = renames
                .lock()
                .expect("rename table mutex poisoned")
                .remove(&rec.file_ref);
            let path = renamed_old.or(path)?;
            cache
                .lock()
                .expect("path cache mutex poisoned")
                .remove(&rec.file_ref);
            if rec.is_directory() {
                return None;
            }
            Some(JournalEvent::Delete { path })
        }
        ReasonKind::AttrChange => {
            if rec.is_directory() {
                return None;
            }
            let path = path?;
            Some(JournalEvent::AttrChange {
                path,
                attrs: rec.file_attributes,
            })
        }
        ReasonKind::RenameOld => {
            let path = path?;
            renames
                .lock()
                .expect("rename table mutex poisoned")
                .insert(rec.file_ref, path);
            None
        }
        ReasonKind::RenameNew => {
            let new_path = path?;
            let old_path = renames
                .lock()
                .expect("rename table mutex poisoned")
                .remove(&rec.file_ref)?;
            cache
                .lock()
                .expect("path cache mutex poisoned")
                .insert(rec.file_ref, new_path.clone());
            if rec.is_directory() {
                return None;
            }
            Some(JournalEvent::Rename { old_path, new_path })
        }
    }
}

fn build_path(handle: &VolumeHandle, rec: &ParsedUsnRecord, cache: &PathCache) -> Option<PathBuf> {
    if let Some(parent) = resolve_dir_path(handle, rec.parent_file_ref, cache) {
        let full = parent.join(&rec.file_name);
        return Some(full);
    }
    cache
        .lock()
        .expect("path cache mutex poisoned")
        .get(&rec.file_ref)
        .cloned()
}

fn resolve_dir_path(handle: &VolumeHandle, frn: u64, cache: &PathCache) -> Option<PathBuf> {
    if let Some(p) = cache
        .lock()
        .expect("path cache mutex poisoned")
        .get(&frn)
        .cloned()
    {
        return Some(p);
    }
    match resolve_path_by_frn(handle, frn) {
        Ok(Some(p)) => {
            cache
                .lock()
                .expect("path cache mutex poisoned")
                .insert(frn, p.clone());
            Some(p)
        }
        Ok(None) => None,
        Err(e) => {
            tracing::trace!(frn, error = %e, "resolve_path_by_frn failed");
            None
        }
    }
}

/// Convert NTFS FILETIME (100ns intervals since 1601-01-01 UTC) to nanoseconds
/// since the UNIX epoch.
fn filetime_to_unix_ns(filetime: i64) -> i128 {
    const FT_TO_UNIX_100NS: i128 = 116_444_736_000_000_000;
    (filetime as i128 - FT_TO_UNIX_100NS) * 100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_unix_epoch_round_trips() {
        let ft: i64 = 116_444_736_000_000_000;
        assert_eq!(filetime_to_unix_ns(ft), 0);
    }

    #[test]
    fn filetime_one_second_post_epoch() {
        let ft: i64 = 116_444_736_000_000_000 + 10_000_000;
        assert_eq!(filetime_to_unix_ns(ft), 1_000_000_000);
    }
}
