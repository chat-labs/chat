// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Files on this machine: ours read to be offered (and pictures cleaned), and fetched ones
//! saved. The engine only sees them through `protocol::files`' traits.

use crate::protocol::crypto::sodium;
use crate::protocol::files::{self, Disk, FILE_HARD_MAX, FILE_VIEW_MAX, Part, Source, format_size};
use crate::protocol::picture;
use crate::protocol::session::OwnFile;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// How a room handles files.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct FileOptions {
    /// The folder fetched files are saved in: None for Downloads.
    pub dir: Option<String>,
    /// Files bigger than this need "anyway" to be fetched (0: 8 MB).
    pub limit: u64,
    /// Fast transfers: slots every few milliseconds while a file goes either way. Faster, but the
    /// burst can be seen.
    pub fast: bool,
    /// Pictures offered cleaned get noise nobody can see, so no two copies are the same bytes.
    pub noise: bool,
}

impl Default for FileOptions {
    fn default() -> Self {
        FileOptions {
            dir: None,
            limit: 0,
            fast: false,
            noise: true,
        }
    }
}

pub(crate) type SharedOptions = Arc<Mutex<FileOptions>>;

/// The home folder, for "~" in typed paths and for Downloads.
pub fn home_dir() -> Option<String> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var(var).ok().filter(|h| !h.is_empty())
}

/// A path as typed: quotes stripped, and "~" for the home folder.
pub fn typed_path_here(path: &str) -> String {
    files::typed_path(path, home_dir().as_deref())
}

/// The Downloads folder, made (private) if it isn't there.
pub fn downloads_dir() -> Option<PathBuf> {
    let dir = Path::new(&home_dir()?).join("Downloads");
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let _ = std::fs::DirBuilder::new().mode(0o700).create(&dir);
    }
    #[cfg(not(unix))]
    let _ = std::fs::create_dir(&dir);
    dir.is_dir().then_some(dir)
}

/// A regular file opened to read: never a device or a pipe, which could block or never end.
fn open_regular(path: &Path) -> Option<(File, u64)> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let f = o.open(path).ok()?;
    let m = f.metadata().ok()?;
    m.is_file().then_some((f, m.len()))
}

/// A file read from where it was opened, so one changed since then no longer matches its hash.
struct FileSource(File);

impl Source for FileSource {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.0.read_exact_at(buf, off).is_ok()
        }
        #[cfg(not(unix))]
        {
            use std::io::Seek;
            self.0.seek(std::io::SeekFrom::Start(off)).is_ok() && self.0.read_exact(buf).is_ok()
        }
    }
}

/// Reads one of ours to offer it: hashed as it's read, and a picture cleaned of what could tell
/// where, when or with what it was made, unless `asis`. Blocking: run it off the event loop.
pub(crate) fn prepare(path: &str, asis: bool, noise: bool) -> Result<OwnFile, String> {
    let Some((mut f, size)) = open_regular(Path::new(path)) else {
        return Err(format!("can't send {path}: not a file chat can read"));
    };
    if size > FILE_HARD_MAX {
        return Err(format!("can't send {path}: files go up to {}", format_size(FILE_HARD_MAX)));
    }
    // Hashed while it's read now. Chunks are read from the same open file later, so a file
    // changed since then gives a hash that doesn't match, and nothing else is sent in its place.
    let mut h = sodium::Sha256::new();
    let mut buf = Zeroizing::new(vec![0u8; 65536]);
    let mut head = Vec::new();
    let mut mem: Option<Zeroizing<Vec<u8>>> = None;
    let mut total = 0u64;
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(format!("can't send {path}: it couldn't be read")),
        };
        if head.len() < picture::CLEAN_HEAD {
            let take = n.min(picture::CLEAN_HEAD - head.len());
            head.extend_from_slice(&buf[..take]);
        }
        // A picture is kept as it's read, to clean it and show it here.
        if total == 0 && size <= FILE_VIEW_MAX && picture::kind(&buf[..n]).is_some() {
            mem = Some(Zeroizing::new(Vec::with_capacity(size as usize)));
        }
        total += n as u64;
        if total > size {
            break;
        }
        if let Some(m) = mem.as_mut() {
            m.extend_from_slice(&buf[..n]);
        }
        h.update(&buf[..n]);
    }
    if total != size {
        return Err(format!("can't send {path}: it changed while it was read"));
    }
    let kind = picture::kind(&head);
    let old_name = files::clean_name(files::basename(path).as_bytes());
    let mut own = OwnFile {
        name: old_name.clone(),
        size,
        sha: h.finish(),
        image: kind.is_some(),
        source: Box::new(FileSource(f)),
        picture: None,
        cleaned: None,
        cannot: None,
    };
    match kind {
        None => own.cannot = picture::cannot(&head, &old_name),
        Some(_) if asis => own.picture = mem,
        Some(kind) => {
            let Some(m) = mem else {
                return Err(format!(
                    "not sent: {path} is a picture too big to clean of where and when it was taken (over 64 MB) - offer \
                     it \"as is\" to send it as it is"
                ));
            };
            let seed = Zeroizing::new(sodium::random_array::<{ picture::CLEAN_SEED_LEN }>());
            let Some((clean, took)) = picture::clean(&m, noise, &seed) else {
                return Err(format!(
                    "not sent: {path} doesn't read as a whole picture, so what it holds can't be taken out - offer it \
                     \"as is\" to send it as it is"
                ));
            };
            let clean = Zeroizing::new(clean);
            // Offered from memory from now on, and shown here as the peers get it.
            own.size = clean.len() as u64;
            own.sha = sodium::sha256(&[&clean]);
            let renamed = picture::name_tells(&old_name).then(|| {
                own.name = kind.plain_name().to_string();
                old_name
            });
            own.cleaned = Some((took, renamed));
            own.picture = Some(clean.clone());
            own.source = Box::new(clean);
        }
    }
    Ok(own)
}

/// Fetched files saved on this machine: in the folder asked for, else the one set for the room,
/// else Downloads.
pub(crate) struct FsDisk {
    pub options: SharedOptions,
}

impl FsDisk {
    fn folder(&self, dir: Option<&str>) -> Option<PathBuf> {
        let set = self.options.lock().expect("file options").dir.clone();
        match dir.map(str::to_string).or(set) {
            Some(d) => {
                let p = PathBuf::from(d);
                p.is_dir().then_some(p)
            }
            None => downloads_dir(),
        }
    }
}

impl Disk for FsDisk {
    fn create(&mut self, dir: Option<&str>) -> Result<Box<dyn Part>, String> {
        let name = self.folder_name(dir);
        let Some(folder) = self.folder(dir) else {
            return Err(format!("{name} isn't a folder chat can write to"));
        };
        // A new hidden file under a name nothing else will use; it gets its real name once its
        // hash matches.
        let path = folder.join(format!(".chat-{}.part", crate::protocol::hex::encode(&sodium::random_array::<6>())));
        let mut o = OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NOCTTY);
        }
        let file = o.open(&path).map_err(|_| format!("can't write a file in {name}"))?;
        Ok(Box::new(FsPart {
            file: Some(file),
            path,
            folder,
        }))
    }

    fn open(&mut self, path: &str) -> Option<(u64, Box<dyn Source>)> {
        let (f, size) = open_regular(Path::new(path))?;
        Some((size, Box::new(FileSource(f))))
    }

    fn folder_name(&self, dir: Option<&str>) -> String {
        let set = self.options.lock().expect("file options").dir.clone();
        dir.map(str::to_string).or(set).unwrap_or_else(|| "Downloads".into())
    }
}

struct FsPart {
    file: Option<File>,
    path: PathBuf,
    folder: PathBuf,
}

impl Part for FsPart {
    fn write(&mut self, data: &[u8]) -> bool {
        self.file.as_mut().is_some_and(|f| f.write_all(data).is_ok())
    }

    fn keep(mut self: Box<Self>, name: &str) -> Option<String> {
        let f = self.file.take()?;
        if f.sync_all().is_err() {
            return None;
        }
        drop(f);
        // "name", then "name (2).ext" and so on: never replacing a file that's there.
        let (stem, ext) = match name.rfind('.') {
            Some(dot) if dot > 0 => name.split_at(dot),
            _ => (name, ""),
        };
        for k in 1..100 {
            let try_name = if k == 1 { name.to_string() } else { format!("{stem} ({k}){ext}") };
            let to = self.folder.join(&try_name);
            match move_new(&self.path, &to) {
                Ok(()) => {
                    self.path = PathBuf::new();
                    return Some(to.to_string_lossy().into_owned());
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return None,
            }
        }
        None
    }
}

impl Drop for FsPart {
    fn drop(&mut self) {
        self.file = None;
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Renames a file to a name that must not exist yet: a hard link fails if it's taken, so
/// nothing is ever replaced.
fn move_new(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::hard_link(from, to) {
        Ok(()) => {
            let _ = std::fs::remove_file(from);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(e),
        // A filesystem without hard links (FAT, some FUSE ones): a rename that won't replace.
        Err(e) => {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::ffi::OsStrExt;
                let (Ok(a), Ok(b)) = (
                    std::ffi::CString::new(from.as_os_str().as_bytes()),
                    std::ffi::CString::new(to.as_os_str().as_bytes()),
                ) else {
                    return Err(e);
                };
                // The system call itself: musl, which the static release links, has no wrapper for it.
                // SAFETY: both are valid, NUL-terminated paths.
                let rc = unsafe {
                    libc::syscall(
                        libc::SYS_renameat2,
                        libc::AT_FDCWD,
                        a.as_ptr(),
                        libc::AT_FDCWD,
                        b.as_ptr(),
                        libc::RENAME_NOREPLACE,
                    )
                };
                if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
            }
            #[cfg(not(target_os = "linux"))]
            Err(e)
        }
    }
}
