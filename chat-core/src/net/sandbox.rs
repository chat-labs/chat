// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! The sandbox, on Linux: Landlock for where chat writes and what it runs, and seccomp for the
//! system calls it never makes, refused with EPERM rather than a kill, so a library that tries one
//! just sees it fail.
//!
//! It can go up at any time, on every thread: seccomp syncs its filter to them, and Landlock, which
//! only binds the thread that asks and the ones it starts after, is asked for by each thread
//! already running, from a signal handler. So an interface puts it up once it knows what a save
//! says, just before chat first reaches the network.

#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;

/// What went up, and why the rest didn't.
#[derive(Clone, Debug, Default)]
pub struct Sandbox {
    /// Landlock: chat writes only in its own folders, and runs only the programs it was given.
    pub files: bool,
    /// seccomp: the calls chat never makes are refused.
    pub calls: bool,
    pub why: Option<String>,
}

/// Where a sandboxed chat may write, besides `extra`: the folders directly in the home folder that
/// aren't hidden (with the checks below), Downloads, chat's own folder (or until a save makes it,
/// the folder it goes in: then true, and [`narrow`] narrows it once it's there), and the private
/// folder temporary files go in.
#[cfg(target_os = "linux")]
fn write_places(extra: &[PathBuf]) -> (Vec<PathBuf>, bool) {
    let mut broad = false;
    let mut out: Vec<PathBuf> = extra.to_vec();
    if let Some(home) = crate::net::files::home_dir().and_then(|h| std::fs::canonicalize(h).ok()) {
        let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).filter_map(|d| std::fs::canonicalize(d).ok()).collect())
            .unwrap_or_default();
        for e in std::fs::read_dir(&home).into_iter().flatten().flatten() {
            if e.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let Ok(real) = std::fs::canonicalize(e.path()) else { continue };
            if !real.is_dir() {
                continue;
            }
            // Not a link to the home folder or above it, nor to a hidden folder in it, nor a folder
            // holding a PATH entry, where a program written would be run by a shell. Dotfiles and
            // dot-folders (.bashrc, .config/autostart, .ssh, .local/bin) stay out of reach.
            let hidden_inside = real
                .strip_prefix(&home)
                .is_ok_and(|rest| rest.components().any(|c| c.as_os_str().to_string_lossy().starts_with('.')));
            if home.starts_with(&real) || hidden_inside || path_dirs.iter().any(|d| d.starts_with(&real)) {
                continue;
            }
            out.push(real);
        }
    }
    out.extend(crate::net::files::downloads_dir());
    if let Some(dir) = crate::net::saves::config_dir() {
        if dir.is_dir() {
            out.push(dir);
        } else if let Some(parent) = dir.parent() {
            let _ = std::fs::create_dir_all(parent);
            out.push(parent.to_path_buf());
            broad = true;
        }
    }
    let temp = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    out.push(temp);
    (out, broad)
}

/// The programs `run` names, and what runs each of them, two levels deep.
#[cfg(target_os = "linux")]
fn with_interpreters(run: &[PathBuf]) -> Vec<PathBuf> {
    let mut programs: Vec<PathBuf> = Vec::new();
    for p in run.iter().filter_map(|p| std::fs::canonicalize(p).ok()) {
        let mut next = Some(p);
        for _ in 0..3 {
            let Some(p) = next.take() else { break };
            if !programs.contains(&p) {
                next = interpreter(&p).and_then(|i| std::fs::canonicalize(i).ok());
                programs.push(p);
            }
        }
    }
    programs
}

/// What the sandbox let in as it went up, for [`narrow`].
#[cfg(target_os = "linux")]
struct Layer {
    abi: i64,
    programs: Vec<PathBuf>,
    extra: Vec<PathBuf>,
    broad: bool,
}

#[cfg(target_os = "linux")]
static LAYER: std::sync::Mutex<Option<Layer>> = std::sync::Mutex::new(None);

/// What execve also opens to run a program: its #! line's program, or an ELF program's loader.
#[cfg(target_os = "linux")]
fn interpreter(path: &Path) -> Option<PathBuf> {
    use std::io::Read;
    let mut head = vec![0u8; 4096];
    let n = std::fs::File::open(path).ok()?.read(&mut head).ok()?;
    head.truncate(n);
    if head.starts_with(b"#!") {
        let line = String::from_utf8_lossy(&head[2..]);
        let prog = line.trim_start_matches([' ', '\t']).split([' ', '\t', '\r', '\n']).next()?;
        return prog.starts_with('/').then(|| PathBuf::from(prog));
    }
    if !head.starts_with(b"\x7fELF") || head.len() < 64 {
        return None;
    }
    // 64-bit or 32-bit, little-endian: the program headers, for PT_INTERP's path.
    let file = std::fs::read(path).ok()?;
    let is64 = head[4] == 2;
    let u = |at: usize, len: usize| -> Option<u64> {
        let b = file.get(at..at + len)?;
        Some(b.iter().rev().fold(0u64, |v, &x| (v << 8) | u64::from(x)))
    };
    let (phoff, phentsize, phnum) = if is64 {
        (u(0x20, 8)?, u(0x36, 2)?, u(0x38, 2)?)
    } else {
        (u(0x1c, 4)?, u(0x2a, 2)?, u(0x2c, 2)?)
    };
    for i in 0..phnum {
        let at = (phoff + i * phentsize) as usize;
        if u(at, 4)? != 3 {
            continue;
        }
        let (off, size) = if is64 {
            (u(at + 8, 8)?, u(at + 32, 8)?)
        } else {
            (u(at + 4, 4)?, u(at + 16, 4)?)
        };
        let raw = file.get(off as usize..(off + size) as usize)?;
        let s = String::from_utf8_lossy(raw).trim_end_matches('\0').to_string();
        return s.starts_with('/').then(|| PathBuf::from(s));
    }
    None
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
    const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
    const CREATE_RULESET_VERSION: u32 = 1;
    const RULE_PATH_BENEATH: libc::c_int = 1;
    pub const EXECUTE: u64 = 1 << 0;
    pub const WRITE_FILE: u64 = 1 << 1;
    const REMOVE_DIR: u64 = 1 << 4;
    const REMOVE_FILE: u64 = 1 << 5;
    const MAKE_CHAR: u64 = 1 << 6;
    const MAKE_DIR: u64 = 1 << 7;
    const MAKE_REG: u64 = 1 << 8;
    const MAKE_SOCK: u64 = 1 << 9;
    const MAKE_FIFO: u64 = 1 << 10;
    const MAKE_BLOCK: u64 = 1 << 11;
    const MAKE_SYM: u64 = 1 << 12;
    const REFER: u64 = 1 << 13;
    const TRUNCATE: u64 = 1 << 14;
    const SCOPE_SIGNAL: u64 = 1 << 1;
    const ABI_REFER: i64 = 2;
    const ABI_TRUNCATE: i64 = 3;
    const ABI_SCOPE: i64 = 6;

    #[repr(C)]
    struct Ruleset {
        handled_fs: u64,
        handled_net: u64,
        scoped: u64,
    }

    #[repr(C, packed)]
    struct Beneath {
        allowed: u64,
        parent_fd: i32,
    }

    pub fn abi() -> i64 {
        // SAFETY: asking the version takes no pointers.
        unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<Ruleset>(),
                0usize,
                CREATE_RULESET_VERSION,
            )
        }
    }

    fn add(ruleset: i32, path: &Path, allowed: u64) {
        let Ok(f) = std::fs::File::options().read(true).custom_flags(libc::O_PATH).open(path) else {
            return;
        };
        let b = Beneath {
            allowed,
            parent_fd: f.as_raw_fd(),
        };
        // SAFETY: the rule is read from the struct, which outlives the call.
        unsafe { libc::syscall(SYS_LANDLOCK_ADD_RULE, ruleset, RULE_PATH_BENEATH, &b as *const Beneath, 0u32) };
    }

    use std::os::unix::fs::OpenOptionsExt;

    /// One layer: writing only under `write`, devices opened to write, and running only `run`.
    pub fn landlock(abi: i64, write: &[std::path::PathBuf], run: &[std::path::PathBuf]) -> Result<(), String> {
        let mut w = WRITE_FILE | REMOVE_DIR | REMOVE_FILE | MAKE_DIR | MAKE_REG;
        let mut handled = w | EXECUTE | MAKE_CHAR | MAKE_SOCK | MAKE_FIFO | MAKE_BLOCK | MAKE_SYM;
        if abi >= ABI_REFER {
            handled |= REFER;
            w |= REFER;
        }
        let mut dev = WRITE_FILE;
        if abi >= ABI_TRUNCATE {
            handled |= TRUNCATE;
            w |= TRUNCATE;
            dev |= TRUNCATE;
        }
        // Nor signals to processes outside the sandbox. Abstract sockets stay open: a D-Bus
        // session bus can be one.
        let attr = Ruleset {
            handled_fs: handled,
            handled_net: 0,
            scoped: if abi >= ABI_SCOPE { SCOPE_SIGNAL } else { 0 },
        };
        // SAFETY: the attributes are read from the struct, which outlives the call.
        let rs = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                &attr as *const Ruleset,
                std::mem::size_of::<Ruleset>(),
                0u32,
            )
        } as i32;
        if rs < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        for p in write {
            add(rs, p, w);
        }
        // Opening a device to write to it: /dev/null, a security key's hidraw, the TPM.
        add(rs, Path::new("/dev"), dev);
        for p in run {
            add(rs, p, EXECUTE);
        }
        every_thread(rs)
    }

    /// The ruleset the signal handler restricts its thread with, and the threads it has run on.
    static RULESET: AtomicI32 = AtomicI32::new(-1);
    static REFUSED: AtomicBool = AtomicBool::new(false);
    const REACHED_MAX: usize = 4096;
    static REACHED: [AtomicI32; REACHED_MAX] = [const { AtomicI32::new(0) }; REACHED_MAX];
    static N_REACHED: AtomicUsize = AtomicUsize::new(0);
    /// How long the threads get to take the sandbox.
    const EVERY_THREAD_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

    /// Runs on each thread asked to take the sandbox, between whatever it was doing, so it only
    /// makes system calls, and leaves errno as it was.
    extern "C" fn take_ruleset(_: libc::c_int) {
        // SAFETY: errno is this thread's own; the calls only read their arguments.
        unsafe {
            let errno = *libc::__errno_location();
            libc::syscall(libc::SYS_prctl, libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, RULESET.load(Ordering::Acquire), 0u32) != 0 {
                REFUSED.store(true, Ordering::Release);
            }
            let i = N_REACHED.fetch_add(1, Ordering::AcqRel);
            if i < REACHED_MAX {
                REACHED[i].store(libc::syscall(libc::SYS_gettid) as i32, Ordering::Release);
            }
            *libc::__errno_location() = errno;
        }
    }

    /// The threads of this process.
    fn threads() -> Vec<i32> {
        std::fs::read_dir("/proc/self/task")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse().ok())
            .collect()
    }

    /// The ruleset on every thread: this one at once, each other one from the signal handler, until
    /// a look at the threads finds none it hasn't reached. A thread started meanwhile by one that
    /// hadn't taken it yet is found on the next look; one started after, by one that had, has it
    /// already. The ruleset's fd is closed after, unless a thread never took it (it blocks the
    /// signal), which then takes it whenever it can.
    fn every_thread(rs: i32) -> Result<(), String> {
        static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: as above.
        if unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, rs, 0u32) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(rs) };
            return Err(err.to_string());
        }
        RULESET.store(rs, Ordering::Release);
        REFUSED.store(false, Ordering::Release);
        N_REACHED.store(0, Ordering::Release);
        for r in &REACHED {
            r.store(0, Ordering::Release);
        }
        let sig = libc::SIGRTMAX() - 1;
        // SAFETY: the handler is set for the signal, and the old one kept to put back; the struct
        // is zeroed, then filled in.
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = take_ruleset as extern "C" fn(libc::c_int) as libc::sighandler_t;
        act.sa_flags = libc::SA_RESTART;
        unsafe { libc::sigemptyset(&mut act.sa_mask) };
        if unsafe { libc::sigaction(sig, &act, &mut old) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(rs) };
            return Err(format!("only this thread has it: {err}"));
        }
        // SAFETY: these take no pointers.
        let (pid, me) = unsafe { (libc::getpid(), libc::syscall(libc::SYS_gettid) as i32) };
        let mut reached = std::collections::HashSet::from([me]);
        let mut asked = std::collections::HashSet::new();
        let until = std::time::Instant::now() + EVERY_THREAD_WAIT;
        let missing = loop {
            let n = N_REACHED.load(Ordering::Acquire).min(REACHED_MAX);
            reached.extend(REACHED[..n].iter().map(|r| r.load(Ordering::Acquire)).filter(|t| *t != 0));
            let left: Vec<i32> = threads().into_iter().filter(|t| !reached.contains(t)).collect();
            if left.is_empty() || std::time::Instant::now() > until {
                break left.len();
            }
            for t in left {
                if asked.insert(t) {
                    // SAFETY: tgkill only signals the thread named.
                    unsafe { libc::syscall(libc::SYS_tgkill, pid, t, sig) };
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        if missing > 0 {
            return Err(format!("{missing} of chat's threads didn't take it"));
        }
        // SAFETY: as above; no thread is still to run the handler.
        unsafe {
            libc::sigaction(sig, &old, std::ptr::null_mut());
            libc::close(rs);
        }
        if REFUSED.load(Ordering::Acquire) {
            return Err("a thread was refused it".into());
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xC000_00B7;
    #[cfg(target_arch = "riscv64")]
    const AUDIT_ARCH: u32 = 0xC000_00F3;

    /// Calls chat never makes, refused for it and what it runs: tracing and reading other
    /// processes, BPF, io_uring, keyrings, mounts and namespaces, kernel modules, and setting the
    /// clock.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64"))]
    fn denied() -> Vec<libc::c_long> {
        let mut v = vec![
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_kcmp,
            libc::SYS_perf_event_open,
            libc::SYS_bpf,
            libc::SYS_userfaultfd,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_chroot,
            libc::SYS_open_tree,
            libc::SYS_move_mount,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
            libc::SYS_fspick,
            libc::SYS_mount_setattr,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_kexec_load,
            libc::SYS_kexec_file_load,
            libc::SYS_reboot,
            libc::SYS_swapon,
            libc::SYS_swapoff,
            libc::SYS_acct,
            libc::SYS_quotactl,
            libc::SYS_open_by_handle_at,
            libc::SYS_name_to_handle_at,
            libc::SYS_lookup_dcookie,
            libc::SYS_vhangup,
            libc::SYS_syslog,
            libc::SYS_settimeofday,
            libc::SYS_clock_settime,
            libc::SYS_clock_adjtime,
            libc::SYS_adjtimex,
        ];
        #[cfg(target_arch = "x86_64")]
        v.extend([libc::SYS_uselib, libc::SYS_iopl, libc::SYS_ioperm, libc::SYS_modify_ldt]);
        v
    }

    /// The filter, on every thread: another architecture's numbers (and on x86-64, x32's) are
    /// refused outright, since they'd get past the list.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64"))]
    pub fn seccomp() -> Result<(), String> {
        const LD_W_ABS: u16 = 0x20;
        const JMP_JEQ_K: u16 = 0x15;
        const JMP_JGE_K: u16 = 0x35;
        const RET_K: u16 = 0x06;
        const RET_ERRNO: u32 = 0x0005_0000;
        const RET_ALLOW: u32 = 0x7fff_0000;
        let stmt = |code, k| libc::sock_filter { code, jt: 0, jf: 0, k };
        let jump = |code, k, jt, jf| libc::sock_filter { code, jt, jf, k };
        let deny = denied();
        let n = deny.len();
        let eperm = RET_ERRNO | libc::EPERM as u32;
        let mut f = vec![
            stmt(LD_W_ABS, 4),
            jump(JMP_JEQ_K, AUDIT_ARCH, 1, 0),
            stmt(RET_K, eperm),
            stmt(LD_W_ABS, 0),
        ];
        if cfg!(target_arch = "x86_64") {
            f.push(jump(JMP_JGE_K, 0x4000_0000, (n + 1) as u8, 0));
        }
        for (i, nr) in deny.iter().enumerate() {
            f.push(jump(JMP_JEQ_K, *nr as u32, (n - i) as u8, 0));
        }
        f.push(stmt(RET_K, RET_ALLOW));
        f.push(stmt(RET_K, eperm));
        let prog = libc::sock_fprog {
            len: f.len() as u16,
            filter: f.as_mut_ptr(),
        };
        // SAFETY: the program is read from memory that outlives the call.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_TSYNC,
                &prog as *const libc::sock_fprog,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().to_string())
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
    pub fn seccomp() -> Result<(), String> {
        Err("there's no filter for this architecture".into())
    }
}

/// Puts the sandbox up, for good, on every thread (see above). `run`: the programs chat may run;
/// `write`: folders it may write in besides its usual ones.
pub fn up(run: &[PathBuf], write: &[PathBuf]) -> Sandbox {
    #[cfg(target_os = "linux")]
    {
        let (places, broad) = write_places(write);
        let programs = with_interpreters(run);
        let s = up_in(&programs, &places);
        if s.files {
            *LAYER.lock().unwrap_or_else(|e| e.into_inner()) = Some(Layer {
                abi: linux::abi(),
                programs,
                extra: write.to_vec(),
                broad,
            });
        }
        s
    }
    #[cfg(not(target_os = "linux"))]
    up_in(run, write)
}

/// The sandbox with nowhere to write but `write`: the updater's.
pub fn up_only(run: &[PathBuf], write: &[PathBuf]) -> Sandbox {
    #[cfg(target_os = "linux")]
    return up_in(&with_interpreters(run), write);
    #[cfg(not(target_os = "linux"))]
    up_in(run, write)
}

/// Once a save has made chat's folder, the sandbox lets chat write in it rather than in the folder
/// it goes in: a narrower layer, on every thread. Nothing if the sandbox isn't up, or already is.
pub fn narrow() {
    #[cfg(target_os = "linux")]
    {
        let mut layer = LAYER.lock().unwrap_or_else(|e| e.into_inner());
        let Some(l) = layer.as_mut().filter(|l| l.broad) else { return };
        let (places, broad) = write_places(&l.extra);
        if !broad && linux::landlock(l.abi, &places, &l.programs).is_ok() {
            l.broad = false;
        }
    }
}

fn up_in(programs: &[PathBuf], write: &[PathBuf]) -> Sandbox {
    #[cfg(target_os = "linux")]
    {
        let mut s = Sandbox::default();
        // Landlock and seccomp both need it, unprivileged.
        // SAFETY: prctl only reads its arguments.
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        let abi = linux::abi();
        if abi <= 0 {
            s.why = Some("this kernel has no Landlock (it needs Linux 5.13 or later, with Landlock on)".into());
        } else {
            match linux::landlock(abi, write, programs) {
                Ok(()) => s.files = true,
                Err(e) => s.why = Some(format!("Landlock refused its rules ({e})")),
            }
        }
        match linux::seccomp() {
            Ok(()) => s.calls = true,
            Err(e) if s.why.is_none() => s.why = Some(format!("seccomp refused its filter ({e})")),
            Err(_) => {}
        }
        s
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (programs, write);
        Sandbox {
            why: Some("the sandbox is only on Linux".into()),
            ..Sandbox::default()
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn finds_what_runs_a_program() {
        let sh = std::env::temp_dir().join(format!("chat-sb-{}.sh", std::process::id()));
        std::fs::write(&sh, "#!/bin/sh -e\necho\n").unwrap();
        assert_eq!(interpreter(&sh), Some(PathBuf::from("/bin/sh")));
        let _ = std::fs::remove_file(&sh);
        // A dynamically linked program names its loader.
        if let Ok(exe) = std::fs::canonicalize("/bin/sh") {
            let loader = interpreter(&exe);
            assert!(loader.as_ref().is_none_or(|l| l.to_string_lossy().contains("ld")), "{loader:?}");
        }
    }
}
