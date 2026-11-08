// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Desktop notifications, straight to the desktop's notification service over the session bus
//! (org.freedesktop.Notifications). Through notify-send, each would start a process anyone can see,
//! with its title and text on a command line every user on the computer can read. Each is marked
//! transient, so desktops that keep a history of notifications don't keep it. A notification never
//! names the room: with a blank password, its id is all someone needs to join it.

/// What a notification says: only as much as `preview` lets it ("off", "nick" or "message").
pub fn compose(preview: &str, nick: &str, text: &str, mentioned: bool) -> (String, String) {
    match preview {
        "message" => (
            if mentioned {
                format!("{nick} mentioned you")
            } else {
                nick.to_string()
            },
            text.to_string(),
        ),
        "nick" => (
            "chat".into(),
            if mentioned {
                format!("{nick} mentioned you")
            } else {
                format!("new message from {nick}")
            },
        ),
        _ => ("chat".into(), if mentioned { "you were mentioned" } else { "new message" }.into()),
    }
}

/// Opens a link in the browser, off the UI's thread: through the desktop portal where there is
/// one (so a sandbox stays as it is), otherwise the platform's opener. The browser fetches it
/// directly, not through chat's Tor or relays.
pub fn open_link(url: String) {
    std::thread::spawn(move || {
        #[cfg(target_os = "linux")]
        if bus::open_uri(&url) {
            return;
        }
        #[cfg(windows)]
        win::open_url(&url);
        #[cfg(not(windows))]
        {
            let program = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
            let _ = std::process::Command::new(program)
                .arg(&url)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        }
    });
}

/// Sent off the UI's thread: a hung bus costs nothing on screen.
pub fn send(title: String, body: String) {
    // A session bus on any Unix, as freedesktop's notification service has it.
    #[cfg(unix)]
    std::thread::spawn(move || bus::notify(&title, &body));
    #[cfg(windows)]
    win::notify(&title, &body);
}

/// The tray icon notifications come from, taken away as chat exits.
pub fn shutdown() {
    #[cfg(windows)]
    win::shutdown();
}

/// A secret on the clipboard (a room's id, an invite) by chat itself, where it can: on Windows,
/// kept out of the clipboard's history, the cloud clipboard and clipboard managers. False where it
/// can't, for the terminal to put it there instead.
pub fn clipboard_set(text: &str) -> bool {
    #[cfg(windows)]
    return win::clipboard_set(text);
    #[cfg(not(windows))]
    {
        let _ = text;
        false
    }
}

/// The secret [`clipboard_set`] put there, taken off unless something else was copied since.
pub fn clipboard_clear() {
    #[cfg(windows)]
    win::clipboard_clear();
}

#[cfg(windows)]
mod win {
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicU32, Ordering};
    use windows_sys::Win32::Foundation::{GlobalFree, HWND};
    use windows_sys::Win32::System::DataExchange::*;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
    use windows_sys::Win32::UI::Shell::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;
    use windows_sys::core::w;

    const WM_CHAT_NOTIFY: u32 = WM_APP + 1;
    const ICON_ID: u32 = 1;
    const START_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

    /// A notification's title and text, as long as the balloon takes them.
    struct Job {
        title: [u16; 64],
        body: [u16; 256],
    }

    /// UTF-16, cut to fit `out` with its NUL, never between the halves of a surrogate pair.
    fn wide_into(s: &str, out: &mut [u16]) {
        let mut w: Vec<u16> = s.encode_utf16().take(out.len() - 1).collect();
        if w.last().is_some_and(|c| (0xd800..0xdc00).contains(c)) {
            w.pop();
        }
        out[..w.len()].copy_from_slice(&w);
        out[w.len()] = 0;
    }

    fn icon_data(hwnd: HWND) -> NOTIFYICONDATAW {
        NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: ICON_ID,
            ..Default::default()
        }
    }

    /// The window the tray icon belongs to (as a number, to cross threads), made once on a thread
    /// of its own that runs its messages. None if there's no tray.
    fn window() -> Option<usize> {
        static WINDOW: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
        *WINDOW.get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                // SAFETY: the class, window and icon are made and used on this thread; a job comes
                // boxed from notify(), and is taken back here once.
                unsafe {
                    let wc = WNDCLASSW {
                        lpfnWndProc: Some(DefWindowProcW),
                        hInstance: GetModuleHandleW(null()),
                        lpszClassName: w!("chat_notify"),
                        ..Default::default()
                    };
                    RegisterClassW(&wc);
                    let hwnd = CreateWindowExW(
                        0,
                        wc.lpszClassName,
                        w!("chat"),
                        0,
                        0,
                        0,
                        0,
                        0,
                        null_mut(),
                        null_mut(),
                        wc.hInstance,
                        null(),
                    );
                    let mut nid = icon_data(hwnd);
                    nid.uFlags = NIF_ICON | NIF_TIP;
                    nid.hIcon = LoadIconW(null_mut(), IDI_APPLICATION);
                    wide_into("chat", &mut nid.szTip);
                    if hwnd.is_null() || Shell_NotifyIconW(NIM_ADD, &nid) == 0 {
                        if !hwnd.is_null() {
                            DestroyWindow(hwnd);
                        }
                        let _ = tx.send(None);
                        return;
                    }
                    nid.Anonymous.uVersion = NOTIFYICON_VERSION_4;
                    Shell_NotifyIconW(NIM_SETVERSION, &nid);
                    let _ = tx.send(Some(hwnd as usize));
                    let mut m: MSG = std::mem::zeroed();
                    while GetMessageW(&mut m, null_mut(), 0, 0) > 0 {
                        if m.message == WM_CHAT_NOTIFY {
                            let job = Box::from_raw(m.lParam as *mut Job);
                            let mut nid = icon_data(hwnd);
                            nid.uFlags = NIF_INFO;
                            nid.dwInfoFlags = NIIF_INFO | NIIF_RESPECT_QUIET_TIME;
                            nid.szInfoTitle = job.title;
                            nid.szInfo = job.body;
                            Shell_NotifyIconW(NIM_MODIFY, &nid);
                            continue;
                        }
                        TranslateMessage(&m);
                        DispatchMessageW(&m);
                    }
                }
            });
            rx.recv_timeout(START_WAIT).ok().flatten()
        })
    }

    pub fn notify(title: &str, body: &str) {
        let Some(hwnd) = window() else { return };
        let mut job = Box::new(Job {
            title: [0; 64],
            body: [0; 256],
        });
        wide_into(title, &mut job.title);
        wide_into(if body.is_empty() { " " } else { body }, &mut job.body);
        let job = Box::into_raw(job);
        // SAFETY: the window's thread takes the job back; if it isn't posted, it's taken back here.
        unsafe {
            if PostMessageW(hwnd as HWND, WM_CHAT_NOTIFY, 0, job as isize) == 0 {
                drop(Box::from_raw(job));
            }
        }
    }

    pub fn shutdown() {
        if let Some(hwnd) = window() {
            // SAFETY: the icon added on the window's thread, taken away.
            unsafe { Shell_NotifyIconW(NIM_DELETE, &icon_data(hwnd as HWND)) };
        }
    }

    /// The clipboard's sequence number once chat put a secret there, or 0.
    static SEQ: AtomicU32 = AtomicU32::new(0);

    /// `data` in memory the clipboard takes over once it's set.
    unsafe fn global(data: &[u8]) -> *mut core::ffi::c_void {
        // SAFETY: the caller's; the block is data.len() bytes.
        unsafe {
            let h = GlobalAlloc(GMEM_MOVEABLE, data.len());
            let p = if h.is_null() { null_mut() } else { GlobalLock(h) };
            if p.is_null() {
                if !h.is_null() {
                    GlobalFree(h);
                }
                return null_mut();
            }
            std::ptr::copy_nonoverlapping(data.as_ptr(), p.cast(), data.len());
            GlobalUnlock(h);
            h
        }
    }

    /// A format that tells Windows what to do with the rest, set to `value`.
    unsafe fn flag(name: windows_sys::core::PCWSTR, value: u32) {
        // SAFETY: the clipboard is open; it owns the block once it's set.
        unsafe {
            let fmt = RegisterClipboardFormatW(name);
            let h = if fmt == 0 { null_mut() } else { global(&value.to_ne_bytes()) };
            if !h.is_null() && SetClipboardData(fmt, h).is_null() {
                GlobalFree(h);
            }
        }
    }

    pub fn clipboard_set(text: &str) -> bool {
        let mut w: zeroize::Zeroizing<Vec<u16>> = zeroize::Zeroizing::new(text.encode_utf16().chain([0]).collect());
        let bytes: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(w.iter().flat_map(|c| c.to_ne_bytes()).collect());
        zeroize::Zeroize::zeroize(&mut *w);
        // SAFETY: the clipboard is opened and closed here, and owns each block once it's set.
        unsafe {
            let h = global(&bytes);
            if h.is_null() {
                return false;
            }
            if OpenClipboard(null_mut()) == 0 {
                GlobalFree(h);
                return false;
            }
            EmptyClipboard();
            if SetClipboardData(u32::from(CF_UNICODETEXT), h).is_null() {
                CloseClipboard();
                GlobalFree(h);
                return false;
            }
            // Clipboard history (Win+V), the cloud clipboard and clipboard managers keep what's
            // copied: these keep the text out of all three.
            flag(w!("ExcludeClipboardContentFromMonitorProcessing"), 0);
            flag(w!("CanIncludeInClipboardHistory"), 0);
            flag(w!("CanUploadToCloudClipboard"), 0);
            CloseClipboard();
            SEQ.store(GetClipboardSequenceNumber(), Ordering::Release);
        }
        true
    }

    pub fn clipboard_clear() {
        let seq = SEQ.swap(0, Ordering::AcqRel);
        // SAFETY: as above.
        unsafe {
            if seq != 0 && GetClipboardSequenceNumber() == seq && OpenClipboard(null_mut()) != 0 {
                EmptyClipboard();
                CloseClipboard();
            }
        }
    }

    pub fn open_url(url: &str) {
        let w: Vec<u16> = url.encode_utf16().chain([0]).collect();
        // SAFETY: both strings are NUL-ended.
        unsafe { ShellExecuteW(null_mut(), w!("open"), w.as_ptr(), null(), null(), SW_SHOWNORMAL) };
    }
}

#[cfg(unix)]
mod bus {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;
    use std::time::Duration;

    /// The connection, kept between notifications; its serial numbers go up.
    static BUS: Mutex<Option<(UnixStream, u32)>> = Mutex::new(None);
    const TIMEOUT: Duration = Duration::from_millis(300);
    const MSG_MAX: usize = 4096;

    /// A D-Bus message being written, little-endian. Values are aligned from its start.
    #[derive(Default)]
    struct Msg(Vec<u8>);

    impl Msg {
        fn pad(&mut self, align: usize) {
            while !self.0.len().is_multiple_of(align) {
                self.0.push(0);
            }
        }
        fn u32(&mut self, v: u32) {
            self.pad(4);
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        fn str(&mut self, s: &str) {
            self.u32(s.len() as u32);
            self.0.extend_from_slice(s.as_bytes());
            self.0.push(0);
        }
        fn sig(&mut self, s: &str) {
            self.0.push(s.len() as u8);
            self.0.extend_from_slice(s.as_bytes());
            self.0.push(0);
        }
        /// A header field: its code, then its value as a variant.
        fn field(&mut self, code: u8, kind: &str, value: &str) {
            self.pad(8);
            self.0.push(code);
            self.sig(kind);
            if kind == "g" { self.sig(value) } else { self.str(value) }
        }
    }

    /// A method call. `body` was written from offset 0, which aligns its values as they are at the
    /// 8-byte boundary the body starts on.
    /// `to`: the destination, object path, interface and member.
    fn call(serial: u32, flags: u8, to: [&str; 4], sig: Option<&str>, body: &[u8]) -> Vec<u8> {
        let [dest, path, iface, member] = to;
        let mut m = Msg::default();
        m.0.extend_from_slice(&[b'l', 1, flags, 1]);
        m.u32(body.len() as u32);
        m.u32(serial);
        let len_at = m.0.len();
        m.u32(0);
        m.pad(8);
        let start = m.0.len();
        m.field(1, "o", path);
        m.field(2, "s", iface);
        m.field(3, "s", member);
        m.field(6, "s", dest);
        if let Some(s) = sig {
            m.field(8, "g", s);
        }
        let fields = (m.0.len() - start) as u32;
        m.0[len_at..len_at + 4].copy_from_slice(&fields.to_le_bytes());
        m.pad(8);
        m.0.extend_from_slice(body);
        m.0
    }

    /// The session bus's socket: the first unix: path or abstract name in DBUS_SESSION_BUS_ADDRESS
    /// (its values %-escaped), otherwise $XDG_RUNTIME_DIR/bus.
    fn connect_bus() -> Option<UnixStream> {
        let env = std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap_or_default();
        let unescape = |v: &str| -> Option<Vec<u8>> {
            let b = v.as_bytes();
            let mut out = Vec::new();
            let mut i = 0;
            while i < b.len() {
                if b[i] == b'%' && i + 2 < b.len() {
                    out.push(u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).ok()?, 16).ok()?);
                    i += 3;
                } else {
                    out.push(b[i]);
                    i += 1;
                }
            }
            (!out.is_empty()).then_some(out)
        };
        let mut sock = None;
        'addrs: for a in env.split(';').filter_map(|a| a.strip_prefix("unix:")) {
            for kv in a.split(',') {
                // Abstract names are Linux's alone.
                #[cfg(target_os = "linux")]
                if let Some(v) = kv.strip_prefix("abstract=").and_then(unescape) {
                    use std::os::linux::net::SocketAddrExt;
                    let addr = std::os::unix::net::SocketAddr::from_abstract_name(&v).ok()?;
                    sock = UnixStream::connect_addr(&addr).ok();
                    break 'addrs;
                }
                if let Some(v) = kv.strip_prefix("path=").and_then(unescape) {
                    sock = UnixStream::connect(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(&v)).ok();
                    break 'addrs;
                }
            }
        }
        let s = match sock {
            Some(s) => s,
            None => {
                let rt = std::env::var("XDG_RUNTIME_DIR").ok().filter(|r| r.starts_with('/'))?;
                UnixStream::connect(format!("{rt}/bus")).ok()?
            }
        };
        s.set_read_timeout(Some(TIMEOUT)).ok()?;
        s.set_write_timeout(Some(TIMEOUT)).ok()?;
        Some(s)
    }

    /// EXTERNAL: the bus checks the uid the kernel reports for the socket, sent as hex of its digits.
    fn open() -> Option<(UnixStream, u32)> {
        let mut s = connect_bus()?;
        // SAFETY: it can't fail and touches no memory.
        let uid = unsafe { libc::geteuid() }.to_string();
        let hex: String = uid.bytes().map(|b| format!("{b:02x}")).collect();
        s.write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes()).ok()?;
        let mut line = String::new();
        BufReader::new(&s).take(160).read_line(&mut line).ok()?;
        if !line.starts_with("OK ") {
            return None;
        }
        s.write_all(b"BEGIN\r\n").ok()?;
        let hello = call(
            1,
            0,
            ["org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello"],
            None,
            &[],
        );
        s.write_all(&hello).ok()?;
        Some((s, 1))
    }

    /// Replies and signals (Hello's answer, NameAcquired, an error) are read and dropped, so they
    /// never pile up. False once the bus has closed the connection.
    fn drain(s: &mut UnixStream) -> bool {
        let _ = s.set_nonblocking(true);
        let mut junk = [0u8; 1024];
        let open = loop {
            match s.read(&mut junk) {
                Ok(0) => break false,
                Ok(_) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break true,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break false,
            }
        };
        let _ = s.set_nonblocking(false);
        open
    }

    fn escape(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
    }

    /// A message's REPLY_SERIAL header field (code 5, a u32), read with every index checked.
    fn reply_serial(h: &[u8], flen: usize) -> Option<u32> {
        let align = |p: usize, a: usize| p.div_ceil(a) * a;
        let rd = |p: usize| -> Option<u32> {
            let b: [u8; 4] = h.get(p..p + 4)?.try_into().ok()?;
            Some(if h[0] == b'l' {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            })
        };
        let mut p = 16;
        while p + 2 < 16 + flen {
            p = align(p, 8);
            let (code, sl, sig) = (*h.get(p)?, *h.get(p + 1)? as usize, *h.get(p + 2)?);
            p += 2 + sl + 1;
            match sig {
                b'u' => {
                    p = align(p, 4);
                    if code == 5 {
                        return rd(p);
                    }
                    p += 4;
                }
                b's' | b'o' => {
                    p = align(p, 4);
                    p += 4 + rd(p)? as usize + 1;
                }
                b'g' => p += 1 + *h.get(p)? as usize + 1,
                _ => return None,
            }
        }
        None
    }

    /// The answer to call `serial`: Some(true) for a return, Some(false) for an error, None if none
    /// came in time.
    fn reply_to(s: &mut UnixStream, serial: u32) -> Option<bool> {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let mut buf: Vec<u8> = Vec::new();
        let align = |p: usize, a: usize| p.div_ceil(a) * a;
        loop {
            let mut off = 0;
            while buf.len() - off >= 16 {
                let h = &buf[off..];
                let rd = |b: &[u8]| {
                    let b: [u8; 4] = b.try_into().expect("4 bytes");
                    if h[0] == b'l' {
                        u32::from_le_bytes(b)
                    } else {
                        u32::from_be_bytes(b)
                    }
                };
                let (body, flen) = (rd(&h[4..8]) as usize, rd(&h[12..16]) as usize);
                let total = align(16 + flen, 8) + body;
                if h.len() < total {
                    break;
                }
                if (h[1] == 2 || h[1] == 3) && reply_serial(h, flen) == Some(serial) {
                    return Some(h[1] == 2);
                }
                off += total;
            }
            buf.drain(..off);
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return None;
            }
            let _ = s.set_read_timeout(Some(left));
            let mut chunk = [0u8; 2048];
            match s.read(&mut chunk) {
                Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                _ => return None,
            }
        }
    }

    /// org.freedesktop.portal.OpenURI. False if there's no bus or the portal said no; a portal still
    /// starting gets the link once it's up, so no answer in time counts as taken.
    // The desktop portal is asked on Linux; macOS's open needs no bus.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn open_uri(url: &str) -> bool {
        let mut args = Msg::default();
        args.str("");
        args.str(url);
        args.u32(0);
        args.pad(8);
        let Ok(mut bus) = BUS.lock() else { return false };
        if bus.is_none() {
            *bus = open();
        }
        let Some((s, serial)) = bus.as_mut() else { return false };
        *serial += 1;
        let to = [
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.OpenURI",
            "OpenURI",
        ];
        let m = call(*serial, 0, to, Some("ssa{sv}"), &args.0);
        if !drain(s) || s.write_all(&m).is_err() {
            *bus = None;
            return false;
        }
        let answer = reply_to(s, *serial);
        let _ = s.set_read_timeout(Some(TIMEOUT));
        answer.unwrap_or(true)
    }

    pub fn notify(title: &str, body: &str) {
        let mut args = Msg::default();
        args.str("chat");
        args.u32(0);
        args.str("");
        args.str(&title.chars().take(150).collect::<String>());
        args.str(&escape(&body.chars().take(1300).collect::<String>()));
        args.u32(0);
        // hints: {"transient": true}. Shown, but not kept in the desktop's notification history.
        args.u32(0);
        let len_at = args.0.len() - 4;
        args.pad(8);
        let at = args.0.len();
        args.str("transient");
        args.sig("b");
        args.u32(1);
        let hints = (args.0.len() - at) as u32;
        args.0[len_at..len_at + 4].copy_from_slice(&hints.to_le_bytes());
        args.u32(u32::MAX);
        let Ok(mut bus) = BUS.lock() else { return };
        // Once more on a new connection if the bus has dropped the old one.
        for _ in 0..2 {
            if bus.is_none() {
                *bus = open();
            }
            let Some((s, serial)) = bus.as_mut() else { return };
            *serial += 1;
            let m = call(
                *serial,
                1,
                [
                    "org.freedesktop.Notifications",
                    "/org/freedesktop/Notifications",
                    "org.freedesktop.Notifications",
                    "Notify",
                ],
                Some("susssasa{sv}i"),
                &args.0,
            );
            if m.len() <= MSG_MAX && drain(s) && s.write_all(&m).is_ok() {
                return;
            }
            *bus = None;
        }
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn messages_are_laid_out_as_the_bus_reads_them() {
            let m = super::call(7, 1, ["d", "/p", "i", "m"], Some("s"), &[1, 0, 0, 0]);
            assert_eq!(&m[..4], &[b'l', 1, 1, 1]);
            assert_eq!(u32::from_le_bytes(m[4..8].try_into().unwrap()), 4, "the body's length");
            assert_eq!(u32::from_le_bytes(m[8..12].try_into().unwrap()), 7, "the serial");
            assert_eq!(m.len() % 8, 4, "the body starts on 8 bytes");
            assert_eq!(&m[m.len() - 4..], &[1, 0, 0, 0]);
        }
    }
}
