// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! What this device is: its id, which a signing key made from a password is made with,
//! so the same password gives the same key on this device.

/// This device's id: the machine id on Linux and the BSDs (systemd's, or D-Bus's), the hardware
/// UUID on macOS, and Windows' MachineGuid. Any program can read it, so it's no secret: it only
/// makes a password's key this device's own. None where there's none (a container without one).
pub fn machine_id() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let mut u = [0u8; 16];
        let wait = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: u is 16 bytes, as gethostuuid writes.
        if unsafe { libc::gethostuuid(u.as_mut_ptr(), &wait) } == 0 {
            return Some(crate::protocol::hex::encode(&u));
        }
        None
    }
    #[cfg(windows)]
    {
        windows_machine_guid()
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        // 32 hex digits; systemd writes "uninitialized" there until the first boot is done.
        ["/etc/machine-id", "/var/lib/dbus/machine-id"].iter().find_map(|path| {
            let text = std::fs::read_to_string(path).ok()?;
            let line = text.lines().next()?.trim_end_matches('\r');
            (line.len() == 32 && line.bytes().all(|c| c.is_ascii_hexdigit())).then(|| line.to_string())
        })
    }
}

#[cfg(windows)]
fn windows_machine_guid() -> Option<String> {
    // The 64-bit registry view, so a 32-bit build reads the same value.
    let out = std::process::Command::new("reg")
        .args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid", "/reg:64"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find(|l| l.trim_start().starts_with("MachineGuid"))
        .and_then(|l| l.split_whitespace().last())
        .map(str::to_string)
}

/// What locks a save to this device: a secret only this device can unseal again. On Linux that's
/// systemd's credential service (systemd 256 or later), which seals for this user with the TPM where
/// there is one, plus systemd's own key, so it needs no access to the TPM's device.
pub mod lock {
    use zeroize::Zeroizing;

    pub const SECRET_LEN: usize = 32;
    /// The sealed form: "SYSD", 'T' (the TPM and systemd's key) or 'H' (systemd's key alone), then
    /// the credential in base64, as systemd gave it.
    const SYSD: &[u8; 4] = b"SYSD";
    /// Sealed by speaking to the TPM directly.
    const DIRECT: &[u8; 4] = b"TPMD";
    #[cfg(target_os = "linux")]
    const CREDS_SOCKET: &str = "/run/systemd/io.systemd.Credentials";
    #[cfg(target_os = "linux")]
    const CRED_NAME: &str = "chat-save";
    const NO_SERVICE: &str = "there's no systemd credential service (systemd 256 or later has one)";

    #[cfg(target_os = "linux")]
    const TPM_DEVICE: &str = "/dev/tpmrm0";

    /// How a save is locked here: through systemd's credential service (with the TPM, or with
    /// systemd's own key alone), or by speaking to the TPM directly.
    #[cfg(target_os = "linux")]
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mech {
        Systemd { tpm: bool },
        Direct,
    }

    #[cfg(target_os = "linux")]
    fn can(path: &str, mode: libc::c_int) -> bool {
        let c = std::ffi::CString::new(path).expect("no NUL");
        // SAFETY: access only reads the path.
        unsafe { libc::access(c.as_ptr(), mode) == 0 }
    }

    #[cfg(target_os = "linux")]
    fn have_tpm2() -> bool {
        std::path::Path::new("/sys/class/tpmrm/tpmrm0").exists()
    }

    /// This user's name, where it's plain enough to put in a command (the portable characters).
    #[cfg(target_os = "linux")]
    fn user() -> Option<String> {
        std::env::var("USER").ok().filter(|u| plain(u))
    }

    #[cfg(target_os = "linux")]
    fn plain(s: &str) -> bool {
        !s.is_empty() && !s.starts_with('-') && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    }

    /// The group the TPM's device is open to, if one, and whether /etc/group lists this user in it
    /// (joined since this login began, so not yet in this process's groups).
    #[cfg(target_os = "linux")]
    fn tpm_group(m: &std::fs::Metadata) -> Option<(String, bool)> {
        use std::os::unix::fs::MetadataExt;
        if m.gid() == 0 || m.mode() & 0o060 != 0o060 {
            return None;
        }
        let user = user();
        let groups = std::fs::read_to_string("/etc/group").ok()?;
        groups.lines().find_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            (f.nth(1)?.parse::<u32>().ok()? == m.gid()).then(|| {
                let listed = f.next().is_some_and(|ms| ms.split(',').any(|u| Some(u) == user.as_deref()));
                (name.to_string(), listed)
            })
        })
    }

    /// Why the TPM can't be opened, and what would fix that.
    #[cfg(target_os = "linux")]
    fn tpm_closed() -> String {
        let Ok(m) = std::fs::metadata(TPM_DEVICE) else {
            return if have_tpm2() {
                format!("the TPM's device, {TPM_DEVICE}, is missing")
            } else {
                format!("there's no TPM 2.0 here, and {NO_SERVICE}")
            };
        };
        match tpm_group(&m) {
            Some((g, true)) => format!("{TPM_DEVICE}, the TPM, is open to the {g} group, which you joined after logging in: log in again"),
            Some((g, false)) => {
                let user = user().unwrap_or_else(|| "YOU".into());
                format!("{TPM_DEVICE}, the TPM, is only open to the {g} group: join it (as root, usermod -aG {g} {user}) and log in again")
            }
            None => format!(
                "{TPM_DEVICE}, the TPM, is only open to root here: tpm2-tss's udev rule opens it to the tss group, which you can then join"
            ),
        }
    }

    /// The command that opens the TPM to this user, where only its device's permissions are in the
    /// way, for the user to run as root through whichever of doas, sudo or su they use: chat can't
    /// run it itself, since its sandbox keeps those from giving root. It takes effect once the user
    /// logs in again. The script has no single quotes, so it goes in them whole.
    pub fn fix() -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            if mechanism().is_ok() {
                return None;
            }
            let m = std::fs::metadata(TPM_DEVICE).ok()?;
            let user = user()?;
            let script = match tpm_group(&m) {
                Some((_, true)) => return None,
                Some((g, false)) if plain(&g) => format!("usermod -aG {g} {user}"),
                Some(_) => return None,
                None => opener(&user),
            };
            Some(format!("sh -c '{script}'"))
        }
        #[cfg(not(target_os = "linux"))]
        None
    }

    /// tpm2-tss's udev rule for the TPM's resource manager, then the tss group, the device opened
    /// to it now (the rule applies from the next boot), and the user in the group.
    #[cfg(target_os = "linux")]
    fn opener(user: &str) -> String {
        let rule = r#"KERNEL==\"tpmrm[0-9]*\", MODE=\"0660\", GROUP=\"tss\""#;
        format!(
            "groupadd -f tss && echo \"{rule}\" > /etc/udev/rules.d/60-tpm-tss.rules && chgrp tss {TPM_DEVICE} \
             && chmod 660 {TPM_DEVICE} && usermod -aG tss {user}"
        )
    }

    /// systemd's service where it's open to this user, since it adds systemd's own key and the
    /// user's id and needs no tss group. Without it, the TPM itself. Checked without connecting to
    /// the service, since each connection starts it, and the journal says so.
    #[cfg(target_os = "linux")]
    fn mechanism() -> Result<Mech, String> {
        let service = std::fs::metadata(CREDS_SOCKET).is_ok_and(|m| std::os::unix::fs::FileTypeExt::is_socket(&m.file_type()));
        if service && can(CREDS_SOCKET, libc::W_OK) {
            return Ok(Mech::Systemd { tpm: have_tpm2() });
        }
        if can(TPM_DEVICE, libc::R_OK | libc::W_OK) {
            return Ok(Mech::Direct);
        }
        Err(tpm_closed())
    }

    /// What sealing here would use, or why it can't.
    pub fn available() -> Result<&'static str, String> {
        #[cfg(target_os = "linux")]
        {
            Ok(match mechanism()? {
                Mech::Systemd { tpm: true } => {
                    "this computer's TPM 2.0, through systemd's credential service: it takes the TPM, systemd's own key \
                     (only root can read it) and your user id to unseal"
                }
                Mech::Systemd { tpm: false } => {
                    "systemd's credential service, with systemd's own key, which only root can read. There's no TPM 2.0 \
                     here, so root, or anyone with a copy of the whole disk, could get past the device part, leaving \
                     only the passphrase"
                }
                Mech::Direct => {
                    "this computer's TPM 2.0, which chat speaks to itself (/dev/tpmrm0), with no systemd credential \
                     service here: the secret is sealed under a key the TPM never lets out, and crosses the TPM's bus \
                     encrypted"
                }
            })
        }
        #[cfg(windows)]
        return Ok(windows::uses(windows::tpm_here()));
        #[cfg(target_os = "macos")]
        return Err(MAC.into());
        #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
        Err("a device lock is only built for Linux, Windows and macOS".into())
    }

    /// Apple's frameworks reach the Secure Enclave, and chat's builds don't link them.
    #[cfg(target_os = "macos")]
    const MAC: &str = "macOS: chat can't reach the Secure Enclave yet, so a save can't be locked to this Mac";

    /// What this device keeps for a sealed secret, destroyed: a save's device file is going, or
    /// being replaced. Only Windows' TPM keeps anything (a key for each save).
    pub fn forget(sealed: &[u8]) {
        #[cfg(windows)]
        windows::forget(sealed);
        #[cfg(not(windows))]
        let _ = sealed;
    }

    /// One TPM command and its answer, through the kernel's resource manager.
    #[cfg(target_os = "linux")]
    fn tpm_transmit(dev: &mut std::fs::File) -> impl FnMut(&[u8]) -> Result<Vec<u8>, String> + '_ {
        use std::io::{Read, Write};
        move |cmd| {
            dev.write_all(cmd).map_err(|e| format!("the TPM: {e}"))?;
            let mut rsp = vec![0u8; 4096];
            let n = dev.read(&mut rsp).map_err(|e| format!("the TPM: {e}"))?;
            rsp.truncate(n);
            Ok(rsp)
        }
    }

    #[cfg(target_os = "linux")]
    fn open_tpm() -> Result<std::fs::File, String> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(TPM_DEVICE)
            .map_err(|_| tpm_closed())
    }

    /// What would lose a save locked here for good, besides its `device` file being deleted and
    /// the computer breaking or being lost.
    pub fn losses() -> Vec<&'static str> {
        // Nothing can lose a save where none can be locked (macOS).
        #[cfg_attr(not(any(target_os = "linux", windows)), allow(unused_mut))]
        let mut out = Vec::new();
        #[cfg(target_os = "linux")]
        {
            let m = mechanism().ok();
            let direct = m == Some(Mech::Direct);
            // Sealed by the TPM alone, the save only needs the TPM: none of systemd's or the OS's parts.
            if !direct && machine_id_transient() {
                out.push(
                    "the computer restarts: its machine id is made anew at each boot (/etc/machine-id is kept in memory \
                     here), so unless it's set to the same one every time, the next restart loses the save",
                );
            }
            if m != Some(Mech::Systemd { tpm: false }) {
                out.extend([
                    "the TPM is cleared: in the firmware settings, by a tool like tpm2_clear, or by a firmware update \
                     (some BIOS and TPM updates clear it)",
                    "the motherboard is replaced, or the CPU where the TPM is part of it (AMD's fTPM), or the firmware \
                     switches to another TPM",
                ]);
            }
            // The credential takes in systemd's key, the user's name and id, and the machine id.
            if !direct {
                out.extend([
                    "the OS is reinstalled, or systemd's key, /var/lib/systemd/credential.secret, is deleted",
                    "your user name, your user id or the machine id (/etc/machine-id) changes",
                ]);
            }
        }
        #[cfg(windows)]
        if windows::tpm_here() {
            out.extend([
                "the TPM is cleared: in the firmware settings, from Windows (Clear TPM, in Windows Security), or by a \
                 firmware update (some BIOS and TPM updates clear it)",
                "the motherboard is replaced, or the CPU where the TPM is part of it (AMD's fTPM), or the firmware \
                 switches to another TPM",
                "Windows is reinstalled or reset, or your Windows profile is deleted",
            ]);
        } else {
            // DPAPI's keys are sealed with the account's password, which an administrator's reset doesn't know.
            out.extend([
                "Windows is reinstalled or reset, or your Windows profile is deleted",
                "an administrator resets your Windows password (changing it yourself is fine)",
            ]);
        }
        out
    }

    /// /etc/machine-id made anew at each boot: on a file system of its own, or in memory.
    #[cfg(target_os = "linux")]
    #[allow(clippy::unnecessary_cast)] // f_type's type differs between architectures
    fn machine_id_transient() -> bool {
        use std::os::unix::fs::MetadataExt;
        let (Ok(id), Ok(etc)) = (std::fs::metadata("/etc/machine-id"), std::fs::metadata("/etc")) else {
            return false;
        };
        if id.dev() != etc.dev() {
            return true;
        }
        // SAFETY: statfs writes into the struct it's given; the path is a NUL-ended literal.
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        unsafe { libc::statfs(c"/etc/machine-id".as_ptr(), &mut fs) == 0 && fs.f_type as i64 == libc::TMPFS_MAGIC as i64 }
    }

    /// Base64 only, so a damaged or planted file can't add anything to the request around it.
    fn blob_ok(s: &[u8]) -> bool {
        !s.is_empty() && s.len() <= 8192 && s.iter().all(|c| c.is_ascii_alphanumeric() || b"+/=".contains(c))
    }

    /// One varlink call: the request and a NUL, then the reply up to its NUL. The first call starts
    /// the service, and some TPMs are slow.
    #[cfg(target_os = "linux")]
    fn call(request: &str) -> Result<serde_json::Value, String> {
        use std::io::{Read, Write};
        let mut s =
            std::os::unix::net::UnixStream::connect(CREDS_SOCKET).map_err(|e| format!("can't reach systemd's credential service ({e})"))?;
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(60)));
        s.write_all(request.as_bytes())
            .and_then(|()| s.write_all(&[0]))
            .map_err(|_| "couldn't ask systemd's credential service".to_string())?;
        let mut reply = Zeroizing::new(Vec::new());
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => return Err("systemd's credential service didn't answer".into()),
                Ok(n) => {
                    reply.extend_from_slice(&buf[..n]);
                    if let Some(end) = reply.iter().position(|b| *b == 0) {
                        reply.truncate(end);
                        break;
                    }
                    if reply.len() > 65536 {
                        return Err("systemd's credential service gave an answer chat can't read".into());
                    }
                }
            }
        }
        serde_json::from_slice(&reply).map_err(|_| "systemd's credential service gave an answer chat can't read".to_string())
    }

    /// The reply's parameters, or why not.
    #[cfg(target_os = "linux")]
    fn params(reply: serde_json::Value, unsealing: bool) -> Result<serde_json::Value, String> {
        let errno = reply.pointer("/parameters/errnoName").and_then(|v| v.as_str()).map(String::from);
        if let Some(err) = reply.get("error").and_then(|e| e.as_str()) {
            let what = errno.unwrap_or_else(|| err.to_string());
            return Err(match err {
                "org.varlink.service.MethodNotFound" | "org.varlink.service.InterfaceNotFound" | "org.varlink.service.InvalidParameter" => {
                    "this systemd's credential service is too old to seal for one user (systemd 256 or later can)".into()
                }
                "io.systemd.Credentials.BadScope" | "io.systemd.Credentials.NoSuchUser" => "it was sealed for another user".into(),
                "io.systemd.Credentials.BadFormat" | "io.systemd.Credentials.NameMismatch" | "io.systemd.Credentials.NullKeyNotAllowed" => {
                    "it isn't a credential chat sealed".into()
                }
                "org.varlink.service.PermissionDenied" | "io.systemd.InteractiveAuthenticationRequired" => {
                    "systemd wants an administrator's permission for it".into()
                }
                _ if unsealing => format!(
                    "systemd couldn't unseal it ({what:.40}): it was sealed on another device, or this one's TPM or systemd's key has changed since"
                ),
                _ => format!("systemd couldn't seal it ({what:.40})"),
            });
        }
        reply
            .get("parameters")
            .filter(|p| p.is_object())
            .cloned()
            .ok_or_else(|| "systemd's credential service gave an answer chat can't read".into())
    }

    /// The secret sealed to this device, in the form a save's device file keeps.
    /// `secret` sealed to this device, then unsealed again to be sure it comes back.
    pub fn seal(secret: &[u8; SECRET_LEN]) -> Result<Vec<u8>, String> {
        let sealed = seal_once(secret)?;
        let r = match unseal(&sealed) {
            Ok(back) if crate::protocol::crypto::sodium::ct_eq(&back[..], secret) => return Ok(sealed),
            Ok(_) => Err("unsealing gave back something other than what was sealed".into()),
            Err(e) => Err(e),
        };
        forget(&sealed);
        r
    }

    fn seal_once(secret: &[u8; SECRET_LEN]) -> Result<Vec<u8>, String> {
        #[cfg(target_os = "linux")]
        {
            if mechanism()? == Mech::Direct {
                let mut dev = open_tpm()?;
                let mut out = DIRECT.to_vec();
                out.extend(crate::net::tpm2::seal(&mut tpm_transmit(&mut dev), secret)?);
                return Ok(out);
            }
            let uses = available()?;
            let data = Zeroizing::new(crate::protocol::base64::encode(secret));
            // No withKey: given one, systemd seals for the whole system whatever the scope. Left to
            // itself, a user-scoped credential takes systemd's own key, and the TPM where it can.
            let request = Zeroizing::new(
                serde_json::json!({"method": "io.systemd.Credentials.Encrypt", "parameters": {"name": CRED_NAME, "data": *data, "scope": "user"}})
                    .to_string(),
            );
            let p = params(call(&request)?, false)?;
            let blob = p.get("blob").and_then(|b| b.as_str()).filter(|b| blob_ok(b.as_bytes()));
            let blob = blob.ok_or("systemd's credential service gave back something chat can't keep")?;
            let mut out = SYSD.to_vec();
            out.push(if uses.starts_with("this computer's TPM") { b'T' } else { b'H' });
            out.extend_from_slice(blob.as_bytes());
            Ok(out)
        }
        #[cfg(windows)]
        return windows::seal(secret);
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = secret;
            Err(available().unwrap_err())
        }
    }

    /// The secret a device file holds, if this device can unseal it.
    pub fn unseal(sealed: &[u8]) -> Result<Zeroizing<[u8; SECRET_LEN]>, String> {
        #[cfg(windows)]
        if let Some(r) = windows::unseal(sealed) {
            return r;
        }
        #[cfg(target_os = "macos")]
        if !sealed.is_empty() {
            return Err("it was locked to another computer: this Mac can't unseal it".into());
        }
        if let Some(direct) = sealed.strip_prefix(&DIRECT[..]) {
            #[cfg(target_os = "linux")]
            {
                let mut dev = open_tpm()?;
                return crate::net::tpm2::unseal(&mut tpm_transmit(&mut dev), direct);
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = direct;
                return Err("it was sealed with a TPM on Linux".into());
            }
        }
        let Some(blob) = sealed.strip_prefix(&SYSD[..]).and_then(|b| b.get(1..)).filter(|b| blob_ok(b)) else {
            return Err("it isn't sealed in a way chat knows".into());
        };
        #[cfg(target_os = "linux")]
        {
            if !std::path::Path::new(CREDS_SOCKET).exists() {
                return Err(NO_SERVICE.into());
            }
            let blob = std::str::from_utf8(blob).map_err(|_| "it isn't sealed in a way chat knows")?;
            // Only a credential sealed for this user, and never one sealed with no key at all.
            let request = serde_json::json!({"method": "io.systemd.Credentials.Decrypt", "parameters": {"name": CRED_NAME, "blob": blob, "scope": "user", "allowNull": false}})
                .to_string();
            let p = params(call(&request)?, true)?;
            let data = p
                .get("data")
                .and_then(|d| d.as_str())
                .and_then(crate::protocol::base64::decode_strict);
            match data.map(Zeroizing::new) {
                Some(d) if d.len() == SECRET_LEN => Ok(Zeroizing::new(d[..].try_into().expect("32 bytes"))),
                _ => Err("systemd unsealed something that isn't chat's".into()),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = blob;
            Err(NO_SERVICE.into())
        }
    }

    /// Windows: a key this computer's TPM makes for the save and never lets out, through NCrypt's
    /// Platform Crypto Provider, or without a TPM, DPAPI. The sealed forms: "NCPT", the padding (an
    /// index into PADS), the length of the TPM key's name, the name, the ciphertext's length (2
    /// bytes, big-endian) and the ciphertext; or "DPAP" and a DPAPI blob.
    #[cfg(windows)]
    mod windows {
        use super::SECRET_LEN;
        use std::ptr::{null, null_mut};
        use windows_sys::Win32::Foundation::{GetLastError, LocalFree, NTE_BAD_DATA, NTE_NOT_SUPPORTED};
        use windows_sys::Win32::Security::Cryptography::*;
        use windows_sys::core::{HRESULT, PCWSTR};
        use zeroize::Zeroizing;

        const TPM_MAGIC: &[u8; 4] = b"NCPT";
        const DPAPI_MAGIC: &[u8; 4] = b"DPAP";
        const PAD_AT: usize = 4;
        const NAME_LEN_AT: usize = 5;
        const NAME_AT: usize = 6;
        /// All of the TPM form but the name and the ciphertext.
        const TPM_HEAD: usize = NAME_AT + 2;
        /// A TPM key's name: the prefix, then 16 random bytes in hex.
        const KEY_PREFIX: &str = "chat-";
        const KEY_NAME_LEN: usize = KEY_PREFIX.len() + 32;
        const RSA_BITS: u32 = 2048;
        const CT_MAX: usize = 512;
        /// An RSA_BITS key's public blob, and the TPM's platform type, with room to spare.
        const PUB_BLOB_MAX: usize = 1024;
        const TPM_TYPE_MAX: usize = 256;
        const DPAPI_LABEL: &[u8] = b"chat device lock v1";
        const OK: HRESULT = 0;

        /// TPMs and their drivers differ in which paddings they take, so the first one that works
        /// both ways is kept.
        const PADS: [(u32, PCWSTR); 3] = [
            (NCRYPT_PAD_OAEP_FLAG, BCRYPT_SHA256_ALGORITHM),
            (NCRYPT_PAD_OAEP_FLAG, BCRYPT_SHA1_ALGORITHM),
            (NCRYPT_PAD_PKCS1_FLAG, null()),
        ];

        /// The provider, if there's a TPM behind it: without one, opening it can still work.
        struct Provider(NCRYPT_PROV_HANDLE);

        impl Drop for Provider {
            fn drop(&mut self) {
                // SAFETY: the handle is the provider's own, freed once.
                unsafe { NCryptFreeObject(self.0) };
            }
        }

        fn open_tpm() -> Option<Provider> {
            let mut h: NCRYPT_PROV_HANDLE = 0;
            // SAFETY: the provider's handle and the property are written into what's given.
            unsafe {
                if NCryptOpenStorageProvider(&mut h, MS_PLATFORM_CRYPTO_PROVIDER, 0) != OK {
                    return None;
                }
                let p = Provider(h);
                let mut kind = [0u8; TPM_TYPE_MAX];
                let mut n = 0u32;
                (NCryptGetProperty(
                    p.0,
                    NCRYPT_PCP_PLATFORM_TYPE_PROPERTY,
                    kind.as_mut_ptr(),
                    kind.len() as u32,
                    &mut n,
                    0,
                ) == OK
                    && n > 0)
                    .then_some(p)
            }
        }

        pub fn tpm_here() -> bool {
            open_tpm().is_some()
        }

        pub fn uses(tpm: bool) -> &'static str {
            if tpm {
                "this computer's TPM: a key it makes for this save and never lets out, kept for your Windows account"
            } else {
                "DPAPI, which ties it to your Windows account on this computer. There's no TPM here, so an administrator, \
                 or anyone with a copy of the disk and your Windows password, could get past the device part, leaving \
                 only the passphrase"
            }
        }

        /// A TPM form: its padding, its key's name (NUL-ended, as NCrypt takes it) and its
        /// ciphertext. Only a name chat made is ever opened, so a planted file can't point it at
        /// another program's key.
        fn parse_tpm(s: &[u8]) -> Option<(usize, Vec<u16>, &[u8])> {
            if s.len() < TPM_HEAD || &s[..4] != TPM_MAGIC || usize::from(s[PAD_AT]) >= PADS.len() {
                return None;
            }
            let nl = usize::from(s[NAME_LEN_AT]);
            let name = s.get(NAME_AT..NAME_AT + nl)?;
            let hex = name.strip_prefix(KEY_PREFIX.as_bytes())?;
            if nl != KEY_NAME_LEN || !hex.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
                return None;
            }
            let cl = usize::from(u16::from_be_bytes([*s.get(NAME_AT + nl)?, *s.get(NAME_AT + nl + 1)?]));
            if cl == 0 || cl > CT_MAX || s.len() != TPM_HEAD + nl + cl {
                return None;
            }
            let wide = name.iter().map(|&c| u16::from(c)).chain([0]).collect();
            Some((usize::from(s[PAD_AT]), wide, &s[TPM_HEAD + nl..]))
        }

        fn status(what: &str, s: HRESULT) -> String {
            format!("{what} (0x{:08x})", s as u32)
        }

        fn oaep(pad: usize) -> BCRYPT_OAEP_PADDING_INFO {
            BCRYPT_OAEP_PADDING_INFO {
                pszAlgId: PADS[pad].1,
                pbLabel: null_mut(),
                cbLabel: 0,
            }
        }

        fn padding(pad: usize, info: &BCRYPT_OAEP_PADDING_INFO) -> *const core::ffi::c_void {
            if PADS[pad].1.is_null() {
                null()
            } else {
                (info as *const BCRYPT_OAEP_PADDING_INFO).cast()
            }
        }

        /// With the key's public half, outside the TPM: the TPM is only needed to unseal.
        fn rsa_encrypt(key: NCRYPT_KEY_HANDLE, pad: usize, secret: &[u8]) -> Result<Vec<u8>, HRESULT> {
            let mut public = [0u8; PUB_BLOB_MAX];
            let mut n = 0u32;
            let info = oaep(pad);
            let mut out = vec![0u8; CT_MAX];
            let mut len = 0u32;
            // SAFETY: each call writes only into the buffers given, with their lengths; the handles
            // made here are freed here.
            unsafe {
                let s = NCryptExportKey(
                    key,
                    0,
                    BCRYPT_RSAPUBLIC_BLOB,
                    null(),
                    public.as_mut_ptr(),
                    public.len() as u32,
                    &mut n,
                    0,
                );
                if s != OK {
                    return Err(s);
                }
                let mut alg: BCRYPT_ALG_HANDLE = null_mut();
                let st = BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_RSA_ALGORITHM, null(), 0);
                if st < 0 {
                    return Err(st);
                }
                let mut bk: BCRYPT_KEY_HANDLE = null_mut();
                let mut st = BCryptImportKeyPair(alg, null_mut(), BCRYPT_RSAPUBLIC_BLOB, &mut bk, public.as_ptr(), n, 0);
                if st >= 0 {
                    st = BCryptEncrypt(
                        bk,
                        secret.as_ptr(),
                        secret.len() as u32,
                        padding(pad, &info),
                        null_mut(),
                        0,
                        out.as_mut_ptr(),
                        out.len() as u32,
                        &mut len,
                        PADS[pad].0,
                    );
                    BCryptDestroyKey(bk);
                }
                BCryptCloseAlgorithmProvider(alg, 0);
                if st < 0 {
                    return Err(st);
                }
            }
            out.truncate(len as usize);
            Ok(out)
        }

        fn tpm_decrypt(key: NCRYPT_KEY_HANDLE, pad: usize, ct: &[u8]) -> Result<Zeroizing<[u8; SECRET_LEN]>, HRESULT> {
            let info = oaep(pad);
            let mut plain = Zeroizing::new([0u8; CT_MAX]);
            let mut n = 0u32;
            // SAFETY: it writes only into `plain`, with its length.
            let s = unsafe {
                NCryptDecrypt(
                    key,
                    ct.as_ptr(),
                    ct.len() as u32,
                    padding(pad, &info),
                    plain.as_mut_ptr(),
                    plain.len() as u32,
                    &mut n,
                    PADS[pad].0 | NCRYPT_SILENT_FLAG,
                )
            };
            match s {
                OK if n as usize == SECRET_LEN => Ok(Zeroizing::new(plain[..SECRET_LEN].try_into().expect("32 bytes"))),
                OK => Err(NTE_BAD_DATA),
                s => Err(s),
            }
        }

        fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
            CRYPT_INTEGER_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            }
        }

        fn dpapi_unseal(s: &[u8]) -> Result<Zeroizing<[u8; SECRET_LEN]>, String> {
            let (input, entropy) = (blob(s), blob(DPAPI_LABEL));
            let mut plain = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: null_mut(),
            };
            // SAFETY: DPAPI reads the blobs given and allocates the one it gives back, freed here.
            unsafe {
                if CryptUnprotectData(&input, null_mut(), &entropy, null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut plain) == 0 {
                    return Err(format!(
                        "DPAPI couldn't unseal it (error {}): it was sealed on another device or Windows account",
                        GetLastError()
                    ));
                }
                let got = std::slice::from_raw_parts_mut(plain.pbData, plain.cbData as usize);
                let r = (got.len() == SECRET_LEN)
                    .then(|| Zeroizing::new(got[..].try_into().expect("32 bytes")))
                    .ok_or_else(|| "DPAPI unsealed something that isn't chat's".to_string());
                zeroize::Zeroize::zeroize(got);
                LocalFree(plain.pbData.cast());
                r
            }
        }

        /// None for a form that isn't Windows', for the caller to say what it is.
        pub fn unseal(sealed: &[u8]) -> Option<Result<Zeroizing<[u8; SECRET_LEN]>, String>> {
            if let Some(d) = sealed.strip_prefix(&DPAPI_MAGIC[..]).filter(|d| !d.is_empty()) {
                return Some(dpapi_unseal(d));
            }
            if !sealed.starts_with(TPM_MAGIC) {
                return None;
            }
            let Some((pad, name, ct)) = parse_tpm(sealed) else {
                return Some(Err("it isn't sealed in a way chat on Windows knows".into()));
            };
            let Some(prov) = open_tpm() else {
                return Some(Err("it was sealed with a TPM, and there's none here".into()));
            };
            let mut key: NCRYPT_KEY_HANDLE = 0;
            // SAFETY: the name is NUL-ended; the key's handle is freed here.
            let s = unsafe { NCryptOpenKey(prov.0, &mut key, name.as_ptr(), 0, NCRYPT_SILENT_FLAG) };
            if s != OK {
                return Some(Err(status(
                    "its TPM key isn't here: it was sealed on another device or Windows account, or the TPM or the key is gone",
                    s,
                )));
            }
            let r = tpm_decrypt(key, pad, ct).map_err(|s| status("the TPM couldn't unseal it", s));
            // SAFETY: as above.
            unsafe { NCryptFreeObject(key) };
            Some(r)
        }

        fn dpapi_seal(secret: &[u8; SECRET_LEN]) -> Result<Vec<u8>, String> {
            let (input, entropy) = (blob(secret), blob(DPAPI_LABEL));
            let mut out = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: null_mut(),
            };
            // SAFETY: as in dpapi_unseal.
            unsafe {
                if CryptProtectData(&input, null(), &entropy, null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out) == 0 {
                    return Err(format!("DPAPI couldn't seal it (error {})", GetLastError()));
                }
                let mut v = DPAPI_MAGIC.to_vec();
                v.extend_from_slice(std::slice::from_raw_parts(out.pbData, out.cbData as usize));
                LocalFree(out.pbData.cast());
                Ok(v)
            }
        }

        /// A key the TPM makes and never lets out, then the first padding it unseals with.
        fn tpm_seal(prov: &Provider, secret: &[u8; SECRET_LEN]) -> Result<Vec<u8>, String> {
            let rnd: [u8; 16] = crate::protocol::crypto::sodium::random_array();
            let name = format!("{KEY_PREFIX}{}", crate::protocol::hex::encode(&rnd));
            let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
            let mut key: NCRYPT_KEY_HANDLE = 0;
            // SAFETY: the name is NUL-ended, and each property is read from what's given; the key's
            // handle is freed (or the key deleted) on every way out.
            unsafe {
                let s = NCryptCreatePersistedKey(prov.0, &mut key, BCRYPT_RSA_ALGORITHM, wide.as_ptr(), 0, 0);
                if s != OK {
                    return Err(status("the TPM couldn't make a key", s));
                }
                // The provider never lets a TPM key's private half out, so there's no export policy to set.
                let (bits, usage) = (RSA_BITS, NCRYPT_ALLOW_DECRYPT_FLAG);
                let mut s = NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (&bits as *const u32).cast(), 4, 0);
                if s == OK {
                    s = NCryptSetProperty(key, NCRYPT_KEY_USAGE_PROPERTY, (&usage as *const u32).cast(), 4, 0);
                }
                if s == OK {
                    s = NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG);
                }
                if s != OK {
                    NCryptFreeObject(key);
                    return Err(status("the TPM couldn't make a key", s));
                }
                let mut last = NTE_NOT_SUPPORTED;
                let mut found = None;
                for pad in 0..PADS.len() {
                    match rsa_encrypt(key, pad, secret).and_then(|ct| tpm_decrypt(key, pad, &ct).map(|back| (ct, back))) {
                        Ok((ct, back)) if crate::protocol::crypto::sodium::ct_eq(&back[..], secret) => {
                            found = Some((pad, ct));
                            break;
                        }
                        Ok(_) => {}
                        Err(e) => last = e,
                    }
                }
                let Some((pad, ct)) = found.filter(|(_, ct)| ct.len() <= CT_MAX) else {
                    NCryptDeleteKey(key, NCRYPT_SILENT_FLAG);
                    return Err(status("the TPM's key couldn't unseal what it sealed", last));
                };
                NCryptFreeObject(key);
                let mut out = TPM_MAGIC.to_vec();
                out.push(pad as u8);
                out.push(KEY_NAME_LEN as u8);
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(&(ct.len() as u16).to_be_bytes());
                out.extend_from_slice(&ct);
                Ok(out)
            }
        }

        /// With a TPM there, its failing is an error, never a reason to fall back to DPAPI.
        pub fn seal(secret: &[u8; SECRET_LEN]) -> Result<Vec<u8>, String> {
            match open_tpm() {
                Some(prov) => tpm_seal(&prov, secret),
                None => dpapi_seal(secret),
            }
        }

        pub fn forget(sealed: &[u8]) {
            let Some((_, name, _)) = parse_tpm(sealed) else { return };
            let mut h: NCRYPT_PROV_HANDLE = 0;
            // SAFETY: as in open_tpm and unseal; deleting a key frees its handle.
            unsafe {
                if NCryptOpenStorageProvider(&mut h, MS_PLATFORM_CRYPTO_PROVIDER, 0) != OK {
                    return;
                }
                let prov = Provider(h);
                let mut key: NCRYPT_KEY_HANDLE = 0;
                if NCryptOpenKey(prov.0, &mut key, name.as_ptr(), 0, NCRYPT_SILENT_FLAG) == OK {
                    NCryptDeleteKey(key, NCRYPT_SILENT_FLAG);
                }
            }
        }

        #[cfg(test)]
        mod tests {
            #[test]
            fn reads_only_a_tpm_form_chat_made() {
                let name = format!("{}{}", super::KEY_PREFIX, "0f".repeat(16));
                let mut s = super::TPM_MAGIC.to_vec();
                s.extend([1, name.len() as u8]);
                s.extend_from_slice(name.as_bytes());
                s.extend([0, 3, 7, 8, 9]);
                let (pad, wide, ct) = super::parse_tpm(&s).unwrap();
                assert_eq!((pad, wide.len(), ct), (1, name.len() + 1, &[7, 8, 9][..]));
                // Another program's key name, a padding there isn't, or a length that doesn't fit.
                let other = s.iter().map(|&b| if b == b'c' { b'x' } else { b }).collect::<Vec<_>>();
                assert!(super::parse_tpm(&other).is_none());
                let mut bad = s.clone();
                bad[super::PAD_AT] = 3;
                assert!(super::parse_tpm(&bad).is_none());
                assert!(super::parse_tpm(&s[..s.len() - 1]).is_none());
            }
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    mod tests {
        #[test]
        fn opener_writes_tpm2_tss_rule() {
            let s = super::opener("ida");
            assert!(!s.contains('\''), "fix puts it in single quotes");
            let echo = s
                .split(" > ")
                .next()
                .and_then(|c| c.split(" && ").nth(1))
                .expect("groupadd && echo ...");
            let out = std::process::Command::new("sh").args(["-c", echo]).output().expect("sh");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                "KERNEL==\"tpmrm[0-9]*\", MODE=\"0660\", GROUP=\"tss\"\n"
            );
            assert!(super::plain("ida.b_c-1") && !super::plain("-o") && !super::plain("a b") && !super::plain("a;b"));
        }
    }
}
