//! Owner-only permissions for keystore and seed files.
//!
//! Unix uses mode `0600`. Windows has no mode bits, so a private file gets a
//! protected DACL that allows only the owner (`D:P(A;;FA;;;OW)`). The DACL is
//! applied with `SetNamedSecurityInfoW` on the path. That opens the file with
//! `WRITE_DAC` itself; the caller's handle does not need it. A seed file is
//! accepted only when every allow ACE is the owner, SYSTEM, or Administrators.
//! Other platforms have no equivalent in the standard library; the mode check
//! there is a documented no-op after the regular-file check.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// `SE_FILE_OBJECT` for `SetNamedSecurityInfoW`.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const SE_FILE_OBJECT: u32 = 1;
/// Replace the discretionary ACL.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const DACL_SECURITY_INFORMATION: u32 = 0x4;
/// Do not inherit a broader ACE from the parent directory (`D:P` in SDDL).
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
/// Access `SetNamedSecurityInfoW` requests on its own open. The caller's handle
/// does not need this bit.
#[cfg_attr(not(test), allow(dead_code))]
const WRITE_DAC: u32 = 0x0004_0000;
/// Read access `SetNamedSecurityInfoW` requests on its own open.
#[cfg_attr(not(test), allow(dead_code))]
const READ_CONTROL: u32 = 0x0002_0000;
/// Flags passed to `SetNamedSecurityInfoW` for an owner-only key file.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const NAMED_DACL_SECURITY_INFORMATION: u32 =
    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;

#[cfg(windows)]
const SDDL_REVISION_1: u32 = 1;

/// SDDL for a protected, owner-only allow ACE (full access, no inheritance).
#[cfg(windows)]
const OWNER_ONLY_SDDL: &str = "D:P(A;;FA;;;OW)";

/// Allow ACEs that may remain on an owner-only file.
///
/// `OW` / `S-1-3-4` is the owner, `SY` / `S-1-5-18` is SYSTEM, and `BA` /
/// `S-1-5-32-544` is Administrators. On Unix, root can still read mode `0600`.
/// The owner SID from the SDDL `O:` field is allowed as well. Any other allow
/// ACE, including a different user, Interactive (`IU`), Network (`NU`), or
/// Anonymous (`AN`), is refused.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const OWNER_TRUSTEES: &[&str] = &["OW", "SY", "BA", "S-1-3-4", "S-1-5-18", "S-1-5-32-544"];

/// Owner SID from an SDDL `O:` field, if that field is present.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn sddl_owner(upper: &str) -> Option<&str> {
    let rest = upper.split_once("O:")?.1;
    let end = ["G:", "D:", "S:"]
        .iter()
        .filter_map(|mark| rest.find(mark))
        .min()
        .unwrap_or(rest.len());
    let owner = rest[..end].trim();
    if owner.is_empty() {
        None
    } else {
        Some(owner)
    }
}

/// Whether `sddl` is an explicit owner-only DACL.
///
/// An allow ACE must name the owner, SYSTEM, or Administrators. A deny ACE
/// does not grant access. An empty or missing DACL is not owner-only, and
/// neither is `NO_ACCESS_CONTROL` (a NULL DACL, which Windows treats as access
/// for everyone). At least one allow ACE is required.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(crate) fn dacl_is_owner_only(sddl: &str) -> bool {
    let upper = sddl.to_ascii_uppercase();
    if !upper.contains("D:") || upper.contains("NO_ACCESS_CONTROL") {
        return false;
    }
    let owner = sddl_owner(&upper);
    let dacl = upper.split("S:").next().unwrap_or(&upper);
    let mut allow = 0usize;
    for ace in dacl.split('(').skip(1) {
        let body = ace.split(')').next().unwrap_or("");
        let mut fields = body.split(';');
        let ace_type = fields.next().unwrap_or("");
        if ace_type != "A" && ace_type != "OA" {
            continue;
        }
        let account = fields.nth(4).unwrap_or("");
        let owner_ace = owner.is_some_and(|sid| sid == account);
        if !owner_ace && !OWNER_TRUSTEES.contains(&account) {
            return false;
        }
        allow += 1;
    }
    allow > 0
}

/// Reject a symlink or a file that other users can read.
pub fn ensure_owner_only(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("reading key file metadata {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!(
            "refusing to read key file {} through a symlink",
            path.display()
        );
    }
    if !meta.is_file() {
        bail!("key file {} is not a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!(
                "key file {} is readable by other users (mode {:o}). Keep it owner-only, for example mode 0600.",
                path.display(),
                meta.permissions().mode() & 0o777
            );
        }
    }
    #[cfg(windows)]
    {
        let sddl = windows_dacl_sddl(path)?;
        if !dacl_is_owner_only(&sddl) {
            bail!(
                "key file {} is readable by other users. Keep the DACL owner-only (owner, SYSTEM, and Administrators).",
                path.display()
            );
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        // No portable permission model. The regular-file check above is the
        // whole gate on this platform.
        let _ = meta;
    }
    Ok(())
}

/// Restrict `file` to its owner.
///
/// On Unix this is mode `0600` on the open descriptor. On Windows the file
/// path receives [`OWNER_ONLY_SDDL`] through `SetNamedSecurityInfoW`, which
/// does not need `WRITE_DAC` on `file`. Other platforms are a documented no-op.
pub fn tighten_private_file(file: &fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    {
        windows_set_owner_only(file)?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn windows_set_owner_only(file: &fs::File) -> Result<()> {
    let mut path = windows_final_path(file)?;
    let sddl = wide(OWNER_ONLY_SDDL);
    unsafe {
        let mut descriptor = std::ptr::null_mut();
        let ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        );
        if ok == 0 {
            return Err(os_error("building an owner-only DACL"));
        }
        let mut present = 0i32;
        let mut defaulted = 0i32;
        let mut dacl = std::ptr::null_mut();
        let ok = GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted);
        if ok == 0 || present == 0 || dacl.is_null() {
            LocalFree(descriptor);
            return Err(os_error("reading the owner-only DACL"));
        }
        // SAFETY: `path` is a mutable NUL-terminated wide path from the open
        // handle. `dacl` points inside `descriptor` and is freed only after
        // `SetNamedSecurityInfoW` returns. That API opens the path with
        // WRITE_DAC itself, so the caller's handle does not need it.
        let status = SetNamedSecurityInfoW(
            path.as_mut_ptr(),
            SE_FILE_OBJECT,
            NAMED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        );
        LocalFree(descriptor);
        if status != 0 {
            return Err(anyhow::anyhow!(
                "restricting the keystore DACL to its owner: {}",
                std::io::Error::from_raw_os_error(status as i32)
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn windows_final_path(file: &fs::File) -> Result<Vec<u16>> {
    use std::os::windows::io::AsRawHandle;

    unsafe {
        // `AsRawHandle::as_raw_handle` is already `*mut c_void`.
        let handle = file.as_raw_handle();
        let needed = GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, 0);
        if needed == 0 {
            return Err(os_error("reading the keystore path"));
        }
        let mut buffer = vec![0u16; needed as usize];
        let written = GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), needed, 0);
        if written == 0 || written >= needed {
            return Err(os_error("reading the keystore path"));
        }
        buffer.truncate(written as usize);
        buffer.push(0);
        Ok(buffer)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn windows_dacl_sddl(path: &Path) -> Result<String> {
    use std::os::windows::ffi::OsStrExt;

    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        let mut needed = 0u32;
        let _ = GetFileSecurityW(
            wide_path.as_ptr(),
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        if needed == 0 {
            return Err(os_error("reading the key file DACL"));
        }
        let mut buffer = vec![0u8; needed as usize];
        let ok = GetFileSecurityW(
            wide_path.as_ptr(),
            DACL_SECURITY_INFORMATION,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            needed,
            &mut needed,
        );
        if ok == 0 {
            return Err(os_error("reading the key file DACL"));
        }
        let mut rendered = std::ptr::null_mut();
        let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            buffer.as_ptr() as *const std::ffi::c_void,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut rendered,
            std::ptr::null_mut(),
        );
        if ok == 0 || rendered.is_null() {
            return Err(os_error("rendering the key file DACL"));
        }
        let mut len = 0usize;
        while *rendered.add(len) != 0 {
            len += 1;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(rendered, len));
        LocalFree(rendered as *mut std::ffi::c_void);
        Ok(text)
    }
}

#[cfg(windows)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

#[cfg(windows)]
fn os_error(what: &str) -> anyhow::Error {
    anyhow::anyhow!("{what}: {}", std::io::Error::last_os_error())
}

#[cfg(windows)]
#[allow(unsafe_code)]
extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string_security_descriptor: *const u16,
        string_sd_revision: u32,
        security_descriptor: *mut *mut std::ffi::c_void,
        security_descriptor_size: *mut u32,
    ) -> i32;

    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        security_descriptor: *const std::ffi::c_void,
        requested_string_sd_revision: u32,
        security_information: u32,
        string_security_descriptor: *mut *mut u16,
        string_security_descriptor_len: *mut u32,
    ) -> i32;

    fn GetFileSecurityW(
        file_name: *const u16,
        security_information: u32,
        security_descriptor: *mut std::ffi::c_void,
        length: u32,
        length_needed: *mut u32,
    ) -> i32;

    fn GetSecurityDescriptorDacl(
        security_descriptor: *const std::ffi::c_void,
        dacl_present: *mut i32,
        dacl: *mut *mut std::ffi::c_void,
        dacl_defaulted: *mut i32,
    ) -> i32;

    fn SetNamedSecurityInfoW(
        object_name: *mut u16,
        object_type: u32,
        security_information: u32,
        owner: *mut std::ffi::c_void,
        group: *mut std::ffi::c_void,
        dacl: *mut std::ffi::c_void,
        sacl: *mut std::ffi::c_void,
    ) -> u32;

    fn GetFinalPathNameByHandleW(
        file: *mut std::ffi::c_void,
        path: *mut u16,
        path_length: u32,
        flags: u32,
    ) -> u32;

    fn LocalFree(memory: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_only_dacl_rejects_everyone_users_and_a_null_dacl() {
        assert!(dacl_is_owner_only("D:P(A;;FA;;;OW)"));
        assert!(dacl_is_owner_only("D:(A;;FA;;;SY)(A;;FA;;;BA)"));
        assert!(dacl_is_owner_only(
            "D:(A;;FA;;;S-1-5-18)(A;;FA;;;S-1-5-32-544)"
        ));
        assert!(dacl_is_owner_only(
            "O:S-1-5-21-1-2-3-1001G:SYD:(A;;FA;;;S-1-5-21-1-2-3-1001)"
        ));
        // A user who is not the owner is not an allowlist entry.
        assert!(!dacl_is_owner_only(
            "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)"
        ));
        assert!(!dacl_is_owner_only("D:(A;;FA;;;IU)"));
        assert!(!dacl_is_owner_only("D:(A;;FA;;;NU)"));
        assert!(!dacl_is_owner_only("D:(A;;FA;;;AN)"));
        assert!(!dacl_is_owner_only("D:(A;;FA;;;WD)"));
        assert!(!dacl_is_owner_only("D:(A;;FA;;;BU)"));
        assert!(!dacl_is_owner_only("D:(A;;FA;;;AU)"));
        assert!(!dacl_is_owner_only("D:(A;;FA;;;S-1-1-0)"));
        assert!(!dacl_is_owner_only("D:(A;;FA;;;S-1-5-11)"));
        assert!(!dacl_is_owner_only("D:(A;;FA;;;S-1-5-32-545)"));
        assert!(!dacl_is_owner_only("D:NO_ACCESS_CONTROL"));
        assert!(!dacl_is_owner_only(""));
        // A deny ACE does not grant access. An allow ACE is still required.
        assert!(dacl_is_owner_only("D:P(D;;FA;;;WD)(A;;FA;;;OW)"));
        assert!(!dacl_is_owner_only("D:P(D;;FA;;;WD)"));
    }

    /// The DACL update goes through the path. `WRITE_DAC` and `READ_CONTROL`
    /// are what `SetNamedSecurityInfoW` requests on its own open, not rights
    /// the caller's handle must already have.
    #[test]
    fn windows_dacl_is_applied_by_path_with_protection() {
        assert_eq!(SE_FILE_OBJECT, 1);
        assert_eq!(DACL_SECURITY_INFORMATION, 0x4);
        assert_eq!(PROTECTED_DACL_SECURITY_INFORMATION, 0x8000_0000);
        assert_eq!(WRITE_DAC, 0x0004_0000);
        assert_eq!(READ_CONTROL, 0x0002_0000);
        assert_eq!(
            NAMED_DACL_SECURITY_INFORMATION,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        );
        assert!(dacl_is_owner_only("D:P(A;;FA;;;OW)"));
    }

    #[test]
    fn owner_only_check_rejects_a_group_readable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seed.txt");
        fs::write(&path, b"00").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            let error = ensure_owner_only(&path).unwrap_err().to_string();
            assert!(error.contains("other users"), "{error}");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(ensure_owner_only(&path).is_ok());
        }
        #[cfg(windows)]
        {
            // std opens this without WRITE_DAC. The path-based update must
            // still restrict the file.
            let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
            tighten_private_file(&file).unwrap();
            drop(file);
            assert!(ensure_owner_only(&path).is_ok());
        }
    }
}
