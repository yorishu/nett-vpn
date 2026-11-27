use std::os::windows::process::CommandExt;
use std::{
    path::{Path, PathBuf},
    process::Command,
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
};

pub(crate) fn crypt(data: &[u8], encrypt: bool) -> Result<Vec<u8>, String> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len().try_into().map_err(|_| "PROFILE TOO LARGE")?,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // DPAPI owns the output allocation; copy it before releasing it with LocalFree.
    unsafe {
        let ok = if encrypt {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(format!(
                "PROFILE ENCRYPTION FAILED - {}",
                std::io::Error::last_os_error()
            ));
        }
        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData as *mut _);
        Ok(result)
    }
}

pub(crate) fn root() -> Result<PathBuf, String> {
    std::env::var_os("LOCALAPPDATA")
        .map(|p| PathBuf::from(p).join("nett-vpn"))
        .ok_or_else(|| "LOCALAPPDATA NOT FOUND".into())
}

pub(crate) struct InstanceGuard(windows_sys::Win32::Foundation::HANDLE);
impl InstanceGuard {
    pub fn acquire(name: &str) -> Result<Option<Self>, String> {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError},
            System::Threading::CreateMutexW,
        };
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        unsafe {
            let handle = CreateMutexW(std::ptr::null(), 0, name.as_ptr());
            if handle.is_null() {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if GetLastError() == ERROR_ALREADY_EXISTS {
                CloseHandle(handle);
                return Ok(None);
            }
            Ok(Some(Self(handle)))
        }
    }
}
impl Drop for InstanceGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

pub(crate) fn secure_directory(root: &Path) -> Result<(), String> {
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let script = "$ErrorActionPreference='Stop'; $acl=New-Object System.Security.AccessControl.DirectorySecurity; $acl.SetAccessRuleProtection($true,$false); foreach($sid in @([System.Security.Principal.WindowsIdentity]::GetCurrent().User, (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')), (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))) { $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'); $acl.AddAccessRule($rule) }; [System.IO.Directory]::SetAccessControl($env:NETT_STORAGE,$acl)";
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("NETT_STORAGE", root)
        .creation_flags(0x08000000)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("CANNOT PROTECT PROFILE DIRECTORY".into());
    }
    Ok(())
}

fn unpack(root: &Path, data: &[u8]) -> Result<PathBuf, String> {
    let split = data
        .iter()
        .position(|b| *b == b'\n')
        .ok_or("INVALID SAVED PROFILE")?;
    let name = std::str::from_utf8(&data[..split]).map_err(|_| "INVALID PROFILE NAME")?;
    if !name.to_ascii_lowercase().ends_with(".conf")
        || name.len() > 20
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_=+.-".contains(&b))
    {
        return Err("INVALID SAVED PROFILE NAME".into());
    }
    let path = root.join(name);
    // The Windows service needs a persistent config path, protected by the directory ACL.
    if std::fs::read(&path).ok().as_deref() != Some(&data[split + 1..]) {
        std::fs::write(&path, &data[split + 1..]).map_err(|e| e.to_string())?;
    }
    Ok(path)
}

pub fn load() -> Result<Option<PathBuf>, String> {
    let root = root()?;
    let encrypted = match std::fs::read(root.join("profile.dpapi")) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    secure_directory(&root)?;
    let data = crypt(&encrypted, false)?;
    unpack(&root, &data).map(Some)
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_one_instance_can_hold_the_store_guard() {
        let name = format!("Local\\nett-test-{}", std::process::id());
        let first = super::InstanceGuard::acquire(&name).unwrap().unwrap();
        assert!(super::InstanceGuard::acquire(&name).unwrap().is_none());
        drop(first);
        assert!(super::InstanceGuard::acquire(&name).unwrap().is_some());
    }
    #[test]
    fn dpapi_roundtrip_and_tampering() {
        let secret = b"PrivateKey=example-secret-key";
        let encrypted = super::crypt(secret, true).unwrap();
        assert!(!encrypted.windows(secret.len()).any(|s| s == secret));
        assert_eq!(super::crypt(&encrypted, false).unwrap(), secret);
        let mut corrupted = encrypted;
        corrupted[20] ^= 0xff;
        assert!(super::crypt(&corrupted, false).is_err());
    }

    #[test]
    fn restored_profile_survives_original_deletion_and_rejects_traversal() {
        let root = std::env::temp_dir().join(format!("nett-storage-test-{}", std::process::id()));
        super::secure_directory(&root).unwrap();
        let encrypted = super::crypt(b"test.conf\n[Interface]\nPrivateKey=example", true).unwrap();
        let profile = super::unpack(&root, &super::crypt(&encrypted, false).unwrap()).unwrap();
        std::fs::remove_file(&profile).unwrap();
        let restored = super::unpack(&root, &super::crypt(&encrypted, false).unwrap()).unwrap();
        assert_eq!(
            std::fs::read(restored).unwrap(),
            b"[Interface]\nPrivateKey=example"
        );
        assert!(super::unpack(&root, b"../bad.conf\nsecret").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
