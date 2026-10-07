use crate::errors::VaultError;
use std::ffi::c_void;
use windows::core::PCWSTR;
use windows::Win32::Security::Credentials::{
    CredUIPromptForWindowsCredentialsW, CredUnPackAuthenticationBufferW, CREDUI_INFOW,
    CRED_PACK_GENERIC_CREDENTIALS, CREDUIWIN_GENERIC,
};
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

// Wine implements this older CredUI dialog, but currently stubs out both
// CredUIPromptForWindowsCredentialsW and CredUnPackAuthenticationBufferW.
// Keep the modern dialog on Windows and use this only when it is unavailable.
#[link(name = "credui")]
extern "system" {
    fn CredUIPromptForCredentialsW(
        ui_info: *const CREDUI_INFOW,
        target_name: *const u16,
        reserved: *const c_void,
        auth_error: u32,
        username: *mut u16,
        username_capacity: u32,
        password: *mut u16,
        password_capacity: u32,
        save: *mut i32,
        flags: u32,
    ) -> u32;
}

const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
const ERROR_CANCELLED: u32 = 1223;
const CREDUI_FLAGS_DO_NOT_PERSIST: u32 = 0x0000_0002;
const CREDUI_FLAGS_ALWAYS_SHOW_UI: u32 = 0x0000_0080;
const CREDUI_FLAGS_GENERIC_CREDENTIALS: u32 = 0x0004_0000;

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Open a CredUI dialog and return (username, password).
/// Wine uses the older CredUI dialog when the modern API is unavailable.
/// The dialog is OS-owned — Python cannot intercept the credentials.
pub fn prompt_credentials(caption: &str, message: &str) -> Result<(String, String), VaultError> {
    let caption_wide = to_wide_null(caption);
    let message_wide = to_wide_null(message);

    let parent = unsafe { GetForegroundWindow() };

    let ui_info = CREDUI_INFOW {
        cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
        hwndParent: parent,
        pszMessageText: PCWSTR(message_wide.as_ptr()),
        pszCaptionText: PCWSTR(caption_wide.as_ptr()),
        hbmBanner: Default::default(),
    };

    let mut auth_package: u32 = 0;
    let mut out_buf: *mut c_void = std::ptr::null_mut();
    let mut out_buf_size: u32 = 0;

    let result = unsafe {
        CredUIPromptForWindowsCredentialsW(
            Some(&ui_info),
            0,
            &mut auth_package,
            None,
            0,
            &mut out_buf,
            &mut out_buf_size,
            None,
            CREDUIWIN_GENERIC,
        )
    };

    if result == ERROR_CALL_NOT_IMPLEMENTED {
        return prompt_legacy_credentials(&ui_info);
    }
    if result == ERROR_CANCELLED {
        return Err(VaultError::CredUiCancelled);
    }
    if result != 0 {
        return Err(VaultError::CredUiFailed(format!(
            "CredUI returned error code {result}"
        )));
    }

    if out_buf.is_null() || out_buf_size == 0 {
        return Err(VaultError::CredUiFailed(
            "CredUI returned empty buffer".to_string(),
        ));
    }

    let unpacked = unsafe { unpack_auth_buffer(out_buf, out_buf_size) };
    unsafe {
        for offset in 0..out_buf_size as usize {
            std::ptr::write_volatile((out_buf as *mut u8).add(offset), 0);
        }
        windows::Win32::System::Com::CoTaskMemFree(Some(out_buf));
    }

    unpacked
}

fn prompt_legacy_credentials(ui_info: &CREDUI_INFOW) -> Result<(String, String), VaultError> {
    // These capacities include the terminating NUL. The legacy dialog writes
    // directly into the supplied buffers, so no auth-buffer unpacking is needed.
    const USER_CAPACITY: usize = 514;
    const PASSWORD_CAPACITY: usize = 256;
    let target = to_wide_null("Deimos");
    let mut username = vec![0u16; USER_CAPACITY];
    let mut password = vec![0u16; PASSWORD_CAPACITY];

    let result = unsafe {
        CredUIPromptForCredentialsW(
            ui_info,
            target.as_ptr(),
            std::ptr::null(),
            0,
            username.as_mut_ptr(),
            username.len() as u32,
            password.as_mut_ptr(),
            password.len() as u32,
            std::ptr::null_mut(),
            CREDUI_FLAGS_DO_NOT_PERSIST
                | CREDUI_FLAGS_ALWAYS_SHOW_UI
                | CREDUI_FLAGS_GENERIC_CREDENTIALS,
        )
    };

    let credentials = match result {
        0 => {
            let user_len = username.iter().position(|&c| c == 0).unwrap_or(username.len());
            let pass_len = password.iter().position(|&c| c == 0).unwrap_or(password.len());
            Ok((
                String::from_utf16_lossy(&username[..user_len]),
                String::from_utf16_lossy(&password[..pass_len]),
            ))
        }
        ERROR_CANCELLED => Err(VaultError::CredUiCancelled),
        code => Err(VaultError::CredUiFailed(format!(
            "Legacy CredUI returned error code {code}"
        ))),
    };

    // Clear the UTF-16 password buffer on every exit path. Volatile writes keep
    // the wipe from being optimized away before the allocation is released.
    for c in &mut password {
        unsafe { std::ptr::write_volatile(c, 0) };
    }

    credentials
}

unsafe fn unpack_auth_buffer(
    buf: *const c_void,
    buf_size: u32,
) -> Result<(String, String), VaultError> {
    // Pre-allocate large buffers — avoids the two-call sizing pattern
    // which segfaults with null PWSTR pointers in windows crate 0.58
    const MAX_FIELD: u32 = 512;
    let mut user_buf: Vec<u16> = vec![0u16; MAX_FIELD as usize];
    let mut domain_buf: Vec<u16> = vec![0u16; MAX_FIELD as usize];
    let mut pass_buf: Vec<u16> = vec![0u16; MAX_FIELD as usize];
    let mut user_size: u32 = MAX_FIELD;
    let mut domain_size: u32 = MAX_FIELD;
    let mut pass_size: u32 = MAX_FIELD;

    let unpacked = CredUnPackAuthenticationBufferW(
        CRED_PACK_GENERIC_CREDENTIALS,
        buf,
        buf_size,
        windows::core::PWSTR(user_buf.as_mut_ptr()),
        &mut user_size,
        windows::core::PWSTR(domain_buf.as_mut_ptr()),
        Some(&mut domain_size),
        windows::core::PWSTR(pass_buf.as_mut_ptr()),
        &mut pass_size,
    );

    if let Err(e) = unpacked {
        for b in &mut pass_buf {
            std::ptr::write_volatile(b, 0);
        }
        return Err(VaultError::CredUiFailed(format!("CredUnPack failed: {e}")));
    }

    // Convert wide strings (sizes include null terminator)
    let user_len = user_size.saturating_sub(1) as usize;
    let pass_len = pass_size.saturating_sub(1) as usize;
    let username = String::from_utf16_lossy(&user_buf[..user_len]);
    let password = String::from_utf16_lossy(&pass_buf[..pass_len]);

    // Zero out password buffer
    for b in &mut pass_buf {
        std::ptr::write_volatile(b, 0);
    }

    Ok((username, password))
}
