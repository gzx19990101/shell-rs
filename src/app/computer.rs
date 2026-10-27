//! What this computer is called.

/// This computer's name, as shells put it in a title: `uname -n` on Unix
/// (zsh's `%m` and bash's `\h` keep what comes before the first dot), the
/// computer name on Windows.
pub fn computer_name() -> Option<String> {
    #[cfg(unix)]
    {
        let mut name = [0u8; 256];
        // SAFETY: `gethostname` writes at most the buffer's length.
        if unsafe { libc::gethostname(name.as_mut_ptr().cast(), name.len()) } != 0 {
            return None;
        }
        let end = name
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(name.len());
        String::from_utf8(name[..end].to_vec())
            .ok()
            .filter(|name| !name.is_empty())
    }
    #[cfg(windows)]
    std::env::var("COMPUTERNAME")
        .ok()
        .filter(|name| !name.is_empty())
}
