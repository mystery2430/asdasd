//! `bosphorus service install [--lang en|tr] [--enable-overlap] [--quic P]
//!    [--profile-dir <p>] [--install-dir <p>] [--start auto|demand] [--force]`

use std::ffi::{CString, OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use bosphorus_core::config::QuicPolicy;

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use bosphorus_divert::{DivertError, Layer, OpenFlags, WinDivertHandle};

pub struct Opts {
    pub lang: crate::i18n::Lang,
    pub enable_overlap: bool,
    pub quic: QuicPolicy,
    pub profile_dir: Option<PathBuf>,
    pub install_dir: Option<PathBuf>,
    pub start_demand: bool,
    pub force: bool,
}

pub fn run(args: &[String]) -> anyhow::Result<()> {
    let opts = Opts {
        lang: crate::resolve_lang(args),
        enable_overlap: args.iter().any(|a| a == "--enable-overlap"),
        quic: crate::parse_quic(args)?,
        profile_dir: value_after(args, "--profile-dir").map(PathBuf::from),
        install_dir: value_after(args, "--install-dir").map(PathBuf::from),
        start_demand: value_after(args, "--start")
            .map(|s| s.eq_ignore_ascii_case("demand"))
            .unwrap_or(false),
        force: args.iter().any(|a| a == "--force"),
    };
    crate::i18n::set(opts.lang);

    // Elevated re-spawn from the double-click launcher: its console is hidden,
    // so also surface the outcome in a MessageBox.
    let from_launcher = args
        .iter()
        .any(|a| a == crate::launcher::FROM_LAUNCHER_FLAG);
    let res = install(&opts);
    if from_launcher {
        crate::launcher::show_install_result(&res);
    }
    res
}

/// Shared with the interactive launcher (4b). Console output only — the
/// launcher adds the MessageBox itself from the returned `Result`.
pub fn install(opts: &Opts) -> anyhow::Result<()> {
    println!("{}", crate::i18n::t(crate::i18n::Msg::DiscoveryWarning));
    println!();

    let exe = resolve_exe(opts)?;
    preflight_windivert(opts.force)?;

    let profile_dir = opts.profile_dir.clone().unwrap_or_else(super::profiles_dir);
    std::fs::create_dir_all(&profile_dir)?;
    std::fs::create_dir_all(super::logs_dir())?;

    let mgr = ServiceManager::local_computer(
        None::<&OsStr>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(super::map_scm_err)?;

    let launch_arguments = build_launch_arguments(opts);

    let info = ServiceInfo {
        name: OsString::from(super::SERVICE_NAME),
        display_name: OsString::from(super::SERVICE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: if opts.start_demand {
            ServiceStartType::OnDemand
        } else {
            ServiceStartType::AutoStart
        },
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments,
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let svc = mgr
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .map_err(super::map_scm_err)?;

    let _ = svc.set_description(super::SERVICE_DISPLAY);
    // Plain AutoStart, not delayed: Windows holds a delayed-auto-start
    // service back ~1-2 minutes after boot to avoid competing with more
    // critical services, but a DPI bypass should be intercepting before the
    // user's other apps start making blocked connections, not after.
    let _ = svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(30),
            },
            ServiceAction {
                action_type: ServiceActionType::None,
                delay: Duration::ZERO,
            },
        ]),
    });
    let _ = svc.set_failure_actions_on_non_crash_failures(true);

    svc.start::<&OsStr>(&[]).map_err(super::map_scm_err)?;

    println!("{}", crate::i18n::svc_created(super::SERVICE_NAME));
    println!("{}", crate::i18n::install_verification());
    Ok(())
}

/// The `service run` argv the SCM launches the service with. Kept separate
/// from [`install`] so it can be unit-tested without touching the SCM.
fn build_launch_arguments(opts: &Opts) -> Vec<OsString> {
    let mut v: Vec<OsString> = vec![
        "service".into(),
        "run".into(),
        "--lang".into(),
        lang_code(opts.lang).into(),
    ];
    if opts.enable_overlap {
        v.push("--enable-overlap".into());
    }
    // Always written out, not just when non-default: the stored argv is what
    // the service runs for years, and it should not silently change meaning if
    // a later build moves the default.
    v.push("--quic".into());
    v.push(opts.quic.as_str().into());
    if let Some(p) = &opts.profile_dir {
        v.push("--profile-dir".into());
        v.push(p.clone().into_os_string());
    }
    v
}

fn lang_code(l: crate::i18n::Lang) -> &'static str {
    match l {
        crate::i18n::Lang::En => "en",
        crate::i18n::Lang::Tr => "tr",
    }
}

fn value_after<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// `%ProgramFiles%\Bosphorus` (or `C:\Program Files\Bosphorus` when the
/// environment variable is absent). The SYSTEM service never runs from the
/// download location by default.
fn default_install_dir_from(program_files: Option<OsString>) -> PathBuf {
    program_files
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
        .join("Bosphorus")
}

fn default_install_dir() -> PathBuf {
    default_install_dir_from(std::env::var_os("ProgramFiles"))
}

/// Absolute path to register as the service binary. The exe and both WinDivert
/// files are always copied to an administrator-controlled directory; the
/// previous default (run in place) let an unprivileged user replace a
/// LocalSystem binary or its DLLs.
fn resolve_exe(opts: &Opts) -> anyhow::Result<PathBuf> {
    let current = std::env::current_exe()?;
    let requested = opts.install_dir.clone().unwrap_or_else(default_install_dir);

    // Only the canonical path is used from here on. It is what the ACL policy
    // inspected, what receives the copies, and what is registered with the SCM.
    // Validating a resolved path and then writing through the caller's original
    // spelling let a reparse point (junction/symlink) or a `..` component point
    // the copy — and therefore the LocalSystem service binary — somewhere the
    // check never saw.
    let dst_dir = prepare_install_dir(&requested, directory_is_safe)?;
    copy_install_files(&current, &dst_dir)?;

    let exe = dst_dir.join("bosphorus.exe");
    verify_resolves_inside(&exe, &dst_dir)?;
    Ok(service_path(&exe))
}

/// Windows verbatim-path prefix, as produced by `canonicalize()`.
const VERBATIM_PREFIX: &str = r"\\?\";

/// The spelling to hand to the Service Control Manager.
///
/// `canonicalize()` yields a Windows verbatim path (`\\?\C:\Program
/// Files\...`), which is correct for file access but unusual in a stored
/// service `ImagePath`. The plain spelling is used only when it provably
/// resolves to the same file that was validated; otherwise the verbatim path is
/// kept, so the registered path can never point somewhere the check did not see.
fn service_path(validated: &Path) -> PathBuf {
    let text = validated.to_string_lossy();
    let Some(plain) = text.strip_prefix(VERBATIM_PREFIX) else {
        return validated.to_path_buf();
    };
    let plain = PathBuf::from(plain);
    match plain.canonicalize() {
        Ok(resolved) if resolved == validated => plain,
        _ => validated.to_path_buf(),
    }
}

/// Create the destination, then prove that *this* path is safe to install a
/// LocalSystem binary into. Returns the canonical path callers must use.
///
/// `probe` returns `true` only when a directory is administrator-controlled (see
/// [`bosphorus_core::service_acl`]). Injecting it keeps the decision testable
/// without installing a service or editing real ACLs.
///
/// Three separate conditions are required:
///
/// 1. the directory itself is administrator-controlled, so its contents cannot
///    be replaced;
/// 2. its **parent** is too — `FILE_DELETE_CHILD` on the parent lets an ordinary
///    user delete and recreate this directory (and then control its contents),
///    no matter how tight the directory's own ACL is;
/// 3. the path still resolves to the same place after the check, so a reparse
///    point cannot be swapped in between the probe and the copy.
///
/// Finally the directory's ACL is rewritten to an explicit administrator-only
/// DACL, so a destination that already existed with inherited or altered
/// permissions cannot keep them.
fn prepare_install_dir(
    requested: &Path,
    probe: impl Fn(&Path) -> std::io::Result<bool>,
) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(requested)?;
    let canonical = requested.canonicalize().map_err(|e| {
        anyhow::anyhow!(
            "install directory cannot be resolved: {}: {e}",
            requested.display()
        )
    })?;

    if !probe(&canonical)? {
        anyhow::bail!(
            "refusing to install a LocalSystem service in '{}': the directory is writable by \
             an unprivileged principal. Choose an administrator-controlled path or omit \
             --install-dir to use {}.",
            canonical.display(),
            default_install_dir().display()
        );
    }

    if let Some(parent) = canonical.parent() {
        if !probe(parent)? {
            anyhow::bail!(
                "refusing to install a LocalSystem service in '{}': its parent '{}' can be \
                 modified by an unprivileged principal, which is enough to replace the whole \
                 directory after it has been checked.",
                canonical.display(),
                parent.display()
            );
        }
    }

    // The probe above ran on `canonical`. If the path now resolves somewhere
    // else, a reparse point changed under us and nothing that follows would be
    // about the directory that was checked.
    let resolved_again = canonical.canonicalize().map_err(|e| {
        anyhow::anyhow!(
            "install directory cannot be re-resolved after validation: {}: {e}",
            canonical.display()
        )
    })?;
    if resolved_again != canonical {
        anyhow::bail!(
            "refusing to install in '{}': the path resolved to '{}' while it was being \
             validated, so the checked directory is not the one that would receive the files.",
            canonical.display(),
            resolved_again.display()
        );
    }

    lock_down(&resolved_again)?;
    Ok(resolved_again)
}

/// Fail closed unless `path` still resolves directly inside `dir`.
///
/// Checked *after* copying, because a destination file could itself be a
/// pre-existing symlink/hardlink pointing outside the validated directory.
fn verify_resolves_inside(path: &Path, dir: &Path) -> anyhow::Result<()> {
    let resolved = path.canonicalize().map_err(|e| {
        anyhow::anyhow!(
            "installed service file cannot be resolved: {}: {e}",
            path.display()
        )
    })?;
    if resolved.parent() != Some(dir) {
        anyhow::bail!(
            "refusing to register '{}': it resolves to '{}', outside the validated install \
             directory '{}'.",
            path.display(),
            resolved.display(),
            dir.display()
        );
    }
    Ok(())
}

/// Restrict `path` to an explicit administrator-only ACL. Windows-only; a no-op
/// elsewhere so the surrounding logic stays testable on any host.
fn lock_down(path: &Path) -> anyhow::Result<()> {
    apply_admin_only_dacl(path).map_err(|e| {
        anyhow::anyhow!(
            "cannot restrict the permissions of '{}': {e}. The service runs as LocalSystem, so \
             everything it loads must be writable only by administrators.",
            path.display()
        )
    })
}

/// SDDL for an install location only administrators may modify: a protected DACL
/// (no inherited ACEs), full control for LocalSystem and Administrators, and
/// read+execute for Users. Entries are inheritable so copied files stay locked
/// down.
#[cfg(windows)]
const ADMIN_ONLY_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

/// `SetNamedSecurityInfoW(..., DACL_SECURITY_INFORMATION |
/// PROTECTED_DACL_SECURITY_INFORMATION)` with [`ADMIN_ONLY_SDDL`].
///
/// The owner is deliberately not rewritten: changing an owner needs extra
/// privileges, and a non-administrator owner is already a hard rejection in
/// [`prepare_install_dir`].
#[cfg(windows)]
fn apply_admin_only_dacl(path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HLOCAL;
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };
    use windows::Win32::System::Memory::LocalFree;

    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                // SAFETY: ConvertStringSecurityDescriptorToSecurityDescriptorW
                // returned this LocalAlloc block.
                unsafe {
                    let _ = LocalFree(HLOCAL(self.0 .0 as isize));
                }
            }
        }
    }

    let sddl: Vec<u16> = ADMIN_ONLY_SDDL
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is NUL-terminated and outlives the call; `sd` receives an
    // owned descriptor freed by `Descriptor`.
    if !unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            1,
            &mut sd,
            None,
        )
    }
    .as_bool()
    {
        return Err(std::io::Error::last_os_error());
    }
    let descriptor = Descriptor(sd);

    // `windows` 0.48 declares these as `*mut i32` (BOOL-compatible), not `BOOL`.
    let mut present: i32 = 0;
    let mut dacl: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
    let mut defaulted: i32 = 0;
    // SAFETY: `sd` is a valid descriptor; the three out-params are valid.
    if !unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) }.as_bool()
        || present == 0
        || dacl.is_null()
    {
        return Err(std::io::Error::other("SDDL produced no DACL"));
    }

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is NUL-terminated; `dacl` belongs to the live `descriptor`,
    // which is dropped only after the call returns.
    let status = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    drop(descriptor);
    if status.0 != 0 {
        return Err(std::io::Error::from_raw_os_error(status.0 as i32));
    }
    Ok(())
}

#[cfg(not(windows))]
fn apply_admin_only_dacl(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

const INSTALL_FILES: [&str; 3] = ["bosphorus.exe", "WinDivert.dll", "WinDivert64.sys"];

/// Copy exactly the three files the service will load, restrict each to
/// administrator-only permissions, and verify it is present and non-empty. A
/// missing DLL/SYS used to be only a warning, which produced a registered service
/// that could not start.
fn copy_install_files(current_exe: &Path, dst_dir: &Path) -> anyhow::Result<()> {
    // Track what this call created so a failure half-way cannot leave a partial
    // set of LocalSystem files (and, later, a service that cannot start) behind.
    let mut created: Vec<PathBuf> = Vec::new();
    let result = copy_install_files_inner(current_exe, dst_dir, &mut created);
    if result.is_err() {
        for path in created.iter().rev() {
            let _ = std::fs::remove_file(path);
        }
    }
    result
}

fn copy_install_files_inner(
    current_exe: &Path,
    dst_dir: &Path,
    created: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    let src_dir = current_exe.parent().unwrap_or_else(|| Path::new("."));
    let sources = [
        ("bosphorus.exe", current_exe.to_path_buf()),
        ("WinDivert.dll", src_dir.join("WinDivert.dll")),
        ("WinDivert64.sys", src_dir.join("WinDivert64.sys")),
    ];
    for (name, source) in &sources {
        if !source.is_file() {
            anyhow::bail!(
                "required service file is missing ({}): {}",
                name,
                source.display()
            );
        }
    }

    for (name, source) in &sources {
        // `dst_dir` is the canonical, validated directory, so this join cannot be
        // redirected by the caller's spelling of the path.
        let destination = dst_dir.join(name);
        // A pre-existing destination could itself be a link pointing outside the
        // validated directory; refuse rather than follow it.
        if destination.symlink_metadata().is_ok() {
            verify_resolves_inside(&destination, dst_dir).map_err(|e| {
                anyhow::anyhow!("refusing to overwrite {name} outside the install directory: {e}")
            })?;
        }
        let existed = destination.symlink_metadata().is_ok();
        let same_file = source.canonicalize().ok() == destination.canonicalize().ok();
        if !same_file {
            std::fs::copy(source, &destination).map_err(|e| {
                anyhow::anyhow!(
                    "copy {} -> {}: {e}",
                    source.display(),
                    destination.display()
                )
            })?;
            if !existed {
                created.push(destination.clone());
            }
        }
        // `fs::copy` onto an existing file keeps that file's ACL, so a
        // world-writable leftover would stay world-writable. Re-apply ours.
        lock_down(&destination)?;
        let meta = std::fs::metadata(&destination)?;
        if !meta.is_file() || meta.len() == 0 {
            anyhow::bail!(
                "installed service file is missing or empty: {}",
                destination.display()
            );
        }
    }
    debug_assert_eq!(INSTALL_FILES.len(), sources.len());
    Ok(())
}

/// Actual DACL + owner inspection for the directory the SYSTEM service will
/// load from.
///
/// The access decision itself is [`service_acl::evaluate`] so it can be tested
/// without Windows. This function only reads the security descriptor:
///
/// * a NULL DACL grants everyone full control -> reject,
/// * every ACE is passed through, including ones for individual user SIDs (a
///   `%USERPROFILE%` install dir inherits those), object/callback ACEs, and ACEs
///   whose SID cannot be resolved; the policy treats all three as untrusted,
/// * a directory owned by a non-administrator is rejected, because an owner can
///   always rewrite its DACL (`WRITE_DAC` is implicit for owners) even when the
///   current ACEs name only administrators.
#[cfg(windows)]
fn directory_is_safe(path: &Path) -> std::io::Result<bool> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    use bosphorus_core::service_acl::{self, AceEntry};
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{HLOCAL, PSID, WIN32_ERROR};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        AclSizeInformation, GetAce, GetAclInformation, ACCESS_ALLOWED_ACE, ACL,
        ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };
    use windows::Win32::System::Memory::LocalFree;

    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                // SAFETY: GetNamedSecurityInfoW returned this LocalAlloc block.
                unsafe {
                    let _ = LocalFree(HLOCAL(self.0 .0 as isize));
                }
            }
        }
    }
    struct SidString(PWSTR);
    impl Drop for SidString {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                // SAFETY: ConvertSidToStringSidW returned this LocalAlloc block.
                unsafe {
                    let _ = LocalFree(HLOCAL(self.0 .0 as isize));
                }
            }
        }
    }

    /// Copy a SID into its string form (`S-1-5-...`). `None` = unusable SID.
    ///
    /// SAFETY: `sid` must point at a valid SID for the duration of the call.
    unsafe fn sid_to_string(sid: PSID) -> Option<String> {
        if sid.0.is_null() {
            return None;
        }
        let mut text = PWSTR::null();
        if !ConvertSidToStringSidW(sid, &mut text).as_bool() {
            return None;
        }
        let guard = SidString(text);
        guard.0.to_string().ok()
    }

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wide` is NUL-terminated and lives for the call; both out-params
    // are valid. The descriptor is owned by `Descriptor` and freed on return.
    let status: WIN32_ERROR = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
    };
    let descriptor = Descriptor(sd);
    if status.0 != 0 {
        return Err(std::io::Error::from_raw_os_error(status.0 as i32));
    }
    let owner_sid = unsafe { sid_to_string(owner) };
    if dacl.is_null() {
        // NULL DACL = everyone. Report the specific reason, then fail closed.
        tracing::warn!(
            target: "bosphorus::service",
            path = %path.display(),
            reason = %service_acl::AclRejection::NullDacl.describe(),
            "install directory rejected by ACL policy"
        );
        return Ok(false);
    }

    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` is valid; `info` is sized exactly for AclSizeInformation.
    let ok = unsafe {
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if !ok.as_bool() {
        return Err(std::io::Error::last_os_error());
    }

    let mut entries: Vec<AceEntry> = Vec::with_capacity(info.AceCount as usize);
    for index in 0..info.AceCount {
        let mut ace: *mut c_void = std::ptr::null_mut();
        // SAFETY: index < AceCount and `ace` is a valid out-param.
        if !unsafe { GetAce(dacl, index, &mut ace) }.as_bool() || ace.is_null() {
            // A DACL we cannot read must not be treated as safe.
            return Ok(false);
        }
        // SAFETY: every file-object ACE starts with ACE_HEADER (AceType) followed
        // by an ACCESS_MASK, so this read is layout-compatible for allow, deny,
        // object and callback ACEs.
        let header = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
        let ace_type = header.Header.AceType;
        // `AceFlags` is only needed to keep the entry faithful; the policy's
        // placeholder rule is documented in `service_acl` and does not depend on
        // an untrusted trustee being inherit-only.
        let ace_flags = header.Header.AceFlags;
        let mask = header.Mask;
        // Only a plain allow ACE carries a trustee this policy can evaluate; the
        // policy rejects other allow types that hold dangerous bits.
        let needs_sid = ace_type == service_acl::ACCESS_ALLOWED_ACE_TYPE
            && mask & service_acl::DANGEROUS_ACCESS != 0;
        let sid = if needs_sid {
            let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            // SAFETY: for an ACCESS_ALLOWED_ACE the SID begins at SidStart and
            // lies inside the ACE block that `GetAce` returned.
            let sid = PSID(unsafe { (ace as *mut u8).add(sid_offset) } as *mut c_void);
            unsafe { sid_to_string(sid) }
        } else {
            None
        };
        entries.push(AceEntry {
            ace_type,
            ace_flags,
            mask,
            sid,
        });
    }
    drop(descriptor);

    match service_acl::evaluate(owner_sid.as_deref(), &entries) {
        Ok(()) => Ok(true),
        Err(reason) => {
            tracing::warn!(
                target: "bosphorus::service",
                path = %path.display(),
                reason = %reason.describe(),
                "install directory rejected by ACL policy"
            );
            Ok(false)
        }
    }
}

#[cfg(not(windows))]
fn directory_is_safe(_path: &Path) -> std::io::Result<bool> {
    Ok(false)
}

/// Try to load the WinDivert driver right here. If it fails now, the SYSTEM
/// service would fail the same way at boot with no visible error.
fn preflight_windivert(force: bool) -> anyhow::Result<()> {
    // A filter that matches ~nothing — exercises driver load without touching
    // real traffic.
    let filter = CString::new("tcp.DstPort == 65535 and tcp.SrcPort == 65534").unwrap();
    match WinDivertHandle::open(&filter, Layer::Network, 0, OpenFlags::new()) {
        Ok(h) => {
            drop(h);
            Ok(())
        }
        Err(DivertError::Open(e)) if force => {
            eprintln!("{}", crate::i18n::preflight_warn_forced(&e.to_string()));
            Ok(())
        }
        Err(DivertError::Open(e)) => {
            anyhow::bail!("{}", crate::i18n::preflight_fail(&e.to_string()))
        }
        Err(e) if force => {
            eprintln!("pre-flight: {e} (--force)");
            Ok(())
        }
        Err(e) => anyhow::bail!("pre-flight WinDivertOpen: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Lang;

    fn opts(lang: Lang, enable_overlap: bool, profile_dir: Option<PathBuf>) -> Opts {
        Opts {
            lang,
            enable_overlap,
            quic: QuicPolicy::default(),
            profile_dir,
            install_dir: None,
            start_demand: false,
            force: false,
        }
    }

    fn as_strings(v: &[OsString]) -> Vec<String> {
        v.iter().map(|o| o.to_string_lossy().into_owned()).collect()
    }

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "bosphorus-install-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn default_install_dir_is_program_files_bosphorus() {
        assert_eq!(
            default_install_dir_from(Some(OsString::from(r"D:\Apps"))),
            PathBuf::from(r"D:\Apps\Bosphorus")
        );
        assert_eq!(
            default_install_dir_from(None),
            PathBuf::from(r"C:\Program Files\Bosphorus")
        );
    }

    #[test]
    fn a_user_writable_directory_is_refused_before_the_service_is_created() {
        let dir = TempDir::new("unsafe");
        let err = prepare_install_dir(&dir.0.join("Bosphorus"), |_| Ok(false))
            .expect_err("a user-writable directory must be rejected");
        let text = err.to_string();
        assert!(text.contains("refusing to install"), "{text}");
        assert!(text.contains("--install-dir"), "{text}");
    }

    #[test]
    fn a_directory_passing_the_acl_probe_is_accepted() {
        let dir = TempDir::new("safe");
        let target = dir.path().join("Bosphorus");
        let accepted = prepare_install_dir(&target, |_| Ok(true)).expect("safe directory");
        assert!(target.is_dir());
        assert_eq!(accepted, target.canonicalize().unwrap());
    }

    /// Regression: the ACL probe used to run on `canonicalize()` while the copy
    /// and the registered `ImagePath` kept the caller's original spelling. Those
    /// can differ (`..`, relative paths, junctions), so the files could land
    /// outside the directory that was checked. The validated path must be the
    /// returned one, and it must be what the probe saw.
    #[test]
    fn the_path_that_is_probed_is_the_path_that_is_returned() {
        let root = TempDir::new("canon");
        let real = root.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let requested = real.join("nested").join("..").join("Bosphorus");

        let probed = std::cell::RefCell::new(Vec::new());
        let canonical = prepare_install_dir(&requested, |p| {
            probed.borrow_mut().push(p.to_path_buf());
            Ok(true)
        })
        .expect("accepted");

        let canonical = canonical.canonicalize().unwrap();
        assert!(
            probed.borrow().contains(&canonical),
            "probe did not see {canonical:?}"
        );
        assert!(!probed
            .borrow()
            .iter()
            .any(|p| p.to_string_lossy().contains("..")));
        // The copy destination derived from the returned path lands in the
        // validated directory, not in whatever the caller spelled.
        let src = TempDir::new("canon-src");
        let exe = src.path().join("downloaded.exe");
        std::fs::write(&exe, b"exe").unwrap();
        std::fs::write(src.path().join("WinDivert.dll"), b"dll").unwrap();
        std::fs::write(src.path().join("WinDivert64.sys"), b"sys").unwrap();
        copy_install_files(&exe, &canonical).expect("copy");
        assert!(canonical.join("bosphorus.exe").is_file());
    }

    /// A reparse point in the requested path is followed once, and the resolved
    /// (validated) directory is what gets returned — not the link.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_install_dir_resolves_to_its_target() {
        let root = TempDir::new("link");
        let real = root.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let canonical =
            prepare_install_dir(&link.join("Bosphorus"), |_| Ok(true)).expect("link ok");
        assert_eq!(canonical, real.canonicalize().unwrap().join("Bosphorus"));
    }

    /// `FILE_DELETE_CHILD` on the parent is enough to replace the whole install
    /// directory after it has been checked, so the parent has to be trusted too.
    #[test]
    fn a_directory_whose_parent_is_user_writable_is_refused() {
        let root = TempDir::new("parent");
        let target = root.path().join("Bosphorus");
        let canonical_parent = root.path().canonicalize().unwrap();

        let err = prepare_install_dir(&target, |p| Ok(p != canonical_parent))
            .expect_err("a user-writable parent must be rejected");
        let text = err.to_string();
        assert!(text.contains("parent"), "{text}");
        assert!(text.contains("refusing to install"), "{text}");
    }

    /// A registration path that resolves outside the validated directory must be
    /// refused, because that is where LocalSystem would load code from.
    #[cfg(unix)]
    #[test]
    fn an_exe_that_resolves_outside_the_install_dir_is_refused() {
        let root = TempDir::new("escape");
        let dir = root.path().join("install");
        std::fs::create_dir_all(&dir).unwrap();
        let elsewhere = root.path().join("elsewhere.exe");
        std::fs::write(&elsewhere, b"evil").unwrap();
        let link = dir.join("bosphorus.exe");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();

        let err = verify_resolves_inside(&link, &dir.canonicalize().unwrap())
            .expect_err("an exe outside the validated directory must be refused");
        assert!(err.to_string().contains("outside"), "{err}");

        // A plain file in the directory is accepted.
        std::fs::remove_file(&link).unwrap();
        std::fs::write(&link, b"exe").unwrap();
        verify_resolves_inside(&link, &dir.canonicalize().unwrap()).expect("inside is fine");
    }

    /// `fs::copy` keeps an existing destination's ACL, so the installer must
    /// re-apply the restrictive ACL and refuse a destination that is a link out
    /// of the validated directory.
    #[cfg(unix)]
    #[test]
    fn copying_over_a_link_that_points_outside_is_refused() {
        let src = TempDir::new("link-src");
        let dst = TempDir::new("link-dst");
        let exe = src.path().join("downloaded.exe");
        std::fs::write(&exe, b"exe").unwrap();
        std::fs::write(src.path().join("WinDivert.dll"), b"dll").unwrap();
        std::fs::write(src.path().join("WinDivert64.sys"), b"sys").unwrap();

        let outside = TempDir::new("link-outside");
        let victim = outside.path().join("WinDivert.dll");
        std::fs::write(&victim, b"original").unwrap();
        std::os::unix::fs::symlink(&victim, dst.path().join("WinDivert.dll")).unwrap();

        let err = copy_install_files(&exe, dst.path())
            .expect_err("writing through a link out of the install dir must be refused");
        assert!(err.to_string().contains("outside"), "{err}");
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"original",
            "the file outside the install directory must be untouched"
        );
        assert!(
            !dst.path().join("bosphorus.exe").exists(),
            "a failed install must not leave a partial set of service files behind"
        );
    }

    /// A wrong prefix constant would silently disable the stripping and leave
    /// `\\?\C:\...` in the service's ImagePath, so pin its exact text.
    #[test]
    fn the_verbatim_prefix_is_exactly_two_backslashes_question_mark_backslash() {
        assert_eq!(VERBATIM_PREFIX, "\\\\?\\");
        assert_eq!(VERBATIM_PREFIX.len(), 4);
        assert!(VERBATIM_PREFIX.starts_with("\\\\"));
        assert!(VERBATIM_PREFIX.ends_with("?\\"));
    }

    /// The path registered with the SCM must always resolve to the exact file
    /// that was validated, whichever spelling is used.
    #[test]
    fn the_registered_path_always_resolves_to_the_validated_file() {
        let dir = TempDir::new("svcpath");
        let exe = dir.path().join("bosphorus.exe");
        std::fs::write(&exe, b"exe").unwrap();
        let canonical = exe.canonicalize().unwrap();
        let registered = service_path(&canonical);
        assert_eq!(
            registered.canonicalize().unwrap(),
            canonical,
            "the registered path must resolve to the validated file"
        );
    }

    #[test]
    fn installer_copies_exactly_the_three_service_files_and_verifies_them() {
        let src = TempDir::new("src");
        let dst = TempDir::new("dst");
        let exe = src.path().join("downloaded.exe");
        std::fs::write(&exe, b"exe").unwrap();
        for (name, bytes) in [
            ("WinDivert.dll", b"dll".as_slice()),
            ("WinDivert64.sys", b"sys".as_slice()),
        ] {
            std::fs::write(src.path().join(name), bytes).unwrap();
        }

        copy_install_files(&exe, dst.path()).expect("copy");
        for name in INSTALL_FILES {
            let target = dst.path().join(name);
            assert!(target.is_file(), "missing {name}");
            assert!(
                std::fs::metadata(&target).unwrap().len() > 0,
                "empty {name}"
            );
        }
        assert_eq!(
            std::fs::read(dst.path().join("bosphorus.exe")).unwrap(),
            b"exe"
        );
        assert_eq!(
            std::fs::read(dst.path().join("WinDivert.dll")).unwrap(),
            b"dll"
        );
        assert_eq!(
            std::fs::read(dst.path().join("WinDivert64.sys")).unwrap(),
            b"sys"
        );
    }

    #[test]
    fn a_missing_driver_file_aborts_the_install() {
        let src = TempDir::new("missing-src");
        let dst = TempDir::new("missing-dst");
        let exe = src.path().join("downloaded.exe");
        std::fs::write(&exe, b"exe").unwrap();
        std::fs::write(src.path().join("WinDivert.dll"), b"dll").unwrap();
        // WinDivert64.sys intentionally absent.
        let err = copy_install_files(&exe, dst.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("WinDivert64.sys"), "{err}");
        // The installer refused before registering a service that cannot start.
        assert!(!dst.path().join("bosphorus.exe").exists());
    }

    #[test]
    fn launch_arguments_minimal_is_just_service_run_lang_and_quic() {
        let v = build_launch_arguments(&opts(Lang::En, false, None));
        assert_eq!(
            as_strings(&v),
            ["service", "run", "--lang", "en", "--quic", "blocked"]
        );
    }

    #[test]
    fn launch_arguments_carry_overlap_and_profile_dir_in_order() {
        let v = build_launch_arguments(&opts(Lang::Tr, true, Some(PathBuf::from(r"C:\pd"))));
        assert_eq!(
            as_strings(&v),
            [
                "service",
                "run",
                "--lang",
                "tr",
                "--enable-overlap",
                "--quic",
                "blocked",
                "--profile-dir",
                r"C:\pd"
            ]
        );
    }

    #[test]
    fn launch_arguments_omit_profile_dir_key_when_none() {
        let v = build_launch_arguments(&opts(Lang::En, true, None));
        assert!(!v.iter().any(|o| o == "--profile-dir"));
        assert_eq!(
            as_strings(&v),
            [
                "service",
                "run",
                "--lang",
                "en",
                "--enable-overlap",
                "--quic",
                "blocked"
            ]
        );
    }

    #[test]
    fn the_quic_policy_is_pinned_into_the_stored_arguments() {
        // Spelled out even at the default, so a later change of default can't
        // silently repurpose an already-installed service.
        for p in [QuicPolicy::Off, QuicPolicy::Blocked, QuicPolicy::All] {
            let mut o = opts(Lang::En, false, None);
            o.quic = p;
            let v = as_strings(&build_launch_arguments(&o));
            let i = v
                .iter()
                .position(|a| a == "--quic")
                .expect("--quic present");
            assert_eq!(v[i + 1], p.as_str());
        }
    }

    #[test]
    fn lang_code_maps_both_languages() {
        assert_eq!(lang_code(Lang::En), "en");
        assert_eq!(lang_code(Lang::Tr), "tr");
    }

    #[test]
    fn value_after_reads_the_following_token_only() {
        let s = [
            "--profile-dir".to_string(),
            "p".to_string(),
            "--force".to_string(),
        ];
        assert_eq!(value_after(&s, "--profile-dir"), Some("p"));
        assert_eq!(value_after(&s, "--force"), None); // flag, nothing after
        assert_eq!(value_after(&s, "--missing"), None);
    }
}
