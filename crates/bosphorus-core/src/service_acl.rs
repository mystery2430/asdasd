//! Pure access-control policy for the directory a LocalSystem service loads its
//! executable and WinDivert driver from.
//!
//! The decision lives here, without any Windows API, so it can be unit-tested on
//! any host. `bosphorus-cli`'s installer reads the directory's owner and DACL
//! with `GetNamedSecurityInfoW` and feeds them in as [`AceEntry`] values.
//!
//! The policy is deliberately *fail-closed*: a directory is acceptable only when
//! every allow ACE that carries a write, delete, `WRITE_DAC` or `WRITE_OWNER`
//! right names an administrator principal (LocalSystem, Administrators,
//! TrustedInstaller) and the directory itself is owned by one of them. Anything
//! the evaluator cannot interpret — an unresolvable SID, an object/callback ACE,
//! a missing owner — rejects the directory.
//!
//! Why the owner matters: a DACL ACE listing a single user SID
//! (`S-1-5-21-...-1001`) grants exactly that user, and it is *not* covered by the
//! well-known group SIDs (`Everyone`, `Users`, `Authenticated Users`,
//! `INTERACTIVE`). Windows profiles are normally ACLed with the individual user
//! SID, so an `--install-dir` under `%USERPROFILE%` passed a broad-SID-only
//! check. Independently, the owner of an object always holds `READ_CONTROL` +
//! `WRITE_DAC`, so a non-administrator owner can rewrite the DACL and grant
//! itself write access; that condition is checked too.
//!
//! Windows' default `C:\Program Files` DACL contains inherited `CREATOR OWNER`
//! entries. They are placeholder SIDs that resolve, at access-check time, to the
//! owner of the object the ACE was inherited *by* — never to an arbitrary
//! principal. Because the installer requires the owner of both the directory and
//! its parent to be an administrator, such an entry can only ever grant
//! administrator principals and is therefore accepted. Every other untrusted
//! trustee, including one carrying inherit-only flags, still rejects.
//!
//! Not established here: SACL/auditing, integrity levels, whether the parent
//! chain above the immediate parent is sound, and TOCTOU between this check and
//! the file copy. This is one gate in the installer, not a proof that the
//! directory stays administrator-only.

/// `ACCESS_ALLOWED_ACE_TYPE` — a plain allow ACE whose trustee is a SID.
pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
/// `ACCESS_DENIED_ACE_TYPE` — never grants access; ignored.
pub const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
/// `ACCESS_ALLOWED_OBJECT_ACE_TYPE` — allow with an object GUID/class mask.
pub const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
/// `ACCESS_ALLOWED_CALLBACK_ACE_TYPE` — allow with a conditional expression.
pub const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 0x09;
/// `ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE` — allow, object + condition.
pub const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0B;

/// File rights that let the holder replace, delete, rewrite the ACL of, or take
/// ownership of the service binary or driver next to it.
pub const DANGEROUS_ACCESS: u32 = 0x0000_0002 // FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x0000_0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

/// Principals that are administrator-controlled and may hold write access to the
/// install directory.
///
/// - `S-1-5-18` LocalSystem
/// - `S-1-5-32-544` BUILTIN\Administrators
/// - `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`
///   NT SERVICE\TrustedInstaller (owner of protected system files)
pub const TRUSTED_SID_ALLOWLIST: [&str; 3] = [
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// `ACE_HEADER::AceFlags` bits the policy cares about.
pub mod ace_flags {
    /// Applies to the object itself.
    pub const EFFECTIVE: u8 = 0x00;
    /// Inherited by child containers.
    pub const CONTAINER_INHERIT: u8 = 0x02;
    /// Inherited by child objects.
    pub const OBJECT_INHERIT: u8 = 0x01;
    /// Only inherited by children; grants nothing on this object.
    pub const INHERIT_ONLY: u8 = 0x08;
    /// Set by Windows on ACEs the object inherited rather than carries itself.
    pub const INHERITED: u8 = 0x10;
}

/// Placeholder trustees whose meaning is "the owner of the object", resolved by
/// the kernel at access-check time. See the module docs for why accepting them
/// does not weaken the owner requirement.
const CREATOR_OWNER_SID: &str = "S-1-3-0";
const OWNER_RIGHTS_SID: &str = "S-1-3-4";

/// One DACL entry, as much of it as the policy needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AceEntry {
    /// `ACE_HEADER::AceType`.
    pub ace_type: u8,
    /// `ACE_HEADER::AceFlags` (see [`ace_flags`]).
    pub ace_flags: u8,
    /// The access mask (`ACCESS_ALLOWED_ACE::Mask`; the first eight bytes of the
    /// ACE are laid out the same way for object and callback allow ACEs).
    pub mask: u32,
    /// Trustee SID in string form. `None` means the installer could not resolve
    /// it — treated as untrusted, never as a reason to accept.
    pub sid: Option<String>,
}

impl AceEntry {
    /// A plain allow ACE for `sid` with `mask`, applying to the object itself.
    pub fn allow(mask: u32, sid: &str) -> Self {
        Self {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            ace_flags: ace_flags::EFFECTIVE,
            mask,
            sid: Some(sid.to_owned()),
        }
    }

    /// An inheritable allow ACE, as Windows records it on the parent.
    pub fn allow_inherited(mask: u32, sid: &str) -> Self {
        Self {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            ace_flags: ace_flags::OBJECT_INHERIT
                | ace_flags::CONTAINER_INHERIT
                | ace_flags::INHERIT_ONLY
                | ace_flags::INHERITED,
            mask,
            sid: Some(sid.to_owned()),
        }
    }
}

/// Whether this trustee only ever resolves to the object's owner.
fn is_owner_scoped_placeholder(sid: &str) -> bool {
    sid.eq_ignore_ascii_case(CREATOR_OWNER_SID) || sid.eq_ignore_ascii_case(OWNER_RIGHTS_SID)
}

/// Why a directory must not host the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AclRejection {
    /// The DACL pointer was NULL, which grants everyone full control.
    NullDacl,
    /// No owner was supplied (fail closed).
    MissingOwner,
    /// The directory's owner can always rewrite the DACL (`WRITE_DAC` is
    /// implicit for owners), so a non-administrator owner is unsafe even if the
    /// current ACEs look fine.
    UntrustedOwner(String),
    /// An allow ACE grants dangerous rights to a non-administrator trustee.
    UntrustedWriteAce { sid: String, mask: u32 },
    /// An allow ACE grants dangerous rights but its trustee could not be read.
    UnresolvedTrustee { ace_type: u8, mask: u32 },
    /// An allow ACE type whose effective grant cannot be evaluated statically
    /// (object/conditional ACE); rejected rather than guessed at.
    UnsupportedAllowAce { ace_type: u8, mask: u32 },
}

impl AclRejection {
    /// One-line explanation for the installer's warning log and error message.
    pub fn describe(&self) -> String {
        match self {
            AclRejection::NullDacl => {
                "the directory has a NULL DACL (full access for everyone)".into()
            }
            AclRejection::MissingOwner => "the directory owner could not be determined".into(),
            AclRejection::UntrustedOwner(sid) => format!(
                "the directory is owned by {sid}, which is not an administrator principal; an \
                 owner can always rewrite the DACL"
            ),
            AclRejection::UntrustedWriteAce { sid, mask } => format!(
                "the directory grants {mask:#x} (write/delete/ACL rights) to {sid}, a \
                 non-administrator principal"
            ),
            AclRejection::UnresolvedTrustee { ace_type, mask } => format!(
                "an allow ACE of type {ace_type:#04x} grants {mask:#x} but its trustee SID could \
                 not be resolved"
            ),
            AclRejection::UnsupportedAllowAce { ace_type, mask } => format!(
                "an allow ACE of type {ace_type:#04x} grants {mask:#x} through an object or \
                 conditional ACE this check cannot evaluate"
            ),
        }
    }
}

fn is_trusted(sid: &str) -> bool {
    TRUSTED_SID_ALLOWLIST
        .iter()
        .any(|trusted| trusted.eq_ignore_ascii_case(sid))
}

fn is_allow_type(ace_type: u8) -> bool {
    matches!(
        ace_type,
        ACCESS_ALLOWED_ACE_TYPE
            | ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
    )
}

/// Decide whether `owner_sid` + `aces` describe an administrator-controlled
/// directory. Deny and audit ACEs are ignored (they cannot grant access).
pub fn evaluate(owner_sid: Option<&str>, aces: &[AceEntry]) -> Result<(), AclRejection> {
    let owner = owner_sid.ok_or(AclRejection::MissingOwner)?;
    if !is_trusted(owner) {
        return Err(AclRejection::UntrustedOwner(owner.to_owned()));
    }

    for ace in aces {
        if !is_allow_type(ace.ace_type) || ace.mask & DANGEROUS_ACCESS == 0 {
            continue;
        }
        // Object/conditional allow ACEs grant through a scope this policy does
        // not model; fail closed instead of assuming the SID is benign.
        if ace.ace_type != ACCESS_ALLOWED_ACE_TYPE {
            return Err(AclRejection::UnsupportedAllowAce {
                ace_type: ace.ace_type,
                mask: ace.mask,
            });
        }
        match ace.sid.as_deref() {
            Some(sid) if is_trusted(sid) => continue,
            // Resolves to the object's owner, which must already be an
            // administrator, so it cannot grant an ordinary principal anything.
            Some(sid) if is_owner_scoped_placeholder(sid) => continue,
            Some(sid) => {
                return Err(AclRejection::UntrustedWriteAce {
                    sid: sid.to_owned(),
                    mask: ace.mask,
                })
            }
            None => {
                return Err(AclRejection::UnresolvedTrustee {
                    ace_type: ace.ace_type,
                    mask: ace.mask,
                })
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADMIN: &str = "S-1-5-32-544";
    const SYSTEM: &str = "S-1-5-18";
    const EVERYONE: &str = "S-1-1-0";
    const USERS: &str = "S-1-5-32-545";
    const AUTH_USERS: &str = "S-1-5-11";
    const INTERACTIVE: &str = "S-1-5-4";
    /// A single local account, e.g. the one whose profile directory this is.
    const ALICE: &str = "S-1-5-21-111111111-222222222-333333333-1001";

    #[test]
    fn a_program_files_style_dacl_is_accepted() {
        let aces = [
            AceEntry::allow(0x001F_01FF, SYSTEM),
            AceEntry::allow(0x001F_01FF, ADMIN),
            AceEntry::allow(0x0012_00A9, USERS), // read + execute
            AceEntry::allow(0x0012_00A9, "S-1-15-2-1"), // ALL APPLICATION PACKAGES, read
        ];
        assert_eq!(evaluate(Some(ADMIN), &aces), Ok(()));
        assert_eq!(evaluate(Some(SYSTEM), &aces), Ok(()));
    }

    /// The gap a broad-SID-only check missed: a profile directory inherits an
    /// ACE for the individual account, not just `Users`.
    #[test]
    fn an_individual_user_sid_with_write_access_is_rejected() {
        let aces = [AceEntry::allow(0x001F_01FF, ALICE)];
        assert_eq!(
            evaluate(Some(ADMIN), &aces),
            Err(AclRejection::UntrustedWriteAce {
                sid: ALICE.to_owned(),
                mask: 0x001F_01FF
            })
        );
    }

    #[test]
    fn the_well_known_broad_sids_are_still_rejected() {
        for sid in [EVERYONE, USERS, AUTH_USERS, INTERACTIVE] {
            for mask in [
                0x0000_0002u32, // FILE_WRITE_DATA
                0x0000_0004,    // FILE_APPEND_DATA
                0x0000_0040,    // FILE_DELETE_CHILD
                0x0001_0000,    // DELETE
                0x0004_0000,    // WRITE_DAC
                0x0008_0000,    // WRITE_OWNER
                0x1000_0000,    // GENERIC_ALL
                0x4000_0000,    // GENERIC_WRITE
            ] {
                assert_eq!(
                    evaluate(Some(ADMIN), &[AceEntry::allow(mask, sid)]),
                    Err(AclRejection::UntrustedWriteAce {
                        sid: sid.to_owned(),
                        mask
                    }),
                    "{sid} with {mask:#x} must be refused"
                );
            }
        }
    }

    #[test]
    fn broad_sids_with_only_read_rights_are_fine() {
        let aces = [
            AceEntry::allow(0x0012_00A9, USERS),
            AceEntry::allow(0x0012_00A9, EVERYONE),
        ];
        assert_eq!(evaluate(Some(ADMIN), &aces), Ok(()));
    }

    #[test]
    fn a_non_administrator_owner_is_rejected_even_with_clean_aces() {
        assert_eq!(
            evaluate(Some(ALICE), &[]),
            Err(AclRejection::UntrustedOwner(ALICE.to_owned()))
        );
        assert_eq!(evaluate(None, &[]), Err(AclRejection::MissingOwner));
    }

    #[test]
    fn an_unresolvable_trustee_on_a_write_ace_fails_closed() {
        let entry = AceEntry {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            ace_flags: ace_flags::EFFECTIVE,
            mask: 0x0000_0002,
            sid: None,
        };
        assert_eq!(
            evaluate(Some(ADMIN), &[entry]),
            Err(AclRejection::UnresolvedTrustee {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                mask: 0x0000_0002
            })
        );
    }

    #[test]
    fn object_and_callback_allow_aces_fail_closed_when_they_carry_write_bits() {
        for ace_type in [
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
        ] {
            let entry = AceEntry {
                ace_type,
                ace_flags: ace_flags::EFFECTIVE,
                mask: 0x4000_0000,
                sid: Some(ADMIN.to_owned()),
            };
            assert_eq!(
                evaluate(Some(ADMIN), &[entry]),
                Err(AclRejection::UnsupportedAllowAce {
                    ace_type,
                    mask: 0x4000_0000
                })
            );
        }
    }

    #[test]
    fn deny_and_audit_aces_never_reject_a_directory() {
        let aces = [
            AceEntry {
                ace_type: ACCESS_DENIED_ACE_TYPE,
                ace_flags: ace_flags::EFFECTIVE,
                mask: 0x001F_01FF,
                sid: Some(ALICE.to_owned()),
            },
            AceEntry {
                ace_type: 0x02, // ACCESS_SYSTEM_AUDIT_ACE_TYPE
                ace_flags: ace_flags::EFFECTIVE,
                mask: 0x001F_01FF,
                sid: Some(USERS.to_owned()),
            },
        ];
        assert_eq!(evaluate(Some(ADMIN), &aces), Ok(()));
    }

    /// A stock `C:\Program Files` DACL carries inherited `CREATOR OWNER` full
    /// control. Rejecting it would refuse every legitimate elevated install, so
    /// the placeholder is accepted — and it can only ever resolve to the owner,
    /// which the policy already requires to be an administrator.
    #[test]
    fn a_program_files_style_dacl_with_creator_owner_is_accepted() {
        let aces = [
            AceEntry::allow(0x001F_01FF, SYSTEM),
            AceEntry::allow(0x001F_01FF, ADMIN),
            AceEntry::allow_inherited(0x001F_01FF, CREATOR_OWNER_SID),
            AceEntry::allow_inherited(0x0012_00A9, USERS),
            AceEntry::allow_inherited(0x0012_00A9, "S-1-15-2-1"),
        ];
        assert_eq!(
            evaluate(
                Some("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"),
                &aces
            ),
            Ok(())
        );
        assert_eq!(evaluate(Some(ADMIN), &aces), Ok(()));
        // A placeholder never rescues a directory owned by an ordinary user.
        assert_eq!(
            evaluate(Some(ALICE), &aces),
            Err(AclRejection::UntrustedOwner(ALICE.to_owned()))
        );
    }

    /// The placeholder exemption must not extend to real users: an inherited
    /// ACE for an individual account still rejects, flags or not.
    #[test]
    fn an_inherited_allow_ace_for_a_real_user_is_still_rejected() {
        for entry in [
            AceEntry::allow_inherited(0x001F_01FF, ALICE),
            AceEntry::allow_inherited(0x001F_01FF, AUTH_USERS),
            AceEntry::allow(0x4000_0000, OWNER_RIGHTS_SID),
        ] {
            let sid = entry.sid.clone();
            let result = evaluate(Some(ADMIN), &[entry]);
            match sid.as_deref() {
                // OWNER RIGHTS is owner-scoped, so that one case must pass.
                Some(sid) if is_owner_scoped_placeholder(sid) => assert_eq!(result, Ok(())),
                _ => assert!(matches!(
                    result,
                    Err(AclRejection::UntrustedWriteAce { .. })
                )),
            }
        }
    }

    #[test]
    fn every_rejection_renders_a_reason() {
        let cases = [
            AclRejection::NullDacl,
            AclRejection::MissingOwner,
            AclRejection::UntrustedOwner(ALICE.into()),
            AclRejection::UntrustedWriteAce {
                sid: ALICE.into(),
                mask: 0x2,
            },
            AclRejection::UnresolvedTrustee {
                ace_type: 0,
                mask: 0x2,
            },
            AclRejection::UnsupportedAllowAce {
                ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
                mask: 0x2,
            },
        ];
        for case in cases {
            assert!(!case.describe().is_empty());
        }
    }
}
