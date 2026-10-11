//! Paperclip session skill install (v1) — pure fetch-free path.
//!
//! Design: `docs/plans/haee-run-envelope.md` §5
//! Plan: `docs/plans/haee-envelope-implementation.md` Iteration 7
//!
//! # Rules
//!
//! - Install only envelope-listed [`SkillRef`] values.
//! - Integrity (sha256 + sizeMax) required for remote packages; hash is over
//!   the exact package bytes (not extracted tree).
//! - Extract + validate only — **never** run package scripts on install.
//! - Layout: `<skill_root>/<runtimeName>/SKILL.md` (+ optional siblings).
//! - Failures omit the skill (caller logs); this module does not panic.
//! - `file://` and other disallowed URI schemes are rejected.
//! - `paperclip-skill://` is recognized but not resolved in v1 (stub fail).
//!
//! Network fetch lives outside this module so unit tests stay hermetic. Callers
//! download bytes (http/https only), then call [`install_skill_package`].

use crate::haee_run_envelope::{SkillIntegrity, SkillRef, SkillScope};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Stable error class names for logs and tests.
pub mod error_class {
    pub const URI_SCHEME_DISALLOWED: &str = "skill_uri_scheme_disallowed";
    pub const URI_SCHEME_UNSUPPORTED: &str = "skill_uri_scheme_unsupported";
    pub const INTEGRITY_REQUIRED: &str = "skill_integrity_required";
    pub const INTEGRITY_SIZE: &str = "skill_integrity_size";
    pub const INTEGRITY_HASH: &str = "skill_integrity_hash";
    pub const MEDIA_TYPE_UNSUPPORTED: &str = "skill_media_type_unsupported";
    pub const ARCHIVE_INVALID: &str = "skill_archive_invalid";
    pub const SKILL_MD_MISSING: &str = "skill_md_missing";
    pub const RUNTIME_NAME_INVALID: &str = "skill_runtime_name_invalid";
    pub const SCOPE_UNSUPPORTED: &str = "skill_scope_unsupported";
    pub const IO: &str = "skill_install_io";
}

/// Install failure with a stable `class` (never panics).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{class}: {message}")]
pub struct SkillInstallError {
    pub class: &'static str,
    pub message: String,
}

impl SkillInstallError {
    fn new(class: &'static str, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
        }
    }
}

/// Successful install of one skill package under a skill root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillInstallReport {
    pub key: String,
    pub runtime_name: String,
    pub scope: SkillScope,
    /// Directory containing `SKILL.md` (`skill_root/runtimeName`).
    pub install_dir: PathBuf,
    pub always: bool,
}

/// Classify a skill URI for the v1 install plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillUriKind {
    /// `http://` or `https://` — fetchable with integrity.
    Http,
    /// `paperclip-skill://…` — logical id; resolve via Paperclip API later.
    PaperclipSkill,
    /// Explicitly rejected (e.g. `file://`, `git://`).
    Disallowed,
    /// Unknown / empty scheme.
    Unsupported,
}

/// Classify `SkillRef.uri` without performing I/O.
pub fn classify_skill_uri(uri: &str) -> SkillUriKind {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return SkillUriKind::Unsupported;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        SkillUriKind::Http
    } else if lower.starts_with("paperclip-skill://") {
        SkillUriKind::PaperclipSkill
    } else if lower.starts_with("file://")
        || lower.starts_with("git://")
        || lower.starts_with("ssh://")
        || lower.starts_with("git+")
    {
        SkillUriKind::Disallowed
    } else {
        SkillUriKind::Unsupported
    }
}

/// True when the URI is allowed for a remote byte fetch in v1.
pub fn is_fetchable_skill_uri(uri: &str) -> bool {
    matches!(classify_skill_uri(uri), SkillUriKind::Http)
}

/// Verify package bytes against integrity (size + sha256 hex).
pub fn verify_package_integrity(
    bytes: &[u8],
    integrity: &SkillIntegrity,
) -> Result<(), SkillInstallError> {
    if bytes.len() as u64 > integrity.size_max {
        return Err(SkillInstallError::new(
            error_class::INTEGRITY_SIZE,
            format!(
                "package size {} exceeds sizeMax {}",
                bytes.len(),
                integrity.size_max
            ),
        ));
    }
    let expected = normalize_sha256_hex(&integrity.sha256)?;
    let actual = hex_sha256(bytes);
    if actual != expected {
        return Err(SkillInstallError::new(
            error_class::INTEGRITY_HASH,
            format!("sha256 mismatch (expected {expected}, got {actual})"),
        ));
    }
    Ok(())
}

fn normalize_sha256_hex(raw: &str) -> Result<String, SkillInstallError> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SkillInstallError::new(
            error_class::INTEGRITY_HASH,
            format!("integrity.sha256 must be 64 hex chars (got len {})", trimmed.len()),
        ));
    }
    Ok(trimmed)
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Compute sha256 hex of package bytes (helper for tests / adapters).
pub fn package_sha256_hex(bytes: &[u8]) -> String {
    hex_sha256(bytes)
}

fn sanitize_runtime_name(name: &str) -> Result<String, SkillInstallError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(SkillInstallError::new(
            error_class::RUNTIME_NAME_INVALID,
            "runtimeName must be non-empty",
        ));
    }
    if trimmed.contains('/') || trimmed.contains('\\') || trimmed == "." || trimmed == ".." {
        return Err(SkillInstallError::new(
            error_class::RUNTIME_NAME_INVALID,
            format!("runtimeName {trimmed:?} must be a single path segment"),
        ));
    }
    if trimmed
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'))
    {
        return Err(SkillInstallError::new(
            error_class::RUNTIME_NAME_INVALID,
            format!("runtimeName {trimmed:?} has unsupported characters"),
        ));
    }
    Ok(trimmed.to_string())
}

/// Detect archive kind from media type and/or magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveKind {
    Tar,
    TarGz,
    Zip,
}

fn detect_archive_kind(media_type: &str, bytes: &[u8]) -> Result<ArchiveKind, SkillInstallError> {
    let mt = media_type.trim().to_ascii_lowercase();
    if mt.contains("zip") {
        return Ok(ArchiveKind::Zip);
    }
    if mt.contains("tar+gzip")
        || mt.contains("x-gtar")
        || mt.contains("gzip")
        || mt.ends_with("+tgz")
        || mt.contains("tgz")
    {
        return Ok(ArchiveKind::TarGz);
    }
    if mt.contains("tar") || mt.contains("vnd.paperclip.skill.v1+tar") {
        // Prefer magic when media type is generic tar.
        if is_gzip_magic(bytes) {
            return Ok(ArchiveKind::TarGz);
        }
        return Ok(ArchiveKind::Tar);
    }
    if is_zip_magic(bytes) {
        return Ok(ArchiveKind::Zip);
    }
    if is_gzip_magic(bytes) {
        return Ok(ArchiveKind::TarGz);
    }
    // bare ustar tar has no reliable short magic; try tar if media empty-ish
    if mt.is_empty() {
        return Err(SkillInstallError::new(
            error_class::MEDIA_TYPE_UNSUPPORTED,
            "mediaType is required to select tar or zip extraction",
        ));
    }
    Err(SkillInstallError::new(
        error_class::MEDIA_TYPE_UNSUPPORTED,
        format!("unsupported skill mediaType {media_type:?}"),
    ))
}

fn is_zip_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0] == 0x50 && bytes[1] == 0x4b && (bytes[2] == 0x03 || bytes[2] == 0x05 || bytes[2] == 0x07)
}

fn is_gzip_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b
}

/// Install one skill package from already-fetched bytes into `skill_root`.
///
/// `skill_root` is the session (or agent) skills directory — **not** the issue
/// git cwd. On success, creates `skill_root/<runtimeName>/` with `SKILL.md`.
///
/// Does **not** execute scripts, run `npm install`, or invoke interpreters.
pub fn install_skill_package(
    skill: &SkillRef,
    package_bytes: &[u8],
    skill_root: &Path,
) -> Result<SkillInstallReport, SkillInstallError> {
    match skill.scope {
        SkillScope::Session | SkillScope::Agent => {}
    }

    match classify_skill_uri(&skill.uri) {
        SkillUriKind::Http => {}
        SkillUriKind::PaperclipSkill => {
            return Err(SkillInstallError::new(
                error_class::URI_SCHEME_UNSUPPORTED,
                "paperclip-skill:// resolution is not implemented in v1 (use http(s) pack URL)",
            ));
        }
        SkillUriKind::Disallowed => {
            return Err(SkillInstallError::new(
                error_class::URI_SCHEME_DISALLOWED,
                format!("skill uri scheme is disallowed: {}", skill.uri.trim()),
            ));
        }
        SkillUriKind::Unsupported => {
            return Err(SkillInstallError::new(
                error_class::URI_SCHEME_UNSUPPORTED,
                format!("skill uri scheme is unsupported: {}", skill.uri.trim()),
            ));
        }
    }

    let integrity = skill.integrity.as_ref().ok_or_else(|| {
        SkillInstallError::new(
            error_class::INTEGRITY_REQUIRED,
            "remote skill package requires integrity",
        )
    })?;
    verify_package_integrity(package_bytes, integrity)?;

    let runtime_name = sanitize_runtime_name(&skill.runtime_name)?;
    let install_dir = skill_root.join(&runtime_name);

    // Replace any prior install of the same runtime name under this root.
    if install_dir.exists() {
        fs::remove_dir_all(&install_dir).map_err(|err| {
            SkillInstallError::new(
                error_class::IO,
                format!("failed to clear prior install dir: {err}"),
            )
        })?;
    }
    fs::create_dir_all(&install_dir).map_err(|err| {
        SkillInstallError::new(
            error_class::IO,
            format!("failed to create install dir: {err}"),
        )
    })?;

    let kind = detect_archive_kind(&skill.media_type, package_bytes)?;
    let extract_result = match kind {
        ArchiveKind::Tar => extract_tar(package_bytes, &install_dir, false),
        ArchiveKind::TarGz => extract_tar(package_bytes, &install_dir, true),
        ArchiveKind::Zip => extract_zip(package_bytes, &install_dir),
    };

    if let Err(err) = extract_result {
        let _ = fs::remove_dir_all(&install_dir);
        return Err(err);
    }

    // Normalize single top-level directory archives into install_dir root.
    if let Err(err) = flatten_single_top_level_dir(&install_dir) {
        let _ = fs::remove_dir_all(&install_dir);
        return Err(err);
    }

    let skill_md = install_dir.join("SKILL.md");
    if !skill_md.is_file() {
        let _ = fs::remove_dir_all(&install_dir);
        return Err(SkillInstallError::new(
            error_class::SKILL_MD_MISSING,
            format!(
                "installed package for runtimeName {runtime_name} is missing SKILL.md at root"
            ),
        ));
    }

    // Defense in depth: never execute anything found under the install tree.
    // (No Command::new, no script hooks — extract-only by construction.)

    Ok(SkillInstallReport {
        key: skill.key.clone(),
        runtime_name,
        scope: skill.scope,
        install_dir,
        always: skill.always.unwrap_or(false),
    })
}

/// Install many skills; omit failures and return both successes and errors.
///
/// Session-scoped refs install under `session_skill_root`. Agent-scoped refs
/// install under `agent_skill_root` when provided; otherwise they are omitted
/// with [`error_class::SCOPE_UNSUPPORTED`].
pub fn install_skill_packages<'a, F>(
    skills: &'a [SkillRef],
    session_skill_root: &Path,
    agent_skill_root: Option<&Path>,
    mut fetch_bytes: F,
) -> (Vec<SkillInstallReport>, Vec<(String, SkillInstallError)>)
where
    F: FnMut(&SkillRef) -> Result<Vec<u8>, SkillInstallError>,
{
    let mut ok = Vec::new();
    let mut failed = Vec::new();
    for skill in skills {
        let root = match skill.scope {
            SkillScope::Session => session_skill_root,
            SkillScope::Agent => match agent_skill_root {
                Some(path) => path,
                None => {
                    failed.push((
                        skill.key.clone(),
                        SkillInstallError::new(
                            error_class::SCOPE_UNSUPPORTED,
                            "agent-scoped skill install requires agent skill root",
                        ),
                    ));
                    continue;
                }
            },
        };
        match fetch_bytes(skill).and_then(|bytes| install_skill_package(skill, &bytes, root)) {
            Ok(report) => ok.push(report),
            Err(err) => failed.push((skill.key.clone(), err)),
        }
    }
    (ok, failed)
}

fn flatten_single_top_level_dir(install_dir: &Path) -> Result<(), SkillInstallError> {
    if install_dir.join("SKILL.md").is_file() {
        return Ok(());
    }
    let mut children = list_dir_entries(install_dir)?;
    // Ignore hidden junk occasionally present in archives.
    children.retain(|p| {
        p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| !n.starts_with('.'))
    });
    if children.len() != 1 || !children[0].is_dir() {
        return Ok(());
    }
    let nested = children.into_iter().next().expect("len checked");
    if !nested.join("SKILL.md").is_file() {
        return Ok(());
    }
    // Move nested contents up into install_dir.
    for entry in list_dir_entries(&nested)? {
        let name = entry.file_name().ok_or_else(|| {
            SkillInstallError::new(error_class::ARCHIVE_INVALID, "archive entry missing name")
        })?;
        let dest = install_dir.join(name);
        fs::rename(&entry, &dest).map_err(|err| {
            SkillInstallError::new(
                error_class::IO,
                format!("failed to flatten archive entry: {err}"),
            )
        })?;
    }
    fs::remove_dir_all(&nested).map_err(|err| {
        SkillInstallError::new(
            error_class::IO,
            format!("failed to remove nested archive dir: {err}"),
        )
    })?;
    Ok(())
}

fn list_dir_entries(dir: &Path) -> Result<Vec<PathBuf>, SkillInstallError> {
    let rd = fs::read_dir(dir).map_err(|err| {
        SkillInstallError::new(error_class::IO, format!("read_dir failed: {err}"))
    })?;
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|err| {
            SkillInstallError::new(error_class::IO, format!("read_dir entry failed: {err}"))
        })?;
        out.push(entry.path());
    }
    out.sort();
    Ok(out)
}

fn extract_tar(bytes: &[u8], dest: &Path, gzip: bool) -> Result<(), SkillInstallError> {
    let reader: Box<dyn Read> = if gzip {
        Box::new(flate2::read::GzDecoder::new(Cursor::new(bytes)))
    } else {
        Box::new(Cursor::new(bytes))
    };
    let mut archive = tar::Archive::new(reader);
    let entries = archive.entries().map_err(|err| {
        SkillInstallError::new(
            error_class::ARCHIVE_INVALID,
            format!("invalid tar archive: {err}"),
        )
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|err| {
            SkillInstallError::new(
                error_class::ARCHIVE_INVALID,
                format!("invalid tar entry: {err}"),
            )
        })?;
        let path = entry.path().map_err(|err| {
            SkillInstallError::new(
                error_class::ARCHIVE_INVALID,
                format!("invalid tar entry path: {err}"),
            )
        })?;
        let rel = safe_archive_relative_path(&path)?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        let out_path = dest.join(&rel);
        match entry.header().entry_type() {
            tar::EntryType::Directory => {
                fs::create_dir_all(&out_path).map_err(|err| {
                    SkillInstallError::new(error_class::IO, format!("mkdir failed: {err}"))
                })?;
            }
            tar::EntryType::Regular
            | tar::EntryType::Continuous
            | tar::EntryType::Fifo
            | tar::EntryType::Char
            | tar::EntryType::Block
            | tar::EntryType::GNUSparse => {
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent).map_err(|err| {
                        SkillInstallError::new(error_class::IO, format!("mkdir failed: {err}"))
                    })?;
                }
                let mut file = File::create(&out_path).map_err(|err| {
                    SkillInstallError::new(error_class::IO, format!("create file failed: {err}"))
                })?;
                io::copy(&mut entry, &mut file).map_err(|err| {
                    SkillInstallError::new(error_class::IO, format!("write file failed: {err}"))
                })?;
            }
            tar::EntryType::Symlink | tar::EntryType::Link | tar::EntryType::XGlobalHeader
            | tar::EntryType::XHeader | tar::EntryType::GNULongName
            | tar::EntryType::GNULongLink => {
                // Skip link/metadata entries — no symlink escape, no scripts.
                continue;
            }
            _ => continue,
        }
    }
    Ok(())
}

fn extract_zip(bytes: &[u8], dest: &Path) -> Result<(), SkillInstallError> {
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader).map_err(|err| {
        SkillInstallError::new(
            error_class::ARCHIVE_INVALID,
            format!("invalid zip archive: {err}"),
        )
    })?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|err| {
            SkillInstallError::new(
                error_class::ARCHIVE_INVALID,
                format!("invalid zip entry: {err}"),
            )
        })?;
        let name = file.name().to_string();
        // Skip symlink-like entries if the crate exposes unix mode; zip crate
        // may not always mark them — still refuse absolute / .. paths.
        if name.ends_with('/') {
            let rel = safe_archive_relative_path(Path::new(name.trim_end_matches('/')))?;
            if rel.as_os_str().is_empty() {
                continue;
            }
            fs::create_dir_all(dest.join(rel)).map_err(|err| {
                SkillInstallError::new(error_class::IO, format!("mkdir failed: {err}"))
            })?;
            continue;
        }
        let rel = safe_archive_relative_path(Path::new(&name))?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        let out_path = dest.join(&rel);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                SkillInstallError::new(error_class::IO, format!("mkdir failed: {err}"))
            })?;
        }
        let mut out = File::create(&out_path).map_err(|err| {
            SkillInstallError::new(error_class::IO, format!("create file failed: {err}"))
        })?;
        io::copy(&mut file, &mut out).map_err(|err| {
            SkillInstallError::new(error_class::IO, format!("write file failed: {err}"))
        })?;
        // Ensure we don't leave the file handle thinking we ran anything.
        out.flush().ok();
    }
    Ok(())
}

fn safe_archive_relative_path(path: &Path) -> Result<PathBuf, SkillInstallError> {
    if path.is_absolute() {
        return Err(SkillInstallError::new(
            error_class::ARCHIVE_INVALID,
            format!("archive entry has absolute path: {}", path.display()),
        ));
    }
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Normal(seg) => out.push(seg),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(SkillInstallError::new(
                    error_class::ARCHIVE_INVALID,
                    format!("archive entry escapes root: {}", path.display()),
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(SkillInstallError::new(
                    error_class::ARCHIVE_INVALID,
                    format!("archive entry has unsupported path: {}", path.display()),
                ));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::haee_run_envelope::{SkillIntegrity, SkillRef, SkillScope};
    use std::process::Command;

    fn skill_ref(uri: &str, runtime: &str, bytes: &[u8], media: &str) -> SkillRef {
        SkillRef {
            key: format!("test/{runtime}"),
            runtime_name: runtime.to_string(),
            version_id: None,
            uri: uri.to_string(),
            integrity: Some(SkillIntegrity {
                sha256: package_sha256_hex(bytes),
                size_max: (bytes.len() as u64).max(1) + 1024,
            }),
            media_type: media.to_string(),
            scope: SkillScope::Session,
            always: Some(true),
        }
    }

    fn make_tar_with_skill_md(body: &str) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        let data = body.as_bytes();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "SKILL.md", data)
            .expect("append SKILL.md");
        // Optional non-executed script sibling — install must not run it.
        let mut sh_header = tar::Header::new_gnu();
        let script = b"#!/bin/sh\necho SHOULD_NOT_RUN\n";
        sh_header.set_size(script.len() as u64);
        sh_header.set_mode(0o755);
        sh_header.set_cksum();
        builder
            .append_data(&mut sh_header, "scripts/hello.sh", &script[..])
            .expect("append script");
        builder.into_inner().expect("finish tar")
    }

    fn make_nested_tar(runtime_inner: &str, body: &str) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        let data = body.as_bytes();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        let path = format!("{runtime_inner}/SKILL.md");
        builder
            .append_data(&mut header, path, data)
            .expect("append nested SKILL.md");
        builder.into_inner().expect("finish tar")
    }

    #[test]
    fn classify_rejects_file_and_git() {
        assert_eq!(classify_skill_uri("file:///tmp/x.tar"), SkillUriKind::Disallowed);
        assert_eq!(classify_skill_uri("git://example/repo"), SkillUriKind::Disallowed);
        assert_eq!(
            classify_skill_uri("https://example/pack.tar"),
            SkillUriKind::Http
        );
        assert_eq!(
            classify_skill_uri("paperclip-skill://co/key@v1"),
            SkillUriKind::PaperclipSkill
        );
    }

    #[test]
    fn good_tar_installs_under_runtime_name() {
        let bytes = make_tar_with_skill_md("---\nname: demo\n---\n# Demo\n");
        let skill = skill_ref(
            "http://127.0.0.1:9/pack.tar",
            "issue-triage",
            &bytes,
            "application/vnd.paperclip.skill.v1+tar",
        );
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let report = install_skill_package(&skill, &bytes, &root).expect("install");
        assert_eq!(report.runtime_name, "issue-triage");
        assert!(report.install_dir.join("SKILL.md").is_file());
        assert!(report.install_dir.join("scripts/hello.sh").is_file());
        assert!(report.always);
        // Scripts must not have been executed (no side-effect file).
        assert!(!report.install_dir.join("SHOULD_NOT_RUN").exists());
    }

    #[test]
    fn nested_single_dir_tar_flattens_to_runtime_root() {
        let bytes = make_nested_tar("pkg", "# Nested\n");
        let skill = skill_ref(
            "https://example.test/n.tar",
            "nested-skill",
            &bytes,
            "application/x-tar",
        );
        let tmp = tempfile::tempdir().unwrap();
        let report = install_skill_package(&skill, &bytes, tmp.path()).unwrap();
        assert!(report.install_dir.join("SKILL.md").is_file());
        assert!(!report.install_dir.join("pkg").exists());
    }

    #[test]
    fn bad_hash_omits_without_partial_dir() {
        let bytes = make_tar_with_skill_md("# x\n");
        let mut skill = skill_ref(
            "http://example.test/x.tar",
            "bad-hash",
            &bytes,
            "application/x-tar",
        );
        skill.integrity.as_mut().unwrap().sha256 =
            "0000000000000000000000000000000000000000000000000000000000000000".into();
        let tmp = tempfile::tempdir().unwrap();
        let err = install_skill_package(&skill, &bytes, tmp.path()).unwrap_err();
        assert_eq!(err.class, error_class::INTEGRITY_HASH);
        assert!(!tmp.path().join("bad-hash").exists());
    }

    #[test]
    fn oversize_rejected() {
        let bytes = make_tar_with_skill_md("# big\n");
        let mut skill = skill_ref(
            "http://example.test/x.tar",
            "oversize",
            &bytes,
            "application/x-tar",
        );
        skill.integrity.as_mut().unwrap().size_max = 4;
        let tmp = tempfile::tempdir().unwrap();
        let err = install_skill_package(&skill, &bytes, tmp.path()).unwrap_err();
        assert_eq!(err.class, error_class::INTEGRITY_SIZE);
    }

    #[test]
    fn missing_skill_md_rejected_and_cleaned() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        let data = b"no skill md";
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "README.md", &data[..])
            .unwrap();
        let bytes = builder.into_inner().unwrap();
        let skill = skill_ref(
            "http://example.test/x.tar",
            "no-md",
            &bytes,
            "application/x-tar",
        );
        let tmp = tempfile::tempdir().unwrap();
        let err = install_skill_package(&skill, &bytes, tmp.path()).unwrap_err();
        assert_eq!(err.class, error_class::SKILL_MD_MISSING);
        assert!(!tmp.path().join("no-md").exists());
    }

    #[test]
    fn file_uri_rejected() {
        let bytes = make_tar_with_skill_md("# x\n");
        let skill = skill_ref(
            "file:///var/lib/paperclip/skills/x.tar",
            "file-skill",
            &bytes,
            "application/x-tar",
        );
        let tmp = tempfile::tempdir().unwrap();
        let err = install_skill_package(&skill, &bytes, tmp.path()).unwrap_err();
        assert_eq!(err.class, error_class::URI_SCHEME_DISALLOWED);
    }

    #[test]
    fn paperclip_skill_uri_stub_fails() {
        let bytes = make_tar_with_skill_md("# x\n");
        let skill = skill_ref(
            "paperclip-skill://company/key@v1",
            "logical",
            &bytes,
            "application/x-tar",
        );
        let tmp = tempfile::tempdir().unwrap();
        let err = install_skill_package(&skill, &bytes, tmp.path()).unwrap_err();
        assert_eq!(err.class, error_class::URI_SCHEME_UNSUPPORTED);
    }

    #[test]
    fn install_does_not_execute_package_scripts() {
        // Stronger check: a script that would create a marker if executed.
        let mut builder = tar::Builder::new(Vec::new());
        let md = b"# Skill\n";
        let mut h1 = tar::Header::new_gnu();
        h1.set_size(md.len() as u64);
        h1.set_mode(0o644);
        h1.set_cksum();
        builder.append_data(&mut h1, "SKILL.md", &md[..]).unwrap();
        let script = b"#!/bin/sh\ntouch ./RAN_ON_INSTALL\n";
        let mut h2 = tar::Header::new_gnu();
        h2.set_size(script.len() as u64);
        h2.set_mode(0o755);
        h2.set_cksum();
        builder
            .append_data(&mut h2, "install.sh", &script[..])
            .unwrap();
        let bytes = builder.into_inner().unwrap();
        let skill = skill_ref(
            "http://example.test/s.tar",
            "no-exec",
            &bytes,
            "application/x-tar",
        );
        let tmp = tempfile::tempdir().unwrap();
        let report = install_skill_package(&skill, &bytes, tmp.path()).unwrap();
        assert!(report.install_dir.join("install.sh").is_file());
        assert!(!report.install_dir.join("RAN_ON_INSTALL").exists());
        // And we never invoked a shell ourselves:
        let status = Command::new("test")
            .arg("!")
            .arg("-f")
            .arg(report.install_dir.join("RAN_ON_INSTALL"))
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn batch_omits_failures_keeps_goods() {
        let good_bytes = make_tar_with_skill_md("# good\n");
        let bad_bytes = make_tar_with_skill_md("# bad\n");
        let good = skill_ref(
            "http://example.test/good.tar",
            "good",
            &good_bytes,
            "application/x-tar",
        );
        let mut bad = skill_ref(
            "http://example.test/bad.tar",
            "bad",
            &bad_bytes,
            "application/x-tar",
        );
        bad.integrity.as_mut().unwrap().sha256 =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
        let tmp = tempfile::tempdir().unwrap();
        let (ok, failed) = install_skill_packages(
            &[good, bad],
            tmp.path(),
            None,
            |skill| {
                if skill.runtime_name == "good" {
                    Ok(good_bytes.clone())
                } else {
                    Ok(bad_bytes.clone())
                }
            },
        );
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].runtime_name, "good");
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].1.class, error_class::INTEGRITY_HASH);
    }

    #[test]
    fn settle_gc_removes_installed_session_skills() {
        use crate::haee_session_settle::{gc_session_skill_root, session_skill_root};
        let bytes = make_tar_with_skill_md("# gc\n");
        let skill = skill_ref(
            "http://example.test/gc.tar",
            "gc-skill",
            &bytes,
            "application/x-tar",
        );
        let tmp = tempfile::tempdir().unwrap();
        let root = session_skill_root(tmp.path(), "sess-iter7");
        install_skill_package(&skill, &bytes, &root).unwrap();
        assert!(root.join("gc-skill/SKILL.md").is_file());
        assert!(gc_session_skill_root(&root).unwrap());
        assert!(!root.exists());
    }
}
