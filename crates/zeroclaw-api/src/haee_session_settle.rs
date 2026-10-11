//! Paperclip session settle helpers (v1).
//!
//! Pure path/layout helpers and durable-config auth inspection for the
//! post-run cleanup path (design §6.3 / §7.1 steps 10–11).
//!
//! Design: `docs/plans/haee-run-envelope.md`
//! Plan: `docs/plans/haee-envelope-implementation.md` Iteration 6
//!
//! # Ownership
//!
//! | Step | Owner |
//! |---|---|
//! | Cancel in-flight turn, close task MCP listener, `session/close` | Adapter |
//! | Drop invocation MCP tools / session skill roots | HAEE on `session/close` |
//!
//! Invocation MCP headers and run bearer tokens live only on the **in-memory**
//! session config clone used to build the agent. They must never be written to
//! durable `config.toml`. Settle clears live agent tool state and GCs the
//! session skill directory (even when empty / never populated — Iteration 7).

use std::fs;
use std::path::{Path, PathBuf};

/// Relative layout under a session workspace for session-scoped skills.
///
/// Full path: `<workspace>/.haee/sessions/<session_id>/skills`.
pub const SESSION_SKILL_REL_SEGMENTS: &[&str] = &[".haee", "sessions"];

/// Result of settling HAEE-side run-scoped material for one ACP session.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionSettleReport {
    /// Whether this session was Paperclip-scoped (invocation MCP / envelope).
    pub paperclip_invocation: bool,
    /// Session skill root that was targeted for GC (may not have existed).
    pub skill_root: Option<PathBuf>,
    /// True when the skill root existed before GC and was removed.
    pub skill_root_removed: bool,
    /// True when agent tool/MCP surface was cleared.
    pub agent_tools_cleared: bool,
    /// True when Paperclip run-auth process env keys were cleared (Iteration 9).
    pub auth_env_cleared: bool,
}

/// Canonical session-scoped skill install root for a Paperclip ACP session.
///
/// Iteration 7 installs under this path; Iteration 6 only defines layout + GC.
pub fn session_skill_root(workspace_dir: &Path, session_id: &str) -> PathBuf {
    let mut path = workspace_dir.to_path_buf();
    for segment in SESSION_SKILL_REL_SEGMENTS {
        path.push(segment);
    }
    path.push(sanitize_session_id_for_path(session_id));
    path.push("skills");
    path
}

/// Restrict session id path segments to a conservative filesystem-safe set.
fn sanitize_session_id_for_path(session_id: &str) -> String {
    let trimmed = session_id.trim();
    if trimmed.is_empty() {
        return "_empty".to_string();
    }
    let mut out = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "_empty".to_string()
    } else {
        out
    }
}

/// Remove a session skill root if present. Missing path is success (no-op).
///
/// Also removes empty parent `…/sessions/<id>` and `…/sessions` when empty so
/// settle does not leave hollow run directories behind.
pub fn gc_session_skill_root(skill_root: &Path) -> std::io::Result<bool> {
    if !skill_root.exists() {
        return Ok(false);
    }
    if skill_root.is_dir() {
        fs::remove_dir_all(skill_root)?;
    } else {
        fs::remove_file(skill_root)?;
    }
    // Best-effort parent cleanup: <workspace>/.haee/sessions/<id>
    if let Some(session_dir) = skill_root.parent() {
        let _ = remove_dir_if_empty(session_dir);
        if let Some(sessions_dir) = session_dir.parent() {
            let _ = remove_dir_if_empty(sessions_dir);
            if let Some(haee_dir) = sessions_dir.parent() {
                let _ = remove_dir_if_empty(haee_dir);
            }
        }
    }
    Ok(true)
}

fn remove_dir_if_empty(path: &Path) -> std::io::Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::DirectoryNotEmpty => Ok(()),
        Err(err) => Err(err),
    }
}

/// True when a config snapshot still carries invocation-style Authorization
/// bearer material on MCP server headers (must not appear on durable config).
pub fn mcp_servers_carry_authorization_bearer(
    servers: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>,
) -> bool {
    servers.into_iter().any(|(name, value)| {
        let name = name.as_ref();
        let value = value.as_ref().trim();
        name.eq_ignore_ascii_case("authorization")
            && value.to_ascii_lowercase().starts_with("bearer ")
            && value.len() > "bearer ".len()
    })
}

/// Scan MCP server header maps for Authorization bearer values.
pub fn config_mcp_headers_carry_run_bearer<'a, I, H>(servers: I) -> bool
where
    I: IntoIterator<Item = H>,
    H: IntoIterator<Item = (&'a str, &'a str)>,
{
    servers
        .into_iter()
        .any(|headers| mcp_servers_carry_authorization_bearer(headers))
}

/// True when text looks like a durable config body that embedded a run bearer.
///
/// Used by settle tests against on-disk `config.toml` without printing secrets.
pub fn durable_config_text_has_invocation_bearer(text: &str) -> bool {
    // Match Authorization = "Bearer …" / Authorization = 'Bearer …' TOML forms
    // and raw Bearer tokens that would indicate a leaked run JWT.
    let lower = text.to_ascii_lowercase();
    if lower.contains("authorization") && lower.contains("bearer ") {
        return true;
    }
    // Paperclip invocation bundle name must not be persisted as durable MCP.
    if text.contains("__paperclip_invocation") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn session_skill_root_layout_is_stable() {
        let root = session_skill_root(Path::new("/tmp/ws"), "sess-abc_01");
        assert_eq!(
            root,
            PathBuf::from("/tmp/ws/.haee/sessions/sess-abc_01/skills")
        );
    }

    #[test]
    fn session_skill_root_sanitizes_path_separators() {
        let root = session_skill_root(Path::new("/tmp/ws"), "a/../b");
        assert_eq!(root, PathBuf::from("/tmp/ws/.haee/sessions/a_.._b/skills"));
    }

    #[test]
    fn gc_session_skill_root_removes_empty_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let skill_root = session_skill_root(tmp.path(), "sess-gc");
        fs::create_dir_all(&skill_root).unwrap();
        assert!(skill_root.is_dir());
        assert!(gc_session_skill_root(&skill_root).unwrap());
        assert!(!skill_root.exists());
        // Parents cleaned when empty.
        assert!(!tmp.path().join(".haee").exists());
    }

    #[test]
    fn gc_session_skill_root_missing_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let skill_root = session_skill_root(tmp.path(), "never-created");
        assert!(!gc_session_skill_root(&skill_root).unwrap());
    }

    #[test]
    fn bearer_detection_on_header_pairs() {
        assert!(mcp_servers_carry_authorization_bearer([(
            "Authorization",
            "Bearer run-token"
        )]));
        assert!(!mcp_servers_carry_authorization_bearer([(
            "Authorization",
            "Basic abc"
        )]));
        assert!(!mcp_servers_carry_authorization_bearer([(
            "X-Run-Id",
            "run-1"
        )]));
    }

    #[test]
    fn durable_config_text_flags_invocation_material() {
        assert!(durable_config_text_has_invocation_bearer(
            r#"
[mcp.servers.paperclip]
headers = { Authorization = "Bearer leaked" }
"#
        ));
        assert!(durable_config_text_has_invocation_bearer(
            "mcp_bundles.__paperclip_invocation = { servers = [] }"
        ));
        assert!(!durable_config_text_has_invocation_bearer(
            r#"
[mcp]
enabled = true
"#
        ));
    }
}
