//! Paperclip session policy compiler (v1).
//!
//! Pure, deterministic compile of a session-local [`SessionPolicy`] from a HAEE
//! risk profile snapshot plus envelope tool facts. No channel/runtime I/O.
//!
//! Design: `docs/plans/haee-run-envelope.md` §6.2
//! Plan: `docs/plans/haee-envelope-implementation.md` Iteration 5
//!
//! # Built-in families (Paperclip mode)
//!
//! | Family | v1 posture | Rationale |
//! |---|---|---|
//! | Envelope MCP (`server__tool`) | **allow** (discovered names only) | Brokered tools; only set when `paperclipToolsOnly` |
//! | Workspace file/search (`file_*`, `glob_search`, `content_search`) | **deny** (not in expectations) | May be opened later via explicit expectations; not default |
//! | Shell (`shell`) | **deny** | Profile/sandbox only; MCP grant never widens shell |
//! | Raw egress (`http_request`, `web_fetch`, `web_search*`, `text_browser`) | **deny** | Bypasses Paperclip brokerage |
//! | Browser automation (`browser_*`) | **deny** | Unbrokered side channel |
//! | Coding CLI delegates (`claude_code`, `codex_cli`, `gemini_cli`, `opencode_cli`, …) | **deny** | Escapes Paperclip tool plane |
//! | Delegation / spawn (`delegate`, `spawn_subagent`, `browser_delegate`) | **deny** | Cross-agent bypass |
//! | Composio / third-party managed tools | **deny** | Not envelope-listed |
//! | Memory tools | stripped on ACP path separately | Session history, not durable memory |
//!
//! v1 `paperclip_builtin_expectations` is **empty**: effective tools are
//! envelope MCP names only (plus optional explicit allow hints that still
//! cannot admit the hard-deny family). Empty MCP catalog ⇒ empty allow list.

use std::collections::BTreeSet;

/// Built-in tool names that must never be admitted on a Paperclip-scoped
/// session, even if listed on the risk profile or in adapter allow hints.
///
/// MCP grant does not remove these denies. Names are exact tool ids.
pub const PAPERCLIP_BUILTIN_HARD_DENY: &[&str] = &[
    // Shell / process
    "shell",
    // Raw network egress
    "http_request",
    "web_fetch",
    "web_search",
    "web_search_tool",
    "text_browser",
    // Browser automation
    "browser_open",
    "browser_delegate",
    "screenshot",
    // Coding CLI side channels
    "claude_code",
    "codex_cli",
    "gemini_cli",
    "opencode_cli",
    // Delegation / multi-agent
    "delegate",
    "spawn_subagent",
    // Third-party managed tool plane
    "composio",
    // Pipeline / cron that can re-widen tool surface
    "pipeline",
    "cron_add",
    "cron_update",
    "cron_list",
    "cron_remove",
    "cron_runs",
];

/// Built-ins Paperclip sessions may admit when the risk profile also allows
/// them (intersection). v1 is empty = MCP-only effective surface.
pub const PAPERCLIP_BUILTIN_EXPECTATIONS: &[&str] = &[];

/// Session-local compiled policy (in memory only; never durable config).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPolicy {
    pub risk_profile_name: String,
    /// Logical MCP server names from the envelope (not `server__tool` ids).
    pub mcp_server_names: Vec<String>,
    /// Built-ins that survived profile ∩ expectations − denies.
    pub builtin_tool_allow: Vec<String>,
    /// Effective deny set applied during compile (hard denies ∪ hints ∪ profile excludes).
    pub builtin_tool_deny: Vec<String>,
    /// Final allow-list for agent tool filtering. Always present for Paperclip
    /// mode: empty means deny-all tools (empty catalog hardening).
    pub allowed_tool_names: Vec<String>,
    pub paperclip_tools_only: bool,
    /// Reserved for session skill install roots (Iteration 7+).
    pub skill_roots: Vec<String>,
}

/// Inputs to [`compile_session_policy`]. Plain data only — no `Config` type.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionPolicyInputs {
    pub risk_profile_name: String,
    /// Risk profile `allowed_tools`. Empty = unrestricted at the profile layer
    /// (still intersected with Paperclip expectations for builtins).
    pub profile_allowed_tools: Vec<String>,
    pub profile_excluded_tools: Vec<String>,
    /// Envelope `tools.mcpServers[].name` values.
    pub envelope_mcp_server_names: Vec<String>,
    /// Runtime-discovered `<server>__<tool>` names after MCP connect.
    pub discovered_mcp_tool_names: Vec<String>,
    pub paperclip_tools_only: bool,
    /// Optional adapter/envelope allow hints for builtins (still hard-deny gated).
    pub builtin_allow_hints: Vec<String>,
    /// Optional adapter/envelope deny hints.
    pub builtin_deny_hints: Vec<String>,
    /// Override default expectations (tests / future envelope field). `None` =
    /// use [`PAPERCLIP_BUILTIN_EXPECTATIONS`].
    pub builtin_expectations_override: Option<Vec<String>>,
}

/// Compile a deterministic [`SessionPolicy`] from profile + envelope tool facts.
pub fn compile_session_policy(inputs: SessionPolicyInputs) -> SessionPolicy {
    let mut hard_deny: BTreeSet<String> = PAPERCLIP_BUILTIN_HARD_DENY
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    for name in &inputs.profile_excluded_tools {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            hard_deny.insert(trimmed.to_string());
        }
    }
    for name in &inputs.builtin_deny_hints {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            hard_deny.insert(trimmed.to_string());
        }
    }

    let expectations: BTreeSet<String> = inputs
        .builtin_expectations_override
        .as_ref()
        .map(|v| {
            v.iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_else(|| {
            PAPERCLIP_BUILTIN_EXPECTATIONS
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        });

    let profile_allow: BTreeSet<String> = inputs
        .profile_allowed_tools
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let hint_allow: BTreeSet<String> = inputs
        .builtin_allow_hints
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Builtins: expectations ∪ hints, then ∩ profile when profile is non-empty,
    // then subtract hard denies. MCP names are never treated as builtins here.
    let mut builtin_allow: BTreeSet<String> = expectations.union(&hint_allow).cloned().collect();
    if !profile_allow.is_empty() {
        builtin_allow = builtin_allow
            .intersection(&profile_allow)
            .cloned()
            .collect();
    }
    builtin_allow.retain(|name| !hard_deny.contains(name) && !is_mcp_tool_name(name));

    let mcp_server_names: Vec<String> = ordered_unique(
        inputs
            .envelope_mcp_server_names
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
    );

    let server_name_set: BTreeSet<String> = mcp_server_names.iter().cloned().collect();

    // MCP tools: only discovered names, and only when paperclipToolsOnly.
    // If envelope listed servers, require the `<server>__` prefix to match;
    // empty server list ⇒ no MCP tools (empty-catalog hardening).
    let mut mcp_allow: BTreeSet<String> = BTreeSet::new();
    if inputs.paperclip_tools_only {
        for name in &inputs.discovered_mcp_tool_names {
            let trimmed = name.trim();
            if trimmed.is_empty() || !is_mcp_tool_name(trimmed) {
                continue;
            }
            if server_name_set.is_empty() {
                continue;
            }
            if let Some(server) = mcp_server_prefix(trimmed) {
                if server_name_set.contains(server) {
                    mcp_allow.insert(trimmed.to_string());
                }
            }
        }
    }

    let mut allowed: BTreeSet<String> = BTreeSet::new();
    if inputs.paperclip_tools_only {
        allowed.extend(builtin_allow.iter().cloned());
        allowed.extend(mcp_allow.iter().cloned());
    } else {
        // Non-Paperclip path should not use this compiler; keep fail-closed.
        allowed.clear();
    }

    SessionPolicy {
        risk_profile_name: inputs.risk_profile_name.trim().to_string(),
        mcp_server_names,
        builtin_tool_allow: builtin_allow.into_iter().collect(),
        builtin_tool_deny: hard_deny.into_iter().collect(),
        allowed_tool_names: allowed.into_iter().collect(),
        paperclip_tools_only: inputs.paperclip_tools_only,
        skill_roots: Vec::new(),
    }
}

/// Convenience: compile Paperclip policy from risk-profile field slices and
/// discovered MCP tool names. Envelope server names are inferred from the
/// `<server>__` prefix of discovered tools when `envelope_mcp_server_names`
/// is empty — callers should pass envelope names explicitly when known so an
/// empty catalog stays empty even if discovery is stale.
pub fn compile_paperclip_session_policy(
    risk_profile_name: impl Into<String>,
    profile_allowed_tools: &[String],
    profile_excluded_tools: &[String],
    envelope_mcp_server_names: &[String],
    discovered_mcp_tool_names: impl IntoIterator<Item = String>,
) -> SessionPolicy {
    compile_session_policy(SessionPolicyInputs {
        risk_profile_name: risk_profile_name.into(),
        profile_allowed_tools: profile_allowed_tools.to_vec(),
        profile_excluded_tools: profile_excluded_tools.to_vec(),
        envelope_mcp_server_names: envelope_mcp_server_names.to_vec(),
        discovered_mcp_tool_names: discovered_mcp_tool_names.into_iter().collect(),
        paperclip_tools_only: true,
        builtin_allow_hints: Vec::new(),
        builtin_deny_hints: Vec::new(),
        builtin_expectations_override: None,
    })
}

fn is_mcp_tool_name(name: &str) -> bool {
    name.contains("__")
}

fn mcp_server_prefix(tool_name: &str) -> Option<&str> {
    tool_name.split_once("__").map(|(server, _)| server)
}

fn ordered_unique<I>(iter: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for item in iter {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_inputs() -> SessionPolicyInputs {
        SessionPolicyInputs {
            risk_profile_name: "elel_lab_permissive".into(),
            profile_allowed_tools: vec![
                "shell".into(),
                "file_read".into(),
                "http_request".into(),
                "glob_search".into(),
            ],
            profile_excluded_tools: vec![],
            envelope_mcp_server_names: vec!["paperclip_tasks".into()],
            discovered_mcp_tool_names: vec![
                "paperclip_tasks__get_task".into(),
                "paperclip_tasks__add_comment".into(),
                // Static-config style name that must not appear unless its
                // server was in the envelope list.
                "gbrain__search".into(),
            ],
            paperclip_tools_only: true,
            builtin_allow_hints: vec![],
            builtin_deny_hints: vec![],
            builtin_expectations_override: None,
        }
    }

    #[test]
    fn deterministic_profile_plus_envelope() {
        let a = compile_session_policy(base_inputs());
        let b = compile_session_policy(base_inputs());
        assert_eq!(a, b);
        assert_eq!(a.risk_profile_name, "elel_lab_permissive");
        assert!(a.paperclip_tools_only);
        assert_eq!(
            a.allowed_tool_names,
            vec![
                "paperclip_tasks__add_comment".to_string(),
                "paperclip_tasks__get_task".to_string(),
            ]
        );
        // v1 expectations empty ⇒ no builtins even if profile allows them.
        assert!(a.builtin_tool_allow.is_empty());
        assert!(!a.allowed_tool_names.iter().any(|n| n == "shell"));
        assert!(!a.allowed_tool_names.iter().any(|n| n == "http_request"));
        assert!(!a.allowed_tool_names.iter().any(|n| n == "file_read"));
    }

    #[test]
    fn static_mcp_not_in_envelope_never_allowed() {
        let policy = compile_session_policy(base_inputs());
        assert!(
            !policy
                .allowed_tool_names
                .iter()
                .any(|n| n == "gbrain__search"),
            "static/non-envelope MCP must not appear: {:?}",
            policy.allowed_tool_names
        );
        assert_eq!(policy.mcp_server_names, vec!["paperclip_tasks".to_string()]);
    }

    #[test]
    fn empty_catalog_deny_all_tools() {
        let mut inputs = base_inputs();
        inputs.envelope_mcp_server_names.clear();
        inputs.discovered_mcp_tool_names.clear();
        let policy = compile_session_policy(inputs);
        assert!(policy.mcp_server_names.is_empty());
        assert!(
            policy.allowed_tool_names.is_empty(),
            "empty catalog must yield empty allow list"
        );
    }

    #[test]
    fn empty_catalog_ignores_stale_discovered_mcp() {
        let mut inputs = base_inputs();
        inputs.envelope_mcp_server_names.clear();
        // Discovery still reports tools — must not leak without envelope servers.
        let policy = compile_session_policy(inputs);
        assert!(policy.allowed_tool_names.is_empty());
    }

    #[test]
    fn hard_deny_blocks_shell_and_http_even_with_expectations() {
        let mut inputs = base_inputs();
        inputs.builtin_expectations_override =
            Some(vec!["shell".into(), "http_request".into(), "file_read".into()]);
        let policy = compile_session_policy(inputs);
        assert!(
            !policy.allowed_tool_names.iter().any(|n| n == "shell"),
            "shell must stay denied"
        );
        assert!(
            !policy
                .allowed_tool_names
                .iter()
                .any(|n| n == "http_request"),
            "http_request must stay denied"
        );
        assert!(
            policy.allowed_tool_names.iter().any(|n| n == "file_read"),
            "non-deny expectation ∩ profile should allow file_read: {:?}",
            policy.allowed_tool_names
        );
        assert!(policy.builtin_tool_deny.iter().any(|n| n == "shell"));
        assert!(policy.builtin_tool_deny.iter().any(|n| n == "http_request"));
    }

    #[test]
    fn profile_intersection_narrows_expectations() {
        let mut inputs = base_inputs();
        inputs.profile_allowed_tools = vec!["glob_search".into()];
        inputs.builtin_expectations_override =
            Some(vec!["file_read".into(), "glob_search".into()]);
        let policy = compile_session_policy(inputs);
        assert!(
            !policy.builtin_tool_allow.iter().any(|n| n == "file_read"),
            "file_read not in profile allow"
        );
        assert!(policy.builtin_tool_allow.iter().any(|n| n == "glob_search"));
    }

    #[test]
    fn unrestricted_profile_still_uses_expectations_only() {
        let mut inputs = base_inputs();
        inputs.profile_allowed_tools.clear(); // unrestricted profile layer
        inputs.builtin_expectations_override = Some(vec!["file_read".into()]);
        let policy = compile_session_policy(inputs);
        assert!(policy.builtin_tool_allow.iter().any(|n| n == "file_read"));
        assert!(
            !policy.allowed_tool_names.iter().any(|n| n == "shell"),
            "unrestricted profile must not admit hard-denied shell"
        );
    }

    #[test]
    fn profile_excluded_tools_extend_deny() {
        let mut inputs = base_inputs();
        inputs.profile_excluded_tools = vec!["glob_search".into()];
        inputs.builtin_expectations_override = Some(vec!["glob_search".into()]);
        let policy = compile_session_policy(inputs);
        assert!(!policy.builtin_tool_allow.iter().any(|n| n == "glob_search"));
        assert!(policy.builtin_tool_deny.iter().any(|n| n == "glob_search"));
    }

    #[test]
    fn non_paperclip_mode_fail_closed() {
        let mut inputs = base_inputs();
        inputs.paperclip_tools_only = false;
        let policy = compile_session_policy(inputs);
        assert!(policy.allowed_tool_names.is_empty());
    }

    #[test]
    fn convenience_wrapper_matches_explicit_inputs() {
        let discovered = vec![
            "paperclip_tasks__get_task".to_string(),
            "gbrain__search".to_string(),
        ];
        let via_wrapper = compile_paperclip_session_policy(
            "default",
            &[],
            &[],
            &["paperclip_tasks".to_string()],
            discovered.clone(),
        );
        let via_inputs = compile_session_policy(SessionPolicyInputs {
            risk_profile_name: "default".into(),
            envelope_mcp_server_names: vec!["paperclip_tasks".into()],
            discovered_mcp_tool_names: discovered,
            paperclip_tools_only: true,
            ..Default::default()
        });
        assert_eq!(via_wrapper, via_inputs);
    }

    #[test]
    fn hard_deny_family_documents_brokerage_bypass_tools() {
        for name in [
            "shell",
            "http_request",
            "web_fetch",
            "composio",
            "delegate",
            "spawn_subagent",
            "claude_code",
            "codex_cli",
        ] {
            assert!(
                PAPERCLIP_BUILTIN_HARD_DENY.contains(&name),
                "{name} must be in PAPERCLIP_BUILTIN_HARD_DENY"
            );
        }
        assert!(
            PAPERCLIP_BUILTIN_EXPECTATIONS.is_empty(),
            "v1 expectations must stay empty (MCP-only default)"
        );
    }
}
