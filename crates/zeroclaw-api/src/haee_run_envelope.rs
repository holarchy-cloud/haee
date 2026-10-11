//! Paperclip → HAEE run envelope (v1): pure parse + validate.
//!
//! Logical schema only — not ACP wire wrappers. ACP session params carry a
//! nested `envelope` object; channel code maps tools into the invocation MCP
//! path. This module must stay free of channel/runtime side effects.
//!
//! Design: `docs/plans/haee-run-envelope.md`
//! Fixtures: `tests/fixtures/haee_run_envelope/`

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use thiserror::Error;

/// Supported envelope schema version.
pub const ENVELOPE_VERSION_V1: u32 = 1;

/// Hard cap for skill `integrity.sizeMax` (100 MiB).
pub const SKILL_SIZE_MAX_HARD_CAP: u64 = 104_857_600;

/// Stable error class names (fixture contract).
pub mod error_class {
    pub const ENVELOPE_VERSION_UNSUPPORTED: &str = "envelope_version_unsupported";
    pub const MCP_TYPE_UNSUPPORTED: &str = "mcp_type_unsupported";
    pub const MCP_NAME_INVALID: &str = "mcp_name_invalid";
    pub const MCP_URL_INVALID: &str = "mcp_url_invalid";
    pub const PAPERCLIP_TOOLS_ONLY_REQUIRED: &str = "paperclip_tools_only_required";
    pub const SKILL_INTEGRITY_REQUIRED: &str = "skill_integrity_required";
    pub const SKILL_SIZE_MAX_EXCEEDED: &str = "skill_size_max_exceeded";
    pub const ENVELOPE_SHAPE_INVALID: &str = "envelope_shape_invalid";
}

/// Parse/validate failure with a stable `class` for tests and logs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{class}: {message}")]
pub struct EnvelopeError {
    pub class: &'static str,
    pub message: String,
}

impl EnvelopeError {
    fn new(class: &'static str, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
        }
    }
}

/// Validated run envelope (v1).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunEnvelope {
    pub envelope_version: u32,
    pub identity: EnvelopeIdentity,
    pub task: EnvelopeTask,
    pub auth: EnvelopeAuth,
    #[serde(default)]
    pub skills: Vec<SkillRef>,
    pub tools: EnvelopeTools,
    #[serde(default)]
    pub policy: EnvelopePolicy,
    #[serde(default)]
    pub session: EnvelopeSession,
}

impl fmt::Debug for RunEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunEnvelope")
            .field("envelope_version", &self.envelope_version)
            .field("identity", &self.identity)
            .field("task", &self.task)
            .field("auth", &"<redacted>")
            .field("skills", &self.skills)
            .field("tools", &self.tools)
            .field("policy", &self.policy)
            .field("session", &self.session)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeIdentity {
    pub run_id: String,
    pub agent_id: String,
    pub company_id: String,
    pub haee_agent_alias: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeTask {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake_reason: Option<String>,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance_hints: Option<String>,
}

/// Auth material for non-model paths. Never log `run_bearer_token`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeAuth {
    pub paperclip_api_base_url: String,
    pub run_bearer_token: String,
    pub run_id_header: String,
}

impl fmt::Debug for EnvelopeAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvelopeAuth")
            .field("paperclip_api_base_url", &self.paperclip_api_base_url)
            .field("run_bearer_token", &"<redacted>")
            .field("run_id_header", &self.run_id_header)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillRef {
    pub key: String,
    pub runtime_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<SkillIntegrity>,
    pub media_type: String,
    pub scope: SkillScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub always: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillIntegrity {
    pub sha256: String,
    pub size_max: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SkillScope {
    Session,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeTools {
    pub paperclip_tools_only: bool,
    #[serde(default)]
    pub mcp_servers: Vec<McpServerRef>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerRef {
    /// Only `"http"` is accepted for Paperclip-scoped sessions.
    #[serde(rename = "type")]
    pub transport: String,
    pub name: String,
    pub url: String,
    /// Design logical shape: object headers (not ACP array form).
    /// Header values may carry bearer tokens — never log via `Debug`.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
}

impl fmt::Debug for McpServerRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_headers: BTreeMap<&str, &str> = self
            .headers
            .keys()
            .map(|name| (name.as_str(), "<redacted>"))
            .collect();
        f.debug_struct("McpServerRef")
            .field("transport", &self.transport)
            .field("name", &self.name)
            .field("url", &self.url)
            .field("headers", &redacted_headers)
            .field("connection_id", &self.connection_id)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeSession {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

/// Parse JSON text into a validated [`RunEnvelope`].
pub fn parse_envelope_str(raw: &str) -> Result<RunEnvelope, EnvelopeError> {
    let value: Value = serde_json::from_str(raw).map_err(|err| {
        EnvelopeError::new(
            error_class::ENVELOPE_SHAPE_INVALID,
            format!("envelope JSON parse failed: {err}"),
        )
    })?;
    parse_envelope_value(value)
}

/// Parse a JSON value into a validated [`RunEnvelope`].
pub fn parse_envelope_value(value: Value) -> Result<RunEnvelope, EnvelopeError> {
    // Version gate before full deserialize so bad-version fixtures get a stable class
    // even when the rest of the document is otherwise well-formed.
    match value.get("envelopeVersion") {
        Some(Value::Number(n)) if n.as_u64() == Some(u64::from(ENVELOPE_VERSION_V1)) => {}
        Some(Value::Number(n)) => {
            return Err(EnvelopeError::new(
                error_class::ENVELOPE_VERSION_UNSUPPORTED,
                format!(
                    "envelopeVersion {} is not supported (expected {ENVELOPE_VERSION_V1})",
                    n
                ),
            ));
        }
        Some(_) => {
            return Err(EnvelopeError::new(
                error_class::ENVELOPE_VERSION_UNSUPPORTED,
                "envelopeVersion must be a number",
            ));
        }
        None => {
            return Err(EnvelopeError::new(
                error_class::ENVELOPE_VERSION_UNSUPPORTED,
                "envelopeVersion is required",
            ));
        }
    }

    let envelope: RunEnvelope = serde_json::from_value(value).map_err(|err| {
        EnvelopeError::new(
            error_class::ENVELOPE_SHAPE_INVALID,
            format!("envelope shape invalid: {err}"),
        )
    })?;
    validate_envelope(&envelope)?;
    Ok(envelope)
}

/// Validate semantic rules on an already-deserialized envelope.
pub fn validate_envelope(envelope: &RunEnvelope) -> Result<(), EnvelopeError> {
    if envelope.envelope_version != ENVELOPE_VERSION_V1 {
        return Err(EnvelopeError::new(
            error_class::ENVELOPE_VERSION_UNSUPPORTED,
            format!(
                "envelopeVersion {} is not supported (expected {ENVELOPE_VERSION_V1})",
                envelope.envelope_version
            ),
        ));
    }

    require_non_empty("identity.runId", &envelope.identity.run_id)?;
    require_non_empty("identity.agentId", &envelope.identity.agent_id)?;
    require_non_empty("identity.companyId", &envelope.identity.company_id)?;
    require_non_empty("identity.haeeAgentAlias", &envelope.identity.haee_agent_alias)?;
    require_non_empty("task.summary", &envelope.task.summary)?;
    require_non_empty(
        "auth.paperclipApiBaseUrl",
        &envelope.auth.paperclip_api_base_url,
    )?;
    require_non_empty("auth.runBearerToken", &envelope.auth.run_bearer_token)?;
    require_non_empty("auth.runIdHeader", &envelope.auth.run_id_header)?;

    // Paperclip-originated envelopes always require tools-only isolation.
    if !envelope.tools.paperclip_tools_only {
        return Err(EnvelopeError::new(
            error_class::PAPERCLIP_TOOLS_ONLY_REQUIRED,
            "tools.paperclipToolsOnly must be true for Paperclip-originated sessions",
        ));
    }

    for (index, server) in envelope.tools.mcp_servers.iter().enumerate() {
        validate_mcp_server(index, server)?;
    }

    for (index, skill) in envelope.skills.iter().enumerate() {
        validate_skill_ref(index, skill)?;
    }

    Ok(())
}

fn validate_mcp_server(index: usize, server: &McpServerRef) -> Result<(), EnvelopeError> {
    if server.transport.trim() != "http" {
        return Err(EnvelopeError::new(
            error_class::MCP_TYPE_UNSUPPORTED,
            format!(
                "tools.mcpServers[{index}].type must be \"http\" (got {:?})",
                server.transport
            ),
        ));
    }
    if server.name.trim().is_empty() {
        return Err(EnvelopeError::new(
            error_class::MCP_NAME_INVALID,
            format!("tools.mcpServers[{index}].name must be a non-empty string"),
        ));
    }
    if server.url.trim().is_empty() {
        return Err(EnvelopeError::new(
            error_class::MCP_URL_INVALID,
            format!("tools.mcpServers[{index}].url must be a non-empty string"),
        ));
    }
    Ok(())
}

fn validate_skill_ref(index: usize, skill: &SkillRef) -> Result<(), EnvelopeError> {
    require_non_empty(&format!("skills[{index}].key"), &skill.key)?;
    require_non_empty(&format!("skills[{index}].runtimeName"), &skill.runtime_name)?;
    require_non_empty(&format!("skills[{index}].uri"), &skill.uri)?;
    require_non_empty(&format!("skills[{index}].mediaType"), &skill.media_type)?;

    if is_remote_skill_uri(&skill.uri) {
        let integrity = skill.integrity.as_ref().ok_or_else(|| {
            EnvelopeError::new(
                error_class::SKILL_INTEGRITY_REQUIRED,
                format!("skills[{index}] remote uri requires integrity"),
            )
        })?;
        require_non_empty(
            &format!("skills[{index}].integrity.sha256"),
            &integrity.sha256,
        )?;
        if integrity.size_max == 0 {
            return Err(EnvelopeError::new(
                error_class::ENVELOPE_SHAPE_INVALID,
                format!("skills[{index}].integrity.sizeMax must be > 0"),
            ));
        }
        if integrity.size_max > SKILL_SIZE_MAX_HARD_CAP {
            return Err(EnvelopeError::new(
                error_class::SKILL_SIZE_MAX_EXCEEDED,
                format!(
                    "skills[{index}].integrity.sizeMax {} exceeds hard cap {SKILL_SIZE_MAX_HARD_CAP}",
                    integrity.size_max
                ),
            ));
        }
    }

    Ok(())
}

fn is_remote_skill_uri(uri: &str) -> bool {
    let lower = uri.trim().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn require_non_empty(field: &str, value: &str) -> Result<(), EnvelopeError> {
    if value.trim().is_empty() {
        return Err(EnvelopeError::new(
            error_class::ENVELOPE_SHAPE_INVALID,
            format!("{field} must be a non-empty string"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/haee_run_envelope")
    }

    fn read_fixture(name: &str) -> String {
        let path = fixture_dir().join(name);
        fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!("failed to read fixture {}: {err}", path.display());
        })
    }

    fn assert_valid(name: &str) -> RunEnvelope {
        parse_envelope_str(&read_fixture(name)).unwrap_or_else(|err| {
            panic!("{name} should parse: {err}");
        })
    }

    fn assert_invalid_class(name: &str, expected_class: &str) {
        let err = parse_envelope_str(&read_fixture(name)).expect_err("expected invalid envelope");
        assert_eq!(
            err.class, expected_class,
            "{name}: unexpected class (message={})",
            err.message
        );
    }

    #[test]
    fn valid_minimal_tools_only_parses() {
        let env = assert_valid("valid-minimal-tools-only.json");
        assert_eq!(env.envelope_version, ENVELOPE_VERSION_V1);
        assert!(env.tools.paperclip_tools_only);
        assert!(env.skills.is_empty());
        assert_eq!(env.tools.mcp_servers.len(), 2);
        assert_eq!(env.tools.mcp_servers[0].name, "paperclip_tasks");
        assert_eq!(
            env.tools.mcp_servers[0]
                .headers
                .get("Authorization")
                .map(String::as_str),
            Some("Bearer TASK_MCP_TOKEN_PLACEHOLDER")
        );
        assert_eq!(
            env.policy.risk_profile.as_deref(),
            Some("elel_lab_permissive")
        );
    }

    #[test]
    fn valid_full_v1_parses() {
        let env = assert_valid("valid-full-v1.json");
        assert_eq!(env.skills.len(), 1);
        assert_eq!(env.skills[0].runtime_name, "issue-triage");
        assert_eq!(env.skills[0].scope, SkillScope::Session);
        assert_eq!(
            env.skills[0]
                .integrity
                .as_ref()
                .map(|i| i.size_max),
            Some(65_536)
        );
        assert_eq!(
            env.session.resume_session_id.as_deref(),
            Some("sess_prior_example")
        );
        assert_eq!(
            env.task.acceptance_hints.as_deref(),
            Some("Comment on the issue with the tool result; finish_task when done.")
        );
    }

    #[test]
    fn invalid_fixtures_map_to_stable_classes() {
        assert_invalid_class(
            "invalid-bad-version.json",
            error_class::ENVELOPE_VERSION_UNSUPPORTED,
        );
        assert_invalid_class(
            "invalid-non-http-mcp.json",
            error_class::MCP_TYPE_UNSUPPORTED,
        );
        assert_invalid_class("invalid-empty-mcp-name.json", error_class::MCP_NAME_INVALID);
        assert_invalid_class("invalid-empty-mcp-url.json", error_class::MCP_URL_INVALID);
        assert_invalid_class(
            "invalid-paperclip-tools-only-false.json",
            error_class::PAPERCLIP_TOOLS_ONLY_REQUIRED,
        );
        assert_invalid_class(
            "invalid-skill-missing-integrity.json",
            error_class::SKILL_INTEGRITY_REQUIRED,
        );
        assert_invalid_class(
            "invalid-skill-oversize-meta.json",
            error_class::SKILL_SIZE_MAX_EXCEEDED,
        );
    }

    #[test]
    fn debug_redacts_run_bearer_token() {
        let env = assert_valid("valid-minimal-tools-only.json");
        let rendered = format!("{env:?}");
        assert!(
            !rendered.contains("RUN_TOKEN_PLACEHOLDER"),
            "Debug must not leak run bearer token: {rendered}"
        );
        assert!(
            !rendered.contains("TASK_MCP_TOKEN_PLACEHOLDER"),
            "Debug must not leak MCP header bearer token: {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
        // Values remain available on the typed struct for non-log paths.
        assert_eq!(
            env.auth.run_bearer_token.as_str(),
            "RUN_TOKEN_PLACEHOLDER"
        );
    }

    #[test]
    fn skill_size_hard_cap_constant_matches_fixture_contract() {
        assert_eq!(SKILL_SIZE_MAX_HARD_CAP, 104_857_600);
        assert!(1_073_741_825 > SKILL_SIZE_MAX_HARD_CAP);
    }
}
