//! Paperclip run auth for non-model channels (v1).
//!
//! Design: `docs/plans/haee-run-envelope.md` §7.2
//! Plan: `docs/plans/haee-envelope-implementation.md` Iteration 9
//!
//! HAEE exposes run auth to **non-model** paths only (process env / shell tool
//! overlays). Never place the run JWT in ACP prompt text or `session/update`
//! logs. Settle must clear the keys this module applies.

use crate::haee_run_envelope::{EnvelopeAuth, EnvelopeIdentity, EnvelopeTask};
use std::collections::BTreeMap;
use std::env;

/// Process / shell env keys injected for Paperclip REST lifecycle (L0 skill).
pub const ENV_API_URL: &str = "PAPERCLIP_API_URL";
pub const ENV_API_KEY: &str = "PAPERCLIP_API_KEY";
pub const ENV_RUN_ID: &str = "PAPERCLIP_RUN_ID";
pub const ENV_AGENT_ID: &str = "PAPERCLIP_AGENT_ID";
pub const ENV_COMPANY_ID: &str = "PAPERCLIP_COMPANY_ID";
pub const ENV_TASK_ID: &str = "PAPERCLIP_TASK_ID";
pub const ENV_WAKE_REASON: &str = "PAPERCLIP_WAKE_REASON";
pub const ENV_RUN_ID_HEADER: &str = "PAPERCLIP_RUN_ID_HEADER";

/// Canonical ordered list of keys this module may set or clear.
pub const RUN_AUTH_ENV_KEYS: &[&str] = &[
    ENV_API_URL,
    ENV_API_KEY,
    ENV_RUN_ID,
    ENV_AGENT_ID,
    ENV_COMPANY_ID,
    ENV_TASK_ID,
    ENV_WAKE_REASON,
    ENV_RUN_ID_HEADER,
];

/// Runtime name of the vendored Paperclip L0 operational skill.
pub const PAPERCLIP_L0_RUNTIME_NAME: &str = "paperclip";

/// Build the non-model env map from a validated envelope's identity + auth.
///
/// Optional task fields populate wake-context vars when present. Empty optional
/// values are omitted (not written as empty strings).
pub fn build_run_auth_env(
    identity: &EnvelopeIdentity,
    auth: &EnvelopeAuth,
    task: Option<&EnvelopeTask>,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert(ENV_API_URL.to_string(), auth.paperclip_api_base_url.clone());
    env.insert(ENV_API_KEY.to_string(), auth.run_bearer_token.clone());
    env.insert(ENV_RUN_ID.to_string(), identity.run_id.clone());
    env.insert(ENV_AGENT_ID.to_string(), identity.agent_id.clone());
    env.insert(ENV_COMPANY_ID.to_string(), identity.company_id.clone());
    env.insert(ENV_RUN_ID_HEADER.to_string(), auth.run_id_header.clone());
    if let Some(task) = task {
        if let Some(issue_id) = task.issue_id.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty())
        {
            env.insert(ENV_TASK_ID.to_string(), issue_id.to_string());
        }
        if let Some(reason) = task
            .wake_reason
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            env.insert(ENV_WAKE_REASON.to_string(), reason.to_string());
        }
    }
    env
}

/// Apply run auth into the process environment (non-model channels).
///
/// Call only for Paperclip-scoped ACP sessions. Concurrent Paperclip sessions
/// on one process share these keys (lab v1 single-tenant assumption).
pub fn apply_run_auth_env(env_map: &BTreeMap<String, String>) {
    for (key, value) in env_map {
        // SAFETY: single-threaded ACP session setup/settle; lab assumes one
        // Paperclip-scoped session owns these keys at a time.
        unsafe { env::set_var(key, value) };
    }
}

/// Remove run auth keys from the process environment.
///
/// Prefer clearing the exact map that was applied; falls back to the canonical
/// key list when only keys are known.
pub fn clear_run_auth_env(env_map: Option<&BTreeMap<String, String>>) {
    let keys: Vec<&str> = match env_map {
        Some(map) if !map.is_empty() => map.keys().map(String::as_str).collect(),
        _ => RUN_AUTH_ENV_KEYS.to_vec(),
    };
    for key in keys {
        unsafe { env::remove_var(key) };
    }
}

/// True when `text` contains any secret value from the run auth map.
///
/// Used by redaction tests against prompts and session/update log payloads.
/// Does not print secrets.
pub fn text_contains_run_secret(text: &str, env_map: &BTreeMap<String, String>) -> bool {
    env_map.values().any(|secret| {
        let secret = secret.trim();
        !secret.is_empty() && text.contains(secret)
    })
}

/// True when text looks like it embeds a Paperclip run bearer / API key.
///
/// Conservative heuristic for log/prompt scans without a live env map.
pub fn text_looks_like_run_bearer_leak(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if lower.contains("paperclip_api_key=") || lower.contains("runbearertoken") {
        return true;
    }
    // Avoid matching the skill prose that *names* the env var.
    if lower.contains("bearer ")
        && (lower.contains("run-token")
            || lower.contains("eyj") // JWT header prefix (base64 "eyJ")
            || text.contains("PAPERCLIP_API_KEY="))
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::haee_run_envelope::{EnvelopeAuth, EnvelopeIdentity, EnvelopeTask};

    fn sample_identity() -> EnvelopeIdentity {
        EnvelopeIdentity {
            run_id: "run_abc".into(),
            agent_id: "agent_xyz".into(),
            company_id: "co_1".into(),
            haee_agent_alias: "hire".into(),
        }
    }

    fn sample_auth() -> EnvelopeAuth {
        EnvelopeAuth {
            paperclip_api_base_url: "https://paperclip.example/api".into(),
            run_bearer_token: "jwt-secret-value-do-not-log".into(),
            run_id_header: "X-Paperclip-Run-Id".into(),
        }
    }

    #[test]
    fn build_run_auth_env_core_keys() {
        let env = build_run_auth_env(&sample_identity(), &sample_auth(), None);
        assert_eq!(env.get(ENV_API_URL).unwrap(), "https://paperclip.example/api");
        assert_eq!(env.get(ENV_API_KEY).unwrap(), "jwt-secret-value-do-not-log");
        assert_eq!(env.get(ENV_RUN_ID).unwrap(), "run_abc");
        assert_eq!(env.get(ENV_AGENT_ID).unwrap(), "agent_xyz");
        assert_eq!(env.get(ENV_COMPANY_ID).unwrap(), "co_1");
        assert_eq!(env.get(ENV_RUN_ID_HEADER).unwrap(), "X-Paperclip-Run-Id");
        assert!(!env.contains_key(ENV_TASK_ID));
        assert!(!env.contains_key(ENV_WAKE_REASON));
    }

    #[test]
    fn build_run_auth_env_includes_task_wake_context() {
        let task = EnvelopeTask {
            issue_id: Some("issue_9".into()),
            wake_reason: Some("heartbeat".into()),
            summary: "do work".into(),
            acceptance_hints: None,
        };
        let env = build_run_auth_env(&sample_identity(), &sample_auth(), Some(&task));
        assert_eq!(env.get(ENV_TASK_ID).unwrap(), "issue_9");
        assert_eq!(env.get(ENV_WAKE_REASON).unwrap(), "heartbeat");
    }

    #[test]
    fn apply_and_clear_round_trip() {
        let env_map = build_run_auth_env(&sample_identity(), &sample_auth(), None);
        // Isolate from ambient process state.
        clear_run_auth_env(Some(&env_map));
        assert!(env::var(ENV_API_KEY).is_err());

        apply_run_auth_env(&env_map);
        assert_eq!(
            env::var(ENV_API_KEY).unwrap(),
            "jwt-secret-value-do-not-log"
        );
        assert_eq!(env::var(ENV_RUN_ID).unwrap(), "run_abc");

        clear_run_auth_env(Some(&env_map));
        assert!(env::var(ENV_API_KEY).is_err());
        assert!(env::var(ENV_RUN_ID).is_err());
        assert!(env::var(ENV_API_URL).is_err());
    }

    #[test]
    fn text_contains_run_secret_detects_jwt() {
        let env_map = build_run_auth_env(&sample_identity(), &sample_auth(), None);
        assert!(text_contains_run_secret(
            "Authorization: Bearer jwt-secret-value-do-not-log",
            &env_map
        ));
        assert!(!text_contains_run_secret(
            "use $PAPERCLIP_API_KEY from the environment",
            &env_map
        ));
    }

    #[test]
    fn l0_runtime_name_is_paperclip() {
        assert_eq!(PAPERCLIP_L0_RUNTIME_NAME, "paperclip");
    }
}
