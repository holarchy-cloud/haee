# HAEE

**Holon Agent Execution Environment**

ZeroClaw-derived agent harness for **Paperclip run-scoped** inference and tool use.

HAEE is the execution environment Paperclip hires: a long-lived agent runtime that accepts a **scoped projection** of skills and tools for one invocation, runs the model loop under that policy, then drops run-scoped material on settle. It is not a second company control plane and not a drop-in replacement for every ZeroClaw deployment.

The CLI binary name remains `zeroclaw` for compatibility with the ZeroClaw lineage.

<p align="center">
  <a href="https://github.com/holarchy-cloud/haee/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/holarchy-cloud/haee/ci.yml?branch=master&label=CI" alt="CI" /></a>
  <a href="LICENSE-APACHE"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache%202.0-blue.svg" alt="License" /></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-edition%202024-orange?logo=rust" alt="Rust Edition 2024" /></a>
  <a href="https://github.com/paperclipai/paperclip"><img src="https://img.shields.io/badge/Paperclip-hired%20runtime-111827" alt="Paperclip hired runtime" /></a>
  <a href="https://github.com/zeroclaw-labs/zeroclaw"><img src="https://img.shields.io/badge/derived%20from-ZeroClaw-0ea5e9" alt="Derived from ZeroClaw" /></a>
</p>

---

## Why HAEE exists

[Paperclip](https://github.com/paperclipai/paperclip) is the company control plane: agents, issues, heartbeats, skill inventory, and tool catalog. Stock [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) is a strong general agent runtime, but its ACP surface does not push **per-run** MCP tool sets the way Paperclip `runtimeMcp` / invocation-scoped tools require.

HAEE keeps the ZeroClaw execution core and extends the Paperclip hire path so that:

| Concern | Owner | HAEE behavior |
| --- | --- | --- |
| Company library, org graph, run JWT | **Paperclip** | HAEE does **not** pull the whole company |
| Map `execute(ctx)` → transport | **Adapter** (`paperclip-*-adapter`) | Thin client only |
| Model loop, skill install, tool bind, settle | **HAEE** | Compile **session policy** for one run |

Task text is untrusted narrative. Tool authority comes from the run-scoped catalog Paperclip (via the adapter) presents for that invocation—not from durable daemon config mutation and not from model-authored auth.

## What HAEE is

- **A Paperclip-hired execution environment** — long-lived process, ACP (and related) session host, single-agent-oriented bootstrap packing.
- **A ZeroClaw derivative** — same crate layout, config lineage, providers, security primitives, and `zeroclaw` binary name.
- **Run-scoped by design** — Paperclip sessions prefer an ephemeral tool/skill projection over a whole-company mount.

## What HAEE is not

- **Not** the Paperclip control plane, issue tracker, or skill library of record.
- **Not** an official ZeroClaw Labs product or release channel.
- **Not** (yet) a published HAEE installer/image that replaces every upstream ZeroClaw install path.
- **Not** a third unrelated runtime binary beside ZeroClaw—fork with a clear hire-path purpose.

## Status

| Area | State |
| --- | --- |
| ZeroClaw-compatible runtime core | Inherited; actively maintained as a fork |
| ACP `session/new` \| `session/resume` with `paperclipToolsOnly` + `mcpServers` | **Implemented** in `zeroclaw-channels` / agent build |
| Empty Paperclip tool catalog ⇒ no tools exposed | **Implemented** |
| Full **run envelope** (skills + policy object + settle contract) | **Design** — see ElEl plan docs linked below |
| Public HAEE release artifacts / installers | **Not published yet** — build from source |
| Multi-agent packing / K8s Operator hire path | Out of scope for current bootstrap |

## Architecture (hire path)

```text
Paperclip                         Adapter                              HAEE
────────                          ───────                              ────
company library                   map execute(ctx) → session params    accept scoped session
desiredSkills / runtimeMcp        open ACP (WS/stdio)                  compile session policy
run JWT + wake context            stream logs / settle                 bind invocation MCP only
heartbeat / run record            never own the agent loop             run model under policy
                                                                       drop run-scoped material
```

**Planes (conceptual):**

- **L — Lifecycle** — Paperclip REST + run JWT; model follows vendored/installed Paperclip skill; no model-authored credentials.
- **T — Tools** — Paperclip `runtimeMcp` / tool gateway projected into the session (`paperclipToolsOnly`).
- **S — Skills** — verified pointers from the company library; install into the proper scope only (envelope design).

### Paperclip-scoped ACP (shipped seam)

For Paperclip-originated sessions, HAEE accepts ACP session params shaped like:

```json
{
  "paperclipToolsOnly": true,
  "mcpServers": [
    {
      "name": "paperclip-task",
      "transport": "…",
      "url": "…"
    }
  ]
}
```

When `paperclipToolsOnly` is true:

- the session tool surface is driven by the **invocation MCP catalog**, not the daemon’s ambient tool soup;
- an **empty** `mcpServers` list exposes **no** tools;
- missing `mcpServers` is rejected for Paperclip-scoped sessions.

This is the hard difference from stock ZeroClaw ACP for the hire path.

## Build from source

HAEE is a Rust workspace (edition 2024). Prefer the containerized helper so the host does not need a full Rust toolchain.

### From a parent workspace that vendors this repo (e.g. ElEl)

```bash
./src/haee/dev/cargo-in-container.sh --version
./src/haee/dev/cargo-in-container.sh test -p zeroclaw-channels \
  session_new_paperclip_tools_only_uses_invocation_mcp
./src/haee/dev/cargo-in-container.sh build-bin zeroclaw --locked
```

Exported binary (gitignored): `.artifacts/haee-binaries/zeroclaw`  
Incremental target dir (gitignored): `.cache/haee-target/`

### Inside this repository

```bash
./dev/ci.sh test
./dev/ci.sh build
# or the same Compose-backed wrapper once paths resolve from repo root:
./dev/cargo-in-container.sh build-bin zeroclaw --locked
```

More detail: [dev/README.md](dev/README.md).

### Runtime note

The process still speaks ZeroClaw config and CLI:

```bash
./.artifacts/haee-binaries/zeroclaw --help
# config default remains under the ZeroClaw-compatible path (e.g. ~/.zeroclaw)
```

Pair it with Paperclip through the external adapter (today `paperclip-zeroclaw-adapter`, rename target `paperclip-haee-adapter`). Do not treat a plain upstream `install.sh` curl as an HAEE install—that path installs **upstream ZeroClaw**, not this fork.

## Repository layout (high level)

| Path | Role |
| --- | --- |
| `crates/zeroclaw-channels` | ACP server, channels; Paperclip session overlay |
| `crates/zeroclaw-runtime` | Agent loop, session cwd / MCP binding |
| `crates/zeroclaw-config` | Schema and policy surfaces |
| `crates/zeroclaw-tools` / `zeroclaw-providers` | Tools and model providers |
| `dev/` | CI image, Compose, `cargo-in-container.sh` |
| `docs/book/` | Inherited ZeroClaw documentation book |

Crate and binary names keep the `zeroclaw_*` / `zeroclaw` identifiers on purpose.

## Related documents

Canonical product vocabulary and decisions live in the ElEl control repo when HAEE is vendored there:

- [ADR-0010 — Use HAEE for Paperclip-hired agents](https://github.com/sematula/elel-dev/blob/main/docs/adr/0010-use-haee-for-paperclip-hired-agents.md)
- [HAEE run envelope (design)](https://github.com/sematula/elel-dev/blob/main/docs/plans/haee-run-envelope.md)
- [ZeroClaw ACP contract (baseline)](https://github.com/sematula/elel-dev/blob/main/docs/plans/zeroclaw-acp-contract.md)

Upstream ZeroClaw book (behavior shared with the lineage): [docs.zeroclaw.com](https://docs.zeroclaw.com/) · local sources under `docs/book/src/`.

## Contributing

1. Prefer small, named seams for Paperclip/HAEE behavior (`paperclipToolsOnly`, session policy, envelope fields)—avoid silent divergence from upstream without a clear hire-path reason.
2. Run the containerized test/build path above before opening a PR.
3. Inherited contributor guide material lives under `docs/book/src/contributing/` and [CONTRIBUTING.md](CONTRIBUTING.md); treat upstream-specific branch/Discord instructions as lineage docs, not HAEE product support channels.

Issues and PRs for **this** fork: [holarchy-cloud/haee](https://github.com/holarchy-cloud/haee).

## Security

Do not file public issues for security vulnerabilities.

Use GitHub private vulnerability reporting on **this** repository:

https://github.com/holarchy-cloud/haee/security/advisories/new

See [SECURITY.md](SECURITY.md) for process expectations. Upstream ZeroClaw security contacts do not cover HAEE-specific changes.

## Upstream project and attribution

HAEE is an **independent derivative** of ZeroClaw, maintained by Holarchy Cloud.

> Upstream: https://github.com/zeroclaw-labs/zeroclaw

This repository is **not** affiliated with or endorsed by ZeroClaw Labs. The ZeroClaw name and logo are trademarks of ZeroClaw Labs. Upstream notices, contributor attribution, and license terms are retained in-tree.

## License

Dual-licensed: [MIT](LICENSE-MIT) **OR** [Apache 2.0](LICENSE-APACHE). You may choose either.

## Credits

HAEE is maintained by Holarchy Cloud and builds on the ZeroClaw community—including original creator [@theonlyhennygod](https://github.com/theonlyhennygod) and project lead [@JordanTheJet](https://github.com/JordanTheJet), plus the broader upstream contributor set.
