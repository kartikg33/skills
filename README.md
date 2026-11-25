# skills

Real skills for real agentic software development.

Skills are written once in the [Agent Skills](https://agentskills.io) `SKILL.md` format and
exposed to several agents:

| Agent | Project discovery (this repo) | User install (`./install.sh`) |
|---|---|---|
| OpenCode (primary) | `.opencode/skills` → `skills/` | `~/.config/opencode/skills/<name>` |
| Claude Code | `.claude/skills` → `skills/` | `~/.claude/skills/<name>` |
| OpenAI Codex | `.agents/skills` → `skills/` (+ `agents/openai.yaml`) | `~/.codex/skills/<name>` |

OpenCode also reads `.claude/skills` and `.agents/skills`, so any of the three works for it.

```sh
./install.sh                         # all agents, symlinked into user dirs
./install.sh --agent claude --copy   # one agent, copied
./install.sh --project ~/work/rdkb   # into another repo's agent dirs
```

## Skills

| Skill | What it does |
|---|---|
| [`rdk-knowledge-parser`](skills/rdk-knowledge-parser/SKILL.md) | Maps every dependency of an RDK / RDK-B component: IPC (sysevent, syscfg, PSM, CCSP bus, rbus, D-Bus, MQTT, msgpack, file IPC), external processes (v_secure_system, systemctl, iptables, ioctl, netlink), data model and cloud (TR-181, RFC, T2, logs, WebConfig, USP), and build (Yocto, autotools, cmake, libraries, feature flags). Ships a scanner and a coverage validator. |

## Layout

```
skills/<name>/
  SKILL.md          # entry point: frontmatter (name, description) + workflow
  references/       # detail loaded on demand
  scripts/          # tools the agent runs
  tests/            # validation of the skill's tools
  agents/openai.yaml  # Codex UI metadata (optional)
```

## Adding a skill

1. `mkdir skills/<name>` with a `SKILL.md`; `name` in the frontmatter must equal the directory name
   (lowercase, hyphens).
2. Keep `description` under 1024 characters and say *when* to use the skill.
3. Put long material in `references/`, executable helpers in `scripts/`.
4. Add tests that prove the skill's claims.
