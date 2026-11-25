#!/usr/bin/env sh
# Install skills from this repo for OpenCode, Claude Code and/or OpenAI Codex.
#
#   ./install.sh                     # all agents, user scope, symlink
#   ./install.sh --agent opencode    # one agent (opencode|claude|codex|all)
#   ./install.sh --copy              # copy instead of symlink
#   ./install.sh --project <dir>     # install into <dir>/.opencode|.claude|.agents/skills
#   ./install.sh --skill rdk-knowledge-parser   # one skill (default: all)
set -eu

REPO="$(cd "$(dirname "$0")" && pwd)"
AGENT=all MODE=link PROJECT="" SKILL=""

while [ $# -gt 0 ]; do
  case "$1" in
    --agent) AGENT="$2"; shift 2 ;;
    --copy) MODE=copy; shift ;;
    --project) PROJECT="$2"; shift 2 ;;
    --skill) SKILL="$2"; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

target_dir() {
  if [ -n "$PROJECT" ]; then
    case "$1" in
      opencode) echo "$PROJECT/.opencode/skills" ;;
      claude) echo "$PROJECT/.claude/skills" ;;
      codex) echo "$PROJECT/.agents/skills" ;;
    esac
  else
    case "$1" in
      opencode) echo "${XDG_CONFIG_HOME:-$HOME/.config}/opencode/skills" ;;
      claude) echo "$HOME/.claude/skills" ;;
      codex) echo "${CODEX_HOME:-$HOME/.codex}/skills" ;;
    esac
  fi
}

install_one() {
  agent="$1" dest="$(target_dir "$1")"
  mkdir -p "$dest"
  for src in "$REPO"/skills/*/; do
    name="$(basename "$src")"
    [ -n "$SKILL" ] && [ "$SKILL" != "$name" ] && continue
    [ -f "$src/SKILL.md" ] || continue
    rm -rf "${dest:?}/$name"
    if [ "$MODE" = link ]; then
      ln -s "${src%/}" "$dest/$name"
    else
      cp -R "${src%/}" "$dest/$name"
    fi
    echo "$agent: $dest/$name ($MODE)"
  done
}

case "$AGENT" in
  all) for a in opencode claude codex; do install_one "$a"; done ;;
  opencode|claude|codex) install_one "$AGENT" ;;
  *) echo "unknown agent: $AGENT" >&2; exit 2 ;;
esac
