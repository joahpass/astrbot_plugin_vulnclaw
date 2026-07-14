#!/usr/bin/env sh
set -eu

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required." >&2
  exit 1
fi

if [ ! -f .env ]; then
  umask 077
  secret="$(openssl rand -hex 32)"
  printf 'VULNCLAW_WORKER_SECRET=%s\n' "$secret" > .env
  echo "Created .env with a random Worker secret."
fi

astrbot_dir="${ASTRBOT_DIR:-${1:-}}"
if [ -n "$astrbot_dir" ]; then
  if [ ! -d "$astrbot_dir/data/plugins" ]; then
    echo "Invalid AstrBot directory: $astrbot_dir (data/plugins not found)." >&2
    exit 1
  fi

  plugin_dir="$astrbot_dir/data/plugins/astrbot_plugin_vulnclaw"
  mkdir -p "$plugin_dir"
  cp -R astrbot_plugin_vulnclaw/. "$plugin_dir/"

  config_dir="$astrbot_dir/data/config"
  config_file="$config_dir/astrbot_plugin_vulnclaw_config.json"
  mkdir -p "$config_dir"
  if [ ! -f "$config_file" ]; then
    worker_secret="$(awk -F= '$1 == "VULNCLAW_WORKER_SECRET" {sub(/^[^=]*=/, ""); print; exit}' .env)"
    case "$worker_secret" in
      *[!A-Za-z0-9._~-]*|'')
        echo "Plugin copied, but Worker secret contains unsupported JSON characters." >&2
        echo "Configure worker_secret manually in AstrBot WebUI." >&2
        ;;
      *)
        umask 077
        printf '{\n  "worker_url": "%s",\n  "worker_secret": "%s",\n  "enable_high_risk_modes": false,\n  "default_task_timeout_seconds": 1800,\n  "approval_ttl_seconds": 600,\n  "agent_max_steps": 24,\n  "tool_timeout_seconds": 120,\n  "report_retention_days": 30,\n  "notify_stage_updates": true,\n  "enable_mcp": false\n}\n' \
          "${VULNCLAW_WORKER_URL:-http://127.0.0.1:8765}" "$worker_secret" > "$config_file"
        echo "Created AstrBot plugin config: $config_file"
        ;;
    esac
  fi
  echo "Installed AstrBot plugin: $plugin_dir"
  echo "Restart AstrBot, then run /vuln doctor."
else
  echo "Set ASTRBOT_DIR or pass the AstrBot root path to install the plugin."
  echo "Example: ASTRBOT_DIR=/root/AstrBot sh scripts/install.sh"
fi

docker compose build
docker compose up -d vulnclaw-supervisor
docker compose ps

