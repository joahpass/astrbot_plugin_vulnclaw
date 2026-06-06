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

docker compose build
docker compose up -d vulnclaw-supervisor
docker compose ps

