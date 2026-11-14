#!/usr/bin/env bash
# Start the self-audit web dashboard. Binds 0.0.0.0 and honours $PORT (Render).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if [[ ! -d .venv ]]; then
  echo "No .venv found. Create one with:"
  echo "  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  echo "Or build and run the Docker image (see README)."
  exit 1
fi

# shellcheck disable=SC1091
source .venv/bin/activate
export PATH="${HOME}/.local/bin:${PATH}"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"

if [[ -z "${APP_PASSWORD:-}" ]]; then
  echo "WARNING: APP_PASSWORD is not set. The dashboard will be open to anyone who can reach ${HOST}:${PORT}."
  echo "         Copy .env.example to .env and set APP_PASSWORD and SECRET_KEY before sharing this URL."
fi

echo "Digital Footprint Self-Audit"
echo "  http://${HOST}:${PORT}/"
echo "  Health:    http://${HOST}:${PORT}/health"
echo "  Audit log: http://${HOST}:${PORT}/audit"
echo "  GEMINI_API_KEY set: $([ -n "${GEMINI_API_KEY:-}" ] && echo yes || echo no)"
echo

exec python -m uvicorn app.main:app --host "$HOST" --port "$PORT" --workers 1
