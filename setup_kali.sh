#!/usr/bin/env bash
# Optional Kali helper. You do not need a VM: the supported
# deploy path is Docker on Render (see README). Use this script only if you
# already have Kali and want apt packages as well as the Python venv.
# PEP 668: never use pip --break-system-packages. App deps go in .venv;
# standalone tools go in pipx.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if [[ ${EUID:-0} -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

echo "==> Installing apt packages"
$SUDO apt-get update
$SUDO apt-get install -y \
  python3 \
  python3-venv \
  python3-pip \
  pipx \
  whois \
  dnsrecon \
  subfinder \
  theharvester \
  h8mail \
  libimage-exiftool-perl

# Sherlock is packaged on Kali; fall back to pipx if apt does not have it.
if ! $SUDO apt-get install -y sherlock; then
  echo "apt package 'sherlock' is not available; will install via pipx."
fi

echo "==> Installing isolated CLIs with pipx (maigret, holehe, sherlock fallback)"
python3 -m pipx ensurepath
export PATH="${HOME}/.local/bin:${PATH}"

pipx install maigret || pipx upgrade maigret || true
pipx install holehe || pipx upgrade holehe || true

if ! command -v sherlock >/dev/null 2>&1; then
  pipx install sherlock-project || pipx upgrade sherlock-project || true
fi

echo "==> Creating the app virtualenv"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo
echo "Setup finished."
echo "Optional environment variables (put them in the shell or a local .env you source):"
echo "  GEMINI_API_KEY      free-tier key from https://aistudio.google.com/"
echo "  GEMINI_MODEL        default is gemini-2.5-flash-lite; recheck the current free-tier id in AI Studio"
echo "                      (as of late 2026, gemini-3.5-flash-lite may have a higher daily cap)"
echo "  HIBP_API_KEY        paid Have I Been Pwned key; without it, the UI links out to hibp.com"
echo "  DEMO=1              show a demo-mode banner (the Load demo result button always works)"
echo
echo "Start the app with:  ./run.sh"
echo "Then open http://127.0.0.1:8000/  (bound to localhost only)"
echo
echo "On PATH now:"
for bin in sherlock maigret holehe h8mail whois dnsrecon subfinder theHarvester theharvester; do
  if command -v "$bin" >/dev/null 2>&1; then
    printf "  %-16s %s\n" "$bin" "$(command -v "$bin")"
  else
    printf "  %-16s MISSING\n" "$bin"
  fi
done
