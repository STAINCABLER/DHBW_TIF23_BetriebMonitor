#!/usr/bin/env bash
set -euo pipefail

VENV_DIR="${VENV_DIR:-.venv}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if [ ! -d "$VENV_DIR" ]; then
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

if [ -f requirements.txt ]; then
    pip install --upgrade pip
    pip install --no-cache-dir -r requirements.txt
fi

if [ -f package.json ]; then
    npm install
fi

exec python server.py
