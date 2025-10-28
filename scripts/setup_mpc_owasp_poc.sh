#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/rymarinelli/MPC_OWASP_POC"
TARGET_DIR="${1:-mpc_owasp_poc}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv_mpc}"

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is required but not installed" >&2
  exit 1
fi

if [ -d "$TARGET_DIR/.git" ]; then
  echo "Repository already appears to be cloned at $TARGET_DIR" >&2
else
  echo "Cloning $REPO_URL into $TARGET_DIR" >&2
  git clone "$REPO_URL" "$TARGET_DIR"
fi

cd "$TARGET_DIR"

if [ -f requirements.txt ]; then
  if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "warning: $PYTHON_BIN not available; skipping dependency installation" >&2
  else
    if [ ! -d "$VENV_DIR" ]; then
      echo "Creating virtual environment $VENV_DIR" >&2
      "$PYTHON_BIN" -m venv "$VENV_DIR"
    else
      echo "Re-using existing virtual environment $VENV_DIR" >&2
    fi
    # shellcheck source=/dev/null
    . "$VENV_DIR/bin/activate"
    echo "Installing Python dependencies from requirements.txt" >&2
    pip install --upgrade pip
    pip install -r requirements.txt
  fi
else
  echo "No requirements.txt found; skipping Python dependency installation" >&2
fi

if [ -f package.json ]; then
  if command -v npm >/dev/null 2>&1; then
    echo "Installing Node dependencies" >&2
    npm install
  else
    echo "warning: npm not available; skipping Node dependency installation" >&2
  fi
fi

echo "Setup complete. Activate the virtual environment with 'source $TARGET_DIR/$VENV_DIR/bin/activate'." >&2

