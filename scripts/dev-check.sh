#!/usr/bin/env bash
set -euo pipefail

echo "== Ruff check =="
. .venv/bin/activate
ruff check .

echo "== ShellCheck =="
find . -type f \( -name "*.sh" -o -path "./scripts/*" \) -print0 \
  | xargs -0 -r shellcheck

echo "== Pytest =="
pytest -q

echo "OK: all dev checks passed."
