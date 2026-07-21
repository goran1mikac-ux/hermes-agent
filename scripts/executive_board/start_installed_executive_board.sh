#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 ]]; then
  echo "usage: $0 <venv> <agents-os-root> <manifest.json> <wheel.whl> [host] [port] [--verify-only]" >&2
  exit 64
fi

VENV=$1
ROOT=$2
MANIFEST=$3
WHEEL=$4
shift 4
HOST=127.0.0.1
PORT=18791
VERIFY_ONLY=0
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify-only) VERIFY_ONLY=1; shift ;;
    --host) [[ $# -ge 2 ]] || { echo "missing --host value" >&2; exit 64; }; HOST=$2; shift 2 ;;
    --port) [[ $# -ge 2 ]] || { echo "missing --port value" >&2; exit 64; }; PORT=$2; shift 2 ;;
    --*) echo "unknown option: $1" >&2; exit 64 ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
if [[ ${#POSITIONAL[@]} -gt 2 ]]; then
  echo "too many positional arguments" >&2
  exit 64
fi
[[ ${#POSITIONAL[@]} -ge 1 ]] && HOST=${POSITIONAL[0]}
[[ ${#POSITIONAL[@]} -ge 2 ]] && PORT=${POSITIONAL[1]}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PYTHON="$VENV/bin/python"
[[ -x "$PYTHON" ]] || { echo "missing venv interpreter: $PYTHON" >&2; exit 66; }
[[ -f "$MANIFEST" ]] || { echo "missing manifest: $MANIFEST" >&2; exit 66; }
[[ -f "$WHEEL" ]] || { echo "missing wheel: $WHEEL" >&2; exit 66; }

unset PYTHONPATH PYTHONHOME
export PYTHONNOUSERSITE=1
cd /tmp
ARGS=(
  "$PYTHON" -I "$SCRIPT_DIR/run_installed_executive_board.py"
  --root "$ROOT"
  --manifest "$MANIFEST"
  --wheel "$WHEEL"
  --host "$HOST"
  --port "$PORT"
)
[[ "$VERIFY_ONLY" -eq 1 ]] && ARGS+=(--verify-only)
exec "${ARGS[@]}"
