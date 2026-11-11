#!/usr/bin/env bash
# Lancement de la démo sous Linux / macOS / Git Bash. Usage : ./run_demo.sh [--pause] [--only 2,5]
set -euo pipefail
cd "$(dirname "$0")"
python3 -c "import cryptography" 2>/dev/null || python3 -m pip install --user cryptography
exec python3 demo_chain.py "$@"
