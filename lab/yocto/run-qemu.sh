#!/usr/bin/env bash
# Y2 - demarre l'image dans QEMU (U-Boot + Mender A/B). Quitter QEMU : Ctrl-A puis X. Login : root (sans mot de passe en demo).
set -euo pipefail
Y="${LAB_YOCTO:-$HOME/lab/yocto}"; cd "$Y/build"
command -v qemu-system-arm >/dev/null || sudo apt-get install -y qemu-system-arm
MACHINE=vexpress-qemu ../sources/meta-mender/meta-mender-qemu/scripts/mender-qemu "${1:-core-image-base}"
