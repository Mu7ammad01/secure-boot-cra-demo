#!/usr/bin/env bash
# Preparation LEGERE de la VM Ubuntu pour le lab "Stage en boite" (~10 min, pas de Docker, pas de Yocto).
# Usage (dans lab-stage/) : bash scripts/vm_setup_light.sh
set -euo pipefail
SUDO=""; [[ $EUID -ne 0 ]] && SUDO="sudo"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
echo "==> 1/3 Paquets (juste ce qu'il faut pour L1, L2, L3, L5)"
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq git make gcc bison flex libssl-dev libgnutls28-dev device-tree-compiler \
  u-boot-tools openssl cryptsetup-bin python3 python3-cryptography curl unzip jq
echo "==> 2/3 Outils U-Boot (mkimage, fit_check_sign) : compilation unique ~3 min"
UBOOT="${UBOOT:-$HOME/u-boot}"
if [[ ! -x "$UBOOT/tools/fit_check_sign" ]]; then
  [[ -d "$UBOOT" ]] || git clone -q --depth 1 --branch v2025.10 https://github.com/u-boot/u-boot.git "$UBOOT"
  (cd "$UBOOT" && make -s tools-only_defconfig && make -s -j"$(nproc)" tools-only NO_SDL=1)
fi
echo "==> 3/3 Verification"
ok=1
chk() { if "$@" >/dev/null 2>&1; then echo "  OK  $*"; else echo "  KO  $*"; ok=0; fi; }
chk python3 -c "import cryptography"
chk test -x "$UBOOT/tools/mkimage"
chk test -x "$UBOOT/tools/fit_check_sign"
chk dtc --version
chk veritysetup --version
chk openssl version
if [[ $ok -eq 1 ]]; then
  echo; echo "Pret. Enchaine : cd $HERE/l1_hab_model && bash run_demo.sh"
  echo "puis : bash $HERE/scripts/l2_fit_sign.sh  (SKIP_APT=1 ... pour ne pas reinstaller)"
else echo; echo "Au moins un KO : colle-moi la sortie."; exit 1; fi
