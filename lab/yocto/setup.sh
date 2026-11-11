#!/usr/bin/env bash
# Y0 - prepare l'arbre Yocto dunfell + Mender (QEMU/U-Boot) dans ~/lab/yocto. ~10 min (clones + image conteneur).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; Y="${LAB_YOCTO:-$HOME/lab/yocto}"
mkdir -p "$Y/sources" "$Y/cache/downloads" "$Y/cache/sstate" "$Y/keys"; chmod 700 "$Y/keys"
cd "$Y/sources"
clone() { [[ -d "$2" ]] || git clone --depth 1 --branch "$3" "$1" "$2"; }
clone https://git.yoctoproject.org/poky poky dunfell
clone https://git.openembedded.org/meta-openembedded meta-openembedded dunfell
clone https://github.com/mendersoftware/meta-mender meta-mender dunfell
rm -rf meta-lab-secure && cp -r "$HERE/meta-lab-secure" .
cp "$HERE/build-inside.sh" "$HERE/local.conf.lab" "$Y/"
# Cles du labo (HORS depot git) : signature d'artefact Mender + signature "stand-in CSF" du build
[[ -f "$Y/keys/artifact-private.key" ]] || { openssl genrsa -out "$Y/keys/artifact-private.key" 3072 2>/dev/null; openssl rsa -in "$Y/keys/artifact-private.key" -pubout -out "$Y/keys/artifact-public.key" 2>/dev/null; }
[[ -f "$Y/keys/lab-sign.key" ]] || { openssl genrsa -out "$Y/keys/lab-sign.key" 3072 2>/dev/null; openssl rsa -in "$Y/keys/lab-sign.key" -pubout -out "$Y/keys/lab-sign.pub" 2>/dev/null; }
command -v docker >/dev/null || { sudo apt-get install -y -qq docker.io; sudo usermod -aG docker "$USER"; }
sudo apt-get install -y -qq qemu-system-arm git >/dev/null
D=docker; docker info >/dev/null 2>&1 || D="sudo docker"
$D pull crops/poky:ubuntu-20.04
echo "OK : lance maintenant  bash $HERE/build.sh   (build long : 2 a 4 h, en arriere-plan)"
