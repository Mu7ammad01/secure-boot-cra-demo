#!/usr/bin/env bash
# Y1 - lance le build Yocto dunfell dans le conteneur CROPS ubuntu-20.04 (dunfell n'est pas supporte sur Ubuntu 24.04).
# Usage : bash build.sh [cible]   (defaut core-image-base). Log : ~/lab/yocto/build.log. Relancer = reprise.
set -euo pipefail
Y="${LAB_YOCTO:-$HOME/lab/yocto}"; T="${1:-core-image-base}"
cd "$Y"
D=docker; docker info >/dev/null 2>&1 || D="sudo docker"
nohup $D run --rm -v "$Y":/workdir crops/poky:ubuntu-20.04 --workdir=/workdir \
  /bin/bash /workdir/build-inside.sh "$T" > "$Y/build.log" 2>&1 &
echo "Build lance en arriere-plan. Suivi : tail -f $Y/build.log   (chercher 'NOTE: Tasks Summary')"
