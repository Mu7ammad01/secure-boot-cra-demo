#!/usr/bin/env bash
# Execute DANS le conteneur : configure les couches une fois, puis bitbake.
set -euo pipefail
cd /workdir
source sources/poky/oe-init-build-env build >/dev/null
if ! grep -q LAB_MARK conf/local.conf; then
  bitbake-layers add-layer ../sources/meta-openembedded/meta-oe ../sources/meta-mender/meta-mender-core \
    ../sources/meta-mender/meta-mender-demo ../sources/meta-mender/meta-mender-qemu ../sources/meta-lab-secure
  cat /workdir/local.conf.lab >> conf/local.conf
fi
bitbake "${1:-core-image-base}"
