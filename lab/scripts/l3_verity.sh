#!/usr/bin/env bash
# L3 - dm-verity : arbre de hash + root hash, puis detection d'une alteration du rootfs.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; W="$HERE/work/l3"; rm -rf "$W"; mkdir -p "$W"; cd "$W"
[[ -z "${SKIP_APT:-}" ]] && sudo apt-get install -y cryptsetup-bin
dd if=/dev/urandom of=rootfs.img bs=1M count=8 status=none          # faux rootfs (8 Mo)
veritysetup format rootfs.img rootfs.hash | tee format.log | grep -E "Data blocks|Hash block size|Root hash"
RH=$(awk '/Root hash/{print $3}' format.log)                           # a mesurer UNE fois (sel aleatoire)
echo "$RH" > root.hash
echo; echo "### Verification image intacte :"; veritysetup verify rootfs.img rootfs.hash "$RH" && echo "OK"
printf '\xff' | dd of=rootfs.img bs=1 seek=4242 conv=notrunc status=none
echo; echo "### Apres alteration d'1 octet :"; veritysetup verify rootfs.img rootfs.hash "$RH" || echo "(echec attendu : en vrai le noyau renvoie une erreur d'E/S / panic)"
echo; echo "Le ROOT HASH est la valeur de confiance : il doit etre protege (cmdline du FIT/initramfs signe)."
