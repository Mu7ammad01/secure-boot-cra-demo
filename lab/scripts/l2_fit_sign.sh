#!/usr/bin/env bash
# L2 - FIT signe (RSA2048/SHA256) avec les VRAIS outils U-Boot : mkimage + fit_check_sign.
# Usage : bash l2_fit_sign.sh      (SKIP_APT=1 pour ne pas installer les paquets)
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; W="$HERE/work/l2"; UBOOT="${UBOOT:-$HOME/u-boot}"
if [[ -z "${SKIP_APT:-}" ]]; then
  sudo apt-get install -y device-tree-compiler libssl-dev bison flex libgnutls28-dev git make gcc openssl python3
fi
if [[ ! -x "$UBOOT/tools/fit_check_sign" ]]; then
  [[ -d "$UBOOT" ]] || git clone --depth 1 --branch v2025.10 https://github.com/u-boot/u-boot.git "$UBOOT"
  (cd "$UBOOT" && make -s tools-only_defconfig && make -s -j"$(nproc)" tools-only NO_SDL=1)
fi
MKIMAGE="$UBOOT/tools/mkimage"; CHECK="$UBOOT/tools/fit_check_sign"
rm -rf "$W"; mkdir -p "$W/keys" "$W/evil"; cd "$W"
head -c 200000 /dev/urandom > Image                     # faux noyau
printf '/dts-v1/;\n/ { model="lab"; };\n' > board.dts; dtc -q -I dts -O dtb -o board.dtb board.dts
cp board.dtb pubkey.dtb                                  # joue le role du DTB d'U-Boot qui recevra la cle publique
openssl genrsa -F4 -out keys/dev.key 2048 2>/dev/null
openssl req -batch -new -x509 -key keys/dev.key -out keys/dev.crt -subj "/CN=lab-dev"
cat > image.its <<'ITS'
/dts-v1/;
/ {
  description = "lab FIT";
  #address-cells = <1>;
  images {
    kernel-1 { description="kernel"; data=/incbin/("./Image"); type="kernel"; arch="arm64"; os="linux"; compression="none"; load=<0x40480000>; entry=<0x40480000>; hash-1 { algo="sha256"; }; };
    fdt-1 { description="dtb"; data=/incbin/("./board.dtb"); type="flat_dt"; arch="arm64"; compression="none"; hash-1 { algo="sha256"; }; };
  };
  configurations {
    default = "conf-1";
    conf-1 { description="signed conf"; kernel="kernel-1"; fdt="fdt-1";
      signature-1 { algo="sha256,rsa2048"; key-name-hint="dev"; sign-images="fdt","kernel"; }; };
  };
};
ITS
echo "### 1. Signature de la configuration + injection de la cle PUBLIQUE dans pubkey.dtb"
"$MKIMAGE" -f image.its -K pubkey.dtb -k keys -r image.fit | tail -2
echo; echo "### 2. Verification avec la cle publique : doit etre OK"
"$CHECK" -f image.fit -k pubkey.dtb 2>&1 | head -2
echo; echo "### 3. Falsification d'un hash signe : doit ECHOUER"
python3 - <<'PY'
import hashlib
d=bytearray(open('image.fit','rb').read()); h=hashlib.sha256(open('Image','rb').read()).digest()
i=d.find(h); d[i]^=0xFF; open('image.tampered','wb').write(d)
PY
"$CHECK" -f image.tampered -k pubkey.dtb 2>&1 | head -3 || true
echo; echo "### 4. FIT signe par une autre cle (attaquant) : doit ECHOUER"
openssl genrsa -F4 -out evil/dev.key 2048 2>/dev/null
openssl req -batch -new -x509 -key evil/dev.key -out evil/dev.crt -subj "/CN=evil"
"$MKIMAGE" -f image.its -k evil -r evil.fit >/dev/null 2>&1
"$CHECK" -f evil.fit -k pubkey.dtb 2>&1 | head -3 || true
echo; echo "### 5. A noter : fit_check_sign verifie la SIGNATURE de config (qui couvre les hash)."
echo "    Le controle des donnees de chaque image contre son hash se fait dans U-Boot au bootm."
