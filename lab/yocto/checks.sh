#!/usr/bin/env bash
# Y3 - verifications post-build : artefact Mender signe, signatures lab-sign, resume CVE, SBOM depuis le manifest.
set -euo pipefail
Y="${LAB_YOCTO:-$HOME/lab/yocto}"; D="$Y/build/tmp/deploy/images/vexpress-qemu"; HERE="$(cd "$(dirname "$0")" && pwd)"
echo "### Artefact Mender signe : validation avec la cle publique"
MA=$(find "$Y/build/tmp/sysroots-components" -name mender-artifact -type f 2>/dev/null | head -1 || true)
ART=$(ls "$D"/*.mender 2>/dev/null | head -1 || true)
if [[ -n "$MA" && -n "$ART" ]]; then "$MA" validate "$ART" -k "$Y/keys/artifact-public.key" || true; else echo "mender-artifact ou .mender introuvable (build termine ?)"; fi
echo; echo "### Signatures lab-sign (stand-in CSF) : verification openssl"
for s in "$D"/*.sig; do [[ -e "$s" ]] || { echo "aucune .sig (tache lab_sign non executee ?)"; break; }
  openssl dgst -sha256 -verify "$Y/keys/lab-sign.pub" -signature "$s" "${s%.sig}" || true; done
echo; echo "### Resume CVE (cve-check)"; ls "$Y"/build/tmp/log/cve/ 2>/dev/null && tail -n 15 "$Y"/build/tmp/log/cve/cve-summary 2>/dev/null || echo "pas de rapport CVE (voir build.log : l'acces NVD de dunfell est un point CRA a raconter)"
echo; echo "### SBOM CycloneDX depuis le manifest"
M=$(ls "$D"/*.manifest 2>/dev/null | head -1 || true)
[[ -n "$M" ]] && python3 "$HERE/manifest2cdx.py" "$M" "$Y/sbom.cdx.json" || echo "manifest introuvable"
