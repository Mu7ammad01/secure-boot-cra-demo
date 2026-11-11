#!/usr/bin/env bash
# L5 - SBOM (CycloneDX + SPDX) puis CVE sur la VM Ubuntu. Outils : syft + grype (Anchore).
# Non teste hors de ta VM : si l'installation echoue, voir GUIDE.md (repli).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; W="$HERE/work/l5"; mkdir -p "$W"; cd "$W"
for t in syft grype; do
  command -v $t >/dev/null || curl -sSfL "https://raw.githubusercontent.com/anchore/$t/main/install.sh" | sudo sh -s -- -b /usr/local/bin
done
syft dir:/usr -o cyclonedx-json=sbom.cdx.json -o spdx-json=sbom.spdx.json -q
echo "Composants dans la SBOM : $(python3 -c "import json;print(len(json.load(open('sbom.cdx.json'))['components']))")"
grype sbom:sbom.cdx.json -q -o table > vulns.txt || true
echo "Vulnerabilites listees : $(($(wc -l < vulns.txt)-1))   (voir work/l5/vulns.txt)"
echo "Critical/High :"; grep -cE "Critical|High" vulns.txt || true
