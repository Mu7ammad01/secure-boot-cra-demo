#!/usr/bin/env python3
"""Convertit un manifest Yocto ('paquet arch version' par ligne) en SBOM CycloneDX 1.5 minimale."""
import json, sys, uuid, datetime
src, dst = sys.argv[1], sys.argv[2]
comps = []
for line in open(src, encoding="utf-8"):
    parts = line.split()
    if len(parts) < 3: continue
    name, arch, ver = parts[0], parts[1], parts[2]
    comps.append({"type": "library", "name": name, "version": ver,
                  "purl": f"pkg:generic/{name}@{ver}?arch={arch}"})
sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     "component": {"type": "firmware", "name": "lab-image", "version": "1.0"}},
        "components": comps}
json.dump(sbom, open(dst, "w"), indent=1)
print(f"SBOM : {len(comps)} composants -> {dst}")
