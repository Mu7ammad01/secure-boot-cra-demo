# Chaîne de confiance embarquée et conformité CRA

Projet pédagogique : Secure Boot matériel (HAB) et mise en conformité Cyber Resilience Act sur une carte i.MX8MQ (Nitrogen8M), avec Yocto dunfell, U-Boot et Mender.

## Le problème en une phrase

Comment être sûr qu’un appareil connecté n’exécute que le code de son fabricant, au démarrage comme après chaque mise à jour ?

## L’idée : chaque maillon vérifie le suivant

| Maillon | Rôle |
|---|---|
| HAB | La BootROM authentifie le SPL puis U-Boot ; le hash de la table de clés est dans les eFuses |
| FIT signé | U-Boot vérifie la signature de la configuration (noyau, DTB, bootargs) |
| dm-verity | Le rootfs est vérifié bloc par bloc, root hash signé via le FIT |
| Mender | Mises à jour A/B signées, rollback automatique |
| CRA | SBOM, suivi des CVE, alerte 24 h et notification 72 h (délais à re-vérifier sur EUR-Lex) |

## Contenu

- `demo/` : démo Python (11 scénarios, 10 secondes, vraies signatures RSA-2048) avec lanceurs Windows et Linux. Voir `demo/README.md`.
- `lab/` : kit du lab réel (build Yocto avec Mender, signature, SBOM CycloneDX, démarrage QEMU). Voir `lab/GUIDE.md`.
- `docs/` : présentation (à exporter en PDF depuis la présentation).

## Lancer la démo

```
cd demo
pip install cryptography
python demo_chain.py --pause
```

Sous Windows : `powershell -ExecutionPolicy Bypass -File .\run_demo.ps1 -Pause`.

## Résultats du lab réel

- Build Yocto : 6029 tâches réussies.
- SBOM CycloneDX : 273 composants.
- Artefact Mender signé et validé ; démarrage A/B dans QEMU.

## Limites

La démo est un modèle pédagogique. L’image QEMU n’intègre ni HAB ni dm-verity ; ces couches sont montrées par la démo Python. HAB réel : outils NXP (CST) et gravure irréversible des eFuses, à faire en carte open d’abord.
