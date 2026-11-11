# Démo : chaîne de confiance embarquée + CRA

Démo Python autonome (un seul fichier, ~10 s) qui rejoue la chaîne du projet
(i.MX8MQ Nitrogen8M, Yocto / U-Boot / Mender) : **HAB → FIT signé → dm-verity → Mender A/B → CRA**.

> **Modèle pédagogique.** Pas de vraie ROM ni de vrais fusibles. Les signatures sont réelles
> (RSA-2048 / SHA-256), le principe dm-verity est réel (arbre de Merkle, sel, root hash).
> L'avis de sécurité du scénario 11 est **fictif** (`DEMO-2026-0001`).

## Lancer

| Système | Commande |
| --- | --- |
| Windows (PowerShell) | `.\run_demo.ps1` ou `.\run_demo.ps1 -Pause` |
| Linux / macOS / Git Bash | `./run_demo.sh` ou `./run_demo.sh --pause` |
| Direct | `pip install cryptography` puis `python demo_chain.py` |

Options : `--pause` (Entrée entre scénarios, pour présenter), `--only 2,5,9`, `--list`,
`--sbom ~/lab/yocto/sbom.cdx.json --affect busybox` (CRA sur le vrai SBOM du build, 273 composants).
Le code de sortie vaut 0 si tous les scénarios se comportent comme attendu.

## Les 11 scénarios

| # | Scénario | Ce que ça montre | Équivalent réel |
| --- | --- | --- | --- |
| 1 | Démarrage nominal (carte closed) | La chaîne complète, étage par étage | `hab_status` sans événement |
| 2 | U-Boot remplacé, carte closed puis open | Pourquoi on ferme la carte | `SEC_CONFIG` (fuse) |
| 3 | Chaîne entièrement signée par l'attaquant | Le hash SRK dans les eFuses est l'ancre | `SRK_HASH` |
| 4 | Noyau modifié | Hash des images du FIT | `mkimage`, `bootm` |
| 5 | Mix and match | Pourquoi signer la **configuration** | `fit_check_sign` |
| 6 | Rootfs modifié, puis arbre recalculé | Root hash signé dans le FIT | `veritysetup verify` |
| 7 | Mise à jour valide A → B + commit | Cycle Mender nominal | `fw_printenv` |
| 8 | Artefact falsifié, puis re-signé | Signature + hash de charge utile | `mender-artifact validate` |
| 9 | Image défaillante | Rollback automatique (bootcount) | `bootlimit` |
| 10 | Rejeu d'une ancienne version | Anti-rollback (option de conception) | à définir selon le produit |
| 11 | CRA : SBOM, CVE, délais | Exposition en secondes, horloge 24 h / 72 h | `cve-check`, SBOM CycloneDX |

## Même chose avec les vrais outils (lab Yocto / QEMU)

```bash
# FIT signé (U-Boot) : signer puis vérifier la signature de configuration
mkimage -f image.its -K pubkey.dtb -k keys -r image.fit
fit_check_sign -f image.fit -k pubkey.dtb

# dm-verity : arbre de hash et root hash
veritysetup format data.img hash.img
veritysetup verify data.img hash.img <root_hash>

# Mender : artefact signé
mender-artifact sign   artefact.mender -k artifact-private.key
mender-artifact validate artefact.mender -k artifact-public.key

# État A/B sur la cible
fw_printenv            # mender_boot_part, upgrade_available, bootcount
```

## Scénario de présentation conseillé (5 minutes)

1. `--only 1` : la chaîne nominale (30 s).
2. `--only 3` puis `--only 5` : les deux idées fortes (ancre dans les eFuses, signature de configuration).
3. `--only 6` : dm-verity, y compris l'arbre recalculé.
4. `--only 9` : le rollback Mender.
5. `--only 11` : le CRA, avec le vrai SBOM si possible.

`sortie_exemple.txt` contient une exécution complète (secours si la démo live ne démarre pas).

## Limites (à dire clairement)

- HAB est modélisé : aucune ROM, aucun fusible, pas de CST NXP ; sur la carte réelle, la procédure est
  PKI → signature SPL / U-Boot → test en open (`hab_status` à zéro événement) → gravure SRK_HASH → fermeture.
- dm-verity : 1 Mio, un sel fixe par version ; le comportement réel dépend du noyau et du bootloader.
- Anti-rollback : mécanisme à définir (compteur en eFuse, RPMB, version minimale).
- Délais CRA : à re-vérifier sur EUR-Lex avant de les citer.
