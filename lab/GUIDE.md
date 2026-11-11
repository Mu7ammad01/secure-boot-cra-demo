# Lab "Stage en boîte" — Secure Boot HAB + CRA + Yocto/Mender sous QEMU (version light)

**Objectif** : pouvoir dire « j'ai manipulé » sur chaque couche de la chaîne du stage, sans matériel,
avec les vrais outils quand c'est possible, et savoir exactement où s'arrête la simulation.

| # | Module | Couche du stage | Vrai ou modèle ? | Durée |
|---|--------|-----------------|------------------|-------|
| L1 | Modèle HAB (SRK → eFuses → signature → open/closed) | BootROM / HAB | **Modèle** pédagogique | 45 min |
| L1b | Fiche « procédure HAB réelle » (CST, CSF, hab_status) | BootROM / HAB | Papier, à connaître par cœur | 30 min |
| L2 | FIT signé RSA2048/SHA256, vérifié, falsifié | U-Boot (verified boot) | **Vrais outils** U-Boot | 60 min |
| L3 | dm-verity : root hash, détection d'altération | Rootfs / Linux | **Vrai** (veritysetup) | 30 min |
| L4 | Artefact Mender signé/vérifié (optionnel) | Mender | Vrai si l'install passe | 20 min |
| L5 | SBOM CycloneDX/SPDX + CVE | CRA Annexe I partie II | **Vrais outils** (syft/grype) | 45 min |
| L6 | CRA : qualification, matrice d'écarts, runbook 24 h/72 h | CRA | Papier (fichier `cra/`) | 60 min |
| Y0-Y1 | Yocto **dunfell** + meta-mender, machine `vexpress-qemu` (U-Boot + Mender A/B), build en arrière-plan | Yocto / U-Boot / Mender | **Vrai build**, cible émulée | 15 min actives + 2-4 h de build |
| Y2 | Démarrage QEMU : U-Boot, partitions A/B, `fw_printenv` | U-Boot / Mender | **Émulateur** | 30 min |
| Y3 | Artefact Mender signé validé, signature « stand-in CSF » du build, CVE (cve-check), SBOM depuis le manifest | Mender / CRA | Vrai (issu du build) | 45 min |

Environnement : L1 marche partout (Python + `pip install cryptography`). L2, L3, L5 dans la VM Ubuntu
(si l'installation n'est pas finie, L1 et L6 suffisent pour commencer). Dossiers : `l1_hab_model/`, `scripts/`, `cra/`.
**Statut des tests** : L1, L2, L3 testés de bout en bout ici. Kit Yocto (`yocto/`) : syntaxe des scripts et convertisseur SBOM testés ; **build Yocto non testé** (trop long ici) → il peut demander 1 ou 2 corrections au premier lancement, on les fait ensemble. L5 et L4 non testés → repli indiqué.

## Démarrage dans la VM Ubuntu (une seule fois)
Sur Windows (PowerShell) : `Copy-Item H:\Downloads\lab-stage.zip E:\lab\downloads\ -Force` (dossier partagé de la VM).
Dans la VM (terminal Ctrl+Alt+T) :
```bash
sudo apt update && sudo apt install -y open-vm-tools open-vm-tools-desktop unzip
sudo mkdir -p /mnt/hgfs && sudo vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other
mkdir -p ~/lab && cd ~/lab && unzip -o /mnt/hgfs/downloads/lab-stage.zip && cd lab-stage
bash scripts/vm_setup_light.sh     # paquets minimaux + outils U-Boot (~5-10 min), 6 contrôles OK
bash yocto/setup.sh                # Docker, QEMU, clones dunfell/meta-mender, clés du lab (~10 min)
bash yocto/build.sh                # lance le build Yocto en arrière-plan (2-4 h), puis L1/L2/L3 pendant qu'il tourne
```
Si `/mnt/hgfs` reste vide : glisser-déposer le zip dans la VM. Les scripts L2/L3 se relancent sans réinstaller (`SKIP_APT=1 bash scripts/l2_fit_sign.sh`).
**Disque** : le build dunfell occupe ≈ 50-70 Go (disque VM de 150 Go : OK) ; relancer `build.sh` reprend là où il s'est arrêté.
**Règle d'arrêt** : si le build n'est pas lancé proprement mercredi 11h, ou échoue deux fois sur la même erreur, on **abandonne le build** et on garde le discours (L1, L2, L3, L6) : l'entretien prime.

---
## L1 — Modèle HAB (45 min)
```bash
cd l1_hab_model && bash run_demo.sh        # ou commandes de run_demo.sh à la main
```
Rejoue les 6 scénarios, **puis relis `hab_mini.py` (100 lignes)** : tu dois pouvoir expliquer chaque fonction.
- *À dire* : « Le hash de la table SRK est gravé en eFuses (OTP). La ROM compare, vérifie la signature,
  et seul le mode **closed** refuse de booter ; en **open**, HAB journalise les événements (`hab_status`). »
- *Limite à assumer* : ce n'est pas le format CST/CSF/IVT réel ; aucun émulateur public de la ROM i.MX8M.

## L1b — Procédure HAB réelle à connaître (30 min, papier)
Chaîne i.MX8M : BootROM → SPL (+ firmware DDR) → ATF BL31 → U-Boot (FIT) → noyau. `flash.bin` = image `imx-boot`
construite par imx-mkimage ; la cible `print_fit_hab` donne les adresses/tailles à signer.
1. **PKI** : `hab4_pki_tree.sh` (fourni avec NXP CST) → clés SRK (table de 4), CSF, IMG.
2. **Table SRK + hash** : `srktool` → `SRK_..._table.bin` et `SRK_..._fuse.bin` (SHA-256 = 8 mots de 32 bits).
3. **CSF** (fichier texte : `[Header]`, `[Install SRK]`, `[Install CSFK]`, `[Authenticate CSF]`, `[Install Key]`, `[Authenticate Data]`) → `cst -i csf.txt -o csf.bin`, binaire concaténé à l'image.
4. **Deux CSF sur i.MX8M** : un pour le SPL (vérifié par la ROM), un pour le FIT/U-Boot (vérifié par le SPL via l'API HAB de la ROM). Sur i.MX8MQ le firmware HDMI/DP signé s'exécute d'abord.
5. **Valider en mode OPEN** : dans U-Boot, `hab_status` ne doit afficher **aucun événement** (CONFIG_IMX_HAB).
6. **Graver SRK_HASH** (`fuse prog` des banks dédiées, *valeurs et banks exacts à vérifier dans le Reference Manual / guide NXP*), puis **fermer** (bit SEC_CONFIG ; `fuse prog 1 3 0x02000000` chez Boundary Devices). **Irréversible** : fermer sans avoir validé en open = carte briquée.
7. **Après fermeture** : désactiver JTAG par eFuses ; recovery SDP/uuu ne boote plus que des images signées.
- *Piège de l'entretien* : HAB ne couvre que jusqu'à U-Boot → il faut FIT signé (L2), dm-verity (L3), anti-rollback, mises à jour signées (Mender, L4).

## L2 — FIT signé avec les vrais outils U-Boot (60 min)
```bash
bash scripts/l2_fit_sign.sh      # installe paquets, compile mkimage/fit_check_sign (~3 min), exécute 4 tests
```
Résultat attendu : étape 2 « Signature check OK », étapes 3 et 4 « error ! » (hash falsifié ; autre clé).
- *Ce que ça prouve* : `mkimage -K` injecte la **clé publique dans le DTB d'U-Boot** ; la **signature porte sur la configuration** (noyau + DTB par leurs hash).
- *Point fin à dire* : `fit_check_sign` contrôle la signature de configuration ; le contrôle des données image vs hash est fait par U-Boot au `bootm`.
- Lien projet : `CONFIG_FIT_SIGNATURE` + clé publique dans le DTB signé par HAB = la chaîne continue après HAB.

## L3 — dm-verity (30 min)
```bash
bash scripts/l3_verity.sh
```
Attendu : « OK » puis « Verification failed at position 4096 » après altération d'un octet.
- *À dire* : « Le root hash est la racine de confiance du rootfs ; il doit être transmis par un canal signé (cmdline du FIT / initramfs). »

## L4 — Artefact Mender signé (optionnel, 20 min)
Doc officielle : `docs.mender.io/artifact-creation/sign-and-verify`. Installer `mender-artifact` (dépôt apt `workstation-tools`
de downloads.mender.io, voir docs.mender.io/downloads/workstation-tools ; la distribution Ubuntu exacte est à vérifier).
```bash
openssl genrsa -out private.key 3072 && openssl rsa -in private.key -pubout -out public.key
mender-artifact write rootfs-image -t imx8mq -n lab-1.0 -f rootfs.ext4 -k private.key -o signed.mender
mender-artifact validate signed.mender -k public.key
```
*Repli sans l'outil* : te limiter au discours (signature d'artefact hors-ligne, A/B, rollback), c'est suffisant.

## L5 — SBOM + CVE (45 min)
```bash
bash scripts/l5_sbom_cve.sh      # syft + grype ; sorties dans work/l5/
```
Repli si l'installation échoue : `dpkg-query -W` liste les paquets installés ; explique à l'oral comment cette liste devient une SBOM (SPDX/CycloneDX) puis un contrôle CVE.
- Lien CRA : l'Annexe I partie II exige d'identifier et documenter les composants (SBOM) et de traiter les vulnérabilités.
- **Côté Yocto à savoir citer** : `INHERIT += "cve-check"` (CVE par recette) ; `create-spdx` n'existe pas sur dunfell *(à vérifier)* → à rapatrier ou alternative ; dunfell n'a plus de support communautaire *(à vérifier)* : sujet CRA majeur.

## L6 — CRA (60 min) → `cra/CRA_fiche.md`
Remplis la matrice et le runbook (pré-remplis). Retiens 3 dates : **11 sept. 2026** (obligations de notification),
**11 déc. 2027** (application complète), puis **24 h / 72 h / rapport final** pour une vulnérabilité activement exploitée.

---
## Y — Yocto dunfell + Mender sous QEMU (U-Boot émulé), version light
Pourquoi cette cible : `vexpress-qemu` (meta-mender-qemu, branche dunfell) est la seule configuration Mender **avec U-Boot** qui tourne entièrement sans matériel ; elle reproduit le mécanisme A/B + bootcount du projet, avec la même version de Yocto (dunfell). Elle ne reproduit pas : la BootROM/HAB, le SPL/ATF i.MX8M, imx-boot/imx-mkimage.
Optimisations de temps : conteneur CROPS ubuntu-20.04 (dunfell n'est pas supporté sur Ubuntu 24.04), `core-image-base` (pas d'image graphique), caches de téléchargement/sstate persistants dans `~/lab/yocto/cache`, build lancé en tâche de fond pendant que tu fais L1-L3.
1. **Y0/Y1** : `bash yocto/setup.sh && bash yocto/build.sh` ; suivi `tail -f ~/lab/yocto/build.log` (fin : « Tasks Summary »). Durée : 2 à 4 h sans cache.
2. **Y2** : `bash yocto/run-qemu.sh` → observe la console U-Boot, connecte-toi en `root`, lance `fw_printenv` (variables `mender_boot_part`, `upgrade_available`, `bootcount`). Quitter QEMU : Ctrl-A puis X.
3. **Y3** : `bash yocto/checks.sh` → valide l'artefact `.mender` signé, vérifie les signatures `lab-sign` (équivalent « CSF » du build), affiche le résumé CVE et génère une SBOM CycloneDX depuis le manifest.
- *À dire* : « La signature s'accroche en fin de build (`meta-lab-secure/classes/lab-sign.bbclass`) avec une clé hors dépôt. Sur i.MX8M ce serait `srktool` + `cst` sur `imx-boot`, avec deux CSF. La mise à jour est un artefact Mender signé, déployé en A/B avec rollback par bootcount. »
- *Point CRA* : si `cve-check` échoue ou renvoie peu de résultats sur dunfell (accès NVD ancien), c'est précisément le sujet : **une branche sans support = pas de suivi CVE fiable** → plan de migration (kirkstone/scarthgap) à proposer.
- *Limites à assumer* : cible ARM32 émulée (pas i.MX8MQ), pas de HAB réel, pas de meta-freescale/Nitrogen8M ; le comportement fusibles/closed n'est couvert que par le modèle L1.

## Planning conseillé (version light, VM + Yocto en tâche de fond)
- **Aujourd'hui** : installation VM → `vm-first-boot.sh` → **lancer le build Yocto (Y0/Y1)** → pendant qu'il tourne : L1, L1b, L2, L3 (≈ 3 h, la compilation de L2 sera plus lente).
- **Ce soir** : L6 (1 h). Le build tourne seul.
- **Demain matin** : Y2, Y3 (1 h 15), L5 si temps. Si le build a échoué : règle d'arrêt ci-dessus.
- **Demain après-midi** : profil (STAR) + entretiens blancs. Priorité si le temps manque : **L1 + L2 + L6**, puis Y2.
