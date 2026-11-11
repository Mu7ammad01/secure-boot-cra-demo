# Fiche CRA — produit : passerelle embarquée i.MX8MQ (Yocto/U-Boot/Mender)
*Références : Règlement (UE) 2024/2847. Les articles/numéros de point sont à re-vérifier sur le texte officiel (EUR-Lex) avant l'entretien.*

## 1. Dates clés
| Date | Quoi |
|------|------|
| 10-11 déc. 2024 | Entrée en vigueur du règlement |
| 11 sept. 2026 | Obligations de notification (vulnérabilités activement exploitées, incidents graves) |
| 11 déc. 2027 | Application complète (exigences essentielles, évaluation de conformité, marquage CE) |

## 2. Qualification du produit (à justifier à l'oral)
Produit avec éléments numériques → catégorie : **défaut / important (classe I ou II) / critique**.
Hypothèse de travail à défendre : *défaut ou important classe I* selon fonction (ex. gestion d'identité/accès, réseau). À valider avec l'Annexe III/IV et la fonction exacte du produit.
Conséquence : **défaut → auto-évaluation** ; **important/critique → parfois tierce partie**.

## 3. Matrice d'écarts (Annexe I partie I — sécurité par conception)
| Exigence (résumé) | Mesure du projet | Preuve / livrable | Écart |
|---|---|---|---|
| Pas de vulnérabilité exploitable connue à la mise sur le marché | cve-check + mise à jour des composants | Rapport CVE signé | dunfell EOL ? |
| Configuration sécurisée par défaut | Image durcie, services minimaux, pas de mot de passe par défaut | Checklist de durcissement | à faire |
| Protection contre l'accès non autorisé | Secure Boot HAB, JTAG fermé, comptes/SSH | Procédure de fermeture | à faire |
| Intégrité du code et des données | HAB → FIT signé → dm-verity | L1–L3 | partiel |
| Mises à jour de sécurité | Mender A/B, artefacts signés, rollback | L4 | à faire |
| Confidentialité des données | Chiffrement des données sensibles/secrets | Choix de stockage | à définir |
| Journalisation / surveillance | Logs de sécurité (échecs de boot, MAJ) | Politique de logs | à définir |
| Effacement sécurisé des données | Procédure de reset usine | Procédure | à définir |

## 4. Annexe I partie II — gestion des vulnérabilités
| Exigence | Mesure | Preuve |
|---|---|---|
| Identifier/documenter les composants (SBOM) | syft/CycloneDX/SPDX | L5 |
| Traiter les vulnérabilités sans délai, tests réguliers | Pipeline CVE + revue | Rapport périodique |
| Divulguer publiquement les vulnérabilités corrigées | Avis de sécurité | Modèle d'avis |
| Politique de divulgation coordonnée | `security.txt` + contact | Fichier publié |
| Distribution sécurisée des mises à jour, correctifs gratuits | Mender signé | L4 |

## 5. Runbook : vulnérabilité activement exploitée (à savoir réciter)
1. **T0** : détection/confirmation → qualifier (produit concerné ? versions ?).
2. **≤ 24 h** : *early warning* (CSIRT désigné / ENISA via plateforme unique).
3. **≤ 72 h** : notification détaillée (nature, mesures d'atténuation prises).
4. **≤ 14 jours après disponibilité du correctif** : rapport final *(délais à re-vérifier)*.
5. En parallèle : correctif signé (Mender), avis public, information des utilisateurs.

## 6. Documentation technique à tenir à jour
Description du produit, évaluation des risques, SBOM, preuves de tests, déclaration UE de conformité, instructions utilisateur.
