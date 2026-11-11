#!/usr/bin/env bash
# Scenario complet (~1 min) : a rejouer et commenter a voix haute pour l'entretien.
set -e
rm -rf work
echo "### 1. Device vierge OUVERT : image non signee/inconnue demarre quand meme"
python3 hab_mini.py keygen; python3 hab_mini.py build; python3 hab_mini.py status; python3 hab_mini.py boot || true
echo; echo "### 2. On grave SRK_HASH (OTP) : image signee OK"
python3 hab_mini.py fuse; python3 hab_mini.py boot
echo; echo "### 3. Image falsifiee, device encore OUVERT : evenement HAB mais boot"
python3 hab_mini.py tamper; python3 hab_mini.py boot work/flash.tampered
echo; echo "### 4. On FERME le device : l'image falsifiee est refusee"
python3 hab_mini.py close; python3 hab_mini.py boot work/flash.tampered || echo "(code retour $? : refus attendu)"
echo; echo "### 5. Image signee par une AUTRE cle racine (attaquant) : refusee"
cp -r work work_ok; python3 hab_mini.py keygen >/dev/null; python3 hab_mini.py build --out work/evil.signed
cp work_ok/fuses.json work/fuses.json; python3 hab_mini.py boot work/evil.signed || echo "(refus attendu)"
echo; echo "### 6. Re-graver une autre SRK_HASH : impossible (OTP)"
python3 hab_mini.py fuse || echo "(refus attendu)"
rm -rf work_ok
