#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
demo_chain.py - Chaîne de confiance embarquée, de la BootROM à la mise à jour OTA, puis CRA.

MODÈLE PÉDAGOGIQUE : pas de vraie ROM, pas de vrais fusibles.
  - Les signatures sont réelles (RSA-2048, SHA-256, module `cryptography`).
  - dm-verity suit le principe réel (arbre de Merkle, sel, root hash), à échelle réduite (1 Mio).
  - Les étapes HAB / FIT / Mender reprennent la logique du projet i.MX8MQ (Nitrogen8M).

Usage :
  python demo_chain.py                 # tout rejouer (11 scénarios, ~10 s)
  python demo_chain.py --pause         # attendre Entrée entre scénarios (pour presenter)
  python demo_chain.py --only 2,5,9    # certains scénarios
  python demo_chain.py --list          # lister les scénarios
  python demo_chain.py --sbom ~/lab/yocto/sbom.cdx.json --affect openssl   # CRA sur le vrai SBOM
Installation : pip install cryptography
"""
import argparse
import copy
import datetime as dt
import hashlib
import json
import os
import sys

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:
    sys.exit("Module manquant. Installer avec : pip install cryptography")

BS = 4096            # taille d'un bloc dm-verity
FAN = BS // 32       # hashes SHA-256 par bloc de hash (128)
NBLOCKS = 256        # rootfs de demonstration : 1 Mio

# --------------------------------------------------------------------------- affichage
if os.name == "nt":
    os.system("chcp 65001 >nul")   # console en UTF-8 (accents)
    os.system("")                  # active les codes ANSI sur Windows 10+
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass
USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def col(code, s):
    return f"\033[{code}m{s}\033[0m" if USE_COLOR else s


def title(n, text):
    print("\n" + col("1;36", f"=== Scénario {n} : {text} ") + col("36", "=" * max(2, 62 - len(text))))


def step(msg):
    print(col("90", "  ..    ") + msg)


def ok(msg):
    print(col("1;32", "  [ OK ] ") + msg)


def ko(msg):
    print(col("1;31", "  [REFUSÉ] ") + msg)


def warn(msg):
    print(col("1;33", "  [ALERTE] ") + msg)


def note(msg):
    print(col("2", "           " + msg))


# --------------------------------------------------------------------------- crypto
def sha(b):
    return hashlib.sha256(b).digest()


def pub_der(pub):
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_pub(der):
    return serialization.load_der_public_key(der)


def sign(priv, data):
    return priv.sign(data, padding.PKCS1v15(), hashes.SHA256())


def verify(pub, sig, data):
    try:
        pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


class Pki:
    """Clés du projet (en vrai : hors ligne, HSM) et clés d'un attaquant."""

    def __init__(self, bits=2048):
        gen = lambda: rsa.generate_private_key(65537, bits)
        self.srk = [gen() for _ in range(4)]      # table SRK : 4 clés, hash gravé dans les eFuses
        self.img = gen()                           # clé de signature des images (certifiée par une SRK)
        self.fit = gen()                           # clé de signature des configurations FIT
        self.art = gen()                           # clé de signature des artefacts Mender
        self.evil = gen()                          # clé de l'attaquant
        self.evil_img = gen()


def filler(tag, size):
    out, i = bytearray(), 0
    while len(out) < size:
        out += sha(f"{tag}:{i}".encode())
        i += 1
    return bytes(out[:size])


# --------------------------------------------------------------------------- 1. HAB (BootROM)
class Fuses:
    """Modele des eFuses : OTP, on ne grave qu'une fois."""

    def __init__(self):
        self.SRK_HASH = None
        self.SEC_CONFIG = 0
        self.SRK_REVOKE = 0

    def burn_srk(self, h):
        if self.SRK_HASH is not None:
            raise RuntimeError("eFuse déjà gravée : OTP, impossible de réécrire")
        self.SRK_HASH = h

    def close(self):
        self.SEC_CONFIG = 1

    @property
    def closed(self):
        return self.SEC_CONFIG == 1


class SignedImage:
    def __init__(self, name, data, srk_table, srk_index, img_cert, cert_sig, sig):
        self.name, self.data = name, data
        self.srk_table, self.srk_index = srk_table, srk_index
        self.img_cert, self.cert_sig, self.sig = img_cert, cert_sig, sig


def srk_table_hash(table):
    return sha(b"".join(len(k).to_bytes(2, "big") + k for k in table))


def sign_image(srk_keys, img_key, name, data, srk_index=0):
    """Équivalent d'un CSF : table SRK + certificat de la clé IMG signé par une SRK + signature de l'image."""
    table = [pub_der(k.public_key()) for k in srk_keys]
    cert = pub_der(img_key.public_key())
    return SignedImage(name, data, table, srk_index, cert, sign(srk_keys[srk_index], cert), sign(img_key, data))


def hab_events(img, fuses):
    """Retourne la liste des événements HAB (vide = image authentique)."""
    ev = []
    if fuses.SRK_HASH is None:
        ev.append("SRK_HASH non gravé dans les eFuses")
    elif srk_table_hash(img.srk_table) != fuses.SRK_HASH:
        ev.append("SHA-256(table SRK de l'image) != SRK_HASH des eFuses")
    if (fuses.SRK_REVOKE >> img.srk_index) & 1:
        ev.append(f"SRK[{img.srk_index}] révoquée (SRK_REVOKE)")
    if not verify(load_pub(img.srk_table[img.srk_index]), img.cert_sig, img.img_cert):
        ev.append("certificat IMG non signé par la SRK choisie")
    if not verify(load_pub(img.img_cert), img.sig, img.data):
        ev.append("signature de l'image invalide (CSF)")
    return ev


def hab_authenticate(stage, img, fuses):
    ev = hab_events(img, fuses)
    if not ev:
        ok(f"{stage} : {img.name} authentifié (hash SRK = eFuses, signature valide)")
        return True
    for e in ev:
        warn(f"HAB event : {e}")
    if fuses.closed:
        ko(f"{stage} : carte CLOSED, {img.name} refusé, la ROM ne passe pas la main")
        return False
    warn(f"{stage} : carte OPEN, événement journalisé mais le démarrage continue (mode test)")
    return True


# --------------------------------------------------------------------------- 2. FIT signe (U-Boot)
class Fit:
    def __init__(self, name, images, hashes_, bootargs, conf_sig=None):
        self.name, self.images, self.hashes = name, images, hashes_
        self.bootargs, self.conf_sig = bootargs, conf_sig


def conf_blob(f):
    return json.dumps({"conf": f.name, "hashes": f.hashes, "bootargs": f.bootargs}, sort_keys=True).encode()


def build_fit(pki, name, kernel, fdt, roothash_hex, signed=True, key=None):
    f = Fit(name, {"kernel": kernel, "fdt": fdt},
            {"kernel": sha(kernel).hex(), "fdt": sha(fdt).hex()},
            f"root=/dev/dm-0 roothash={roothash_hex}")
    if signed:
        f.conf_sig = sign(key or pki.fit, conf_blob(f))
    return f


def fit_hash_check(f):
    """Contrôle NAÏF : chaque image contre son hash (ne suffit pas)."""
    for n, data in f.images.items():
        if sha(data).hex() != f.hashes[n]:
            return False, f"hash de l'image '{n}' incorrect"
    return True, "hash de chaque image conforme"


def fit_sig_check(f, pub, required):
    """Signature de CONFIGURATION : lie noyau + DTB + bootargs (donc le root hash verity)."""
    if f.conf_sig is None:
        if required:
            return False, "configuration non signée alors que la clé est 'required'"
        return True, "FIT non signé accepté (clé non 'required') : DANGEREUX"
    if not verify(pub, f.conf_sig, conf_blob(f)):
        return False, "signature de configuration invalide"
    return True, "signature de configuration valide"


# --------------------------------------------------------------------------- 3. dm-verity
def build_tree(data, salt):
    blocks = [data[i:i + BS] for i in range(0, len(data), BS)]
    cur = [sha(salt + b) for b in blocks]
    levels = []
    while True:
        hb = [b"".join(cur[k:k + FAN]).ljust(BS, b"\0") for k in range(0, len(cur), FAN)]
        levels.append(hb)
        if len(hb) == 1:
            break
        cur = [sha(salt + b) for b in hb]
    return levels, sha(salt + levels[-1][0])


def verity_read(data, levels, salt, trusted_root, i):
    h, idx = sha(salt + bytes(data[i * BS:(i + 1) * BS])), i
    for lvl, hb in enumerate(levels):
        blk = hb[idx // FAN]
        if h != blk[(idx % FAN) * 32:(idx % FAN) * 32 + 32]:
            raise IOError(f"bloc {i} : hash incorrect au niveau {lvl} de l'arbre")
        h, idx = sha(salt + blk), idx // FAN
    if h != trusted_root:
        raise IOError(f"bloc {i} : l'arbre ne remonte pas au root hash signe (arbre recalcule ?)")


def verity_scan(data, levels, salt, trusted_root):
    for i in range(len(data) // BS):
        verity_read(data, levels, salt, trusted_root, i)


# --------------------------------------------------------------------------- 4. Slot, appareil, Mender
class Slot:
    def __init__(self, version, fit, rootfs, levels, salt):
        self.version, self.fit, self.rootfs, self.levels, self.salt = version, fit, rootfs, levels, salt


def vtuple(v):
    return tuple(int(x) for x in v.split("."))


def build_slot(pki, version, faulty=False, product="A", fit_key=None):
    head = f"ROOTFS version={version}\nSERVICE={'CRASH' if faulty else 'OK'}\n".encode()
    rootfs = bytearray((head + filler("rootfs" + version, NBLOCKS * BS))[:NBLOCKS * BS])
    salt = sha(("sel" + version).encode())[:16]
    levels, root = build_tree(bytes(rootfs), salt)
    kernel = f"KERNEL {version} product={product}\n".encode() + filler("k" + version + product, 64 * 1024)
    fdt = f"DTB board=nitrogen8m product={product}\n".encode() + filler("d" + product, 8 * 1024)
    return Slot(version, build_fit(pki, f"conf-{version}", kernel, fdt, root.hex(), key=fit_key), rootfs, levels, salt)


def uboot_blob(fit_pub, required=True):
    return b"U-BOOT 2020.01\n" + json.dumps({"fit_pub": fit_pub.hex(), "required": required}).encode()


class Device:
    def __init__(self, pki, closed=True):
        self.pki = pki
        self.fuses = Fuses()
        self.spl = sign_image(pki.srk, pki.img, "SPL (CSF n1)", b"SPL v1 : init DDR, charge U-Boot")
        self.uboot = sign_image(pki.srk, pki.img, "u-boot.itb (CSF n2)", uboot_blob(pub_der(pki.fit.public_key())))
        self.slots = {"A": build_slot(pki, "1.0"), "B": None}
        self.env = {"mender_boot_part": "A", "upgrade_available": 0, "bootcount": 0, "bootlimit": 1}
        self.art_pub = pki.art.public_key()
        self.min_version = (1, 0)
        self.fuses.burn_srk(srk_table_hash(self.spl.srk_table))
        if closed:
            self.fuses.close()

    def boot(self):
        """Retourne 'OK', 'REFUSED' ou 'CRASH'."""
        if not hab_authenticate("BootROM -> SPL     ", self.spl, self.fuses):
            return "REFUSED"
        if not hab_authenticate("SPL     -> U-Boot  ", self.uboot, self.fuses):
            return "REFUSED"
        cfg = json.loads(self.uboot.data.partition(b"\n")[2])
        fit_pub, required = load_pub(bytes.fromhex(cfg["fit_pub"])), cfg["required"]
        e = self.env
        if e["upgrade_available"]:
            e["bootcount"] += 1
            step(f"U-Boot : mise à jour en essai, bootcount={e['bootcount']} (limite {e['bootlimit']})")
            if e["bootcount"] > e["bootlimit"]:
                back = "A" if e["mender_boot_part"] == "B" else "B"
                warn(f"U-Boot : limite dépassée, ROLLBACK vers la partition {back}")
                e.update(mender_boot_part=back, upgrade_available=0, bootcount=0)
        part = e["mender_boot_part"]
        slot = self.slots[part]
        step(f"U-Boot : partition active {part} (version {slot.version})")
        okh, msg = fit_hash_check(slot.fit)
        oks, msgs = fit_sig_check(slot.fit, fit_pub, required)
        if not oks:
            ko(f"U-Boot -> FIT : {msgs}")
            return "REFUSED"
        ok(f"U-Boot -> FIT : {msgs}")
        if not okh:
            ko(f"U-Boot -> FIT : {msg}")
            return "REFUSED"
        ok(f"U-Boot -> FIT : {msg}")
        roothash = bytes.fromhex(slot.fit.bootargs.split("roothash=")[1])
        try:
            verity_scan(slot.rootfs, slot.levels, slot.salt, roothash)
        except IOError as err:
            ko(f"noyau -> dm-verity : {err}")
            return "REFUSED"
        ok(f"noyau -> dm-verity : {NBLOCKS} blocs lus et vérifiés jusqu'au root hash {roothash.hex()[:16]}...")
        if b"SERVICE=CRASH" in bytes(slot.rootfs[:200]):
            warn("userland : le service applicatif plante, la mise à jour n'est pas validée")
            return "CRASH"
        if e["upgrade_available"]:
            e.update(upgrade_available=0, bootcount=0)
            ok(f"mender-client : COMMIT, la partition {part} devient la référence")
        ok(f"système démarré : version {slot.version} sur la partition {part}")
        return "OK"

    def install(self, art):
        """Retourne True si l'artefact est accepté et écrit sur la partition inactive."""
        if not verify(self.art_pub, art.sig, art.manifest):
            ko("mender-client : signature de l'artefact invalide (clé publique de l'appareil)")
            return False
        ok("mender-client : signature de l'artefact valide")
        if json.loads(art.manifest)["payload_sha256"] != payload_hash(art.slot):
            ko("mender-client : charge utile modifiée (hash différent du manifeste signé)")
            return False
        ok("mender-client : charge utile conforme au manifeste signé")
        if vtuple(art.slot.version) < self.min_version:
            ko(f"anti-rollback : version {art.slot.version} < version minimale {'.'.join(map(str, self.min_version))}")
            return False
        inactive = "B" if self.env["mender_boot_part"] == "A" else "A"
        self.slots[inactive] = copy.deepcopy(art.slot)
        self.env.update(mender_boot_part=inactive, upgrade_available=1, bootcount=0)
        ok(f"écrit sur la partition inactive {inactive} ; U-Boot : upgrade_available=1, bootcount=0 ; reboot")
        return True


class Artifact:
    def __init__(self, slot, manifest, sig):
        self.slot, self.manifest, self.sig = slot, manifest, sig


def payload_hash(slot):
    f = slot.fit
    return sha(bytes(slot.rootfs) + f.images["kernel"] + f.images["fdt"] + conf_blob(f) + (f.conf_sig or b"")).hex()


def make_artifact(slot, signer):
    manifest = json.dumps({"name": f"release-{slot.version}", "version": slot.version,
                           "payload_sha256": payload_hash(slot)}, sort_keys=True).encode()
    return Artifact(slot, manifest, sign(signer, manifest))


# --------------------------------------------------------------------------- scénarios
def s1(pki, a):
    title(1, "Démarrage nominal d'une carte CLOSED")
    d = Device(pki)
    step(f"usine : SRK_HASH gravé = {d.fuses.SRK_HASH.hex()[:24]}... ; SEC_CONFIG = {d.fuses.SEC_CONFIG} (closed)")
    return d.boot() == "OK"


def s2(pki, a):
    title(2, "Attaque : U-Boot remplacé par celui de l'attaquant. Carte CLOSED puis OPEN")
    res = []
    for closed in (True, False):
        d = Device(pki, closed=closed)
        d.uboot.data = uboot_blob(pub_der(pki.evil.public_key()), required=False)
        d.slots["A"] = build_slot(pki, "6.6.6", fit_key=pki.evil)      # système de l'attaquant, signé avec SA clé
        print(col("1", f"  -- carte {'CLOSED' if closed else 'OPEN'}"))
        r = d.boot()
        if r == "OK":
            warn("carte OPEN : le système de l'attaquant a démarré, rien ne l'a bloqué")
        res.append(r == ("REFUSED" if closed else "OK"))
    note("En production la carte est closed : l'attaque s'arrête à la BootROM. En open, rien ne la bloque.")
    return all(res)


def s3(pki, a):
    title(3, "Attaque : chaîne entièrement signée par l'attaquant (table SRK remplacée)")
    d = Device(pki)
    d.uboot = sign_image([pki.evil], pki.evil_img, "u-boot.itb (attaquant)", uboot_blob(pub_der(pki.evil.public_key()), False))
    note("signatures internes cohérentes, mais la table SRK n'est pas celle dont le hash est dans les eFuses")
    return d.boot() == "REFUSED"


def s4(pki, a):
    title(4, "Attaque : noyau modifié dans le FIT")
    d = Device(pki)
    k = bytearray(d.slots["A"].fit.images["kernel"])
    k[1000] ^= 0x01
    d.slots["A"].fit.images["kernel"] = bytes(k)
    note("un seul bit changé dans le noyau")
    return d.boot() == "REFUSED"


def s5(pki, a):
    title(5, "Attaque 'mix and match' : noyau légitime + DTB légitime d'un autre produit")
    d = Device(pki)
    other = build_slot(pki, "1.0", product="B")             # autre produit, lui aussi signé par la même clé
    f = copy.deepcopy(d.slots["A"].fit)
    f.images["fdt"], f.hashes["fdt"] = other.fit.images["fdt"], other.fit.hashes["fdt"]
    naive_ok, _ = fit_hash_check(f)
    (warn if naive_ok else ko)("contrôle naïf (hash de chaque image) : " + ("PASSE, l'attaque réussirait" if naive_ok else "refuse"))
    d.slots["A"].fit = f
    r = d.boot()
    note("chaque image est valide seule ; c'est la signature de CONFIGURATION qui interdit la combinaison")
    return naive_ok and r == "REFUSED"


def s6(pki, a):
    title(6, "Attaque : rootfs modifié. Puis l'attaquant recalcule l'arbre dm-verity")
    res = []
    d = Device(pki)
    s = d.slots["A"]
    s.rootfs[137 * BS + 10] ^= 0x01
    step("un bit modifié dans le bloc 137 du rootfs")
    res.append(d.boot() == "REFUSED")
    d = Device(pki)
    s = d.slots["A"]
    s.rootfs[137 * BS + 10] ^= 0x01
    s.levels, _ = build_tree(bytes(s.rootfs), s.salt)
    step("l'attaquant recalcule tout l'arbre : l'arbre est cohérent avec ses données")
    res.append(d.boot() == "REFUSED")
    note("le root hash est dans la configuration FIT signée : l'attaquant ne peut pas le changer")
    return all(res)


def s7(pki, a):
    title(7, "Mise à jour Mender valide : 1.0 → 2.0 sur la partition B, puis commit")
    d = Device(pki)
    art = make_artifact(build_slot(pki, "2.0"), pki.art)
    if not d.install(art):
        return False
    r = d.boot()
    return r == "OK" and d.env["mender_boot_part"] == "B" and d.env["upgrade_available"] == 0


def s8(pki, a):
    title(8, "Artefact falsifié : charge utile modifiée, puis re-signé par l'attaquant")
    d = Device(pki)
    art = make_artifact(build_slot(pki, "2.0"), pki.art)
    art.slot.rootfs[5000] ^= 0x01
    print(col("1", "  -- (a) charge utile modifiée, manifeste d'origine"))
    ra = d.install(art)
    art2 = make_artifact(art.slot, pki.evil)
    print(col("1", "  -- (b) l'attaquant re-signe le manifeste avec sa clé"))
    rb = d.install(art2)
    ok_state = d.env["mender_boot_part"] == "A" and d.env["upgrade_available"] == 0
    step(f"état de l'appareil inchangé : partition {d.env['mender_boot_part']}, version {d.slots['A'].version}")
    return (not ra) and (not rb) and ok_state


def s9(pki, a):
    title(9, "Image signée mais défaillante : rollback automatique")
    d = Device(pki)
    art = make_artifact(build_slot(pki, "2.1", faulty=True), pki.art)
    if not d.install(art):
        return False
    print(col("1", "  -- démarrage 1 (partition B)"))
    r1 = d.boot()
    print(col("1", "  -- démarrage 2 (reboot après échec)"))
    r2 = d.boot()
    return r1 == "CRASH" and r2 == "OK" and d.env["mender_boot_part"] == "A"


def s10(pki, a):
    title(10, "Rejeu d'une ancienne version signée (anti-rollback, option de conception)")
    d = Device(pki)
    art = make_artifact(build_slot(pki, "0.9"), pki.art)
    note("la signature est valide : seule une version minimale stockée sur l'appareil bloque le rejeu")
    return not d.install(art)


def s11(pki, a):
    title(11, "CRA : SBOM, CVE et délais de notification")
    if a.sbom:
        try:
            with open(os.path.expanduser(a.sbom), encoding="utf-8") as fh:
                comps = [(c["name"], c.get("version", "?")) for c in json.load(fh).get("components", [])]
        except (OSError, ValueError, KeyError) as err:
            ko(f"SBOM illisible ({err}) : utiliser un fichier CycloneDX JSON (sbom.cdx.json)")
            return False
        step(f"SBOM chargé : {len(comps)} composants ({a.sbom})")
    else:
        comps = [("linux-yocto", "5.4.273"), ("u-boot", "2020.01"), ("openssl", "1.1.1"), ("busybox", "1.31"),
                 ("systemd", "244"), ("glibc", "2.31"), ("mender", "3.x"), ("dropbear", "2020.81")]
        step(f"SBOM d'exemple : {len(comps)} composants (option --sbom pour utiliser celui du build)")
    adv = {"id": "DEMO-2026-0001", "component": a.affect, "exploited": True,
           "note": "avis FICTIF créé pour la démonstration"}
    hit = [c for c in comps if c[0] == adv["component"]]
    step(f"avis {adv['id']} ({adv['note']}) : composant concerné = '{adv['component']}', exploité activement")
    if not hit:
        ok(f"'{adv['component']}' absent du SBOM : produit non concerné (réponse en quelques secondes grâce au SBOM)")
        return True
    warn("produit CONCERNÉ : " + ", ".join(f"{n} {v}" for n, v in hit))
    t0 = dt.datetime.now()
    fmt = lambda t: t.strftime("%d/%m %H:%M")
    print(col("1", "  Horloge CRA (à re-vérifier sur EUR-Lex) :"))
    step(f"T0  prise de connaissance        : {fmt(t0)}")
    step(f"T0 + 24 h  alerte précoce        : avant {fmt(t0 + dt.timedelta(hours=24))}")
    step(f"T0 + 72 h  notification complète : avant {fmt(t0 + dt.timedelta(hours=72))}")
    step("rapport final : environ 14 jours après la disponibilité du correctif")
    ok("correctif : artefact Mender signé (scénario 7), déploiement sans intervention sur site")
    return True


SCENARIOS = [
    (1, "Démarrage nominal", s1, "boot OK"),
    (2, "U-Boot remplacé (closed / open)", s2, "refusé en closed, toléré en open"),
    (3, "Chaîne signée par l'attaquant", s3, "refusé : hash SRK"),
    (4, "Noyau modifié (FIT)", s4, "refusé : hash image"),
    (5, "Mix and match (FIT)", s5, "refusé : signature de configuration"),
    (6, "Rootfs modifié (dm-verity)", s6, "refusé : root hash"),
    (7, "Mise à jour valide (Mender)", s7, "boot B + commit"),
    (8, "Artefact falsifié (Mender)", s8, "refusé avant écriture"),
    (9, "Image défaillante (Mender)", s9, "rollback vers A"),
    (10, "Rejeu ancienne version", s10, "refusé : anti-rollback"),
    (11, "CRA : SBOM + délais", s11, "exposition + horloge 24 h / 72 h"),
]


def main():
    ap = argparse.ArgumentParser(description="Démo : chaîne de confiance embarquée + CRA (modèle pédagogique)")
    ap.add_argument("--only", help="scénarios à jouer, ex. 2,5,9")
    ap.add_argument("--pause", action="store_true", help="attendre Entrée entre scénarios")
    ap.add_argument("--list", action="store_true", help="lister les scénarios")
    ap.add_argument("--sbom", help="SBOM CycloneDX du build (sbom.cdx.json)")
    ap.add_argument("--affect", default="openssl", help="composant visé par l'avis fictif (défaut : openssl)")
    ap.add_argument("--bits", type=int, default=2048, help="taille des clés RSA (défaut 2048)")
    a = ap.parse_args()
    if a.list:
        for n, t, _, exp in SCENARIOS:
            print(f"{n:>2}  {t:<36} attendu : {exp}")
        return 0
    wanted = {int(x) for x in a.only.split(",")} if a.only else {n for n, *_ in SCENARIOS}
    print(col("1", "Démo : chaîne de confiance embarquée (modèle pédagogique, signatures RSA réelles)"))
    step(f"génération des clés RSA-{a.bits} (SRK x4, IMG, FIT, artefact, attaquant)...")
    pki = Pki(a.bits)
    results = []
    for n, t, fn, exp in SCENARIOS:
        if n not in wanted:
            continue
        passed = fn(pki, a)
        results.append((n, t, exp, passed))
        if a.pause and sys.stdin.isatty():
            input(col("2", "\n  [Entrée] scénario suivant... "))
    print("\n" + col("1;36", "=== Bilan " + "=" * 56))
    print(f"  {'#':>2}  {'Scénario':<36} {'Attendu':<36} Résultat")
    for n, t, exp, p in results:
        print(f"  {n:>2}  {t:<36} {exp:<36} " + (col("1;32", "CONFORME") if p else col("1;31", "ÉCART")))
    bad = [n for n, _, _, p in results if not p]
    print("\n  " + (col("1;32", "Tous les scénarios se comportent comme attendu.") if not bad
                   else col("1;31", f"Écarts sur les scénarios : {bad}")))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
