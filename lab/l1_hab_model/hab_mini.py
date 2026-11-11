#!/usr/bin/env python3
"""
Mini-labo pedagogique : modele simplifie de la chaine de confiance HAB (i.MX8M).
NE PAS confondre avec le vrai format CST/CSF : on illustre le MECANISME
(table SRK -> hash en eFuses -> signature de l'image -> verification par la ROM,
puis device ouvert vs ferme), pas le format binaire reel.
Usage : python3 hab_mini.py <keygen|build|fuse|close|boot|status|tamper> [options]
"""
import argparse, hashlib, json, struct, sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

W = Path("work"); FUSES = W / "fuses.json"
IVT_TAG, IVT_VER = 0xD1, 0x41          # tag/version d'un IVT HAB (en-tete reel : 0xD1 ... 0x41)

def pub_der(k): return k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
def load_key(p): return serialization.load_pem_private_key(Path(p).read_bytes(), None)

def keygen(_):
    W.mkdir(exist_ok=True)
    srk = []
    for i in range(4):                        # table SRK : 4 cles racine (revocables une par une)
        k = rsa.generate_private_key(65537, 2048)
        (W / f"SRK{i+1}.pem").write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        srk.append(pub_der(k))
    table = b"".join(struct.pack(">H", len(d)) + d for d in srk)
    h = hashlib.sha256(table).digest()         # hash de la table SRK = ce qu'on grave en eFuses
    (W / "srk_table.bin").write_bytes(table)
    (W / "srk_hash.bin").write_bytes(h)
    print("Table SRK : 4 cles RSA-2048 generees dans work/")
    print("SRK_HASH (SHA-256 de la table) =", h.hex())
    print("Mots 32 bits a graver :", " ".join(f"0x{int.from_bytes(h[i:i+4],'big'):08x}" for i in range(0, 32, 4)))

def build(a):
    key = load_key(W / f"SRK{a.srk}.pem")     # (simplification : on signe directement avec la SRK choisie)
    payload = Path(a.payload).read_bytes() if a.payload else b"U-BOOT-FAKE-IMAGE v1\n" * 50
    ivt = struct.pack(">BHBIIIIII", IVT_TAG, 0x20, IVT_VER, 0, 0, 0, 0, 0, 0)  # IVT factice
    body = ivt + payload
    sig = key.sign(body, padding.PKCS1v15(), hashes.SHA256())
    table = (W / "srk_table.bin").read_bytes()
    out = struct.pack(">III", len(body), len(table), len(sig)) + body + table + sig
    Path(a.out).write_bytes(out)
    print(f"Image signee : {a.out} ({len(body)} o utiles, signature SRK{a.srk}, {len(sig)*8} bits)")

def state():
    return json.loads(FUSES.read_text()) if FUSES.exists() else {"SRK_HASH": None, "SEC_CONFIG_CLOSED": False}
def save(s): W.mkdir(exist_ok=True); FUSES.write_text(json.dumps(s, indent=1))

def fuse(_):
    s = state()
    new = (W / "srk_hash.bin").read_bytes().hex()
    if s["SRK_HASH"] and s["SRK_HASH"] != new:    # semantique OTP : un bit a 1 ne repasse jamais a 0
        sys.exit("ERREUR : eFuses SRK_HASH deja gravees avec une autre valeur (OTP, irreversible)")
    s["SRK_HASH"] = new; save(s); print("SRK_HASH gravee (OTP) :", new[:16], "...")

def close(_):
    s = state()
    if not s["SRK_HASH"]: sys.exit("REFUS : ne JAMAIS fermer sans SRK_HASH valide (brique definitive)")
    s["SEC_CONFIG_CLOSED"] = True; save(s); print("Device FERME (SEC_CONFIG) : irreversible")

def status(_):
    s = state(); print("SRK_HASH :", (s["SRK_HASH"] or "non gravee")[:16], "| etat :", "FERME" if s["SEC_CONFIG_CLOSED"] else "OUVERT")

def boot(a):
    s = state(); data = Path(a.image).read_bytes()
    blen, tlen, slen = struct.unpack(">III", data[:12]); body = data[12:12+blen]
    table = data[12+blen:12+blen+tlen]; sig = data[12+blen+tlen:12+blen+tlen+slen]
    problems = []
    if not s["SRK_HASH"]: problems.append("SRK_HASH absente des eFuses")
    elif hashlib.sha256(table).hexdigest() != s["SRK_HASH"]: problems.append("table SRK != hash en eFuses (cle racine inconnue)")
    else:
        # la ROM verifie la signature avec une cle de la table (ici : on essaie chacune non revoquee)
        ok = False; off = 0
        while off < len(table):
            n = struct.unpack(">H", table[off:off+2])[0]; der = table[off+2:off+2+n]; off += 2+n
            try:
                serialization.load_der_public_key(der).verify(sig, body, padding.PKCS1v15(), hashes.SHA256()); ok = True; break
            except Exception: pass
        if not ok: problems.append("signature invalide (image modifiee ?)")
    mode = "FERME" if s["SEC_CONFIG_CLOSED"] else "OUVERT"
    print(f"[ROM] mode {mode}")
    if not problems: print("[ROM] HAB : image authentique -> BOOT OK"); return
    for p in problems: print("[ROM] HAB event :", p)
    if s["SEC_CONFIG_CLOSED"]: print("[ROM] -> BOOT REFUSE (device ferme)"); sys.exit(1)
    print("[ROM] -> boot QUAND MEME (device ouvert : evenements HAB seulement journalises, `hab_status`)")

def tamper(a):
    d = bytearray(Path(a.image).read_bytes()); d[12+40] ^= 0xFF; Path(a.out).write_bytes(d); print("1 octet modifie ->", a.out)

p = argparse.ArgumentParser(); sp = p.add_subparsers(dest="c", required=True)
sp.add_parser("keygen").set_defaults(f=keygen)
b = sp.add_parser("build"); b.add_argument("--out", default="work/flash.signed"); b.add_argument("--srk", type=int, default=1); b.add_argument("--payload"); b.set_defaults(f=build)
sp.add_parser("fuse").set_defaults(f=fuse); sp.add_parser("close").set_defaults(f=close); sp.add_parser("status").set_defaults(f=status)
bo = sp.add_parser("boot"); bo.add_argument("image", nargs="?", default="work/flash.signed"); bo.set_defaults(f=boot)
t = sp.add_parser("tamper"); t.add_argument("image", nargs="?", default="work/flash.signed"); t.add_argument("--out", default="work/flash.tampered"); t.set_defaults(f=tamper)
a = p.parse_args(); a.f(a)
