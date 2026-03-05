# Firmware Patch Diffing & 1-day Research

## 1. Présentation du Projet

Ce projet consiste en une analyse de sécurité comparative (Patch Diffing) sur le firmware **OpenWRT**. L'objectif est d'automatiser l'identification de correctifs de sécurité entre deux versions mineures afin de comprendre les vulnérabilités sous-jacentes.

- **Cible principale :** `libuclient.so` (Client HTTP/HTTPS d'OpenWRT, lié OpenSSL).
- **Cible secondaire :** `sshkeys.js` (Interface LuCI — CVE confirmé).
- **Architecture :** MIPS32 Little Endian (ramips/mt7621).

> **Note :** `uhttpd` a été écarté après vérification SHA-256 — hash identique entre v33 et v35, non affecté par ce patch.

---

## 2. Environnement de Recherche

### Matériel et Versions

| Version | État | Date de sortie | Fichier Binaire |
| :--- | :--- | :--- | :--- |
| **v22.03.3** | Vulnérable (Cible) | 04 Janv. 2023 | `openwrt-22.03.3.bin` |
| **v22.03.5** | Patchée (Référence) | 28 Avr. 2023 | `openwrt-22.03.5.bin` |

### Outillage (Stack Technique)

| Outil | Rôle |
| :--- | :--- |
| `Binwalk` | Extraction et analyse des couches firmware |
| `Ghidra 11.x` | Désassemblage statique ELF MIPS |
| `GhidraFunctionHasher.py` | Export JSON des fonctions + hashing opcodes |
| `DiffEngine.py` | Comparaison multi-critères (hash + taille) |
| `diff_engine.py` | Similarité Jaccard sur ensembles d'opcodes |
| `NVD API (NIST)` | Corrélation CVE automatisée |

---

## 3. Structure du Projet

```
projet3-patch-diffing/
├── firmwares/              # Images .bin OpenWRT
├── extracted/
│   ├── v33_rootfs/         # SquashFS extrait v22.03.3
│   └── v35_rootfs/         # SquashFS extrait v22.03.5
├── analysis/
│   ├── libuclient/         # JSONs Ghidra libuclient.so
│   ├── wpad/               # JSONs Ghidra wpad
│   ├── libc/               # JSONs Ghidra libc.so
│   └── busybox/            # JSONs Ghidra busybox
├── scripts/
│   ├── GhidraFunctionHasher.py   # Script Ghidra (Jython)
│   ├── DiffEngine.py             # Moteur de diff principal
│   └── diff_engine.py            # Variante Jaccard
├── reports/                # Rapports générés
└── README.md
```

---

## 4. Méthodologie d'Analyse

Le pipeline suit les étapes suivantes :

1. **Extraction du RootFS** — Décompression des images SquashFS via Binwalk
2. **Identification des binaires modifiés** — Diff SHA-256 sur l'ensemble des fichiers
3. **Import Ghidra** — Format ELF, langage `MIPS:LE:32:default:default`
4. **Fingerprinting** — Export JSON des fonctions via `GhidraFunctionHasher.py` (hash SHA-256 des mnémoniques)
5. **Diff Engine** — Comparaison hash opcodes + taille + similarité Jaccard
6. **Corrélation CVE** — Liaison fonctions modifiées ↔ NVD API

---

## 5. Empreintes SHA-256

### Firmwares

| Version | SHA-256 |
| :--- | :--- |
| v22.03.3 | `bc0823dd...329a72966` |
| v22.03.5 | `eccde131...bed264207` |

### Binaires ELF analysés

| Binaire | v22.03.3 | v22.03.5 | Modifié |
| :--- | :--- | :--- | :--- |
| `/usr/lib/libuclient.so` | `26e11c0a...acaa76f3` | `3d86e323...fde03ad8` | ✅ Oui |
| `/usr/sbin/wpad` | — | — | ✅ Oui |
| `/lib/libc.so` | — | — | ✅ Oui |
| `/usr/lib/liblucihttp.so.0.1` | — | — | ✅ Oui |
| `/bin/busybox` | — | — | ✅ Oui |
| `/usr/sbin/uhttpd` | identique | identique | ❌ Non |
| `/usr/sbin/dnsmasq` | identique | identique | ❌ Non |
| `/usr/lib/libwolfssl.so` | `b3297dad...ecda6b3` | `b3297dad...ecda6b3` | ❌ Non |

### Offsets SquashFS

| Version | Offset décimal | Offset hex |
| :--- | :--- | :--- |
| v22.03.3 | `2713605` | `0x296805` |
| v22.03.5 | `2722263` | `0x2989D7` |

---

## 6. Résultats & CVE

### CVE analysés

| CVE | CVSS | Type | Statut |
| :--- | :--- | :--- | :--- |
| CVE-2023-24182 | 5.4 | Stored XSS (LuCI) | ✅ **Confirmé** |
| CVE-2023-24181 | 5.4 | Reflected XSS (OpenVPN) | ⚠️ Non applicable |
| CVE-2023-0464 | 7.5 | DoS OpenSSL X.509 | 🔄 En cours |
| CVE-2023-0465 | 5.3 | OpenSSL cert policies | 🔄 En cours |

### CVE-2023-24182 — CONFIRMÉ ✅

**Fichier :** `/www/luci-static/resources/view/system/sshkeys.js`, ligne 30

```diff
# v22.03.3 (vulnérable)
- E('pre', delkey)

# v22.03.5 (patché)
+ E('pre', [delkey])
```

**Impact :** Une clé SSH contenant du HTML/JavaScript était passée directement au DOM LuCI sans échappement → XSS stocké. Le patch enveloppe la valeur dans un tableau, forçant LuCI à la traiter comme texte brut.

**Vecteur d'attaque :**
```
ssh-rsa AAAA... <img src=x onerror=alert(document.cookie)>
```

### CVE-2023-24181 — Non applicable ⚠️

Le fichier `pageswitch.htm` (module OpenVPN) est absent de ce firmware — le module OpenVPN n'est pas installé sur le TP-Link WDR4300 v1.

### CVE-2023-0464 / CVE-2023-0465 — En cours 🔄

Les SHA-256 de `libuclient.so` et `libc.so` diffèrent entre v33 et v35, ce qui constitue une présomption forte de patch OpenSSL. La corrélation au niveau fonction (X.509 policy check) est en attente de la correction de la procédure d'export Ghidra.

---

## 7. Analyse Ghidra — libuclient.so

### Statistiques d'extraction

| Métrique | v33 | v35 |
| :--- | :--- | :--- |
| Fonctions extraites | 81 | 81 |
| Fonctions avec opcodes | 78 | 78 |
| Fonctions stub (PLT) | 3 | 3 |
| Taille min (bytes) | 1 | 1 |
| Taille max (bytes) | 422 | 422 |

### Bug identifié — Export Ghidra

> ⚠️ Les deux exports JSON actuels (`libuclient_v33.json` / `libuclient_v35.json`) sont identiques car le script a été exécuté deux fois sur le même programme Ghidra au lieu de deux imports séparés.

**Correction à appliquer :**
```
1. File > New Project  →  importer libuclient_v33.so  →  analyser  →  exporter JSON
2. File > New Project  →  importer libuclient_v35.so  →  analyser  →  exporter JSON
3. Vérifier : sha256sum des deux JSON doivent être différents
```

---

## 8. Utilisation des Scripts

### GhidraFunctionHasher.py

À exécuter depuis `Window > Script Manager` dans Ghidra :
```
# Produit : <binary_name>_analysis.json dans ~/
```

### DiffEngine.py

```bash
# Modifier les chemins V33_PATH / V35_PATH dans le script, puis :
python3 scripts/DiffEngine.py
```

### diff_engine.py (variante Jaccard)

```bash
python3 scripts/diff_engine.py
# Seuil de similarité configurable : threshold=0.8
```

---

## 9. Références

- [NIST NVD](https://nvd.nist.gov)
- [OpenWRT Project](https://openwrt.org)
- [Ghidra NSA](https://ghidra-sre.org)
- [Binwalk](https://github.com/ReFirmLabs/binwalk)
- A. T. Anne, *Analyse de la pertinence des métriques système natives pour la détection d'anomalies sous Linux en environnements contraints*, HAL Open Science, 2026. [hal-05486729](https://hal.science/hal-05486729v1)
