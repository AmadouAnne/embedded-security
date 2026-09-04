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
| `NVD (NIST)` | Recherche manuelle des CVE publiées, croisées avec les fonctions/fichiers modifiés — pas d'appel API automatisé dans ce projet |

---

## 3. Structure du Projet

```
patch-diffing/
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
6. **Corrélation CVE** — Recherche manuelle sur NVD, croisée avec les fonctions/fichiers effectivement modifiés

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
| CVE-2023-0464 | 7.5 | DoS OpenSSL X.509 | ❌ Non corrélé (voir ci-dessous) |
| CVE-2023-0465 | 5.3 | OpenSSL cert policies | ❌ Non corrélé (voir ci-dessous) |

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

### CVE-2023-0464 / CVE-2023-0465 — Non corrélé ❌

Une fois le bug d'export Ghidra corrigé (§7) et le diff fonctionnel réellement produit, `libuclient.so` ne montre qu'une seule fonction modifiée : `uclient_disconnect` (voir §7). Son diff décompilé ne touche à aucune logique X.509/policy — ce n'est donc **pas** le patch CVE-2023-0464/0465. Le SHA-256 différent de `libc.so` reste une piste distincte (uClibc/musl embarque sa propre copie d'OpenSSL ou de code lié) mais n'a pas été analysée au niveau fonction dans ce projet — statut honnête : non corrélé, pas juste "en cours" indéfiniment.

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

### Bug corrigé — Export Ghidra ✅

Les deux exports JSON étaient identiques car le script GUI (`GhidraFunctionHasher.py`) avait été exécuté deux fois sur le même programme Ghidra ouvert, au lieu de deux imports séparés — un piège classique du workflow manuel `File > New Project`.

**Fix :** `scripts/run_hasher_headless.py`, un script Python 3 autonome (via [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra)) qui importe, analyse et exporte chaque binaire dans un projet Ghidra jetable dédié, sans étape manuelle où l'erreur peut se reproduire :

```bash
pip install pyghidra
export GHIDRA_INSTALL_DIR=/path/to/ghidra   # ou laissez PyGhidra le détecter
python3 scripts/run_hasher_headless.py extracted/v33_rootfs/usr/lib/libuclient.so analysis/libuclient_v33.json
python3 scripts/run_hasher_headless.py extracted/v35_rootfs/usr/lib/libuclient.so analysis/libuclient_v35.json
sha256sum analysis/libuclient_v33.json analysis/libuclient_v35.json   # doivent différer
```

**Résultat réel** (`python3 scripts/DiffEngine.py`), une seule fonction modifiée sur 81 :

```
[!] 1 FONCTION(S) MODIFIÉE(S) TROUVÉE(S) :
--> uclient_disconnect
    [v33] Taille: 52 bytes | Hash: 30c776cab131...
    [v35] Taille: 68 bytes | Hash: a1d5df02a1dc...
```

Décompilation comparée (Ghidra) :

```c
// v33
void uclient_disconnect(int *param_1) {
    uloop_timeout_cancel(param_1 + 0x1a);
    if (param_1[0x1c/4] != 0) { (*(code*)param_1[0x1c/4])(param_1); }
}

// v35 -- annule un DEUXIÈME timer avant le disconnect callback
void uclient_disconnect(int *param_1) {
    uloop_timeout_cancel(param_1 + 0x1a);
    uloop_timeout_cancel(param_1 + 0x22);   // <-- ajouté
    if (param_1[0x1c/4] != 0) { (*(code*)param_1[0x1c/4])(param_1); }
}
```

v35 annule un second timer `uloop` (un champ distinct de la struct de contexte uclient) qui n'était pas nettoyé en v33 — cohérent avec la correction d'un timer pendant/use-after-free : si le contexte est libéré après `uclient_disconnect()` sans que ce timer soit annulé, la boucle d'événements `uloop` peut déclencher plus tard son callback sur de la mémoire déjà libérée. Le diff binaire brut (`libuclient_diff.txt`, 505 octets modifiés, tous de la forme `valeur → valeur+0x10`) corrobore indépendamment ce décalage de +16 octets sur tout le reste du binaire, sans qu'aucun octet ne remette en cause cette lecture.

Ce n'est **pas** un correctif X.509/OpenSSL (voir §6) — c'est une correction de fuite/UAF spécifique à `libuclient`, non répertoriée dans les CVE ciblées par ce projet mais bien réelle.

---

## 8. Utilisation des Scripts

### run_hasher_headless.py (recommandé)

```bash
pip install pyghidra
python3 scripts/run_hasher_headless.py <binaire> <sortie.json> [dossier_projet_ghidra]
```

Automatise l'import + l'analyse + l'export pour un binaire en un seul processus non-interactif — voir §7 pour le contexte (corrige le bug d'export dupliqué).

### GhidraFunctionHasher.py (legacy, GUI)

À exécuter depuis `Window > Script Manager` dans Ghidra — nécessite un import Ghidra séparé par binaire (voir le piège documenté en §7) :
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
