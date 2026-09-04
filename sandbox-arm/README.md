# Projet 5 — ARM Malware Analysis Sandbox

[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-required-2496ED)](https://docker.com)
[![Flask](https://img.shields.io/badge/Flask-3.x-black)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

Sandbox d'analyse de binaires ARM malveillants sous QEMU isolé.
Analyse statique (entropie), dynamique (syscalls via strace), réseau,
corrélation MITRE ATT&CK, et dashboard web.

## Prérequis

| Outil | Version | Installation |
|-------|---------|-------------|
| Python | 3.10+ | [python.org](https://python.org) |
| Docker | 24+ | [docs.docker.com](https://docs.docker.com/get-docker/) |
| Docker Compose | v2 | inclus avec Docker Desktop |

> **Linux uniquement** — testé sur Arch Linux et Debian Bookworm.

## Installation en 3 commandes

```bash
# 1. Clone le repo
git clone https://github.com/AmadouAnne/embedded-security
cd embedded-security/sandbox-arm

# 2. Installe les dépendances Python
pip install -r requirements.txt

# 3. Lance tout
python3 launch.py
```

Ouvre ensuite : **http://127.0.0.1:5000**

C'est tout. Le script gère Docker automatiquement.

## Structure du projet

```
sandbox-arm/
├── launch.py                  # Orchestrateur principal
├── Dockerfile                 # Image sandbox (Debian + QEMU + strace)
├── docker-compose.yml         # Isolation réseau (network_mode: none)
├── requirements.txt           # Dépendances Python
└── src/
    ├── app.py                 # Dashboard Flask
    ├── templates/
    │   └── index.html         # UI dark theme
    ├── engine/
    │   ├── analyzer.py        # Analyse statique + dynamique
    │   ├── network.py         # Capture syscalls réseau
    │   └── report_gen.py      # Rapport JSON unifié
    ├── samples/               # Binaires ARM à analyser
    │   ├── malware_arm_bin    # Sample de test inclus
    │   └── test_malware.c     # Code source du sample
    └── reports/               # Rapports JSON générés
```

## Commandes disponibles

```bash
# Pipeline complet (build Docker + analyse + dashboard)
python3 launch.py

# Analyser un autre binaire ARM
python3 launch.py --binary src/samples/mon_malware

# Sans Docker (analyse directe sur l'hôte)
python3 launch.py --local

# Rebuild forcé de l'image Docker
python3 launch.py --rebuild

# Analyse uniquement, sans lancer Flask
python3 launch.py --no-server

# Dashboard uniquement (rapports déjà générés)
python3 launch.py --server-only

# Nettoyage complet Docker
python3 launch.py --clean
```

## Architecture

```
launch.py
│
├── [1/5] docker compose build
│         └── Dockerfile : debian:bookworm-slim + qemu-user-static + strace
│
├── [2/5] Vérification du binaire ARM
│         └── file, chmod, taille
│
├── [3/5] docker run --network none
│         └── analyzer.py → QEMU strace → rapport JSON
│
├── [4/5] Résumé des rapports (Risk Score, MITRE, IOC)
│
└── [5/5] Flask → http://127.0.0.1:5000
```

## Ce que le sandbox détecte

| Indicateur | Détection | MITRE |
|------------|-----------|-------|
| Entropie > 7.0 | Binaire packé/chiffré | - |
| Accès `/etc/shadow` | Vol de credentials | T1083 |
| Accès `/etc/passwd` | Reconnaissance | T1083 |
| Connexion réseau | C2 potentiel | T1071 |
| Port 4444/1337/31337 | Metasploit/backdoor | T1071 |
| DNS lookup | C2 via DNS | T1071.004 |
| Timeout QEMU | Binaire en attente C2 | - |

## Compiler le sample de test

```bash
# Requiert arm-linux-gnueabi-gcc
sudo apt install gcc-arm-linux-gnueabi

arm-linux-gnueabi-gcc -static \
    src/samples/test_malware.c \
    -o src/samples/malware_arm_bin
```

## Isolation de sécurité

Le conteneur Docker tourne avec :
- `network_mode: none` — aucun accès réseau, le malware ne peut pas sortir
- Volumes en lecture seule pour les samples
- `--rm` — conteneur supprimé après chaque analyse

## Échantillons réels

`src/samples/` contient des échantillons ARM/MIPS réels (source : MalwareBazaar) sous forme de **zip chiffrés AES uniquement** (mot de passe standard MalwareBazaar : `infected`) — jamais en clair. Des binaires non protégés avaient été committés par erreur dans une révision antérieure ; ils ont été retirés de tout l'historique git (purge + force-push), pas seulement du dernier commit. Si vous voulez analyser un échantillon réel, extrayez-le vous-même dans un environnement isolé avant de le placer dans `samples/` — ne committez jamais le binaire extrait.

## Bugs corrigés

- **`launch.py` → `docker_analyze()` ignorait `--binary`.** Le `Dockerfile` définit `ENTRYPOINT ["python3", "src/engine/analyzer.py"]` ; `docker run IMAGE <args>` **ajoute** `<args>` à cet entrypoint plutôt que de le remplacer. L'ancien code passait `"python3", "src/engine/analyzer.py"` comme `<args>`, donnant l'argv réel `["python3","src/engine/analyzer.py","python3","src/engine/analyzer.py"]` — `analyzer.py` recevait donc toujours `"python3"` comme chemin de binaire, jamais le fichier demandé. Corrigé pour passer uniquement le chemin conteneur du binaire.
- **`NetworkAnalyzer` codait en dur `qemu-arm-static`**, alors que `ARMAnalyzer` détecte correctement l'architecture (ARM/MIPS/PPC/x86_64/ARM64/RISC-V) et choisit le bon `qemu-*-static`. Toute analyse réseau sur un échantillon non-ARM échouait silencieusement (mauvais émulateur = "impossible d'exécuter"). Corrigé pour recevoir le binaire `qemu` détecté par `ARMAnalyzer` (`a.qemu`) au lieu de le redéviner.
- Les listes d'échantillons (`app.py`, `api.py`) incluaient les `.zip` chiffrés comme s'ils étaient directement analysables — exclus désormais, comme les `.c`.
- `docker-compose.yml` : suppression du champ `version` obsolète (ignoré silencieusement par Docker Compose v2, avec avertissement).

Le pipeline statique (détection d'architecture, entropie, sections ELF, génération de rapport JSON) a été testé de bout en bout localement sur un binaire ELF réel non-ARM (`/usr/bin/ls`, x86_64) pour valider la correction ci-dessus sans exécuter de malware. Le chemin Docker complet (build + `qemu-user` + `strace`) nécessite un accès réseau normal à `deb.debian.org` pour `apt-get install` dans le `Dockerfile` — non disponible dans le sandbox d'exécution utilisé pour ce travail, donc non re-testé de bout en bout ici ; à valider avec `python3 launch.py --binary <sample>` sur une machine avec accès Internet standard.

## Références

- [MITRE ATT&CK](https://attack.mitre.org)
- [QEMU User Mode](https://www.qemu.org/docs/master/user/main.html)
- [MalwareBazaar](https://bazaar.abuse.ch) — samples ARM réels
- A. T. Anne, *Analyse de la pertinence des métriques système natives*, HAL, 2026.
  https://hal.science/hal-05486729v1
