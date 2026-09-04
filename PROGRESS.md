# Fiche d'avancement — compte GitHub AmadouAnne

**Date :** 2026-09-04
**Repo principal :** `AmadouAnne/embedded-security` (clone réel dans `/home/mercy/Documents/github-audit/embedded-security`)
**État git embedded-security :** ✅ commité et poussé (`94ef98d`). `academic-projects`, `N0M3R5Y` et `ProjetsEmbarques` déjà commités/poussés au fil de la session.

---

## Réorganisation du compte (fait, déjà en ligne)

Regroupement des petits projets de coursework publics dispersés, pour un profil plus lisible :

- **`academic-projects`** (nouveau repo public) : regroupe `Projet-immersion-python` → `platformer-game/`, `Compilation-FLEX-BISON` → `flex-bison-compiler/`, `csp-project` → `csp-solver/`, `TEA-SDD` → `red-black-tree-c/`, `nonogram_en_C` → `nonogram-solver-c/`, `SmartHome-Secure` → `smarthome-dashboard-demo/`, `Modelisation-BD` → `database-modeling/`. Historique git complet préservé pour chacun (import via `git filter-repo` + merge, pas juste une copie).
- **`N0M3R5Y`** : `RootMe` fusionné dedans comme `ctf-writeups/RootMe/` (historique préservé).
- **`anomaly-detection-research`** (nouveau repo public) : regroupe les 5 petits repos vitrine qui prolongeaient tous la même recherche HAL — `ot-ids-lite`, `tinyml-embedded-anomaly-detection`, `hal-anomaly-detection-reproduction`, `embedded-linux-hardening-auditor`, `ics-honeypot`. **Important : ces repos étaient auparavant cités individuellement (CV, notes) — si vous retrouvez une ancienne référence à l'un de ces noms de repo, remplacez par `anomaly-detection-research/<nom>/`.**
- **`coursework-archive`** (nouveau repo **privé**) : regroupe 6 petits projets personnels/coursework privés dispersés — `mini-resto`, `mini-recettes` → `mini-recettes/`, `Inversion-list-en-C` → `inversion-list-c/`, `Jeux` → `jeux/`, `Electromyographie-de-surface-EMG-` → `emg-signal-processing/`, `Virus-compagnon` → `virus-compagnon/`. Reste privé (aucun impact visibilité).
- Les 15 repos sources (8 + 5 vitrine + 6 privés, dont un doublon déjà compté) ont été **supprimés** après vérification que tout était bien répliqué (rien n'est perdu, juste consolidé).
- **Résultat final : 29 → 13 dépôts au total**, profil public passé de ~19 à **7 dépôts visibles**.

Repos publics restants : `embedded-security`, `academic-projects`, `anomaly-detection-research`, `N0M3R5Y`, `ProjetsEmbarques`, `TravelExplorer`, `AmadouAnne` (profil).

Repos privés restants : `portfolio`, `Yupata_Backoffice` (archivé), `coursework-archive`, `ics-multilevel-dataset` (reste privé+cité sur CV), `librairie-online` (interdit d'y toucher), `kouclean` (interdit d'y toucher).

---

## Contexte

Objectif : compléter les 6 sous-projets de `embedded-security` pour qu'aucun ne soit un "creux" (code manquant, résultats fabriqués, ou écart entre le README et ce que le code fait réellement), en vue d'un dossier de candidature stage recherche / doctorat 2026.

Décisions actées précédemment (voir aussi ancien `STATUS.md`) :
- `librairie-online` et `kouclean` : ne pas toucher.
- `ics-multilevel-dataset` : reste privé, cité sur le CV.
- README du profil GitHub : style inchangé.

---

## P1 — FreeRTOS Hardened STM32 : ✅ Codé et compilé

- MPU réelle activée (FreeRTOS-MPU V1, régions privilégiées flash 64K / RAM 32K, tâche `Untrusted` isolée via `xTaskCreateRestricted`).
- Watchdog matériel IWDG (~1.6s) remplaçant le timer logiciel, avec heartbeat multi-tâches.
- Authentification UART par challenge-response HMAC-SHA256 (mbedTLS vendorisé minimalement, sans `platform_util.c`).
- Gestion de faults MemManage/BusFault/UsageFault avec diagnostic UART + reset contrôlé.
- **Compilation réelle réussie** (`arm-none-eabi-gcc`) : `freertos_hardened.bin` généré, 33 KB texte. Plusieurs incompatibilités de versions vendor (HAL/CMSIS) corrigées au passage.
- **Reste à faire :** test sur le vrai Nucleo-F411RE (demain, avec le matériel).

## P2 — Secure Boot RPi4 : ✅ Codé, signé et vérifié

- `keys/generate_keys.sh`, `scripts/sign_fit.sh`, `scripts/verify_chain.sh`, `boot/boot.cmd`, `docs/attack-vectors.md` écrits.
- Signature RSA-2048/SHA-256 réelle testée : `fitImage` signé et vérifié indépendamment (openssl + fdtget), y compris 2 scénarios d'attaque (falsification simple, falsification + re-signature par une clé attaquante) — tous deux correctement rejetés.
- `docs/attack-vectors.md` documente aussi honnêtement 2 limites réelles non couvertes (rollback, root of trust de U-Boot lui-même).
- **Reste à faire :** test du boot réel sur le Raspberry Pi 4 (demain).

## P3 — Patch Diffing OpenWRT : ✅ Bug corrigé, vrais résultats obtenus

- Bug trouvé et corrigé : les exports JSON Ghidra (`libuclient_v33.json`/`v35.json`) étaient identiques car le script GUI avait tourné deux fois sur le même programme.
- Nouveau script `scripts/run_hasher_headless.py` (PyGhidra) : automatise import + analyse + export, testé réellement sur les deux binaires `libuclient.so`.
- **Vrai résultat obtenu** : 1 seule fonction modifiée entre v33 et v35 — `uclient_disconnect` — qui annule un second timer `uloop` non nettoyé en v33 (probable fix UAF/timer pendant). Corroboré indépendamment par le diff binaire brut déjà présent (`libuclient_diff.txt`, décalage +16 octets cohérent).
- CVE-2023-0464/0465 (OpenSSL X.509) : requalifiées honnêtement de "en cours" à "non corrélées" — le vrai diff ne montre aucun lien avec ces CVE.

## P4 — Fuzzer Modbus : ✅ Bugs corrigés, résultats réels mesurés

- Bug d'adressage corrigé : `ModbusSequentialDataBlock` prend une adresse de départ en base 1, pas 0 — `scada_monitor.py` affichait des valeurs décalées d'un registre. Confirmé empiriquement contre un serveur live.
- `report.py` : détection de crash corrigée (la clé `ConnectionRefusedError` ne pouvait jamais correspondre à la vraie chaîne enregistrée) et détection d'exception Modbus corrigée (recherche du bon octet plutôt qu'un `'83' in ...` trop permissif).
- **Nouveau script `src/setpoint_attack.py`** : le README affirmait reproduire l'attaque "Class 7" du dataset Morris, mais aucun code ne le faisait — script ajouté et **testé en vrai** contre le PLC live : alarme LL déclenchée en 24s.
- pymodbus épinglé à `3.12.1` dans `requirements.txt` (3.15 casse l'API utilisée — confirmé par test).
- Résultats de fuzzing 1000 itérations re-mesurés pour de vrai : 410 succès, 355 exceptions gérées, 235 timeouts (23.5%), 0 crash.

## P5 — Sandbox ARM Malware : ⚠️ Incident de sécurité traité + bugs corrigés

- **Incident trouvé et résolu** : `src/samples/` contenait plusieurs vrais malwares fonctionnels **en clair** (non chiffrés) dans le dépôt public — un script dropper IoT réel (masquage de process, C2 codé en dur) et 3 binaires ELF ARM/MIPS exécutables. Purgés de **tout l'historique git** (`git filter-repo` + force-push), pas seulement du dernier commit. Seuls les `.zip` chiffrés AES (convention MalwareBazaar) restent.
- Bug corrigé : `launch.py` → `docker_analyze()` ignorait complètement l'argument `--binary` à cause d'une mauvaise construction de la commande Docker (l'`ENTRYPOINT` recevait deux fois `"python3 src/engine/analyzer.py"` au lieu du chemin du binaire).
- Bug corrigé : `NetworkAnalyzer` codait en dur `qemu-arm-static`, cassant l'analyse réseau pour tout échantillon non-ARM (MIPS/PPC/etc.), alors que `ARMAnalyzer` détecte correctement l'architecture.
- Pipeline statique testé en vrai (entropie, sections ELF, génération de rapport JSON) sur un binaire bénin. Le chemin Docker complet n'a pas pu être re-testé de bout en bout ici (accès réseau `deb.debian.org` bloqué dans ce sandbox d'exécution) — à valider avec `python3 launch.py --binary <sample>` sur une machine avec accès Internet normal.

## P6 — CPA Side-Channel AES-128 : ✅ Codé et testé (simulé)

- Framework CPA complet : générateur de traces simulées (modèle Hamming weight + bruit gaussien), attaque par corrélation de Pearson, démonstration de contre-mesure par masquage.
- **Résultats réels** : récupération complète de la clé AES-128 (16/16 octets) sur traces simulées ; le masquage fait chuter la corrélation du signal (~0.82) au bruit (~0.08), échec total de récupération (0/16).
- README honnête : validé sur modèle de fuite simulé, en attente de vraies captures matérielles.

## P7 — Marauder ESP32 : ✅ Nettoyé

- C'était une référence de submodule git cassée (dangling gitlink) vers `justcallmekoko/ESP32Marauder`, avec un `.gitignore` qui excluait tout le dossier — signe que ce n'était pas censé être suivi. Supprimé entièrement sur votre confirmation.

---

## État git actuel

Tout est **non commité**, 46 fichiers modifiés/nouveaux à travers P1-P7 (hors l'historique déjà purgé et poussé pour P5, qui est *déjà sur GitHub*). Rien d'autre n'a été poussé.

## Prochaines étapes suggérées

1. **Vous validez** les changements (`git diff` / `git status` dans `embedded-security/`).
2. **Commit + push** une fois validé.
3. **Demain, sur place avec le matériel** : test P1 (Nucleo-F411RE), test P2 (Raspberry Pi 4), et si possible début de capture réelle pour P6.
4. Ensuite : regrouper les projets restants (petits exercices scattered) en dépôts thématiques, sur le modèle d'`embedded-security` — hors `librairie-online` et `kouclean`.
5. Rédaction d'un article/prépublication à partir des résultats les plus solides (P1 sécurité RTOS, ou P3 patch diffing avec la découverte concrète sur `uclient_disconnect`).
