# Isolation de tâches non fiables en systèmes embarqués contraints : étude comparative MPU ARM Cortex-M4 / PMP RISC-V, avec validation matérielle réelle

**Amadou Tidiane Anne**
Master Logiciels et Systèmes Embarqués, UBO Brest

---

## Résumé

L'isolation mémoire d'une tâche non fiable au sein d'un même microcontrôleur — sans MMU, sans virtualisation matérielle complète — repose sur deux familles de mécanismes concurrentes selon l'architecture cible : la *Memory Protection Unit* (MPU) d'ARM Cortex-M et la *Physical Memory Protection* (PMP) de RISC-V. Ces deux mécanismes visent le même objectif (borner ce qu'un code non privilégié peut lire, écrire et exécuter) mais reposent sur des modèles structurellement différents : régions à priorité fixe et recouvrement explicite pour l'une, plages adressées par registres empilés (TOR/NAPOT) pour l'autre. Ce travail implémente le même scénario de menace — une tâche non privilégiée légitimement bornée à sa propre mémoire, qui tente délibérément un accès hors de ses droits — sur les deux architectures : sur ARM Cortex-M4 (Nucleo-F411RE) via FreeRTOS-MPU, validé sur matériel réel ; sur RISC-V (rv64imac) en bare-métal sous QEMU, en attente de validation sur silicium. Nous documentons non seulement le résultat obtenu — l'accès illégal est intercepté avant d'aboutir, vérifié à l'octet près par confrontation aux symboles du binaire lié, sur les deux plateformes — mais surtout le processus qui y mène : le passage au matériel réel a révélé, sur la cible ARM, une chaîne de onze bugs réels — dans le firmware, dans le port FreeRTOS-MPU et dans le script d'édition de liens — dont aucun n'était visible à la seule compilation ni à l'inspection du code. Cette chaîne constitue en elle-même une contribution méthodologique : elle illustre concrètement l'écart entre « compile et semble correct » et « fonctionne réellement », dans un domaine où cet écart a un coût direct en sécurité.

---

## 1. Introduction et motivation

Les systèmes embarqués contraints (microcontrôleurs sans MMU) exécutent de plus en plus fréquemment des charges hétérogènes sur un seul cœur : code applicatif propriétaire, bibliothèques tierces, parfois du code partiellement non fiable (plugin, module tiers, tâche isolée par défense en profondeur). Sans unité de gestion mémoire complète, l'isolation entre ces charges ne peut reposer que sur les mécanismes de protection mémoire *physique* offerts par le cœur : la MPU sur ARM Cortex-M, la PMP sur RISC-V. Ces deux mécanismes sont fonctionnellement comparables — un nombre restreint de régions matérielles, une granularité contrainte par l'alignement, un basculement de privilège explicite (SVC/`svc` côté ARM, ECALL/`ecall` côté RISC-V) — mais structurellement distincts.

La question de recherche n'est pas « l'isolation fonctionne-t-elle sur les deux architectures » — par construction, oui, si le matériel est correctement configuré. La question est double :

1. **Comment le même modèle de menace se traduit-il** dans deux mécanismes de région structurellement différents, et à quel coût en complexité de configuration ?
2. **Que révèle le passage du papier (ou de la simulation) au matériel réel** sur la fiabilité de ce qui est présenté, dans la littérature et dans les ports logiciels existants, comme une isolation « prête à l'emploi » ?

Ce travail apporte une réponse empirique aux deux questions à partir de deux implémentations complètes : `freertos-stm32` (ARM Cortex-M4, matériel réel) et `riscv-pmp-isolation` (RISC-V rv64imac, QEMU).

## 2. Modèle de menace

Le scénario est identique sur les deux plateformes, délibérément minimal pour isoler la variable architecturale :

- Une tâche « de confiance » (le noyau RTOS ou le code M-mode) configure l'unité de protection mémoire pour accorder à une tâche non privilégiée l'accès **exclusif** à sa propre pile et à une petite zone de travail (« scratch »).
- La tâche non privilégiée exécute une boucle légitime (écriture bornée dans sa zone de travail), puis, sur déclenchement, tente délibérément une écriture **hors de toute région qui lui est accordée** — une variable globale `g_secure_secret`, physiquement adjacente à sa zone de travail mais jamais incluse dans ses droits.
- Le succès du test n'est pas « la tâche a été bloquée » en soi (résultat garanti si le matériel est configuré) : c'est que **l'écriture illégitime est interceptée avant d'atteindre la mémoire cible**, que le gestionnaire de faute identifie précisément l'adresse fautive, et que cette adresse corresponde exactement — au mot ou à l'octet près — à la variable protégée, vérifié en croisant le rapport de faute avec la table des symboles du binaire lié.

Ce dernier point — la vérification croisée contre les symboles de l'ELF plutôt que la simple observation d'un message de faute — est ce qui distingue une démonstration réellement instrumentée d'une démonstration illustrative.

## 3. Implémentation ARM Cortex-M4 (P1 — `freertos-stm32`)

### 3.1 Plateforme et architecture logicielle

Cible : STM32F411RE (Cortex-M4, 512 Ko Flash, 128 Ko RAM) sur carte Nucleo-F411RE, sondée en temps réel via ST-Link V2.1 (SWD, OpenOCD, GDB). RTOS : FreeRTOS V10.6.2, port `ARM_CM4_MPU`, `configUSE_MPU_WRAPPERS_V1 = 1`.

Quatre tâches coexistent : trois tâches système privilégiées (`LED` — battement de vie et rafraîchissement du chien de garde matériel IWDG ; `UART` — protocole d'authentification par défi-réponse HMAC-SHA256 et rapport périodique ; `Sensor` — lecture ADC du capteur de température interne) et une tâche `Untrusted`, créée via `xTaskCreateRestricted()` sans le bit de privilège, à qui seules sa propre pile et une zone `scratch` de 32 octets sont accordées. Sur commande `VIOLATE` reçue par UART, `Untrusted` écrit délibérément dans `g_secure_secret`, placée par construction hors de ses deux régions.

Le script d'édition de liens (`STM32F411RETx_FLASH.ld`) réserve explicitement deux zones « privilégiées seules » — 64 Ko de Flash pour le code noyau et les points d'entrée d'appel système, 32 Ko de RAM pour les structures internes de FreeRTOS et le tas — dimensionnées en puissance de deux et alignées sur leur propre taille, condition requise par l'encodage des registres de région du Cortex-M4 (`RBAR`/`RASR`).

### 3.2 Résultat obtenu et méthode de validation

Le système de base a été validé sur matériel réel, non par une exécution unique mais par plusieurs passages continus de 15 à 60 secondes sans redémarrage ni faute : l'ordonnanceur tourne, le chien de garde matériel IWDG est correctement rafraîchi à chaque cycle, le rapport périodique UART s'affiche à intervalle régulier, et la chaîne de mesure complète (ADC → conversion → affichage `printf` flottant) restitue une température plausible et stable (26–28 °C ambiants) sur toute la durée de l'essai. Chacun de ces quatre comportements a, à un moment de ce travail, été rompu par l'un des bugs listés en §4 ; leur observation conjointe et stable est donc elle-même la preuve que la correction a bien été apportée à la cause, non contournée par un correctif local.

La démonstration de faute MPU proprement dite (commande `VIOLATE`) **aboutit** désormais sur matériel réel. Y parvenir a nécessité de lever deux obstacles supplémentaires une fois la tâche `Untrusted` effectivement ordonnancée (bug n°10, §4) : d'abord l'hypothèse d'un sous-dimensionnement de pile, explicitement écartée par test (128, 256 puis 512 mots, échec rigoureusement identique dans les trois cas) — signe qu'il ne s'agissait jamais d'un dépassement réel ; puis, en lisant en direct par GDB le contenu de la pile de la tâche au moment de l'échec, la cause véritable (bug n°11, §4) : une collision entre le canari de pile propre à ce projet et le mécanisme natif de détection de dépassement de FreeRTOS lui-même, les deux inspectant par coïncidence exactement le même mot mémoire. Une fois cette collision levée, la commande `VIOLATE` déclenche une vraie faute MemManage, capturée :

```
[SECURITY] MemManage fault (unauthorized memory access) trapped by MPU/fault unit
  CFSR=0x00000082 MMFAR=0x20008000 BFAR=0x20008000
```

`MMFAR` correspond exactement à l'adresse de `g_secure_secret` (`arm-none-eabi-nm`), confirmant que la faute a bien été levée sur cet accès précis. La carte se réinitialise ensuite une seule fois, par conception, puis reprend un fonctionnement stable — comportement identique, à l'octet près et sur silicium réel, à celui obtenu en simulation côté RISC-V (§5.2-5.3).

## 4. Ce que le matériel réel a révélé : onze bugs, une méthodologie

Le projet compilait sans erreur et son architecture suivait les conventions documentées du port FreeRTOS-MPU avant sa première exécution sur matériel réel. Le flashage sur la Nucleo-F411RE a immédiatement révélé une chaîne de bugs réels, chacun masquant le suivant, découverts par instrumentation directe (GDB sur SWD, lecture de registres et de mémoire vive en direct, corrélation avec les sources du port FreeRTOS-MPU et le script de liaison) plutôt que par relecture de code :

1. **Blocage du gestionnaire de faute** — `HAL_UART_Transmit()` mesure son délai via `HAL_GetTick()`, qui dépend de l'interruption SysTick ; or un gestionnaire de faute matérielle s'exécute à une priorité qui bloque SysTick. Le délai de 200 ms ne pouvait donc jamais expirer : le gestionnaire censé signaler la faute puis réinitialiser la carte restait bloqué indéfiniment. Corrigé par une écriture UART en scrutation directe des registres, sans dépendance à l'horloge système.
2. **Périphérique UART jamais réellement initialisé** — l'horloge de l'USART2 et le mode alternatif des broches PA2/PA3 n'étaient jamais activés : le périphérique était configuré alors qu'il restait électriquement de simples broches GPIO. Rien n'était physiquement transmis.
3. **Tâches système non privilégiées par inadvertance** — créées via `xTaskCreate(..., priorité, ...)` sans le bit `portPRIVILEGE_BIT` que FreeRTOS-MPU exige explicitement, chacune de ces trois tâches ordinaires provoquait une tempête de fautes MPU dès son premier changement de contexte.
4. **Canari planté avant le remplissage de la pile qu'il protège** — la valeur sentinelle de détection de dépassement de pile était écrite *avant* l'appel à `xTaskCreateRestricted()`, dont la propre initialisation remplit l'intégralité du tampon de pile avec le motif de diagnostic `0xA5` de FreeRTOS — écrasant immédiatement le canari et provoquant une boucle de redémarrage par faux positif permanent.
5. **Incompatibilité de calendrier entre chien de garde et tâches** — la période de la tâche `Sensor` (2000 ms) dépassait le délai d'expiration du chien de garde matériel IWDG (≈1,6 s) : la condition « toutes les tâches se sont manifestées » ne pouvait, par construction, jamais être satisfaite dans une même fenêtre, garantissant des redémarrages périodiques indépendamment de tout blocage réel.
6. **Horloge ADC1 jamais activée** — même classe de bug que le n°2, pour le capteur de température.
7. **Utilisation de `xQueueOverwrite()` sur une file de longueur 8** au lieu de la longueur 1 qu'exige cette fonction (invariant vérifié par `configASSERT()` dans FreeRTOS) : le système se figeait intégralement, interruptions désactivées, à chaque exécution — symptôme extérieurement indiscernable d'une nouvelle boucle de redémarrage du chien de garde.
8. **`configUSE_TICK_HOOK` valait 0** — FreeRTOS possède entièrement le gestionnaire `SysTick_Handler` ; rien n'appelait donc jamais `HAL_IncTick()` du HAL STM32, et tout délai fondé sur `HAL_GetTick()` restait bloqué indéfiniment dès que la condition matérielle attendue n'était pas immédiatement vraie.
9. **Le remplissage de la zone RAM privilégiée dans le script de liaison ne réservait pas réellement l'espace annoncé** — une affectation `. = début + TAILLE;` placée *après* l'accolade fermante d'une section ne fait que déplacer le compteur de position symbolique ; elle ne réserve pas cet espace pour le placement de la section suivante. La section `.data` — et donc toute variable globale initialisée qu'elle contient, y compris `uwTickFreq` du HAL lui-même — se retrouvait physiquement à l'intérieur de la zone « privilégiée, réinitialisée à zéro au démarrage », de sorte que la boucle de remise à zéro de cette zone, exécutée par `Reset_Handler` juste après la copie de `.data`, effaçait silencieusement chaque variable globale initialisée immédiatement après qu'elle eut été correctement positionnée. Corrigé en transformant ce remplissage en section à part entière, rattachée explicitement à la région mémoire, ce qui fait réellement avancer le curseur d'allocation du linker.
10. **La passerelle d'appel système non privilégiée de FreeRTOS-MPU se trouvait placée derrière le mur qu'elle existe pour traverser** — la section `.freertos_system_calls` (les fonctions enveloppes `MPU_xxx`, contenant l'instruction `svc` qu'un appelant non privilégié doit pouvoir atteindre pour élever son propre privilège) se trouvait dans la même zone Flash « exécution réservée au code privilégié » que l'implémentation réelle du noyau. Configuration intrinsèquement contradictoire : du code non privilégié ne peut pas récupérer la première instruction de l'enveloppe pour atteindre le `svc` qui le laisserait entrer. Confirmé par une véritable faute d'accès à l'exécution (`IACCVIOL`) au moment précis où la tâche `Untrusted` — une fois effectivement ordonnancée — appelait `vTaskDelay()`. Corrigé en déplaçant cette section après la zone réservée, où elle est couverte par la région générique « lecture+exécution non privilégiée sur toute la Flash ».
11. **Le canari de pile propre à ce projet entrait en collision avec le mécanisme natif de détection de dépassement de FreeRTOS** — une fois le bug n°10 corrigé, `vApplicationStackOverflowHook()` se déclenchait pour la tâche `Untrusted` dès son tout premier changement de contexte, quelle qu'en soit la cause, sans aucun message de faute (un simple `NVIC_SystemReset()` silencieux). L'hypothèse d'un sous-dimensionnement de pile a été explicitement écartée (128, 256 puis 512 mots, échec identique). La lecture directe, par GDB, du contenu de la pile au moment de l'échec a révélé la vraie cause : `stack_macros.h` compare en permanence les 4 premiers mots de la pile de la tâche au motif `0xa5a5a5a5` que FreeRTOS y écrit à la création — or le canari de sécurité propre à ce projet (`Security_RegisterTask()`, voir bug n°4) était planté au tout premier de ces 4 mots. Deux mécanismes d'intégrité indépendants et individuellement corrects, mais partageant sans le savoir la même adresse. Corrigé en déplaçant le canari du projet au cinquième mot de la pile, hors de la zone que FreeRTOS surveille lui-même.

Chacun de ces onze bugs n'est devenu observable qu'une fois le précédent corrigé — une architecture en cascade typique du débogage matériel réel, où un symptôme en masque systématiquement un autre. Aucun n'aurait été détecté par la seule lecture du code, la compilation, ou une simulation ne modélisant pas fidèlement le comportement du chien de garde matériel, des horloges de périphérique et de la sémantique exacte de l'édition de liens.

## 5. Implémentation RISC-V (P7 — `riscv-pmp-isolation`)

### 5.1 Plateforme et modèle PMP

Cible : RISC-V rv64imac (extensions `_zicsr_zifencei` requises explicitement par les chaînes d'outils binutils récentes, l'extension `zicsr` n'étant plus implicitement incluse dans le jeu d'instructions de base), simulé sous QEMU (machine `virt`), en bare-métal, sans RTOS. Le mécanisme d'isolation, la *Physical Memory Protection*, diffère structurellement de la MPU ARM : un jeu de registres de contrôle et d'état (CSR) accessibles uniquement en mode M — `pmpaddr0-15`, `pmpcfg0-3` — encode jusqu'à 16 plages, chacune adressée en mode TOR (*Top-Of-Range*), où l'entrée *i* couvre l'intervalle `[pmpaddr(i-1), pmpaddr(i))`. Contrairement à la MPU Cortex-M4 (régions à base+taille explicites, priorité par numéro croissant en cas de recouvrement), le mode TOR construit des plages contiguës par accumulation d'adresses successives — une différence de modèle mental non anodine lors du portage d'un même schéma de régions.

Autre différence structurelle : le mode M est par défaut **exempté** de tout contrôle PMP (sauf verrouillage explicite d'une entrée), alors que le mode U échoue fermé — toute adresse ne correspondant à aucune entrée PMP est refusée par défaut. La carte mémoire (RAM à `0x80000000`, UART NS16550A à `0x10000000`, périphérique de fin d'exécution `sifive_test` à `0x100000`) a été confirmée empiriquement via le DTB généré par QEMU plutôt que supposée depuis la documentation.

### 5.2 Résultat obtenu — Phase 2 : isolation à tâche unique

Quatre entrées PMP configurent deux plages effectives accordées à une tâche U-mode : lecture+exécution sur son propre code, lecture+écriture sur sa propre zone de travail et sa pile. La tâche touche légitimement sa zone de travail, puis écrit délibérément dans `g_secure_secret`, hors de toute plage accordée. Sortie réelle, capturée (non illustrative) :

```
=== TRAP CAUGHT (M-mode) ===
Store/AMO access fault (PMP denied write)
mcause: 0x0000000000000007
mepc  : 0x0000000080000074
mtval : 0x0000000080000660
```

Croisement avec la table de symboles du binaire lié (`riscv64-elf-nm`) :

```
0000000080000660 D g_secure_secret        <- mtval correspond exactement
0000000080000660 D _scratch_end           <- au premier octet suivant
                                              la région accordée
0000000080000044 T _untrusted_text_start
0000000080000084 T _untrusted_text_end    <- mepc tombe à l'intérieur
```

`mtval` correspond exactement à l'adresse de `g_secure_secret`, laquelle se situe au tout premier octet suivant la fin de la région de travail accordée — la frontière est appliquée précisément, sans marge. `mepc` se situe à l'intérieur du code accordé à la tâche non privilégiée, confirmant que la faute a bien été levée depuis du code exécuté en mode U, non depuis un autre contexte.

### 5.3 Résultat obtenu — Phase 3 : ordonnanceur multi-tâches et isolation entre tâches sœurs

La Phase 2 répond à la question « du code non privilégié peut-il atteindre un secret du noyau » — elle ne dit rien du **coût d'intégration RTOS** que le §6 de la version précédente de cette étude laissait justement en suspens côté RISC-V. La Phase 3 comble ce manque : un ordonnanceur M-mode minimal, à tour de rôle, préempte deux tâches U-mode structurellement identiques via une interruption matérielle réelle (minuteur CLINT de la machine QEMU `virt`, confirmé à 10 MHz par l'arbre de périphériques de la machine elle-même) et **reconfigure les entrées PMP à chaque changement de contexte** — l'équivalent structurel exact, côté RISC-V, du réarmement des `MemoryRegions` par tâche qu'effectue `xTaskCreateRestricted()` côté ARM (§3).

La tâche A travaille légitimement pendant plusieurs quanta d'ordonnancement (les deux compteurs progressent de façon réellement entrelacée, non en simple alternance, preuve que la préemption est authentique), puis écrit délibérément dans le compteur de la tâche B — une mémoire qu'aucune des deux tâches ne partage, isolée uniquement par les régions PMP que l'ordonnanceur substitue à chaque commutation. Sortie réelle, capturée :

```
[sched] tick -- TaskA=counter: 0x0000000000000004
[sched]         TaskB=counter: 0x0000000000000005

=== TRAP: PMP violation ===
Task: TaskA
Store/AMO access fault (PMP denied write)
mepc : 0x0000000080000078
mtval: 0x0000000080000d00
[sched] tick -- TaskA=counter: 0x0000000000000005
[sched]         TaskB=counter: 0x0000000000000005
[sched] tick -- TaskA=counter: 0x0000000000000005
[sched]         TaskB=counter: 0x0000000000000006
```

`mtval` correspond exactement à l'adresse du compteur de la tâche B, qui se trouve être le tout premier octet de sa propre région de données — soit un octet après la fin de la région accordée à la tâche A. La tâche fautive est immédiatement écartée de l'ordonnancement (son compteur reste figé dans tous les relevés suivants) tandis que la tâche B, à qui rien n'a été accordé par la configuration PMP de la tâche A et qu'elle n'a jamais touchée, continue de progresser sans interruption. La violation a été **contenue à sa source**, non simplement détectée : c'est la différence entre un mécanisme de protection et un simple journal d'incident.

Cette phase a elle-même produit une observation méthodologique transférable, dans le droit fil du §4 : un premier bug — omettre de configurer le PMP pour la première tâche avant le tout premier retour en mode utilisateur, puisque le PMP démarre avec toutes les entrées désactivées et que le mode U échoue alors fermé sur absolument tout, y compris sa propre première instruction — a été trouvé et corrigé rapidement. Un second symptôme, en revanche, a été activement pris pour un bug de commutation de contexte (mauvais registre restauré, compteur de programme obsolète) pendant un temps non négligeable d'investigation par GDB, alors qu'il s'agissait d'un artefact de vitesse : la boucle d'attente active des tâches, dimensionnée pour du silicium réel, prenait sous l'émulation logicielle QEMU plusieurs secondes réelles par itération complète — bien plus long que n'importe quelle fenêtre d'observation utilisée pour la diagnostiquer. Un symptôme sensible au facteur temps peut être visuellement indiscernable d'une erreur de logique ; ce n'est pas parce qu'un compteur semble figé que l'algorithme qui le fait progresser est erroné.

### 5.4 Limite explicite : validation en simulation uniquement

Contrairement à P1, ce résultat n'est **pas encore validé sur silicium réel** : aucune carte RISC-V n'était disponible au moment de ce travail (vérifié explicitement via `lsusb` : seul le ST-Link de la cible ARM était détecté). La Phase 4 (validation matérielle, par exemple sur ESP32-C3) reste une étape ouverte. Ce travail assume pleinement cette limite plutôt que de la dissimuler — c'est précisément parce que P1 a révélé une chaîne de onze bugs invisibles hors matériel réel (dont deux découverts après la rédaction initiale de cette étude, voir §4) que le résultat QEMU de P7, aussi propre soit-il désormais pour les Phases 2 et 3, doit être présenté comme provisoire tant qu'il n'a pas subi la même épreuve.

### 5.5 Synthèse des résultats obtenus

Avant de comparer les deux mécanismes eux-mêmes (§6), il est utile de résumer ce qui a été *effectivement démontré*, indépendamment de l'architecture :

| | ARM Cortex-M4 (P1) | RISC-V rv64imac (P7) |
|---|---|---|
| Isolation tâche/secret noyau | démontrée et vérifiée à l'octet près, sur matériel réel (§3.2) | démontrée et vérifiée à l'octet près, en simulation (Phase 2, §5.2) |
| Isolation entre deux tâches sœurs | non testée dans ce travail | démontrée, faute contenue, tâche saine non affectée (Phase 3, §5.3) |
| Bugs réels trouvés et corrigés | 11, sur matériel réel | 2, en simulation |
| Validation | matérielle réelle (Nucleo-F411RE) | simulée (QEMU), matérielle en attente |

Ce tableau illustre une asymétrie volontaire, pas un déséquilibre accidentel : P1 a été poussé jusqu'au bout sur la question de la fiabilité matérielle (onze bugs trouvés parce que le matériel réel a été utilisé comme juge, jusqu'à obtenir une démonstration de faute complète et reproductible), tandis que P7 a été poussé jusqu'au bout sur la question de la couverture fonctionnelle (isolation entre pairs, pas seulement entre une tâche et le noyau). Chaque implémentation a atteint son propre axe jusqu'au bout ; aucune ne couvre encore les deux à la fois — P1 n'a pas été étendu à une isolation entre pairs, P7 n'a pas encore affronté le silicium réel. C'est précisément ce que la section 8 formalise en travaux futurs plutôt que de le présenter comme acquis.

## 6. Analyse comparative

| | ARM Cortex-M4 (MPU) | RISC-V rv64imac (PMP) |
|---|---|---|
| Nombre de régions (cible testée) | 8 régions matérielles | jusqu'à 16 entrées PMP |
| Adressage des régions | base + taille (puissance de deux, alignée) | TOR : accumulation d'adresses successives, ou NAPOT |
| Élévation de privilège | instruction `SVC`, gestion par `vPortSVCHandler`, vérification de la plage appelante | instruction `ECALL`, gestion logicielle en mode M |
| Comportement par défaut hors région | dépend de la configuration (`PRIVDEFENA`) | mode U : échec fermé systématique ; mode M : exempté sauf verrouillage |
| Exemption du mode privilégié | oui, mais pas de la logique applicative (RTOS entier soumis au même schéma de régions) | oui, intégrale pour le mode M |
| Ordonnancement multi-tâches avec reconfiguration par tâche | oui (FreeRTOS-MPU, port dédié `ARM_CM4_MPU`) | oui (ordonnanceur M-mode minimal, écrit pour ce travail) |
| Isolation vérifiée entre tâches sœurs (pas seulement tâche/noyau) | non testé dans ce travail (P1 s'arrête à la démo tâche/secret noyau) | oui (Phase 3, §5.3) |
| Validation | matérielle réelle (Nucleo-F411RE) | simulée (QEMU `virt`), matérielle en attente |

Le constat central n'est pas que l'un des deux mécanismes serait supérieur : les deux atteignent l'objectif de sécurité visé, avec une précision comparable (interception au mot près, vérifiée par confrontation aux symboles du binaire). La différence significative se situe dans **la surface d'intégration**. Sur ARM, l'isolation est indissociable du port RTOS complet (`ARM_CM4_MPU`, `MPU_WRAPPERS_V1`) : la majorité des onze bugs rencontrés (n° 3, 4, 9, 10, 11) proviennent précisément de cette intégration — l'interaction entre le schéma de régions, l'ordonnanceur, le script de liaison, les conventions du port et même le propre code de sécurité de ce projet, plutôt que du mécanisme MPU pris isolément. Sur RISC-V, l'ordonnanceur minimal de la Phase 3 réalise la même intégration en substance (reconfiguration des régions à chaque commutation, cohabitation avec une interruption matérielle) avec une chaîne de bugs bien plus courte (deux, contre onze côté ARM) — mais cette comparaison brute doit être lue avec prudence : l'ordonnanceur RISC-V ici est un code minimal écrit spécifiquement pour ce travail, non un port tiers largement déployé suivant des conventions externes (comme `ARM_CM4_MPU`/`MPU_WRAPPERS_V1`), et il n'a pas encore affronté l'épreuve du matériel réel qui a précisément révélé la majorité des bugs côté ARM. L'écart observé dit peut-être autant sur la maturité relative des deux implémentations que sur les mécanismes eux-mêmes.

## 7. Discussion : au-delà du résultat, la méthode

La contribution la plus généralisable de ce travail n'est peut-être pas la comparaison architecturale elle-même, mais l'écart mesuré entre **code jugé correct à la compilation et respect des conventions documentées d'un port largement utilisé (FreeRTOS-MPU)**, d'une part, et **comportement réel sur silicium**, d'autre part. Les onze bugs listés en §4 ne relèvent pas d'erreurs de débutant isolées : ils touchent des points d'interaction subtils — sémantique exacte de l'affectation du compteur de position dans un script de liaison GNU ld, ordre relatif entre plantation d'un canari et initialisation interne d'une tâche RTOS, dépendance implicite d'un HAL constructeur à un mécanisme d'horloge que le RTOS s'approprie entièrement, ou encore deux mécanismes de sécurité indépendants et chacun individuellement correct qui, sans coordination explicite, finissent par inspecter le même mot mémoire (bug n°11). Chacun est individuellement plausible dans n'importe quel projet FreeRTOS-MPU suivant les mêmes conventions ; leur accumulation, non détectée avant le premier flashage réel, illustre concrètement pourquoi une revue de sécurité de systèmes à isolation mémoire physique ne peut se limiter à l'inspection statique du schéma de régions déclaré.

## 8. Limites et travaux futurs

- La validation RISC-V est actuellement limitée à la simulation QEMU ; la Phase 4 (validation sur matériel réel) reste à réaliser. La Phase 3 (ordonnanceur multi-tâches reconfigurant la PMP à chaque changement de contexte) est désormais faite (§5.3), mais reste elle-même non validée sur silicium — et, comme discuté au §6, il s'agit d'un code minimal écrit pour ce travail, non d'un port tiers largement déployé comme `ARM_CM4_MPU` : la comparaison du coût d'intégration entre les deux architectures reste donc partielle tant que l'ordonnanceur RISC-V n'a pas subi une épreuve de maturité comparable (usage réel, matériel réel, revue externe).
- Le protocole d'authentification UART par défi-réponse HMAC-SHA256 (P1) n'a pas encore été testé en conditions de charge réelle une fois le système stabilisé.

## 9. Conclusion

Ce travail pose la même question de sécurité — une tâche non privilégiée peut-elle être bornée à sa propre mémoire de façon à ce qu'une violation soit interceptée avant d'aboutir, plutôt que de corrompre silencieusement autre chose — sur deux mécanismes de protection mémoire physique structurellement différents, et y répond deux fois, avec deux formes de rigueur complémentaires plutôt qu'une seule répétée deux fois.

Côté ARM Cortex-M4, la rigueur porte sur le matériel réel : un système FreeRTOS-MPU qui compilait sans erreur et respectait les conventions documentées du port `ARM_CM4_MPU` s'est révélé, dès le premier flashage sur une Nucleo-F411RE, porteur d'une chaîne de onze bugs réels — dans le firmware applicatif, dans l'interaction avec le port RTOS, et dans le script d'édition de liens — dont aucun n'était visible à la seule lecture du code ni détecté par la compilation. Le système de base en sort stabilisé et vérifié sur des exécutions continues de plusieurs dizaines de secondes, et la démonstration de faute proprement dite aboutit désormais elle aussi : la commande `VIOLATE` déclenche une véritable faute MemManage sur silicium réel, dont l'adresse fautive correspond exactement, à l'octet près, à la variable protégée. Les deux derniers bugs de la chaîne (n° 10 et 11) ont eux-mêmes suivi la méthodologie décrite en §7 jusqu'au bout — chacun découvert, root-causé par lecture directe de la mémoire en GDB, puis corrigé — plutôt que d'être laissés en échec documenté.

Côté RISC-V, la rigueur porte sur la couverture fonctionnelle : au-delà de la question « du code non privilégié peut-il atteindre un secret du noyau » (Phase 2, répondue et vérifiée à l'octet près), un ordonnanceur M-mode minimal, écrit pour ce travail, démontre la question structurellement plus proche d'un déploiement réel — deux tâches sœurs isolées l'une de l'autre par rien d'autre que des régions PMP reconfigurées à chaque changement de contexte, où la tâche fautive est tuée et contenue tandis que sa sœur poursuit son exécution sans interruption mesurable (Phase 3). Cette démonstration, à ce stade, n'a subi ni l'épreuve du matériel réel ni celle d'un usage extérieur à ce travail — deux limites explicitement assumées plutôt que dissimulées.

Le résultat le plus généralisable de ce travail n'est donc ni « MPU » ni « PMP » pris isolément, mais la conjonction des deux expériences : un mécanisme d'isolation mémoire physique peut être correctement *conçu* — architecture saine, conventions respectées, revue de code favorable — et rester néanmoins faux tant qu'il n'a pas été mis à l'épreuve, que ce soit par le silicium réel (ce que P1 a démontré à travers onze bugs, jusqu'à obtenir la démonstration complète) ou par un scénario de menace plus exigeant que celui initialement visé (ce que P7 a démontré en passant d'une isolation tâche/noyau à une isolation entre pairs). Dans un domaine où l'isolation mémoire est un mécanisme de sécurité et non une simple optimisation de performance, ni la lecture de code, ni la simulation, ni même une première démonstration réussie ne suffisent à en établir la fiabilité — seule l'épreuve continuée, sur du matériel réel et contre des scénarios de plus en plus proches du déploiement final, le permet. C'est cette épreuve, plus que son résultat à un instant donné, que ce travail documente.

---

## Disponibilité des données et du code

Le code source complet des deux implémentations, les instructions de compilation et l'historique complet des commits documentant la découverte et la correction de chaque bug sont disponibles publiquement : [github.com/AmadouAnne/embedded-security](https://github.com/AmadouAnne/embedded-security), dossiers `freertos-stm32` (P1) et `riscv-pmp-isolation` (P7).

- **P1 (ARM)** nécessite une carte Nucleo-F411RE, une sonde ST-Link, la chaîne d'outils `arm-none-eabi` et OpenOCD. `make` compile le firmware ; `openocd -f openocd/stm32f4.cfg -c "program build/freertos_hardened.bin 0x08000000 verify reset exit"` le flashe. La commande `VIOLATE`, envoyée sur l'UART de la carte (115200 8N1) une fois le système démarré, déclenche la démonstration de faute du §3.2.
- **P7 (RISC-V)** ne nécessite que la chaîne d'outils `riscv64-elf` et QEMU (`qemu-system-riscv64`) — aucun matériel. `make run` compile et démarre directement la démonstration de l'ordonnanceur Phase 3 du §5.3, l'UART étant routé vers l'entrée/sortie standard.

Chaque sortie réelle capturée et citée dans ce document (§3.2, §5.2, §5.3) est reproductible exactement avec les commandes ci-dessus, sur le commit référencé par l'historique du dépôt.
