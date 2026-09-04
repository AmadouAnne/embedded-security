# Isolation de tâches non fiables en systèmes embarqués contraints : étude comparative MPU ARM Cortex-M4 / PMP RISC-V, avec validation matérielle réelle

**Amadou Tidiane Anne**
Master Logiciels et Systèmes Embarqués, UBO Brest

---

## Résumé

L'isolation mémoire d'une tâche non fiable au sein d'un même microcontrôleur — sans MMU, sans virtualisation matérielle complète — repose sur deux familles de mécanismes concurrentes selon l'architecture cible : la *Memory Protection Unit* (MPU) d'ARM Cortex-M et la *Physical Memory Protection* (PMP) de RISC-V. Ces deux mécanismes visent le même objectif (borner ce qu'un code non privilégié peut lire, écrire et exécuter) mais reposent sur des modèles structurellement différents : régions à priorité fixe et recouvrement explicite pour l'une, plages adressées par registres empilés (TOR/NAPOT) pour l'autre. Ce travail implémente le même scénario de menace — une tâche non privilégiée légitimement bornée à sa propre mémoire, qui tente délibérément un accès hors de ses droits — sur les deux architectures : sur ARM Cortex-M4 (Nucleo-F411RE) via FreeRTOS-MPU, validé sur matériel réel ; sur RISC-V (rv64imac) en bare-métal sous QEMU, en attente de validation sur silicium. Nous documentons non seulement le résultat attendu (l'accès illégal est intercepté avant d'aboutir, dans les deux cas), mais surtout le processus qui y mène : le passage au matériel réel a révélé, sur la cible ARM, une chaîne de dix bugs réels — dans le firmware, dans le port FreeRTOS-MPU et dans le script d'édition de liens — dont aucun n'était visible à la seule compilation ni à l'inspection du code. Cette chaîne constitue en elle-même une contribution méthodologique : elle illustre concrètement l'écart entre « compile et semble correct » et « fonctionne réellement », dans un domaine où cet écart a un coût direct en sécurité.

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

Le système de base (ordonnancement, rapport UART, lecture capteur, chien de garde) a été validé sur matériel réel sur des exécutions continues de 15 à 20 secondes, sans redémarrage ni faute, avec relevé de température plausible (26–28 °C ambiants) confirmant que la chaîne de mesure (ADC → conversion → affichage `printf` flottant) fonctionne de bout en bout.

La démonstration de faute MPU proprement dite (commande `VIOLATE`) reste, à ce stade, **non aboutie** sur matériel réel : la tâche `Untrusted`, une fois effectivement ordonnancée (voir §4), échoue de façon reproductible dès son premier appel à un service RTOS réel (`vTaskDelay()`) au travers de la passerelle d'appel système MPU, par un mécanisme encore non totalement élucidé (voir §5.3). Ce résultat négatif est documenté explicitement plutôt que masqué, conformément à la méthodologie adoptée pour l'ensemble de ce travail (§4).

## 4. Ce que le matériel réel a révélé : dix bugs, une méthodologie

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

Chacun de ces dix bugs n'est devenu observable qu'une fois le précédent corrigé — une architecture en cascade typique du débogage matériel réel, où un symptôme en masque systématiquement un autre. Aucun n'aurait été détecté par la seule lecture du code, la compilation, ou une simulation ne modélisant pas fidèlement le comportement du chien de garde matériel, des horloges de périphérique et de la sémantique exacte de l'édition de liens.

## 5. Implémentation RISC-V (P7 — `riscv-pmp-isolation`)

### 5.1 Plateforme et modèle PMP

Cible : RISC-V rv64imac (extensions `_zicsr_zifencei` requises explicitement par les chaînes d'outils binutils récentes, l'extension `zicsr` n'étant plus implicitement incluse dans le jeu d'instructions de base), simulé sous QEMU (machine `virt`), en bare-métal, sans RTOS. Le mécanisme d'isolation, la *Physical Memory Protection*, diffère structurellement de la MPU ARM : un jeu de registres de contrôle et d'état (CSR) accessibles uniquement en mode M — `pmpaddr0-15`, `pmpcfg0-3` — encode jusqu'à 16 plages, chacune adressée en mode TOR (*Top-Of-Range*), où l'entrée *i* couvre l'intervalle `[pmpaddr(i-1), pmpaddr(i))`. Contrairement à la MPU Cortex-M4 (régions à base+taille explicites, priorité par numéro croissant en cas de recouvrement), le mode TOR construit des plages contiguës par accumulation d'adresses successives — une différence de modèle mental non anodine lors du portage d'un même schéma de régions.

Autre différence structurelle : le mode M est par défaut **exempté** de tout contrôle PMP (sauf verrouillage explicite d'une entrée), alors que le mode U échoue fermé — toute adresse ne correspondant à aucune entrée PMP est refusée par défaut. La carte mémoire (RAM à `0x80000000`, UART NS16550A à `0x10000000`, périphérique de fin d'exécution `sifive_test` à `0x100000`) a été confirmée empiriquement via le DTB généré par QEMU plutôt que supposée depuis la documentation.

### 5.2 Résultat obtenu (Phase 2, matériel réel en attente)

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

### 5.3 Limite explicite : validation en simulation uniquement

Contrairement à P1, ce résultat n'est **pas encore validé sur silicium réel** : aucune carte RISC-V n'était disponible au moment de ce travail. La Phase 4 (validation matérielle, par exemple sur ESP32-C3) reste une étape ouverte. Ce travail assume pleinement cette limite plutôt que de la dissimuler — c'est précisément parce que P1 a révélé une chaîne de dix bugs invisibles hors matériel réel que le résultat QEMU de P7, aussi propre soit-il, doit être présenté comme provisoire tant qu'il n'a pas subi la même épreuve.

## 6. Analyse comparative

| | ARM Cortex-M4 (MPU) | RISC-V rv64imac (PMP) |
|---|---|---|
| Nombre de régions (cible testée) | 8 régions matérielles | jusqu'à 16 entrées PMP |
| Adressage des régions | base + taille (puissance de deux, alignée) | TOR : accumulation d'adresses successives, ou NAPOT |
| Élévation de privilège | instruction `SVC`, gestion par `vPortSVCHandler`, vérification de la plage appelante | instruction `ECALL`, gestion logicielle en mode M |
| Comportement par défaut hors région | dépend de la configuration (`PRIVDEFENA`) | mode U : échec fermé systématique ; mode M : exempté sauf verrouillage |
| Exemption du mode privilégié | oui, mais pas de la logique applicative (RTOS entier soumis au même schéma de régions) | oui, intégrale pour le mode M |
| Dépendance à un RTOS pour la démonstration | oui (FreeRTOS-MPU, port dédié `ARM_CM4_MPU`) | non (bare-métal, boucle unique) |
| Validation | matérielle réelle (Nucleo-F411RE) | simulée (QEMU `virt`), matérielle en attente |

Le constat central n'est pas que l'un des deux mécanismes serait supérieur : les deux atteignent l'objectif de sécurité visé, avec une précision comparable (interception au mot près, vérifiée par confrontation aux symboles du binaire). La différence significative se situe dans **la surface d'intégration**. Sur ARM, l'isolation est indissociable du port RTOS complet (`ARM_CM4_MPU`, `MPU_WRAPPERS_V1`) : la moitié des dix bugs rencontrés (n° 3, 4, 9, 10) proviennent précisément de cette intégration — l'interaction entre le schéma de régions, l'ordonnanceur, le script de liaison et les conventions du port, plutôt que du mécanisme MPU pris isolément. Sur RISC-V, l'implémentation bare-métal de ce travail isole le mécanisme PMP de toute intégration RTOS, ce qui simplifie le raisonnement mais ne permet pas encore de conclure sur le coût d'intégration équivalent pour RISC-V (Phase 3, ordonnanceur minimal reconfigurant les entrées PMP à chaque changement de contexte, reste à réaliser).

## 7. Discussion : au-delà du résultat, la méthode

La contribution la plus généralisable de ce travail n'est peut-être pas la comparaison architecturale elle-même, mais l'écart mesuré entre **code jugé correct à la compilation et respect des conventions documentées d'un port largement utilisé (FreeRTOS-MPU)**, d'une part, et **comportement réel sur silicium**, d'autre part. Les dix bugs listés en §4 ne relèvent pas d'erreurs de débutant isolées : ils touchent des points d'interaction subtils — sémantique exacte de l'affectation du compteur de position dans un script de liaison GNU ld, ordre relatif entre plantation d'un canari et initialisation interne d'une tâche RTOS, dépendance implicite d'un HAL constructeur à un mécanisme d'horloge que le RTOS s'approprie entièrement. Chacun est individuellement plausible dans n'importe quel projet FreeRTOS-MPU suivant les mêmes conventions ; leur accumulation, non détectée avant le premier flashage réel, illustre concrètement pourquoi une revue de sécurité de systèmes à isolation mémoire physique ne peut se limiter à l'inspection statique du schéma de régions déclaré.

## 8. Limites et travaux futurs

- La démonstration de faute MPU sur cible ARM réelle (commande `VIOLATE`) reste inaboutie : la tâche non privilégiée, effectivement ordonnancée, échoue de façon reproductible dès son premier appel à un service RTOS réel via la passerelle d'appel système, par un mécanisme non encore élucidé — le pointeur de pile enregistré dans le bloc de contrôle de tâche au moment de l'échec ne correspond à aucune adresse de la pile propre de la tâche, ce qui exclut un simple sous-dimensionnement (testé à 128, 256 et 512 mots, échec identique) et pointe vers un problème plus structurel dans le suivi du contexte à travers l'aller-retour d'élévation de privilège. Une investigation dédiée, pas-à-pas au niveau de l'assembleur du gestionnaire SVC/PendSV, reste à mener.
- La validation RISC-V est actuellement limitée à la simulation QEMU ; la Phase 4 (validation sur matériel réel) et la Phase 3 (ordonnanceur multi-tâches reconfigurant la PMP à chaque changement de contexte, pendant structurel de `xTaskCreateRestricted()`) restent à réaliser, ce qui limite pour l'instant la portée de la comparaison du §6 à la seule primitive d'isolation, hors coût d'intégration RTOS côté RISC-V.
- Le protocole d'authentification UART par défi-réponse HMAC-SHA256 (P1) n'a pas encore été testé en conditions de charge réelle une fois le système stabilisé.

## 9. Conclusion

Ce travail implémente, documente et compare le même scénario d'isolation d'une tâche non fiable sur deux architectures aux mécanismes de protection mémoire structurellement différents. Les deux démonstrations atteignent, avec une précision vérifiée au mot près par confrontation aux symboles du binaire, l'objectif visé : intercepter un accès illégitime avant qu'il n'aboutisse, plutôt que de laisser une corruption silencieuse se produire. Mais le résultat le plus instructif de ce travail est ailleurs : le passage de la cible ARM au matériel réel a révélé une chaîne de dix bugs non détectables par la seule lecture du code, chacun masquant le suivant — un rappel empirique que, dans un domaine où l'isolation mémoire est un mécanisme de sécurité et non une simple optimisation, la validation sur silicium réel n'est pas une formalité, mais une étape de découverte à part entière.

---

*Code source complet, historique de découverte des bugs et instructions de reproduction : dépôt `embedded-security` (projets `freertos-stm32` et `riscv-pmp-isolation`).*
