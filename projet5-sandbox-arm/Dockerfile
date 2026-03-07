# Utilisation d'une base Debian légère pour la stabilité des outils ARM
FROM debian:bookworm-slim

# Installation des dépendances minimales pour l'analyse
RUN apt-get update && apt-get install -y \
    qemu-user \
    qemu-user-static \
    strace \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Création de l'espace de travail
WORKDIR /home/sandbox
COPY src/ /home/sandbox/src/

# Création du dossier de rapports pour éviter les erreurs de permission
RUN mkdir -p /home/sandbox/src/reports

# Commande par défaut : lancer l'analyseur sur le binaire test
ENTRYPOINT ["python3", "src/engine/analyzer.py"]
