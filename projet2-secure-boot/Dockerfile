# Image de base Jenkins LTS
FROM jenkins/jenkins:lts

# On passe en root pour installer les outils de ton Master 1
USER root

# Installation des outils nécessaires pour ton Projet 2 (Secure Boot)
# build-essential : pour compiler
# gcc-aarch64-linux-gnu : pour la cross-compilation ARM (RPi)
# u-boot-tools : pour l'outil mkimage (signature du binaire)
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc-aarch64-linux-gnu \
    u-boot-tools \
    libssl-dev \
    device-tree-compiler \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# On repasse sur l'utilisateur jenkins
USER jenkins
