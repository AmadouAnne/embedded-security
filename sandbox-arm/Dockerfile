# ARM Malware Sandbox v2 -- Multi-architecture
# Supporte : ARM, MIPS, PowerPC, ARM64, RISC-V
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    # QEMU multi-architecture
    qemu-user \
    qemu-user-static \
    # Outils d'analyse
    strace \
    binutils \
    binutils-arm-linux-gnueabi \
    binutils-mips-linux-gnu \
    binutils-powerpc-linux-gnu \
    file \
    upx-ucl \
    # Python
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Vérifie que QEMU est bien installé pour toutes les archs
RUN qemu-arm-static --version && \
    qemu-mips-static --version && \
    qemu-ppc-static --version

WORKDIR /home/sandbox
COPY src/ /home/sandbox/src/
RUN mkdir -p /home/sandbox/src/reports /home/sandbox/src/samples

# Analyzer par défaut (accepte un arg pour choisir le binaire)
ENTRYPOINT ["python3", "src/engine/analyzer.py"]
