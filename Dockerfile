FROM docker.io/debian:trixie

RUN dpkg --add-architecture arm64 && \
    apt update && \
    apt install -y \
    build-essential \
    git \
    bison \
    flex \
    python3 \
    python3-venv \
    ninja-build \
    gcc-aarch64-linux-gnu \
    pkgconf \
    libglib2.0-dev \
    libglib2.0-dev:arm64
