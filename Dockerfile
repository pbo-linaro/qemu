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
    python3-setuptools \
    ninja-build \
    gcc-aarch64-linux-gnu \
    pkgconf \
    libglib2.0-dev \
    libglib2.0-dev:arm64 \
    libpixman-1-dev:arm64 \
    libattr1-dev:arm64 \
    libcap-ng-dev:arm64 \
    libslirp-dev:arm64
