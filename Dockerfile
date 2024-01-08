ARG arch=
FROM docker.io/${arch}/debian:bookworm

RUN apt update && apt upgrade -y
# https://wiki.qemu.org/Hosts/Linux#Building_QEMU_for_Linux
RUN apt update && apt install -y \
    git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev ninja-build\
    git-email\
    libaio-dev libbluetooth-dev libcapstone-dev libbrlapi-dev libbz2-dev\
    libcap-ng-dev libcurl4-gnutls-dev libgtk-3-dev\
    libibverbs-dev libjpeg-dev libncurses5-dev libnuma-dev\
    librbd-dev librdmacm-dev\
    libsasl2-dev libsdl2-dev libseccomp-dev libsnappy-dev libssh-dev\
    libvde-dev libvdeplug-dev libvte-2.91-dev liblzo2-dev\
    valgrind xfslibs-dev

RUN apt update && apt install -y \
    python3-venv meson coreutils build-essential git ccache

RUN apt update && apt install -y xvfb

ARG arch=
ENV ARCH=${arch}
