#!/usr/bin/env bash

set -euo pipefail

b=/aarch64/virt/generic-pcihost/pci-bus-generic/pcie-bus/tdisp-testdev/tdisp-testdev-tests
QTEST_QEMU_BINARY=./build/qemu-system-aarch64 \
    ./build/tests/qtest/qos-test \
    -p $b/get-vca \
    -p $b/authenticate \
    -p $b/secure-session
