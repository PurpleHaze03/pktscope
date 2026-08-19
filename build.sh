#!/usr/bin/env bash
# Build pktscope. Installs no packages -- see README for the apt one-liner.
set -e
cd "$(dirname "$0")"

command -v cmake >/dev/null || { echo "cmake not found -- see README prerequisites"; exit 1; }

mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j"$(nproc)"

echo
echo "Built: $(pwd)/pktscope"
echo "Run the tests with:   ./pktscope_tests"
echo "Try it:               ./pktscope -r ../tests/data/port_scan.pcap"
echo "Live capture:         sudo ./pktscope -i <interface>"
