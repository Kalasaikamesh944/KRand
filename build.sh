#!/bin/bash

set -e  # Exit on error

echo "[+] Creating build directory..."
rm -rf build && mkdir build && cd build

echo "[+] Running CMake..."
cmake ..

echo "[+] Compiling..."
make -j$(nproc)

echo "[+] Installing..."
sudo make install

echo "[+] Build complete!"
