#!/bin/sh
# Build the CUDA miner next to its source. Needs the CUDA toolkit (nvcc) and an NVIDIA driver; sm_80 covers the A100/GA100
# family (CMP 170HX); add -gencode lines or change -arch for other cards (e.g. -arch=sm_86 for RTX 30, sm_89 for RTX 40).
set -e; cd "$(dirname "$0")"
nvcc -O3 -std=c++17 -arch=sm_80 -o bitcheque-miner bitcheque_miner.cu
