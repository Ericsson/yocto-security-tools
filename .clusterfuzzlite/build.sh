#!/bin/bash -eu
# SPDX-License-Identifier: MIT
# Build every fuzz/fuzz_*.py target into a standalone fuzzer binary.

pip3 install --require-hashes -r requirements-fuzz.txt
pip3 install --no-deps .

for fuzzer in fuzz/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer"
done
