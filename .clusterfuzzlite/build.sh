#!/bin/bash -eu
# SPDX-License-Identifier: MIT
# Build every fuzz/fuzz_*.py target into a standalone fuzzer binary.

pip3 install .

for fuzzer in fuzz/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer"
done
