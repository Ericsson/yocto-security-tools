# SPDX-License-Identifier: MIT
# ClusterFuzzLite build image. Base image pinned by digest (Scorecard
# Pinned-Dependencies); Dependabot's docker ecosystem keeps it current.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:6ccbb6b02fcbb8e07d15680e933a6d835cdb579636032cec7d256d0f25d483e4
COPY . $SRC/yocto-security-tools
WORKDIR $SRC/yocto-security-tools
COPY .clusterfuzzlite/build.sh $SRC/
