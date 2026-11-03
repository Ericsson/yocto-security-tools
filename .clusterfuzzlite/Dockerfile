# SPDX-License-Identifier: MIT
# ClusterFuzzLite build image. Base image pinned by digest (Scorecard
# Pinned-Dependencies); Dependabot's docker ecosystem keeps it current.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:21f6fab17ace4dc76e1c56de91ee95d3d03da021df94b41056ba036f6c6f55e9
COPY . $SRC/yocto-security-tools
WORKDIR $SRC/yocto-security-tools
COPY .clusterfuzzlite/build.sh $SRC/
