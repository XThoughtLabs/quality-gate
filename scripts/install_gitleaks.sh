#!/usr/bin/env bash
# Install gitleaks at its pinned version, and refuse a file whose hash differs.
set -euo pipefail
target="$1"
version="8.30.1"
sha256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
archive="gitleaks_${version}_linux_x64.tar.gz"
mkdir -p "$target"
curl --fail --silent --show-error --location --output "$target/$archive" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${version}/${archive}"
echo "$sha256  $target/$archive" | sha256sum --check --quiet
tar -xzf "$target/$archive" -C "$target" gitleaks
rm "$target/$archive"
