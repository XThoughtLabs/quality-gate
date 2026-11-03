#!/usr/bin/env bash
# Install actionlint at its pinned version, and refuse a file whose hash differs.
set -euo pipefail
target="$1"
version="1.7.12"
sha256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
archive="actionlint_${version}_linux_amd64.tar.gz"
mkdir -p "$target"
curl --fail --silent --show-error --location --output "$target/$archive" \
  "https://github.com/rhysd/actionlint/releases/download/v${version}/${archive}"
echo "$sha256  $target/$archive" | sha256sum --check --quiet
tar -xzf "$target/$archive" -C "$target" actionlint
rm "$target/$archive"
