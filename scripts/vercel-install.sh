#!/usr/bin/env bash
# Vercel build bootstrap.
#
# Vercel's build image has Node but no Rust, and the analyzer ships as
# WebAssembly, so the toolchain and the matching wasm-bindgen CLI have to be
# installed before `npm run build`. Vercel caps the install command at 256
# characters, which is not enough to inline this, hence the script.
#
# The wasm-bindgen CLI version is read out of Cargo.lock rather than pinned a
# second time: its output format is unstable between releases and a mismatch
# fails the build with an error that does not obviously mean "wrong version".
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
  curl -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi

rustup target add wasm32-unknown-unknown

version="$(cargo tree -p naksheap-wasm -i wasm-bindgen --depth 0 \
  | sed -n 's/.*wasm-bindgen v\(.*\)/\1/p' | head -1)"
if [ -z "$version" ]; then
  echo "could not determine the wasm-bindgen version from the lockfile" >&2
  exit 1
fi
echo "installing wasm-bindgen-cli $version"
cargo install wasm-bindgen-cli --version "$version" --locked

cd web
npm ci