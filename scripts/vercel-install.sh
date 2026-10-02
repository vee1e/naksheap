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

# Always install rustup and the pinned toolchain, even when a cargo is already
# on PATH. Build images ship whatever rustc happened to be current: Vercel's
# image carries 1.92, which is below this workspace's rust-version, and a
# pre-existing cargo makes a "is cargo installed" check skip the install and
# then fail with "package requires rustc 1.95". rustup honours
# rust-toolchain.toml, so this selects the version the repo asks for.
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
# shellcheck disable=SC1091
. "$HOME/.cargo/env"

rustup show active-toolchain >/dev/null
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