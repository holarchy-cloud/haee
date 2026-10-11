#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <cargo arguments...>" >&2
  echo "       $0 build-bin <binary-name> [cargo build arguments...]" >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
compose_file="$script_dir/docker-compose.ci.yml"
target_dir="$repo_root/.cache/haee-target"
artifact_dir="$repo_root/.artifacts/haee-binaries"
mkdir -p "$target_dir"

if [[ $1 == "build-bin" ]]; then
  shift
  if [[ $# -lt 1 ]]; then
    echo "Usage: $0 build-bin <binary-name> [cargo build arguments...]" >&2
    exit 2
  fi

  binary_name=$1
  shift
  profile=debug
  for arg in "$@"; do
    case "$arg" in
      --release|-r) profile=release ;;
      --target|--target=*)
        echo "build-bin currently supports native builds only" >&2
        exit 2
        ;;
    esac
  done

  docker compose -f "$compose_file" run --build --rm local-ci cargo build --bin "$binary_name" "$@"
  install -D -m 0755 "$target_dir/$profile/$binary_name" "$artifact_dir/$binary_name"
  printf 'Exported binary: %s\n' "$artifact_dir/$binary_name"
  exit 0
fi

exec docker compose -f "$compose_file" run --build --rm local-ci cargo "$@"