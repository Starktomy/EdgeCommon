#!/usr/bin/env bash
set -euo pipefail

module_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$module_dir"
source "$module_dir/build/verify-lib.sh"
verify_module EdgeCommon "$@"
