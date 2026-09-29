#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/../.."

find scripts sensor/scripts elk/elasticsearch/setup -type f -name '*.sh' -print | while IFS= read -r script; do
  first_line=$(sed -n '1p' "$script")
  case "$first_line" in
    '#!'*bash*) bash -n "$script" ;;
    '#!'*sh*) sh -n "$script" ;;
    *) echo "Unsupported shell shebang: $script" >&2; exit 1 ;;
  esac
done
