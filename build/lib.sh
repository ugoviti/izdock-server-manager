#!/bin/bash
# Helpers shared by the Dockerfile (inside the image build) and by tools/ and
# .gitea/ (outside it). Source it, do not run it.
#
# load_versions [FILE]          export the KEY=value lines of versions.env

build_die() { echo "build: $*" >&2; exit 1; }

# load_versions [FILE]: export every KEY=value of versions.env (no shell code runs)
load_versions() {
  local file=${1:-$(dirname "${BASH_SOURCE[0]}")/../versions.env} line
  [ -r "$file" ] || build_die "cannot read $file"
  while IFS= read -r line || [ -n "$line" ]; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=([^[:space:]]+)$ ]] || build_die "bad line in $file: $line"
    export "${BASH_REMATCH[1]}=${BASH_REMATCH[2]}"
  done < "$file"
}
