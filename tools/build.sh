#!/bin/bash
# Local build with the versions of versions.env (the same build args as CI).
#
#   tools/build.sh [docker build args...]     eg. tools/build.sh --no-cache
#
# The image is tagged izdock/server-manager:local (override with IMAGE=name:tag).
# Use podman instead of docker with DOCKER=podman (eg. DOCKER=podman tools/build.sh --dns 1.1.1.1).
# Verify it like CI does:
#   docker run -i --rm --entrypoint "" -e APP_VER_EXPECTED=<APP_VER> izdock/server-manager:local \
#     bash -s < .gitea/actions/build-push/verify-image.sh
set -Eeuo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=build/lib.sh
. "$root/build/lib.sh"
load_versions "$root/versions.env"
image=${IMAGE:-izdock/server-manager:local}
from=$(base_image)
echo "building $image (APP_VER=$APP_VER) from $from"
exec "${DOCKER:-docker}" build \
  --build-arg IMAGE_FROM="$from" \
  --build-arg APP_VER="$APP_VER" \
  --build-arg APP_VER_BUILD=local \
  --build-arg OS_UPDATE_STAMP="$(date -u +%G-W%V)" \
  --build-arg APP_BUILD_COMMIT="$(git -C "$root" rev-parse --short=7 HEAD 2>/dev/null || echo local)" \
  --build-arg APP_BUILD_DATE="$(date +%s)" \
  -t "$image" "$@" "$root"
