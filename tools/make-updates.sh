#!/bin/bash
# Compare versions.env with upstream and propose updates.
#
#   tools/make-updates.sh [--apply] [--versions FILE]
#
# Prints one line per component of versions.env: current, latest, status
# (ok | UPDATE | unavailable), and for every UPDATE the new KEY=value lines with
# the sha256 of the new files. Every component stays on its major version
# (Zabbix and MySQL on their release line, Node.js on its major, Debian on its
# codename): a newer major is only shown as a note, change it by hand.
# The base image is also proposed when its tag was rebuilt upstream
# (same codename, new digest: OS security updates).
# "unavailable" = the upstream lookup failed (eg. GitHub API rate limit).
#
# Pin: a <NAME>_PIN=<version> line in versions.env (for any <NAME>_VER or
# <NAME>_VERSION) keeps that component on <version>: never moved by an update.
#
# --apply writes the proposed lines into versions.env (only KEY=value lines
# already present; every value checked, nothing written if one is missing or
# invalid). Then: tools/build.sh, test, bump APP_VER, commit.
#
# Exit code: 0 all current (or, with --apply, updates applied), 10 updates
# available, 2 incomplete (lookups unavailable), 1 error. GITHUB_API_TOKEN
# (optional, a GitHub token: never the Gitea one) raises the GitHub API rate limit.
# Requires: curl, jq, sha256sum, xz.

set -Eeuo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
versions="$root/versions.env"
apply=''
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) apply=1 ;;
    --versions) versions=${2:?--versions FILE}; shift ;;
    -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 1 ;;
  esac
  shift
done
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
# shellcheck source=build/lib.sh
. "$root/build/lib.sh"
load_versions "$versions"

updates=0
unavailable=0
proposals=()

row() { printf '%-24s %-24s %-24s %s\n' "$1" "$2" "$3" "$4"; }
report() { # component current latest [note]
  local name=$1 cur=$2 new=$3 note=${4:-}
  if [ "$cur" == "$new" ]; then row "$name" "$cur" "$new" "ok${note:+ ($note)}"
  else row "$name" "$cur" "$new" "UPDATE${note:+ ($note)}"; updates=$((updates + 1)); return 1
  fi
}
propose() { proposals+=("$@"); }
# lookup: like report, but an empty "latest" means the upstream lookup failed
lookup() { # component current latest source [note]
  if [ -z "$3" ]; then row "$1" "$2" "?" "unavailable ($4)"; unavailable=$((unavailable + 1)); return 0; fi
  report "$1" "$2" "$3" "${5:-}"
}
# apply_pin KEY: with <NAME>_PIN set (NAME = KEY without _VER/_VERSION), the pinned
# version replaces the upstream one (new) and the note says so
apply_pin() {
  local k="${1%_VERSION}"; k="${k%_VER}_PIN"; local up=$new
  [ -n "${!k:-}" ] || return 0
  new=${!k}
  if [ -n "$up" ] && [ "$up" != "$new" ]; then note="pinned, latest $up${note:+, $note}"
  else note="pinned${note:+, $note}"; fi
}
# every request retries transient failures; curl messages only when it fails for good
fetch() {
  local err rc=0
  err=$(mktemp)
  curl -fsSL --proto '=https' --connect-timeout 30 --speed-limit 1024 --speed-time 60 --retry 3 --retry-delay 2 --retry-connrefused "$@" 2>"$err" || rc=$?
  [ "$rc" -eq 0 ] || tail -n 1 "$err" >&2
  rm -f "$err"
  return "$rc"
}
# sha256 of a download; empty when the download fails (never the sha256 of an empty file)
sha_of() { local t; t=$(mktemp); if fetch -o "$t" "$1"; then sha256sum "$t" | cut -d' ' -f1; fi; rm -f "$t"; }

gh_api() { fetch ${GITHUB_API_TOKEN:+-H "Authorization: Bearer $GITHUB_API_TOKEN"} -H 'Accept: application/vnd.github+json' "https://api.github.com/$1"; }
gh_tags() { local j; j=$(gh_api "repos/$1/tags?per_page=100") || return 1; jq -r '.[].name' <<< "$j" | sed 's/^v//' | grep -E '^[0-9]+(\.[0-9]+)*$' | sort -V; }
# same_major CURRENT: reads versions on stdin, prints "<newest on the major of CURRENT>|<note>"
# (note = a newer major); split it with split_major
same_major() {
  local cur=$1 all top new note=''
  all=$(sort -V)
  new=$(grep -E "^${cur%%.*}\." <<< "$all" | tail -1 || true)
  top=$(tail -1 <<< "$all")
  if [ -n "$top" ] && [ "${top%%.*}" != "${cur%%.*}" ]; then note="major $top available"; fi
  echo "$new|$note"
}
# split_major "NEW|NOTE": sets new and note
split_major() { new=${1%%|*} note=${1#*|}; }

row COMPONENT CURRENT LATEST STATUS

# --- base image: digest of debian:<codename>-slim (a newer codename is only a note)
new='' note=''
token=$(fetch "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/debian:pull" | jq -r '.token // empty' || true)
if [ -n "$token" ]; then
  new=$(fetch -I -H "Authorization: Bearer $token" -H 'Accept: application/vnd.oci.image.index.v1+json' \
    "https://registry-1.docker.io/v2/library/debian/manifests/${DEBIAN_CODENAME}-slim" |
    tr -d '\r' | sed -n 's/^docker-content-digest: *//Ip' || true)
fi
stable=$(fetch https://deb.debian.org/debian/dists/stable/Release | sed -n 's/^Codename: *//p' || true)
[ -z "$stable" ] || [ "$stable" == "$DEBIAN_CODENAME" ] || note="Debian stable is now $stable"
lookup DEBIAN_DIGEST "${DEBIAN_DIGEST:7:12}" "${new:7:12}" "Docker Hub" "$DEBIAN_CODENAME-slim${note:+, $note}" ||
  propose "DEBIAN_DIGEST=$new"

# --- Adminer
split_major "$( (gh_tags vrana/adminer || true) | same_major "$ADMINER_VERSION")"
apply_pin ADMINER_VERSION
lookup ADMINER_VERSION "$ADMINER_VERSION" "$new" "GitHub API" "$note" ||
  propose "ADMINER_VERSION=$new" "ADMINER_SHA256=$(sha_of "https://github.com/vrana/adminer/releases/download/v$new/adminer-$new.php")"

# --- phpMyAdmin (version.json lists the newest release of each supported line)
split_major "$( (fetch https://www.phpmyadmin.net/home_page/version.json || true) | jq -r '.releases[]?.version' | same_major "$PMA_VERSION")"
apply_pin PMA_VERSION
lookup PMA_VERSION "$PMA_VERSION" "$new" "phpmyadmin.net" "$note" ||
  propose "PMA_VERSION=$new" "PMA_SHA256=$(sha_of "https://files.phpmyadmin.net/phpMyAdmin/$new/phpMyAdmin-$new-all-languages.tar.gz")"

# --- Zabbix: newest zabbix-release package of the ZABBIX_VERSION line for this Debian
debian_major=$(fetch "https://deb.debian.org/debian/dists/$DEBIAN_CODENAME/Release" | sed -n 's/^Version: *\([0-9]*\).*/\1/p' || true)
pool="https://repo.zabbix.com/zabbix/$ZABBIX_VERSION/debian/pool/main/z/zabbix-release/"
new=$(fetch "$pool" | grep -oE "zabbix-release_${ZABBIX_VERSION//./\\.}-[0-9]+\+debian${debian_major:-x}_all\.deb" |
  sed -E "s/^zabbix-release_([^+]+)\+.*/\1/" | sort -uV | tail -1 || true)
note=''
lines=$(fetch https://repo.zabbix.com/zabbix/ | grep -oE 'href="[0-9]+\.[0-9]+/"' | grep -oE '[0-9]+\.[0-9]+' | sort -V | tail -1 || true)
[ -z "$lines" ] || [ "$lines" == "$ZABBIX_VERSION" ] || note="line $lines available"
lookup ZABBIX_RELEASE "$ZABBIX_RELEASE" "$new" "repo.zabbix.com" "$note" ||
  propose "ZABBIX_RELEASE=$new" "ZABBIX_RELEASE_SHA256=$(sha_of "${pool}zabbix-release_${new}+debian${debian_major}_all.deb")"

# --- MySQL apt config package: the apt index of the MySQL repository for this codename
# (the download page of repo.mysql.com lags behind)
new=$( (fetch "https://repo.mysql.com/apt/debian/dists/$DEBIAN_CODENAME/mysql-apt-config/binary-amd64/Packages" || true) |
  awk '/^Package: mysql-apt-config$/{f=1} f&&/^Version:/{print $2; f=0}' | sort -V | tail -1) note=''
apply_pin MYSQL_APT_CONFIG_VERSION
lookup MYSQL_APT_CONFIG_VERSION "$MYSQL_APT_CONFIG_VERSION" "$new" "repo.mysql.com" "series mysql-$MYSQL_SERIES${note:+, $note}" ||
  propose "MYSQL_APT_CONFIG_VERSION=$new" "MYSQL_APT_CONFIG_SHA256=$(sha_of "https://repo.mysql.com/mysql-apt-config_${new}_all.deb")"

# --- Node.js: the major is changed by hand, only a newer LTS major is reported
new='' note=''
if j=$(fetch https://nodejs.org/dist/index.json); then
  lts=$(jq -r '[.[] | select(.lts != false) | .version | ltrimstr("v") | split(".")[0] | tonumber] | max' <<< "$j")
  new=$NODEJS_VERSION
  [ "$lts" -le "$NODEJS_VERSION" ] || note="LTS major $lts available"
fi
lookup NODEJS_VERSION "$NODEJS_VERSION" "$new" "nodejs.org" "$note" || true

# --- Cronicle
split_major "$( (gh_tags jhuckaby/Cronicle || true) | same_major "$CRONICLE_VERSION")"
apply_pin CRONICLE_VERSION
lookup CRONICLE_VERSION "$CRONICLE_VERSION" "$new" "GitHub API" "$note" ||
  propose "CRONICLE_VERSION=$new" "CRONICLE_SHA256=$(sha_of "https://github.com/jhuckaby/Cronicle/archive/v$new.tar.gz")"

# --- gcsfuse: newest package of the Google repository for this codename
new=$( (fetch "https://packages.cloud.google.com/apt/dists/gcsfuse-$DEBIAN_CODENAME/main/binary-amd64/Packages" || true) |
  awk '/^Package: gcsfuse$/{f=1} f&&/^Version:/{print $2; f=0}' | same_major "$GCSFUSE_VERSION")
split_major "$new"
apply_pin GCSFUSE_VERSION
lookup GCSFUSE_VERSION "$GCSFUSE_VERSION" "$new" "packages.cloud.google.com" "$note" || propose "GCSFUSE_VERSION=$new"

# --- izmysqlsync (tag archive)
new=$( (gh_tags ugoviti/izmysqlsync || true) | tail -1) note=''
apply_pin IZMYSQLSYNC_VER
lookup IZMYSQLSYNC_VER "$IZMYSQLSYNC_VER" "$new" "GitHub API" "$note" ||
  propose "IZMYSQLSYNC_VER=$new" "IZMYSQLSYNC_SHA256=$(sha_of "https://github.com/ugoviti/izmysqlsync/archive/$new.tar.gz")"

# --- izmysqlrestore (no tags: head of the default branch)
new=$(git ls-remote https://github.com/ugoviti/izmysqlrestore.git HEAD 2>/dev/null | cut -f1 || true)
lookup IZMYSQLRESTORE_COMMIT "${IZMYSQLRESTORE_COMMIT::12}" "${new::12}" "github.com" ||
  propose "IZMYSQLRESTORE_COMMIT=$new" "IZMYSQLRESTORE_SHA256=$(sha_of "https://raw.githubusercontent.com/ugoviti/izmysqlrestore/$new/izmysqlrestore")"

# --- mysqltuner (tag)
split_major "$( (gh_tags major/MySQLTuner-perl || true) | same_major "$MYSQLTUNER_VER")"
apply_pin MYSQLTUNER_VER
lookup MYSQLTUNER_VER "$MYSQLTUNER_VER" "$new" "GitHub API" "$note" ||
  propose "MYSQLTUNER_VER=$new" "MYSQLTUNER_SHA256=$(sha_of "https://raw.githubusercontent.com/major/MySQLTuner-perl/v$new/mysqltuner.pl")"

echo
[ "$unavailable" -eq 0 ] || echo "$unavailable lookup(s) unavailable: the report is incomplete" >&2
if [ "$updates" -eq 0 ]; then
  [ "$unavailable" -eq 0 ] || exit 2
  echo "all components are current"
  exit 0
fi
echo "$updates update(s) available, proposed versions.env lines:"
printf '  %s\n' "${proposals[@]}"
[ -n "$apply" ] || exit 10

# --- --apply: replace the KEY=value lines, all or nothing
for line in "${proposals[@]}"; do
  k=${line%%=*} v=${line#*=}
  [[ "$k" =~ ^[A-Z0-9_]+$ ]] || { echo "apply: invalid line '$line'" >&2; exit 1; }
  grep -q "^$k=" "$versions" || { echo "apply: $k is not in $versions" >&2; exit 1; }
  [ -n "$v" ] || { echo "apply: $k has no value (upstream lookup failed): nothing written" >&2; exit 1; }
  case "$k" in
    *_SHA256) [[ "$v" =~ ^[0-9a-f]{64}$ ]] || { echo "apply: $k is not a sha256 ('$v'): nothing written" >&2; exit 1; } ;;
    *_DIGEST) [[ "$v" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "apply: $k is not a digest ('$v'): nothing written" >&2; exit 1; } ;;
  esac
done
out=$(mktemp "$versions.XXXXXX")
awk 'NR == FNR { i = index($0, "="); val[substr($0, 1, i - 1)] = substr($0, i + 1); next }
     !/^#/ && (i = index($0, "=")) > 1 && ((k = substr($0, 1, i - 1)) in val) { print k "=" val[k]; next }
     { print }' <(printf '%s\n' "${proposals[@]}") "$versions" > "$out"
chmod --reference="$versions" "$out"
mv -f "$out" "$versions"
echo
echo "applied ${#proposals[@]} line(s) to $versions"
echo "next: tools/build.sh, test, bump APP_VER, then commit (git diff to review)"
[ "$unavailable" -eq 0 ] || exit 2
exit 0
