#!/bin/bash
# verify-image.sh: post-build checks run INSIDE the image, before it is published.
#   docker run -i --rm --entrypoint "" -e APP_VER_EXPECTED=1.14.3 IMAGE bash -s < verify-image.sh
# The expected component versions are read from the versions.env shipped in the image.
# Prints one OK/FAIL line per check, exit 1 if any check fails.
set -u

FAIL=0
ok() { echo "OK   $*"; }
ko() { echo "FAIL $*"; FAIL=1; }
has() { if [ -e "$1" ]; then ok "${2:-$1}"; else ko "${2:-$1} missing"; fi; }
cmd() { local c; for c in "$@"; do if command -v "$c" >/dev/null 2>&1; then ok "command $c"; else ko "command $c missing"; fi; done; }

src=/usr/src/server-manager
[ -r "$src/versions.env" ] || { ko "$src/versions.env missing"; exit 1; }
# shellcheck source=build/lib.sh
. "$src/build/lib.sh"
load_versions "$src/versions.env"

# base image: the Debian release of versions.env
codename=$(. /etc/os-release && echo "${VERSION_CODENAME:-}")
if [ "$codename" == "$DEBIAN_CODENAME" ]; then ok "Debian $codename $(cat /etc/debian_version)"; else ko "Debian '$codename', expected $DEBIAN_CODENAME"; fi

# image version: APP_VER of the image and of versions.env agree with the one CI built
expected=${APP_VER_EXPECTED:-}
[ -n "$expected" ] || ko "APP_VER_EXPECTED not set"
if [ "${APP_VER:-}" == "$expected" ]; then ok "APP_VER=$APP_VER"; else ko "APP_VER='${APP_VER:-}', expected $expected"; fi

# services and tools started by supervisord or used by the entrypoint
cmd tini supervisord rsyslogd cron sshd proftpd apache2ctl php openvpn nrpe zabbix_agent2 \
  certbot dma mysql mysqldump psql node npm gcsfuse 7z synbak izmysqlsync izmysqlrestore mysqltuner.pl

# Node.js major (NodeSource repository of NODEJS_VERSION)
node_ver=$(node -v 2>/dev/null | sed 's/^v//')
if [ "${node_ver%%.*}" == "$NODEJS_VERSION" ]; then ok "node $node_ver"; else ko "node '$node_ver', expected major $NODEJS_VERSION"; fi

# Cronicle
cronicle=/usr/local/cronicle
has "$cronicle/bin/control.sh"
cronicle_ver=$(jq -r '.version // empty' "$cronicle/package.json" 2>/dev/null)
if [ "$cronicle_ver" == "$CRONICLE_VERSION" ]; then ok "Cronicle $cronicle_ver"; else ko "Cronicle '$cronicle_ver', expected $CRONICLE_VERSION"; fi
has "$cronicle/htdocs/index.html" "Cronicle built (htdocs)"

# gcsfuse and MySQL client
gcs=$(gcsfuse --version 2>/dev/null | head -1)
if [[ "$gcs" == *"version $GCSFUSE_VERSION"* ]]; then ok "$gcs"; else ko "gcsfuse '$gcs', expected $GCSFUSE_VERSION"; fi
my=$(mysql --version 2>/dev/null)
if [[ "$my" == *" ${MYSQL_SERIES%%-*}."* ]]; then ok "$my"; else ko "mysql '$my', expected ${MYSQL_SERIES%%-*}.x"; fi

# Zabbix agent 2 release
zbx=$(zabbix_agent2 -V 2>/dev/null | head -1)
if [[ "$zbx" == *" $ZABBIX_VERSION."* ]]; then ok "$zbx"; else ko "zabbix_agent2 '$zbx', expected $ZABBIX_VERSION.x"; fi

# phpMyAdmin and Adminer
pma=/var/www/html/admin/pma
has "$pma/index.php" "phpMyAdmin"
if grep -qs "VERSION = '$PMA_VERSION'" "$pma/libraries/classes/Version.php"; then ok "phpMyAdmin $PMA_VERSION"; else ko "phpMyAdmin is not $PMA_VERSION"; fi
if grep -qs "version=$ADMINER_VERSION" /var/www/html/admin/adminer/index.php; then ok "Adminer $ADMINER_VERSION"; else ko "Adminer is not $ADMINER_VERSION"; fi

# PHP: the php.ini edited by the entrypoint (the one of the installed PHP, never a fixed version)
mapfile -t php_ini < <(ls -1 /etc/php/*/apache2/php.ini 2>/dev/null)
php_ver=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null)
if [ "${#php_ini[@]}" -eq 1 ] && [ "${php_ini[0]}" == "/etc/php/$php_ver/apache2/php.ini" ]; then ok "PHP $php_ver ${php_ini[0]}"; else ko "PHP $php_ver: apache2 php.ini '${php_ini[*]}'"; fi
if grep -qE '^: \$\{PHP_CONF:="/etc/php/[0-9]' /entrypoint-hooks.sh; then ko "/entrypoint-hooks.sh has a fixed PHP_CONF version"; else ok "PHP_CONF not fixed in /entrypoint-hooks.sh"; fi
mods=$(php -m 2>/dev/null)
for m in mysqli pdo_mysql pgsql pdo_pgsql gd mbstring curl xml zip bcmath gmp bz2 json; do
  if grep -qix "$m" <<< "$mods"; then ok "php $m"; else ko "php module $m missing"; fi
done

# Apache configuration of the image
if apache2ctl -t >/dev/null 2>&1; then ok "apache2ctl -t"; else ko "apache2ctl -t: $(apache2ctl -t 2>&1 | tail -1)"; fi

# izcertbot: a valid certificate must not be seen with a wrong CN (it would be moved away and
# requested again at every start). The check of izcertbot runs on two self-signed certificates:
# CN equal to the main domain, and main domain only in the SANs (certbot puts the first -d in the CN)
izc_check() { # SUBJECT SAN MAIN -> 0 when izcertbot keeps the certificate
  local d f
  d=$(mktemp -d); f="$d/fullchain.pem"
  openssl req -x509 -nodes -newkey rsa:2048 -keyout "$d/k" -out "$f" -days 1 -subj "$1" ${2:+-addext "subjectAltName=$2"} >/dev/null 2>&1
  # shellcheck disable=SC2034 # read by the lines of izcertbot evaluated below
  CERTBOT_FULLCHAIN=$f CERTBOT_DOMAIN_MAIN=$3
  eval "$(sed -n '/CERTBOT_CN="$(openssl/p; /CERTBOT_NAMES="$(printf/p' /usr/local/sbin/izcertbot)"
  rm -rf "$d"
  grep -qxF "$CERTBOT_DOMAIN_MAIN" <<< "${CERTBOT_NAMES:-}"
}
if izc_check "/CN=example.com" "" example.com; then ok "izcertbot: CN of a valid certificate"; else ko "izcertbot sees a wrong CN on a valid certificate (CN=example.com)"; fi
if izc_check "/CN=www.example.com" "DNS:example.com,DNS:www.example.com" example.com; then ok "izcertbot: main domain in the SANs"; else ko "izcertbot: main domain in the SANs not recognized"; fi
if izc_check "/CN=other.example.org" "" example.com; then ko "izcertbot: a certificate of another domain is accepted"; else ok "izcertbot: certificate of another domain recreated"; fi

# entrypoint
has /entrypoint.sh
has /entrypoint-hooks.sh

exit $FAIL
