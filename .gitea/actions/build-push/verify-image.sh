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
. "$src/lib.sh"
load_versions "$src/versions.env"

# image version: APP_VER of the image and of versions.env agree with the one CI built
expected=${APP_VER_EXPECTED:-}
[ -n "$expected" ] || ko "APP_VER_EXPECTED not set"
if [ "${APP_VER:-}" == "$expected" ]; then ok "APP_VER=$APP_VER"; else ko "APP_VER='${APP_VER:-}', expected $expected"; fi

# services and tools started by supervisord or used by the entrypoint
cmd tini supervisord rsyslogd cron sshd proftpd apache2ctl php openvpn nrpe zabbix_agent2 \
  certbot dma mysql mysqldump psql node npm gcsfuse synbak izmysqlsync izmysqlrestore mysqltuner.pl

# Node.js major (NodeSource repository of NODEJS_VERSION)
node_ver=$(node -v 2>/dev/null | sed 's/^v//')
if [ "${node_ver%%.*}" == "$NODEJS_VERSION" ]; then ok "node $node_ver"; else ko "node '$node_ver', expected major $NODEJS_VERSION"; fi

# Cronicle
cronicle=/usr/local/cronicle
has "$cronicle/bin/control.sh"
cronicle_ver=$(sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' "$cronicle/package.json" 2>/dev/null | head -1)
if [ "$cronicle_ver" == "$CRONICLE_VERSION" ]; then ok "Cronicle $cronicle_ver"; else ko "Cronicle '$cronicle_ver', expected $CRONICLE_VERSION"; fi
has "$cronicle/htdocs/index.html" "Cronicle built (htdocs)"

# Zabbix agent 2 release
zbx=$(zabbix_agent2 -V 2>/dev/null | head -1)
if [[ "$zbx" == *" $ZABBIX_VERSION."* ]]; then ok "$zbx"; else ko "zabbix_agent2 '$zbx', expected $ZABBIX_VERSION.x"; fi

# phpMyAdmin and Adminer
pma=/var/www/html/admin/pma
has "$pma/index.php" "phpMyAdmin"
if grep -qs "VERSION = '$PMA_VERSION'" "$pma/libraries/classes/Version.php"; then ok "phpMyAdmin $PMA_VERSION"; else ko "phpMyAdmin is not $PMA_VERSION"; fi
if grep -qs "version=$ADMINER_VERSION" /var/www/html/admin/adminer/index.php; then ok "Adminer $ADMINER_VERSION"; else ko "Adminer is not $ADMINER_VERSION"; fi

# PHP: the php.ini edited by the entrypoint (PHP_CONF default of the Debian branch) and the modules
php_conf=$(sed -n 's/^: \${PHP_CONF:="\([^"]*\)"}.*/\1/p' /entrypoint-hooks.sh | head -1)
if [ -n "$php_conf" ] && [ -w "$php_conf" ]; then ok "PHP_CONF $php_conf"; else ko "PHP_CONF '$php_conf' of /entrypoint-hooks.sh not found (PHP $(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null))"; fi
mods=$(php -m 2>/dev/null)
for m in mysqli pdo_mysql pgsql pdo_pgsql gd mbstring curl xml zip bcmath gmp bz2 json; do
  if grep -qix "$m" <<< "$mods"; then ok "php $m"; else ko "php module $m missing"; fi
done

# Apache configuration of the image
if apache2ctl -t >/dev/null 2>&1; then ok "apache2ctl -t"; else ko "apache2ctl -t: $(apache2ctl -t 2>&1 | tail -1)"; fi

# entrypoint
has /entrypoint.sh
has /entrypoint-hooks.sh

exit $FAIL
