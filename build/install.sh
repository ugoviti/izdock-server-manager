#!/bin/bash
# install.sh: the whole image build, run by the Dockerfile on top of the Debian slim image.
# Versions and sha256 come from versions.env only (build/lib.sh load_versions).
#   OS_UPDATE_STAMP (build arg)  changes every week in CI, so this layer (apt upgrade) is rebuilt
set -Eeuo pipefail

src=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=build/lib.sh
. "$src/build/lib.sh"
load_versions "$src/versions.env"

codename=$(. /etc/os-release && echo "${VERSION_CODENAME:-}")
[ "$codename" == "$DEBIAN_CODENAME" ] ||
  build_die "the base image is Debian '$codename', versions.env says DEBIAN_CODENAME=$DEBIAN_CODENAME"
tmp=$(mktemp -d)
keyrings=/etc/apt/keyrings

# repo_key NAME URL: armored or binary OpenPGP key into $keyrings/NAME.gpg (for signed-by=)
repo_key() {
  curl -fsSL --proto '=https' --connect-timeout 30 --retry 3 "$2" | gpg --dearmor --yes -o "$keyrings/$1.gpg"
  chmod 644 "$keyrings/$1.gpg"
}

echo "---------- OS packages (OS_UPDATE_STAMP=${OS_UPDATE_STAMP:-none})"
apt-get update
apt-get upgrade -y
apt-get install -y --no-install-recommends curl wget ca-certificates apt-utils gnupg dirmngr lsb-release debconf-utils
update-ca-certificates

echo "---------- extra apt repositories ($codename)"
install -d -m 755 "$keyrings"
# PostgreSQL (newest client)
repo_key pgdg https://www.postgresql.org/media/keys/ACCC4CF8.asc
echo "deb [signed-by=$keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt ${codename}-pgdg main" > /etc/apt/sources.list.d/pgdg.list
# Google Cloud Storage FUSE
repo_key gcsfuse https://packages.cloud.google.com/apt/doc/apt-key.gpg
echo "deb [signed-by=$keyrings/gcsfuse.gpg] https://packages.cloud.google.com/apt gcsfuse-${codename} main" > /etc/apt/sources.list.d/gcsfuse.list
# Node.js (NodeSource)
repo_key nodesource https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key
echo "deb [signed-by=$keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODEJS_VERSION}.x nodistro main" > /etc/apt/sources.list.d/nodesource.list
# MySQL (the package installs its own keyring and sources)
download "https://repo.mysql.com/mysql-apt-config_${MYSQL_APT_CONFIG_VERSION}_all.deb" "$MYSQL_APT_CONFIG_SHA256" "$tmp/mysql-apt-config.deb"
echo "mysql-apt-config mysql-apt-config/select-server select mysql-${MYSQL_SERIES}" | debconf-set-selections
apt-get install -y --no-install-recommends "$tmp/mysql-apt-config.deb"
# Zabbix (the package installs its own keyring and sources)
download "https://repo.zabbix.com/zabbix/${ZABBIX_VERSION}/debian/pool/main/z/zabbix-release/zabbix-release_${ZABBIX_RELEASE}+debian$(cut -d. -f1 /etc/debian_version)_all.deb" \
  "$ZABBIX_RELEASE_SHA256" "$tmp/zabbix-release.deb"
apt-get install -y --no-install-recommends "$tmp/zabbix-release.deb"

echo "---------- packages"
apt-get update
apt-get install -y --no-install-recommends \
  "gcsfuse=${GCSFUSE_VERSION}" \
  tini bash coreutils procps net-tools iproute2 iputils-ping gzip bzip2 file dos2unix xz-utils bc \
  jq vim less tar zip unzip 7zip netcat-openbsd dnsutils xauth imagemagick wget rsync screen \
  tcpdump fuse locales sudo fail2ban iptables supervisor rsyslog dma bsd-mailx cron \
  apache2 openssh-client openssh-server \
  proftpd-core proftpd-mod-crypto proftpd-mod-geoip proftpd-mod-geoip2 proftpd-mod-autohost \
  proftpd-mod-case proftpd-mod-counter proftpd-mod-fsync proftpd-mod-msg proftpd-mod-statsd \
  proftpd-mod-tar proftpd-mod-vroot \
  openvpn nagios-nrpe-server monitoring-plugins certbot tree git redis-tools sshpass task-spooler \
  ghostscript zbar-tools dbus composer mc lftp ftp gawk elinks postgresql-client \
  php php-common php-cli php-mysql php-zip php-gd php-mbstring php-curl php-xml php-bcmath \
  php-bz2 php-gmp php-pgsql libapache2-mod-php \
  mysql-community-client zabbix-agent2 zabbix-sender nodejs

echo "---------- tools"
download "https://github.com/ugoviti/izmysqlsync/archive/$IZMYSQLSYNC_VER.tar.gz" "$IZMYSQLSYNC_SHA256" "$tmp/izmysqlsync.tar.gz"
tar xzf "$tmp/izmysqlsync.tar.gz" --strip-components 1 -C /usr/local/bin/ "izmysqlsync-$IZMYSQLSYNC_VER/izmysqlsync"
download "https://raw.githubusercontent.com/ugoviti/izmysqlrestore/$IZMYSQLRESTORE_COMMIT/izmysqlrestore" "$IZMYSQLRESTORE_SHA256" /usr/local/bin/izmysqlrestore
download "https://raw.githubusercontent.com/major/MySQLTuner-perl/v$MYSQLTUNER_VER/mysqltuner.pl" "$MYSQLTUNER_SHA256" /usr/local/bin/mysqltuner.pl
chmod 755 /usr/local/bin/izmysqlsync /usr/local/bin/izmysqlrestore /usr/local/bin/mysqltuner.pl
# synbak: the package of the repository (files/), copied by the Dockerfile in /tmp
dpkg -i /tmp/synbak_*.deb

echo "---------- phpMyAdmin $PMA_VERSION, Adminer $ADMINER_VERSION"
download "https://files.phpmyadmin.net/phpMyAdmin/$PMA_VERSION/phpMyAdmin-$PMA_VERSION-all-languages.tar.gz" "$PMA_SHA256" "$tmp/pma.tar.gz"
mkdir -p /var/www/html/admin/pma /var/www/html/admin/adminer
tar -xzf "$tmp/pma.tar.gz" -C /var/www/html/admin/pma --strip-components=1
download "https://github.com/vrana/adminer/releases/download/v$ADMINER_VERSION/adminer-$ADMINER_VERSION.php" "$ADMINER_SHA256" /var/www/html/admin/adminer/index.php

echo "---------- Cronicle $CRONICLE_VERSION (node $(node -v))"
download "https://github.com/jhuckaby/Cronicle/archive/v$CRONICLE_VERSION.tar.gz" "$CRONICLE_SHA256" "$tmp/cronicle.tar.gz"
mkdir -p /usr/local/cronicle
tar -xzf "$tmp/cronicle.tar.gz" -C /usr/local/cronicle --strip-components 1
(cd /usr/local/cronicle && npm install --no-audit --no-fund && node bin/build.js dist)
rm -rf /root/.npm

echo "---------- layout"
mkdir -p /run/apache2
# merged /usr: /usr/bin/bash already exists on recent Debian
[ -e /usr/bin/bash ] || ln -s /bin/bash /usr/bin/bash
# postfix spool (volume of the Dockerfile)
mkdir -p /var/spool/postfix/pid
chown root: /var/spool/postfix/ /var/spool/postfix/pid

echo "---------- cleanup"
apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false
rm -rf /var/lib/apt/lists/* /tmp/* "$tmp"
