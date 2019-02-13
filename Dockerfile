FROM golang:1.11.5-stretch AS gcsfuse
ENV GOPATH /go
RUN set -xe && go get -u github.com/googlecloudplatform/gcsfuse

FROM debian:buster-slim

MAINTAINER Ugo Viti <ugo.viti@initzero.it>

# Application post init exported env variables
ENV APP_NAME          "server-manager"
ENV APP_DESCRIPTION   "Cloud Server Manager"
ENV APP_CHART         ""
ENV APP_RELEASE       ""
ENV APP_NAMESPACE     ""

# debian apt warnings workaround
ENV DEBIAN_FRONTEND   noninteractive

# addons packages versions
#ENV TINI_VERSION      0.18.0
ENV PMA_VERSION       4.8.5
ENV ZABBIX_VERSION    4.0
ENV ZABBIX_BUILD      2
# install packages
RUN set -xe \
  # install curl and update ca certificates
  && apt-get update && apt-get install -y --no-install-recommends curl ca-certificates apt-utils gnupg software-properties-common dirmngr \
  && update-ca-certificates \
  && apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xF1656F24C74CD1D8 \
  && add-apt-repository 'deb [arch=amd64] https://mirrors.nxthost.com/mariadb/repo/10.2/debian buster main' \
  # zabbix agent
  && curl -fSL --connect-timeout 30 https://repo.zabbix.com/zabbix/${ZABBIX_VERSION}/debian/pool/main/z/zabbix-release/zabbix-release_${ZABBIX_VERSION}-${ZABBIX_BUILD}+stretch_all.deb -o /tmp/zabbix-release_${ZABBIX_VERSION}-${ZABBIX_BUILD}+stretch_all.deb \
  && dpkg -i /tmp/zabbix-release_${ZABBIX_VERSION}-${ZABBIX_BUILD}+stretch_all.deb \
  && rm -f /tmp/zabbix-release_${ZABBIX_VERSION}-${ZABBIX_BUILD}+stretch_all.deb \
  # stretch php 7.3 support
#  && curl -fSL --connect-timeout 30 https://packages.sury.org/php/apt.gpg -o /etc/apt/trusted.gpg.d/php.gpg \
#  && echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/php7.3.list \
#  && apt-get update && apt-get upgrade -y \
  # upgrade the system
  && apt-get update && apt-get upgrade -y \
  # instal all needed packages
  && apt-get install -y --no-install-recommends \
    tini \
    bash \
   	coreutils \
    procps \
    net-tools \
    iputils-ping \
    gzip \
    bzip2 \
    file \
    dos2unix \
    xz-utils \
    bc \
    lsb-release \
    apt-transport-https \
    jq \
    vim \
    less \
    tar \
    zip \
    unzip \
    p7zip \
    netcat-openbsd \
    dnsutils \
    xauth \
    imagemagick \
    wget \
    rsync \
    screen \
    tcpdump \
    fuse \
    locales \
    sudo \
    fail2ban \
    iptables \
    supervisor \
    rsyslog \
    dma \
    bsd-mailx \
    cron \
    apache2 \
    openssh-client \
    openssh-server \
    proftpd \
    proftpd-mod-vroot \
    openvpn \
    nagios-nrpe-server \
    monitoring-plugins \
    certbot \
    # install mariadb 10.2 because in default 10.3 exist this problem https://jira.mariadb.org/browse/MDEV-17429
    mariadb-client-10.2 \
    sysbench \
    mc \
    zabbix-agent \
    php7.3 php7.3-common php7.3-cli php7.3-fpm php7.3-json php7.3-mysql php7.3-zip php7.3-gd php7.3-mbstring php7.3-curl php7.3-xml php7.3-bcmath php7.3-json php7.3-bz2 php7.3-mbstring libapache2-mod-php7.3 \
  # phpmyadmin config
  && mkdir -p /var/www/html/admin/pma \
  && curl -fSL --connect-timeout 30 https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.tar.gz | tar -xz -C /var/www/html/admin/pma --strip-components=1 \
  # apache config
  && mkdir -p /run/apache2 \
  # postfix config
  && mkdir -p /var/spool/postfix/ \
  && mkdir -p /var/spool/postfix/pid \
  && chown root: /var/spool/postfix/ \
  && chown root: /var/spool/postfix/pid \
  # cleanup system
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/* /tmp/*

# install gcsfuse
COPY --from=gcsfuse /go/bin/gcsfuse /usr/local/bin/

# main variables
ENV ROOT_PASSWORD     ""
ENV ROOT_MAILTO       "root@localhost"

# supervisord services
ENV CRON_ENABLED      "true"
ENV HTTPD_ENABLED     "true"
ENV OPENVPN_ENABLED   "false"
ENV SYSLOG_ENABLED    "true"
ENV NRPE_ENABLED      "false"
ENV ZABBIX_ENABLED    "false"
ENV SSH_ENABLED       "true"
ENV FTP_ENABLED       "true"
ENV PMA_ENABLED       "true"
ENV CERTBOT_ENABLED   "false"
ENV MTA_ENABLED       "true"
ENV POSTFIX_ENABLED   "false"

ENV ZABBIX_USR        "zabbix"
ENV ZABBIX_GRP        "zabbix"
ENV ZABBIX_SERVER     "127.0.0.1"
ENV ZABBIX_SERVER_ACTIVE "127.0.0.1"
ENV ZABBIX_HOSTNAME   ""
ENV ZABBIX_HOSTMETADATA "Linux"

ENV SSH_PERMIT_ROOT   "yes"
ENV SSH_PORT          2222
ENV SSH_SSL_KEYS_DIR  "/etc/ssh"

ENV FTP_PORT          21
ENV FTP_PASV_ADDR     ""
ENV FTP_PASV_MIN      21000
ENV FTP_PASV_MAX      21100
ENV FTP_FTPS_ENABLED  "false"
ENV FTP_FTPS_PORT     990
ENV FTP_FTPS_FORCED   "false"
ENV FTP_SFTP_ENABLED  "true"
ENV FTP_SFTP_PORT     22
ENV FTP_SSL_KEYS_DIR  "/etc/ssl/private"

ENV HTTPD_PORT        80

ENV CSV_USERS         "/.users.csv"
ENV CSV_GROUPS        "/.groups.csv"
ENV CSV_REMOVE        "true"

# certbot support (TEST)
ENV CERT_DOMAIN       ""
ENV CERT_MAIL         ""
ENV CERT_WEBROOT      ""

# add files to container
ADD Dockerfile filesystem /

# prepare the env
RUN set -xe \
  && install -m 0770 -o ${ZABBIX_USR} -g ${ZABBIX_GRP} -d /var/run/zabbix/ -d /var/log/zabbix/ \
  && rm -rf /etc/ssh/ssh_host_* \
  #&& ssh-keygen -A \
  && mkdir -p /run/sshd \
  && mkdir -p /root/.ssh \
  && chmod 700 /root/.ssh

# define volumes
VOLUME	[ "/var/spool/cron/crontabs", "/var/spool/postfix", "/etc/postfix" ]

# exposed ports
EXPOSE ${SSH_PORT}/tcp ${FTP_PORT}/tcp ${FTP_FTPS_PORT}/tcp ${FTP_SFTP_PORT}/tcp ${FTP_PASV_MIN}-${FTP_PASV_MAX}/tcp ${HTTPD_PORT}/tcp

# container pre-entrypoint variables
ENV MULTISERVICE    "false"
ENV ENTRYPOINT_TINI "true"
ENV UMASK           0002

# add files to container
ADD Dockerfile filesystem VERSION README.md /

# start the container process
ENTRYPOINT ["/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisor/supervisord.conf"]
