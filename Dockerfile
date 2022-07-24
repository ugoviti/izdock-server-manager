# docker build --pull --rm --build-arg APP_DEBUG=1 --build-arg APP_VER_BUILD=1 --build-arg APP_BUILD_COMMIT=fffffff --build-arg APP_BUILD_DATE=$(date +%s) -t server-manager .
# docker run -it --rm --name server-manager server-manager
# docker exec -it server-manager bash
# test build

# https://hub.docker.com/_/golang
#FROM golang:1.18.4-bullseye AS gcsfuse
#ENV GOPATH /go
#RUN set -xe && go get -u github.com/googlecloudplatform/gcsfuse

# https://hub.docker.com/_/debian
FROM debian:bullseye-slim

MAINTAINER Ugo Viti <ugo.viti@initzero.it>

# Application post init exported env variables
ENV APP_NAME          "server-manager"
ENV APP_DESCRIPTION   "Cloud Native Server Manager"
ENV APP_CHART         ""
ENV APP_RELEASE       ""
ENV APP_NAMESPACE     ""

# full app version
ARG APP_VER
ENV APP_VER "${APP_VER}"

# debian apt warnings workaround
ENV DEBIAN_FRONTEND   noninteractive

# addons packages versions
# https://www.phpmyadmin.net/downloads/
ENV PMA_VERSION       5.2.0

ENV ZABBIX_VERSION    6.2
#ENV ZABBIX_BUILD      2

ADD files /tmp

# install packages
RUN set -xe && \
  # install curl and update ca certificates
  apt update && apt install -y --no-install-recommends curl ca-certificates apt-utils gnupg software-properties-common dirmngr && \
  update-ca-certificates && \
  # install extra repositories
  echo "deb http://packages.cloud.google.com/apt gcsfuse-buster main" | tee /etc/apt/sources.list.d/gcsfuse.list && \
  curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add - && \
  # upgrade the system
  apt update && apt upgrade -y && \
  # instal all needed packages
  apt install -y --no-install-recommends \
    gcsfuse \
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
    proftpd-basic \
    proftpd-core \
    proftpd-mod-crypto \
    proftpd-mod-geoip \
    proftpd-mod-autohost \
    proftpd-mod-case \
    proftpd-mod-counter \
    proftpd-mod-fsync \
    proftpd-mod-msg \
    proftpd-mod-geoip2 \
    proftpd-mod-msg \
    proftpd-mod-statsd \
    proftpd-mod-tar \
    proftpd-mod-vroot \
    openvpn \
    nagios-nrpe-server \
    monitoring-plugins \
    certbot \
    tree \
    git \
    redis-tools \
    sshpass \
    nodejs \
    task-spooler \
    ghostscript \
    zbar-tools \
    dbus \
    composer \
    mc \
    lftp \
    ftp \
    gawk \
    php php-common php-cli php-json php-mysql php-zip php-gd php-mbstring php-curl php-xml php-bcmath php-json php-bz2 php-mbstring libapache2-mod-php \
    && \
  \
  # add repo mariadb 10.2 (because in default 10.3 exist this problem https://jira.mariadb.org/browse/MDEV-17429)
  #apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xF1656F24C74CD1D8 && \
  #add-apt-repository "deb [arch=amd64] http://mirror.biznetgio.com/mariadb/repo/10.2/debian stretch main" && \
  \
  # add repo mysql 8
  curl -fSL --connect-timeout 30 https://repo.mysql.com/mysql-apt-config_0.8.22-1_all.deb -o /tmp/mysql-apt-config_0.8.22-1_all.deb && \
  echo mysql-apt-config mysql-apt-config/select-server select mysql-8.0 | debconf-set-selections && \
  dpkg -i /tmp/mysql-apt-config_0.8.22-1_all.deb && \
  rm -f /tmp/mysql-apt-config_0.8.22-1_all.deb && \
  \
  # add repo zabbix agent
  curl -fSL --connect-timeout 30 http://repo.zabbix.com/zabbix/${ZABBIX_VERSION}/debian/pool/main/z/zabbix-release/zabbix-release_${ZABBIX_VERSION}-1+debian10_all.deb -o zabbix-release_${ZABBIX_VERSION}-1+debian10_all.deb && \
  dpkg -i zabbix-release_${ZABBIX_VERSION}-1+debian10_all.deb && rm -f zabbix-release_${ZABBIX_VERSION}-1+debian10_all.deb && \
  \
  # add repo sysbench
  #curl -fSL --connect-timeout 30 https://packagecloud.io/install/repositories/akopytov/sysbench/script.deb.sh | bash && \
  \
  # update apt cache
  apt update && \
  \
  # install mariadb 10.2
  #apt -y install mariadb-client mariadb-client-10.2 && \
  # install mysql 8
  apt -y install mysql-community-client && \
  # install zabbix agent
  apt -y install zabbix-agent2 zabbix-sender && \
  # install sysbench
  #apt -y install sysbench && \
  \
  # install izmysqlsync
  curl -fSL --connect-timeout 30 https://raw.githubusercontent.com/ugoviti/izmysqlsync/master/izmysqlsync -o /usr/local/bin/izmysqlsync && \
  chmod 755 /usr/local/bin/izmysqlsync && \
  # phpmyadmin config
  mkdir -p /var/www/html/admin/pma && \
  curl -fSL --connect-timeout 30 https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.tar.gz | tar -xz -C /var/www/html/admin/pma --strip-components=1 && \
  # apache config
  mkdir -p /run/apache2 && \
  # install synbak
  dpkg -i /tmp/synbak*.deb && \
  rm -f /tmp/synbak*.deb && \
  # fix bash path
  ln -s /bin/bash /usr/bin/bash && \
  # postfix config
  mkdir -p /var/spool/postfix/ && \
  mkdir -p /var/spool/postfix/pid && \
  chown root: /var/spool/postfix/ && \
  chown root: /var/spool/postfix/pid && \
  # cleanup system
  apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false && \
  rm -rf /var/lib/apt/lists/* /tmp/*

# install gcsfuse
#COPY --from=gcsfuse /go/bin/gcsfuse /usr/local/bin/

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

# certbot support
ENV CSV_CERTBOT       "/.certbot.csv"

# prepare the env
RUN set -xe \
  && install -m 0770 -o ${ZABBIX_USR} -g ${ZABBIX_GRP} -d /var/run/zabbix/ -d /var/log/zabbix/ \
  && rm -rf /etc/ssh/ssh_host_* \
  #&& ssh-keygen -A \
  && mkdir -p /run/sshd \
  && mkdir -p /root/.ssh \
  && chmod 700 /root/.ssh

# define volumes
VOLUME [ "/var/spool/cron/crontabs", "/var/spool/postfix", "/etc/postfix" ]

# exposed ports
EXPOSE ${SSH_PORT}/tcp ${FTP_PORT}/tcp ${FTP_FTPS_PORT}/tcp ${FTP_SFTP_PORT}/tcp ${FTP_PASV_MIN}-${FTP_PASV_MAX}/tcp ${HTTPD_PORT}/tcp

# add files to container
ADD Dockerfile rootfs README.md /

# container pre-entrypoint variables
ENV APP_RUNAS          "false"
ENV MULTISERVICE       "false"
ENV ENTRYPOINT_TINI    "true"
ENV UMASK              0002

## CI args
ARG APP_VER_BUILD
ARG APP_BUILD_COMMIT
ARG APP_BUILD_DATE

# define other build variables
ENV APP_VER_BUILD    "${APP_VER_BUILD}"
ENV APP_BUILD_COMMIT "${APP_BUILD_COMMIT}"
ENV APP_BUILD_DATE   "${APP_BUILD_DATE}"

# start the container process
ENTRYPOINT ["/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisor/supervisord.conf"]
