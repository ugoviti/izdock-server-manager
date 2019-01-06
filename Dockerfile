FROM golang:1.11.4-stretch AS gcsfuse
ENV GOPATH /go
RUN set -xe && go get -u github.com/googlecloudplatform/gcsfuse

FROM debian:stretch-slim

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
ENV TINI_VERSION      0.18.0
ENV PMA_VERSION       4.8.4

# install packages
RUN set -xe \
  && apt-get update && apt-get upgrade -y \
  && apt-get install -y --no-install-recommends \
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
    ca-certificates \
    curl \
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
    msmtp \
    heirloom-mailx \
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
#    phpmyadmin \
  && update-ca-certificates \
  # php 7.3 support
  && curl -fSL --connect-timeout 30 https://packages.sury.org/php/apt.gpg -o /etc/apt/trusted.gpg.d/php.gpg \
  && echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/php7.3.list \
  && apt-get update && apt-get upgrade -y \
  && apt-get install -y --no-install-recommends \
    php7.3 php7.3-common php7.3-cli php7.3-fpm php7.3-json php7.3-mysql php7.3-zip php7.3-gd  php7.3-mbstring php7.3-curl php7.3-xml php7.3-bcmath php7.3-json php7.3-bz2 php7.3-mbstring libapache2-mod-php7.3 \
  #&& cd /etc/apache2/mods-enabled/ \
  #&& ln -s ../mods-available/php7.3.load \
  #&& ln -s ../mods-available/php7.3.conf \
  # phpmyadmin
  && mkdir -p /var/www/html/admin/pma \
  && curl -fSL --connect-timeout 30 https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.tar.gz | tar -xz -C /var/www/html/admin/pma --strip-components=1 \
  # install tini as init container
  && curl -fSL --connect-timeout 30 http://github.com/krallin/tini/releases/download/v${TINI_VERSION}/tini_${TINI_VERSION}-amd64.deb -o tini_${TINI_VERSION}-amd64.deb \
  && dpkg -i tini_$TINI_VERSION-amd64.deb \
  && rm -f tini_$TINI_VERSION-amd64.deb \
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

# main services
ENV CRON_ENABLED      "true"
ENV HTTPD_ENABLED     "true"
ENV OPENVPN_ENABLED   "false"
ENV SYSLOG_ENABLED    "true"
ENV NRPE_ENABLED      "false"
ENV SSH_ENABLED       "true"
ENV FTP_ENABLED       "true"
ENV PMA_ENABLED       "true"
ENV CERTBOT_ENABLED   "false"
ENV MTA_ENABLED       "true"
ENV POSTFIX_ENABLED   "false"

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
  && rm -rf /etc/ssh/ssh_host_* \
  #&& ssh-keygen -A \
  && mkdir -p /run/sshd \
  && mkdir -p /root/.ssh \
  && chmod 700 /root/.ssh

# define volumes
VOLUME	[ "/var/spool/cron/crontabs", "/var/spool/postfix", "/etc/postfix" ]

# exposed ports
EXPOSE ${SSH_PORT}/tcp ${FTP_PORT}/tcp ${FTP_FTPS_PORT}/tcp ${FTP_SFTP_PORT}/tcp ${FTP_PASV_MIN}-${FTP_PASV_MAX}/tcp ${HTTPD_PORT}/tcp

# init supervisord
ENTRYPOINT ["tini", "-g", "--"]
CMD ["/entrypoint.sh", "supervisord", "-c", "/etc/supervisor/supervisord.conf"]

ENV APP_VER "1.0.2-5"
