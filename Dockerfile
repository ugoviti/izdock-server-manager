# syntax=docker/dockerfile:1
# check=skip=InvalidDefaultArgInFrom,SecretsUsedInArgOrEnv
# (IMAGE_FROM is always passed, no default on purpose; ROOT_PASSWORD is empty, set at runtime)
# izdock/server-manager: Cloud Native Server Manager (multi services, supervisord).
#
# Versions and sha256: versions.env (single source of truth). Build logic: build/install.sh.
# IMAGE_FROM has no default: it comes from versions.env (DEBIAN_CODENAME, DEBIAN_DIGEST).
#   tools/build.sh          local build (the same build args as CI)
# CI: .gitea/workflows/build.yml (build + verify), .gitea/workflows/publish.yml (Docker Hub + GitHub)
# docker run -it --rm --name server-manager izdock/server-manager:local
# docker exec -it server-manager bash

ARG IMAGE_FROM
FROM ${IMAGE_FROM}
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

LABEL maintainer="Ugo Viti <ugo.viti@initzero.it>"

## Application post init exported env variables
ENV APP_NAME="server-manager"
ENV APP_DESCRIPTION="Cloud Native Server Manager"
ENV APP_CHART=""
ENV APP_RELEASE=""
ENV APP_NAMESPACE=""

## full app version (APP_VER of versions.env, passed by tools/build.sh and CI)
ARG APP_VER
ENV APP_VER="${APP_VER}"

## debian apt warnings workaround
ENV DEBIAN_FRONTEND=noninteractive

## install: OS packages, extra repositories, tools, phpMyAdmin, Adminer, Cronicle (build/install.sh)
# OS_UPDATE_STAMP: changes every week in CI, so the cached OS upgrade layer is rebuilt
ARG OS_UPDATE_STAMP=""
COPY files/ /tmp/
COPY versions.env /usr/src/server-manager/versions.env
COPY build/ /usr/src/server-manager/build/
RUN /usr/src/server-manager/build/install.sh

# main variables
ENV ROOT_PASSWORD=""
ENV ROOT_MAILTO="root@localhost"

# supervisord services
ENV CRON_ENABLED="true"
ENV HTTPD_ENABLED="true"
ENV OPENVPN_ENABLED="false"
ENV SYSLOG_ENABLED="true"
ENV NRPE_ENABLED="false"
ENV ZABBIX_ENABLED="false"
ENV SSH_ENABLED="true"
ENV FTP_ENABLED="true"
ENV PMA_ENABLED="true"
ENV CERTBOT_ENABLED="false"
ENV MTA_ENABLED="true"
ENV POSTFIX_ENABLED="false"
ENV CRONICLE_ENABLED="false"

ENV ZABBIX_USR="zabbix"
ENV ZABBIX_GRP="zabbix"
ENV ZABBIX_SERVER="127.0.0.1"
ENV ZABBIX_SERVER_ACTIVE="127.0.0.1"
ENV ZABBIX_HOSTNAME=""
ENV ZABBIX_HOSTMETADATA="Linux"

ENV SSH_PERMIT_ROOT="yes"
ENV SSH_PORT=2222
ENV SSH_SSL_KEYS_DIR="/etc/ssh"

ENV FTP_PORT=21
ENV FTP_PASV_ADDR=""
ENV FTP_PASV_MIN=21000
ENV FTP_PASV_MAX=21100
ENV FTP_FTPS_ENABLED="false"
ENV FTP_FTPS_PORT=990
ENV FTP_FTPS_FORCED="false"
ENV FTP_SFTP_ENABLED="true"
ENV FTP_SFTP_PORT=22
ENV FTP_SSL_KEYS_DIR="/etc/ssl/private"

ENV HTTPD_PORT=80

ENV CRONICLE_PORT=3012

ENV CSV_USERS="/.users.csv"
ENV CSV_GROUPS="/.groups.csv"
ENV CSV_REMOVE="true"

# certbot support
ENV CSV_CERTBOT="/.certbot.csv"

# prepare the env
RUN install -m 0770 -o "${ZABBIX_USR}" -g "${ZABBIX_GRP}" -d /var/run/zabbix/ -d /var/log/zabbix/ \
  && rm -rf /etc/ssh/ssh_host_* \
  && mkdir -p /run/sshd \
  && mkdir -p /root/.ssh \
  && chmod 700 /root/.ssh

# define volumes
VOLUME [ "/var/spool/cron/crontabs", "/var/spool/postfix", "/etc/postfix", "/usr/local/cronicle/data", "/usr/local/cronicle/plugins", "/usr/local/cronicle/logs" ]

# exposed ports
EXPOSE ${SSH_PORT}/tcp ${FTP_PORT}/tcp ${FTP_FTPS_PORT}/tcp ${FTP_SFTP_PORT}/tcp ${FTP_PASV_MIN}-${FTP_PASV_MAX}/tcp ${HTTPD_PORT}/tcp ${CRONICLE_PORT}/tcp

# add files to container
COPY Dockerfile README.md /
COPY rootfs/ /

# container pre-entrypoint variables
ENV APP_RUNAS="false"
ENV MULTISERVICE="false"
ENV ENTRYPOINT_TINI="true"
ENV UMASK=0002

## CI args
ARG APP_VER_BUILD
ARG APP_BUILD_COMMIT
ARG APP_BUILD_DATE

# define other build variables
ENV APP_VER_BUILD="${APP_VER_BUILD}"
ENV APP_BUILD_COMMIT="${APP_BUILD_COMMIT}"
ENV APP_BUILD_DATE="${APP_BUILD_DATE}"

# start the container process
ENTRYPOINT ["/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisor/supervisord.conf"]
