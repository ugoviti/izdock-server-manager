FROM golang:1.10.3-alpine3.8 AS gcsfuse
RUN apk add --no-cache git
ENV GOPATH /go
RUN go get -u github.com/googlecloudplatform/gcsfuse

FROM alpine:3.8

MAINTAINER Ugo Viti <ugo.viti@initzero.it>

ENV APP                   "CloudWMS Manager"
ENV APP_NAME              "server-manager"

ENV APP_ADMIN_PASSWORD    ""

ENV APP_SSH_ENABLE        "YES"
ENV APP_SSH_PORT          22
ENV APP_SSH_PERMIT_ROOT   "YES"
ENV APP_SSH_HOST_KEYS_DIR ""

ENV APP_FTP_ENABLE        "YES"
ENV APP_FTP_PORT          21
ENV APP_FTP_PASV_MIN      21000
ENV APP_FTP_PASV_MAX      21005
ENV APP_FTP_SSL           "NO"

ENV APP_OPENVPN_ENABLE    "NO"
ENV APP_NRPE_ENABLE       "YES"

# certbot support
ENV CERT_DOMAIN           ""
ENV CERT_MAIL             ""
ENV CERT_WEBROOT          ""

#RUN echo "@edge http://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories
RUN echo "@edgecommunity http://dl-cdn.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories
# 20180715 alpine 3.8 certbot fix for error: (pkg_resources.ContextualVersionConflict: (idna 2.7 (/usr/lib/python2.7/site-packages), Requirement.parse('idna<2.7,>=2.5'))
RUN echo "@v3.6 http://dl-cdn.alpinelinux.org/alpine/v3.6/main" >> /etc/apk/repositories

RUN apk --update --no-cache upgrade \
  && apk add \
	tini \
	runit \
	socklog \
	supervisor \
	coreutils \
	bash \
	bc \
	curl \
	file \
	vim \
	procps \
	tar \
	zip \
	gzip \
	bzip2 \
	xz \
	p7zip \
	netcat-openbsd \
	wget \
	rsync \
	openssh-client \
	openssh \
	vsftpd \
	apache2 \
	apache2-ctl \
	apache2-utils \
	phpmyadmin \
	php7-apache2 \
	php7-mbstring \
	php7-session \
	mysql-client \
	py2-future \
	screen \
	socat \
	openvpn \
	tcpdump \
	dcron \
	ca-certificates \
	fuse \
	heirloom-mailx \
	msmtp \
	openssl \
	nrpe \
	nagios-plugins-load \
	nagios-plugins-disk \
	nagios-plugins-procs \
	nagios-plugins-users \
	# 20180715 certbot fixes
	py-idna@v3.6 \
	py2-idna@v3.6 \
	py-requests-toolbelt@edgecommunity \
	py2-requests-toolbelt@edgecommunity \
	certbot \
#	py-acme@edgecommunity \
#	certbot@edgecommunity \
#	rsyslog \
#	ssmtp \
#	util-linux \
#	acct \
#	postfix \
#	apk-tools@edge \
### TEST
# && wget -q https://dl.eff.org/certbot-auto \
# && chmod a+x certbot-auto \
 && mkdir -p /run/apache2 \
# bash config
 && echo "alias d='ls -al'" > /etc/profile.d/iz.sh \
# postfix config
 && mkdir -p /var/spool/postfix/ \
 && mkdir -p /var/spool/postfix/pid \
 && chown root: /var/spool/postfix/ \
 && chown root: /var/spool/postfix/pid \
 && rm -rf /var/cache/apk/* /tmp/*

# alpine user www-data compatibility
RUN set -x \
	&& adduser -u 82 -D -S -G www-data www-data

# install gcsfuse
COPY --from=gcsfuse /go/bin/gcsfuse /usr/local/bin/

# rsyslog config
#RUN sed 's/mail.*/mail.info \/dev\/stdout/' -i /etc/rsyslog.conf

# add files to container
ADD Dockerfile /
ADD filesystem /

# prepare the env
RUN rm -rf /etc/ssh/ssh_host_* \
 && ssh-keygen -A \
 && mkdir /root/.ssh \
 && chmod 700 /root/.ssh

# define volumes
VOLUME	[ "/var/spool/cron/crontabs", "/var/spool/postfix", "/etc/postfix" ]

# exposed ports
EXPOSE ${APP_SSH_PORT}/tcp ${APP_FTP_PORT}/tcp ${APP_FTP_PASV_MIN}-${APP_FTP_PASV_MAX}/tcp 80/tcp

# init supervisord
ENTRYPOINT ["tini", "-g", "--"]
CMD ["/entrypoint.sh", "supervisord", "-c", "/etc/supervisord.conf"]

ENV APP_VER "3.8.0-4"
