# Description
Production ready multi services Server Manager

# Supported tags
-	`1.0.5-BUILD`, `1.0.5`, `1.0`, `1`, `latest`

Where **BUILD** is the build number (look into project [Tags](tags/) page to discover the latest BUILD NUMBER)

# Dockerfile
- https://github.com/ugoviti/izdock/blob/master/server-manager/Dockerfile

# Features
- Small image footprint (based on **slim** version of [Linux Debian](/_/debian/) **buster** image)
- Many customizable variables to use
- Using [tini](https://github.com/krallin/tini) as init process
- Using supervisord for service management
- Supported services:
  - Rsyslog
  - Crond
  - OpenSSH
  - ProFTPd
  - Apache
  - PHP 7.3
  - phpMyAdmin
  - OpenVPN Server
  - nrpe agent
  - zabbix agent
- Automatic Users and Groups creation via external csv file

# What is Server Manager?
Server Manager is useful when you need a containerized full stack server within classic services running inside it.
For example an SSH server, FTP server, OpenVPN Client/Server, run cron jobs, etc...
For example you can use server-manager when you need a way to upload files via FTP inside your docker infrastructure shared by NFS server
You can automatically create users and group using ad formatted csv file

# How to use this image

```docker pull izdock/server-manager```

```docker run -it --rm izdock/server-manage```

You can test it by configuring your ssh client to use **container-ip:22**

If you need access outside the host, on port 21, 22, 80:
```docker run -it --rm -p 21:21 -p 22:22 -p 80:80 -p 222:222 izdock/postfix```

Run server-manager creating users and grups from external file:

```docker run -it --rm -p 21:21 -p 22:22 -p 80:80 -p 222:222 -e CSV_REMOVE=false -v /local/path/.users.csv:/.users.csv -v /local/path/.groups.csv:/.groups.csv izdock/postfix```

## Users csv file format:

```id;username;password;groups;home;shell```

Example:
```
1000;john;8EZyYtUNeNS8XSrz;sudo,admins,tomcat,www-data;;/bin/bash
1001;mario.rossi;HaDDoY2nUc7gnfdM;www-data;;/bin/bash
1002;webcommerce;sCoLSt7TCdP6GkDd;tomcat,www-data;/frontend/webcommerce;/sbin/nologin

```

## Groups csv file format:

```id;groupname```

Example:
```
512;admins
33;www-data
91;tomcat
```

# Environment variables

Follow all usable runtime environment variables with default values

```
## hostname configuration
: ${SERVERNAME:=$HOSTNAME}      # (**$HOSTNAME**) default web server hostname

## user and groups management
: ${CSV_USERS:="/.users.csv"}   # import users using this csv
: ${CSV_GROUPS:="/.groups.csv"} # import groups using this csv
: ${CSV_REMOVE:="true"}         # remove the import files for security reason

## security
: ${ROOT_PASSWORD:="$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 13 ; echo '')"} # default root password
: ${ROOT_MAILTO:="root@localhost"} # default root mail address

## supervisord services
: ${CRON_ENABLED:="true"}
: ${HTTPD_ENABLED:="true"}
: ${OPENVPN_ENABLED:="false"}
: ${SYSLOG_ENABLED:="true"}
: ${NRPE_ENABLED:="false"}
: ${ZABBIX_ENABLED:="false"}
: ${SSH_ENABLED:="true"}
: ${FTP_ENABLED:="true"}
: ${PMA_ENABLED:="true"}
: ${CERTBOT_ENABLED:="false"}
: ${MTA_ENABLED:="true"}
: ${POSTFIX_ENABLED:="false"}

## zabbix configuration
: ${ZABBIX_USR:="zabbix"}
: ${ZABBIX_GRP:="zabbix"}
: ${ZABBIX_SERVER:="127.0.0.1"}
: ${ZABBIX_SERVER_ACTIVE:="127.0.0.1"}
: ${ZABBIX_HOSTNAME:="${HOSTNAME}"}
: ${ZABBIX_HOSTMETADATA:="Linux"}

## service name mapping
: ${ZABBIX_DAEMON:="zabbix-agent"}
: ${SSH_DAEMON:="sshd"}
: ${FTP_DAEMON:="proftpd"}
: ${SYSLOG_DAEMON:="rsyslog"}

## ssh configuration
: ${SSH_PERMIT_ROOT:="yes"}
: ${SSH_PORT:=2222}
: ${SSH_SSL_KEYS_DIR:="/etc/ssh"}

## ftp service configuration
: ${FTP_PORT:=21}
: ${FTP_PASV_ADDR:="$(ip route|awk '/^default/ {print $3}')"}
: ${FTP_PASV_MIN:=21000}
: ${FTP_PASV_MAX:=21100}
: ${FTP_FTPS_ENABLED:="false"}
: ${FTP_FTPS_PORT:=990}
: ${FTP_FTPS_FORCED:="false"}
: ${FTP_SFTP_ENABLED:="true"}
: ${FTP_SFTP_PORT:=22}
: ${FTP_SSL_KEYS_DIR:="/etc/ssl/private"}

## http service configuration
: ${HTTPD_PORT:=80}

## smtp options
: ${domain:="$HOSTNAME"}                # local hostname
: ${from:="root@localhost.localdomain"} # default From email address
: ${host:="localhost"}                  # remote smtp server
: ${port:=25}                           # smtp port
: ${tls:="off"}                         # (**on**|**off**) enable tls
: ${starttls:="off"}                    # (**on**|**off**) enable starttls
: ${username:=""}                       # username for auth smtp server
: ${password:=""}                       # password for auth smtp server
: ${timeout:=3600}                      # connection timeout
```

### Configuration
Customize environment variables


# Quick reference

-	**Where to get help**:
	[InitZero Enterprise Support](https://www.initzero.it/)

-	**Where to file issues**:
	[https://github.com/ugoviti](https://github.com/ugoviti)

-	**Maintained by**:
	[Ugo Viti](https://github.com/ugoviti)

-	**Supported architectures**:
	[`amd64`]

-	**Supported Docker versions**:
	[the latest release](https://github.com/docker/docker-ce/releases/latest) (down to 1.6 on a best-effort basis)

# License

As with all Docker images, these likely also contain other software which may be under other licenses (such as Bash, etc from the base distribution, along with any direct or indirect dependencies of the primary software being contained).

As for any pre-built image usage, it is the image user's responsibility to ensure that any use of this image complies with any relevant licenses for all software contained within.
