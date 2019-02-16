#!/bin/bash

## detect current operating system
: ${OS_RELEASE:="$(cat /etc/os-release | grep ^ID | awk -F"=" '{print $2}')"}
: ${HTTPD_CONF_DIR:=/etc/apache2} # (**/etc/apache2**) # apache config dir
PASSWORD_TYPE="$([ ${ROOT_PASSWORD} ] && echo preset || echo random)"

## app specific variables
: ${APP_DESCRIPTION:="Cloud Server Manager"}
: ${APP_CHART:=""}
: ${APP_RELEASE:=""}
: ${APP_NAMESPACE:=""}

## hostname configuration
: ${SERVERNAME:=$HOSTNAME}      # (**$HOSTNAME**) default web server hostname

## user and groups management
: ${CSV_IMPORT:="true"}         # create users and groups importing from csv files
: ${CSV_REMOVE:="true"}         # for security reasons, after importing user and groups, remove the csv files
: ${CSV_USERS:="/.users.csv"}   # import users using this csv
: ${CSV_GROUPS:="/.groups.csv"} # import groups using this csv

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

# operating system specific variables
if   [ "$OS_RELEASE" = "debian" ]; then
# debian paths
: ${SUPERVISOR_DIR:="/etc/supervisor/conf.d/"}
: ${PMA_DIR:="/var/www/html/admin/pma"}
: ${PMA_CONF:="$PMA_DIR/config.inc.php"}
#: ${PMA_CONF:="/etc/phpmyadmin/config.inc.php"}
: ${PMA_CONF_APACHE:="/etc/phpmyadmin/apache.conf"}
: ${PHP_CONF:="/etc/php/7.3/apache2/php.ini"}
: ${NRPE_CONF:="/etc/nagios/nrpe.cfg"}
: ${NRPE_CONF_LOCAL:="/etc/nagios/nrpe_local.cfg"}
: ${ZABBIX_CONF:="/etc/zabbix/zabbix_agentd.conf"}
: ${ZABBIX_CONF_LOCAL:="/etc/zabbix/zabbix_agentd.conf.d/local.conf"}
elif [ "$OS_RELEASE" = "alpine" ]; then
# alpine paths
: ${SUPERVISOR_DIR:="/etc/supervisor.d"}
: ${PMA_CONF:="/etc/phpmyadmin/config.inc.php"}
: ${PMA_CONF_APACHE:="/etc/apache2/conf.d/phpmyadmin.conf"}
: ${PHP_CONF:="/etc/php/php.ini"}
: ${NRPE_CONF:="/etc/nrpe.cfg"}
fi


# enable/disable and configure services
chkService() {
  local SERVICE_VAR="$1"
  eval local SERVICE_ENABLED="\$$(echo $SERVICE_VAR)"
  eval local SERVICE_DAEMON="\$$(echo $SERVICE_VAR | sed 's/_.*//')_DAEMON"
  local SERVICE="$(echo $SERVICE_VAR | sed 's/_.*//' | sed -e 's/\(.*\)/\L\1/')"
  [ -z "$SERVICE_DAEMON" ] && local SERVICE_DAEMON="$SERVICE"
  if [ "$SERVICE_ENABLED" = "true" ]; then
    autostart=true
    echo "=> Enabling $SERVICE_DAEMON service... because $SERVICE_VAR=$SERVICE_ENABLED"
    echo "--> Configuring $SERVICE_DAEMON service..."
    cfgService_$SERVICE
   else
    autostart=false
    echo "=> Disabling $SERVICE_DAEMON service... because $SERVICE_VAR=$SERVICE_ENABLED"
  fi
  sed "s/autostart=.*/autostart=$autostart/" -i ${SUPERVISOR_DIR}/$SERVICE_DAEMON.ini
}

## users management
# create csv users file from helm range function output
# example... map[id:1000 password:s3cur4PWD shell:/bin/bash username:initzero groups:sudo,admins,tomcat,www-data]
# NOT USED RIGHT NOW
mkCSVUsers() {
echo "id;username;password;groups;home;shell"
cat - | cut -d "[" -f2 | cut -d "]" -f1 | while read user; do
  for field in $user; do
    var="$(echo $field | cut -d':' -f1)"
    val="$(echo $field | cut -d':' -f2)"
    eval $var="$val"
  done
  echo "$id;$username;$password;$groups;$home;$shell"
done
}

# create groups if not exists (comma separated list)
groupsAdd() {
groups="$1"
for groupname in $(echo "$groups" | sed 's/,/ /g'); do
  if ! grep -q -E "^${groupname}:" /etc/group ; then
    echo "---> creating group '$groupname'"
    groupadd $([ ! -z "$id" ] && echo "-g $id") $groupname
    else
    echo "---> not creating already existent group '$groupname'"
  fi
done
}

# create user
userAdd() {
    echo "---> creating user '$username'"
    #set -x
    groupsAdd $username
    # create the basedir home directory if not exist
    [ ! -z "$home" ] && ([ ! -e "$(dirname $home)" ] && mkdir -p "$(dirname $home)")
    useradd $([ -n "$shell" ] && echo "-s $shell" || echo "-s /sbin/nologin") \
            $([ ! -z "$home" ] && echo "-d $home" || echo "-m") \
            $([   -e "$home" ] && echo "-M") \
            $([ ! -z "$id" ] && echo "-u $id") \
            -K UMASK=0007 -c "$username" -g "$username" $username;
    # set user password
    [ ! -z "$password" ] && echo $username:$password | chpasswd;
}

addCSVUsers() {
#if [ -z "$1" ] || [ ! -e "$1" ]; then echo "unable to fine input file $file. exiting..." && exit 1 ; fi

cat "$1" | grep -v "^id;" | while read line; do
  # csv fields order: id;username;password;groups;home;shell
  id="$(echo $line | cut -d';' -f1)"
  username="$(echo $line | cut -d';' -f2)"
  password="$(echo $line | cut -d';' -f3)"
  groups="$(echo $line | cut -d';' -f4)"
  home="$(echo $line | cut -d';' -f5)"
  shell="$(echo $line | cut -d';' -f6)"
  # create user
  userAdd
done
}

addCSVUsers2Groups() {
cat "$1" | grep -v "^id;" | while read line; do
  username="$(echo $line | cut -d';' -f2)"
  groups="$(echo $line | cut -d';' -f4)"
  for groupname in $(echo "$groups" | sed 's/,/ /g'); do
    if grep -q -E "^${groupname}:" /etc/group ;then
      echo "---> adding user '$username' to group '$groupname'"
      usermod -a -G $groupname $username
    fi
  done
done
}

addCSVGroups() {
#if [ -z "$1" ] || [ ! -e "$1" ]; then echo "unable to fine input file $file. exiting..." && exit 1 ; fi

cat "$1" | grep -v "^id;" | while read line; do
  # csv fields order: id;groupname
  id="$(echo $line | cut -d';' -f1)"
  groups="$(echo $line | cut -d';' -f2)"
  # create group
  groupsAdd $groups
done
}

## syslog service
cfgService_syslog() {
  # rsyslog daemon support
  echo '$ModLoad immark.so # provides --MARK-- message capability
  $ModLoad imuxsock.so # provides support for local system logging (e.g. via logger command)
  # default permissions for all log files.
  $FileOwner root
  $FileGroup adm
  $FileCreateMode 0640
  $DirCreateMode 0755
  $Umask 0022
  # log all to stdout
  *.* /dev/stdout
  ' > /etc/rsyslog.conf
}

## cron service
cfgService_cron() {
  cronDir="/var/spool/cron/crontabs"
  if [ -e "$cronDir" ]; then
    if [ "$(stat -c "%U %G %a" "$cronDir")" != "root crontab 1730" ];then
      echo "---> Fixing "$cronDir" permissions..."
      chown root:crontab "$cronDir"
      chmod u=rwx,g=wx,o=t "$cronDir"
    fi
    #origDir="$PWD"
    #cd "$cronDir"
    #for cronUser in *; do
    #  if [ "$(stat -c "%U %G %a" "$cronUser")" != "$cronUser crontab 600" ];then
    #    echo "---> Fixing $cronUser crontab permissions..."
    #    chown "$cronUser" "$cronUser"
    #    chmod 600 "$cronUser"
    #  fi
    #done
    #cd "$origDir"
  fi
}

## ssh service
cfgService_ssh() {
  sed "s/#PermitRootLogin.*/PermitRootLogin ${SSH_PERMIT_ROOT:-no}/" -i /etc/ssh/sshd_config
  sed "s/#Port.*/Port ${SSH_PORT:-22}/" -i /etc/ssh/sshd_config

  # replace rsa key if needed
  if [ ! -z "$SSH_SSL_KEYS_DIR" ];then
     if [ ! -e "$SSH_SSL_KEYS_DIR/ssh_host_rsa_key" ];then
      echo "---> Generating SSH server certificates into $SSH_SSL_KEYS_DIR"
      mkdir -p "$SSH_SSL_KEYS_DIR"
      ssh-keygen -f "$SSH_SSL_KEYS_DIR/ssh_host_rsa_key" -N '' -t rsa 1>/dev/null
     fi
     sed "s|#HostKey \/etc\/ssh\/ssh_host_rsa_key|HostKey $SSH_SSL_KEYS_DIR/ssh_host_rsa_key|" -i /etc/ssh/sshd_config
   else
     echo "---> Generating SSH server certificates into /etc/ssh"
     ssh-keygen -A 1>/dev/null
  fi
}


## ftp service
cfgService_ftp() {
  # user shell fixes
  echo "/sbin/nologin" >> /etc/shells
  # fix alpine proftpd
  mkdir -p /run/proftpd/
  chown $proftpd:$proftpd /run/proftpd/
  [ -f "/etc/proftpd/conf.d/sftp.conf" ] && mv /etc/proftpd/conf.d/sftp.conf /etc/proftpd/conf.d/sftp.conf-dist

  # tls support
  cn="${FTP_PASV_ADDR}"

  # Generate TLS Certificates if missing
  if [ ! -e "${FTP_SSL_KEYS_DIR}/${cn}.key" ] || [ ! -e "${FTP_SSL_KEYS_DIR}/${cn}.crt" ] ;then
    echo "---> INFO: generating TLS Certificates files used by system daemons into $FTP_SSL_KEYS_DIR"
    [ ! -e "${FTP_SSL_KEYS_DIR}" ] && install -m 0750 -g root -d "${FTP_SSL_KEYS_DIR}"
    openssl req -x509 -nodes -newkey rsa:2048 -keyout "${FTP_SSL_KEYS_DIR}/${cn}.key" -out "${FTP_SSL_KEYS_DIR}/${cn}.crt" -days 365 -subj "/O=Self Signed/OU=FTP Services/CN=$cn" 1>/dev/null
  fi

  [ "$FTP_ENABLED" = "true" ] && autostart=true || autostart=false
  sed "s/autostart=.*/autostart=$autostart/" -i ${SUPERVISOR_DIR}/${FTP_DAEMON}.ini

  # vsftpd config (DEPRECATED)
  print_vsftp_config() {
  echo "
  # general configuration
  ftpd_banner=Welcome to FTP Server
  listen=YES
  local_enable=YES
  chroot_local_user=YES
  allow_writeable_chroot=YES
  background=NO
  dirmessage_enable=YES
  max_clients=100
  max_per_ip=32
  write_enable=YES
  local_umask=002
  passwd_chroot_enable=yes
  listen_ipv6=NO
  hide_ids=YES

  # enable passive mode
  pasv_enable=YES
  pasv_addr_resolve=YES
  pasv_address=${FTP_PASV_ADDR}
  pasv_min_port=${FTP_PASV_MIN}
  pasv_max_port=${FTP_PASV_MAX}
  pasv_promiscuous=NO

  # enable active mode
  port_enable=YES
  connect_from_port_20=YES
  ftp_data_port=20

  # security command
  ls_recurse_enable=YES

  # avoid child died error
  seccomp_sandbox=NO

  # virtual user settings
  #guest_enable=YES
  #guest_username=ftp
  #user_config_dir=/etc/vsftpd/users

  # no anonymous users
  anonymous_enable=NO
  anon_upload_enable=NO
  anon_mkdir_write_enable=NO
  anon_other_write_enable=NO

  # logging Options
  dual_log_enable=NO
  log_ftp_protocol=NO
  syslog_enable=YES
  vsftpd_log_file=/var/log/vsftpd.log
  xferlog_enable=YES
  xferlog_std_format=NO

  # tls support
  ssl_enable=$([ "$FTP_FTPS_ENABLED" = "true" ] && echo YES || echo NO)
  #rsa_cert_file=${FTP_SSL_KEYS_DIR}/${FTP_PASV_ADDR}.crt
  #rsa_private_key_file=${FTP_SSL_KEYS_DIR}/${FTP_PASV_ADDR}.key
  allow_anon_ssl=NO
  force_local_data_ssl=YES
  force_local_logins_ssl=YES
  ssl_tlsv1=YES
  ssl_sslv2=NO
  ssl_sslv3=NO
  require_ssl_reuse=NO
  ssl_ciphers=HIGH
  "
  }

  # proftpd confi
  print_proftpd_config() {
  echo "
  # load modules
  <IfModule mod_dso.c>
  ModulePath /usr/lib/proftpd

  ModuleControlsACLs insmod,rmmod allow user root
  ModuleControlsACLs lsmod allow user *

  #LoadModule mod_ctrls_admin.c
  LoadModule mod_tls.c
  #LoadModule mod_radius.c
  #LoadModule mod_sql.c
  #LoadModule mod_sql_mysql.c
  #LoadModule mod_sql_passwd.c
  #LoadModule mod_quotatab_sql.c
  LoadModule mod_quotatab.c
  LoadModule mod_quotatab_file.c
  #LoadModule mod_quotatab_radius.c
  LoadModule mod_wrap.c
  LoadModule mod_rewrite.c
  LoadModule mod_load.c
  LoadModule mod_ban.c
  LoadModule mod_wrap2.c
  LoadModule mod_wrap2_file.c
  LoadModule mod_dynmasq.c
  LoadModule mod_exec.c
  LoadModule mod_shaper.c
  LoadModule mod_ratio.c
  LoadModule mod_site_misc.c
  LoadModule mod_sftp.c
  LoadModule mod_sftp_pam.c
  LoadModule mod_facl.c
  LoadModule mod_unique_id.c
  LoadModule mod_copy.c
  LoadModule mod_deflate.c
  LoadModule mod_ifversion.c
  LoadModule mod_tls_memcache.c
  LoadModule mod_ifsession.c
  LoadModule mod_vroot.c
  </IfModule>

  # server configuration
  ServerName        \"$APP_DESCRIPTION FTP Server\"
  ServerAdmin       $ROOT_MAILTO

  Port              0

  TimesGMT          on
  #SetEnv           TZ Europe/Rome

  ServerType        standalone
  DeferWelcome      on
  DefaultServer     on
  UseIPv6           off
  UseReverseDNS     off
  IdentLookups      off
  UseSendfile       off
  #AuthPAMConfig     proftpd
  #AuthOrder         mod_auth_pam.c* mod_auth_unix.c
  # If you use NIS/YP/LDAP you may need to disable PersistentPasswd
  #PersistentPasswd  off

  MaxInstances      30
  MaxClientsPerHost 30  \"Only %m connections per host allowed\"
  MaxClients        512 \"Only %m total simultanious logins allowed\"
  MaxHostsPerUser   30

  # define the log formats
  LogFormat         default \"%h %l %u %t '%r' %s %b\"
  LogFormat         auth    \"%v [%P] %h %t '%r' %s\"
  LogFormat         traff   \"%b %u\"
  LogFormat         awstats \"%t %h %u %m %f %s %b\"

  ScoreboardFile    /run/proftpd/proftpd.scoreboard

  <Global>
  ServerIdent       on \"$APP_DESCRIPTION FTP Server ready...\"
  Umask             002 002
  User              proftpd
  Group             nogroup
  DefaultRoot       ~ !admins
  AllowOverwrite    on
  WtmpLog           off

  DisplayLogin      /etc/proftpd/.welcome    # Textfile to display on login
  DisplayConnect    /etc/proftpd/.connect    # Textfile to display on connection
  DisplayChdir      /etc/proftpd/.firstchdir # Textfile to display on first changedir

  TransferLog       /var/log/xferlog
  ExtendedLog       /var/log/proftpd/access.log     READ,WRITE default
  ExtendedLog       /var/log/proftpd/auth.log       AUTH       auth
  ExtendedLog       /var/log/proftpd/traff.log      READ,WRITE traff
  ExtendedLog       /var/log/proftpd/awstats.log    READ,WRITE awstats
  #ExtendedLog       /var/log/proftpd/debug.log      ALL default
  #SQLLogFile        /var/log/proftpd/mysql.log
  QuotaLog          /var/log/proftpd/quota.log

  AllowStoreRestart on
  AllowRetrieveRestart on
  RequireValidShell on
  #PathDenyFilter    \"(\\.ftpaccess|\\.htaccess)$\"
  #DenyFilter        \*.*/

  # needed to force umask in sftp without errors
  #<Limit SITE_CHMOD>
  #  DenyAll
  #</Limit>

  <IfModule mod_vroot.c>
    VRootEngine     on
  </IfModule>

  <IfModule mod_delay.c>
    DelayEngine off
  </IfModule>

  # di default permetto connessioni non tls
  <IfModule mod_tls.c>
    TLSEngine                     off
    TLSRequired                   $([ "$FTP_FTPS_FORCED" = "true" ] && echo on || echo off)
    TLSRSACertificateFile         ${FTP_SSL_KEYS_DIR}/${FTP_PASV_ADDR}.crt
    TLSRSACertificateKeyFile      ${FTP_SSL_KEYS_DIR}/${FTP_PASV_ADDR}.key
    TLSCipherSuite                ALL:!ADH:!DES
    TLSOptions                    NoSessionReuseRequired
    TLSVerifyClient               off
    TLSRenegotiate                none
    #TLSRenegotiate               ctrl 3600 data 512000 required off timeout 300
    TLSLog                        /var/log/proftpd/tls.log
  </IfModule>
  </Global>

  <IfModule mod_tls.c>
    # dedicato al tls esplicito
    <VirtualHost 0.0.0.0>
    Port                          ${FTP_PORT}
    TLSEngine                     $([ "$FTP_FTPS_ENABLED" = "true" ] && echo on || echo off)
    MasqueradeAddress             ${FTP_PASV_ADDR}
    PassivePorts                  ${FTP_PASV_MIN} ${FTP_PASV_MAX}
    </VirtualHost>

    # ip dedicato al tls implicito
    <VirtualHost 0.0.0.0>
    TLSEngine                     on
    Port                          ${FTP_FTPS_PORT}
    TLSOptions                    UseImplicitSSL
    MasqueradeAddress             ${FTP_PASV_ADDR}
    PassivePorts                  ${FTP_PASV_MIN} ${FTP_PASV_MAX}
    </VirtualHost>
  </IfModule>

  <IfModule mod_sftp.c>
    <VirtualHost 0.0.0.0>
          SFTPEngine              $([ "$FTP_SFTP_ENABLED" = "true" ] && echo on || echo off)
          Port                    ${FTP_SFTP_PORT}
          SFTPLog                 /var/log/proftpd/sftp.log
          SFTPAuthorizedUserKeys  file:~/.sftp/authorized_keys
          SFTPHostKey             $SSH_SSL_KEYS_DIR/ssh_host_rsa_key
          SFTPAuthMethods         publickey password
          SFTPCompression         delayed
          MaxLoginAttempts        6
          SFTPOptions             IgnoreSFTPUploadPerms IgnoreSCPUploadPerms
    </VirtualHost>
  </IfModule>

  # Dynamic ban lists (http://www.proftpd.org/docs/contrib/mod_ban.html)
  <IfModule mod_ban.c>
    BanEngine                     on
    BanLog                        /var/log/proftpd/ban.log
    BanTable                      /var/run/proftpd/ban.tab

    # If the same client reaches the MaxLoginAttempts limit 2 times
    # within 10 minutes, automatically add a ban for that client that
    # will expire after one hour.
    BanOnEvent                    MaxLoginAttempts 5/00:10:00 00:30:00

    # Inform the user that it's not worth persisting
    BanMessage                    \"Host %a has been banned\"

    # Allow the FTP admin to manually add/remove bans
    BanControlsACLs               all allow user ftpadm
  </IfModule>

  Include /etc/proftpd/conf.d/*.conf
  "
  }

  [ -f /etc/${FTP_DAEMON}/${FTP_DAEMON}.conf ] && mv /etc/${FTP_DAEMON}/${FTP_DAEMON}.conf /etc/${FTP_DAEMON}/${FTP_DAEMON}.conf-dist
  print_${FTP_DAEMON}_config > /etc/${FTP_DAEMON}/${FTP_DAEMON}.conf
}


## nrpe service
cfgService_nrpe() {
 if   [ "$OS_RELEASE" = "debian" ]; then
  # nrpe user defined local config
  echo "
  allowed_hosts=127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
  debug=1
  dont_blame_nrpe=1
  allow_bash_command_substitution=1
  # hard coded right now
  command[check_disk_data]=/usr/lib/nagios/plugins/check_disk -w 20% -c 10% -p /data
  " > "$NRPE_CONF_LOCAL"
 elif [ "$OS_RELEASE" = "alpine" ]; then
  # nrpe global config
  if [ -w "$NRPE_CONF" ]; then
    #sed 's/log_facility=/#log_facility=/g' -i $NRPE_CONF
    sed 's/debug=.*/debug=1/g' -i $NRPE_CONF
    sed 's/allowed_hosts=.*/allowed_hosts=127.0.0.1,10.0.0.0\/8,172.16.0.0\/12,192.168.0.0\/16/g' -i $NRPE_CONF
    sed 's/#nrpe_user=/nrpe_user=/g' -i $NRPE_CONF
    sed 's/#nrpe_group=/nrpe_group=/g' -i $NRPE_CONF
    sed 's/dont_blame_nrpe=.*/dont_blame_nrpe=1/g' -i $NRPE_CONF
    sed 's/allow_bash_command_substitution=.*/allow_bash_command_substitution=1/g' -i $NRPE_CONF
    sed 's/#command/command/g' -i $NRPE_CONF
  fi
 fi
}

## zabbix service
cfgService_zabbix() {
 if   [ "$OS_RELEASE" = "debian" ]; then
  # zabbix user defined local config
  echo "#DebugLevel=4
#LogFileSize=1
LogType=system
Hostname=${ZABBIX_HOSTNAME}
Server=${ZABBIX_SERVER}
ServerActive=${ZABBIX_SERVER_ACTIVE}
#HostMetadataItem=system.uname
HostMetadata=${ZABBIX_HOSTMETADATA}
" > "$ZABBIX_CONF_LOCAL"
  # zabbix global config
  if [ -w "$ZABBIX_CONF" ]; then
    sed 's/^LogFile=/#LogFile=/g' -i $ZABBIX_CONF
    #sed 's/^Hostname=/#Hostname=/g' -i $ZABBIX_CONF
    #sed 's/Hostname=.*/Hostname=${ZABBIX_HOSTNAME}/g' -i $ZABBIX_CONF
  fi
 fi
}


## openvpn service
cfgService_openvpn() {
  local funcPH=""
  #openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem
}

## apache service
cfgService_httpd() {
  echo "---> Configuring Apache ServerName to ${SERVERNAME}"
  if   [ "$OS_RELEASE" = "debian" ]; then
    sed "s/#ServerName .*/ServerName ${SERVERNAME}/" -i "${HTTPD_CONF_DIR}/sites-enabled/000-default.conf"
    echo "ServerName ${SERVERNAME}" >> "${HTTPD_CONF_DIR}/apache2.conf"
  elif [ "$OS_RELEASE" = "alpine" ]; then
    sed "s/^#ServerName.*/ServerName ${SERVERNAME}/" -i "${HTTPD_CONF_DIR}/httpd.conf"
  fi
  }

## phpmyadmin service
cfgService_pma() {
  echo "=> Configuring PHPMyAdmin..."
  # copy default sample config
  if [ ! -e "${PMA_CONF}" ];then
    cp "${PMA_DIR}/config.sample.inc.php" "${PMA_CONF}"
    sed "s/\$cfg\['blowfish_secret'\] =.*;/\$cfg\['blowfish_secret'\] = '$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)';/" -i ${PMA_CONF}
    sed 's/localhost/127.0.0.1/g' -i ${PMA_CONF}
    chown www-data:www-data ${PMA_CONF}
  fi
  # configure pma apache conf file if exist
  if [ -e "${PMA_CONF_APACHE}" ]; then
    sed 's@Alias /phpmyadmin@Alias /admin/pma@' -i ${PMA_CONF_APACHE}
    sed 's/Order allow,deny/#Order allow,deny/' -i ${PMA_CONF_APACHE}
    sed 's/Allow from all/Require all granted/' -i ${PMA_CONF_APACHE}
    sed 's/Require .*/Require ip ::1\nRequire ip 127.0.0.1\/8\nRequire ip 192.168.0.0\/16\nRequire ip 10.0.0.0\/8\nRequire ip 172.16.0.0\/12\n/' -i ${PMA_CONF_APACHE}
    # enable phpmyadmin virtual location
    [ "$OS_RELEASE" = "debian" ] && ln -s ${PMA_CONF_APACHE} /etc/apache2/conf-enabled/phpmyadmin.conf
  fi
}

# let's encrypt / certbot service
cfgService_certbot() {
  echo "=> Configuring Let's Encrypt SSL with certbot..."
  if [ ! -z "$CERT_DOMAIN" ] && [ ! -z "$CERT_MAIL" ] && [ ! -z "$CERT_WEBROOT" ]; then
    echo "--> Generating SSL certificate for '$CERT_DOMAIN' domain using '$CERT_WEBROOT' as webroot"
    certbot certonly -n --agree-tos --webroot -m $CERT_MAIL -w $CERT_WEBROOT -d $CERT_DOMAIN
  #else
  #  echo "No CERT_DOMAIN variable found, skipping ssl certificate creation"
  fi
}

cfgService_mta() {
## SSMTP MTA Agent
if [ -e "/usr/sbin/ssmtp" ]; then
 echo "=> Configuring SSMTP MTA..."
 mv /usr/sbin/sendmail /usr/sbin/sendmail.ssmtp
 print_ssmtp_conf() {
  #echo "rewriteDomain=$domain"
  #echo "FromLineOverride=$from"
  echo "hostname=$domain"
  echo "root=$from"
  echo "mailhub=$host"
  echo "UseTLS=$tls"
  echo "UseSTARTTLS=$starttls"
  if [ -n "$username" ] && [ -n "$password" ]; then
   echo "auth on"
   echo "AuthUser=$username"
   echo "AuthPass=$password"
  fi
 }
 print_ssmtp_conf > /etc/ssmtp/ssmtp.conf
fi

## MSMTP MTA Agent
if [ -e "/usr/bin/msmtp" ]; then
 echo "=> Configuring MSMTP MTA..."
 print_msmtp_conf() {
  echo "defaults"
  echo "logfile -"
  echo "account default"
  echo "domain $domain"
  echo "from $from"
  echo "host $host"
  echo "port $port"
  echo "tls $tls"
  echo "tls_starttls $starttls"
  echo "timeout $timeout"
  if [ -n "$username" ] && [ -n "$password" ]; then
    echo "auth on"
    echo "user $username"
    echo "password $password"
    #passwordeval gpg2 --no-tty -q -d /etc/msmtp-password.gpg
  fi
 }
 print_msmtp_conf > /etc/msmtp.conf
fi

## DMA MTA Agent
if [ -e "/usr/sbin/dma" ]; then
 echo "=> Configuring DMA MTA..."

 print_dma_conf() {
  [ $host ] && echo "SMARTHOST $host"
  [ $tls = "on" ] && echo "SECURETRANSFER"
  [ $starttls = "on" ] && echo "STARTTLS"
  [ $port ] && echo "PORT $port"
  [ $from ] && echo "MASQUERADE $from"
  echo "MAILNAME /etc/mailname"
 }
 print_auth_conf() {
  echo $([ ! -z "${username}" ] && echo -n "$username|")${host}$([ ! -z "${password}" ] && echo -n ":${password}|")
 }
 [ $domain ] && echo "$domain" > /etc/mailname
 print_dma_conf > /etc/dma/dma.conf
 print_auth_conf > /etc/dma/auth.conf
fi

echo -n "--> forwarding all emails to: $host"
[ -n "$username" ] && echo -n " using username: $username"
echo

## izdsendmail config
echo "--> Configuring izSendmail MTA Wrapper..."
[ -e "/usr/sbin/sendmail" ] && mv /usr/sbin/sendmail /usr/sbin/sendmail.dist
ln -s /usr/local/sbin/izsendmail /usr/sbin/sendmail
sed "s/;sendmail_path =.*/sendmail_path = \/usr\/local\/sbin\/izsendmail -t -i/" -i ${PHP_CONF}
sed "s/auto_prepend_file =.*/auto_prepend_file = \/usr\/local\/share\/izsendmail-env.php/" -i ${PHP_CONF}
}

## postfix service
cfgService_postfix() {
# Set up host name
if [ ! -z "$HOSTNAME" ]; then
	postconf -e myhostname="$HOSTNAME"
else
	postconf -# myhostname
fi

# Set up a relay host, if needed
if [ ! -z "$RELAYHOST" ]; then
	echo -n "- Forwarding all emails to $RELAYHOST"
	postconf -e relayhost=$RELAYHOST

	if [ -n "$RELAYHOST_USERNAME" ] && [ -n "$RELAYHOST_PASSWORD" ]; then
		echo " using username $RELAYHOST_USERNAME."
		echo "$RELAYHOST $RELAYHOST_USERNAME:$RELAYHOST_PASSWORD" >> /etc/postfix/sasl_passwd
		postmap hash:/etc/postfix/sasl_passwd
		postconf -e "smtp_sasl_auth_enable=yes"
		postconf -e "smtp_sasl_password_maps=hash:/etc/postfix/sasl_passwd"
		postconf -e "smtp_sasl_security_options=noanonymous"
	else
		echo " without any authentication. Make sure your server is configured to accept emails coming from this IP."
	fi
else
	echo "- Will try to deliver emails directly to the final server. Make sure your DNS is setup properly!"
	postconf -# relayhost
	postconf -# smtp_sasl_auth_enable
	postconf -# smtp_sasl_password_maps
	postconf -# smtp_sasl_security_options
fi

# Set up my networks to list only networks in the local loopback range
#network_table=/etc/postfix/network_table
#touch $network_table
#echo "127.0.0.0/8    any_value" >  $network_table
#echo "10.0.0.0/8     any_value" >> $network_table
#echo "172.16.0.0/12  any_value" >> $network_table
#echo "192.168.0.0/16 any_value" >> $network_table
## Ignore IPv6 for now
##echo "fd00::/8" >> $network_table
#postmap $network_table
#postconf -e mynetworks=hash:$network_table

if [ ! -z "$MYNETWORKS" ]; then
	postconf -e mynetworks=$MYNETWORKS
else
	postconf -e "mynetworks=127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
fi

# split with space
if [ ! -z "$ALLOWED_SENDER_DOMAINS" ]; then
	echo -n "- Setting up allowed SENDER domains:"
	allowed_senders=/etc/postfix/allowed_senders
	rm -f $allowed_senders $allowed_senders.db > /dev/null
	touch $allowed_senders
	for i in $ALLOWED_SENDER_DOMAINS; do
		echo -n " $i"
		echo -e "$i\tOK" >> $allowed_senders
	done
	echo
	postmap $allowed_senders

	postconf -e "smtpd_restriction_classes=allowed_domains_only"
	postconf -e "allowed_domains_only=permit_mynetworks, reject_non_fqdn_sender reject"
	postconf -e "smtpd_recipient_restrictions=reject_non_fqdn_recipient, reject_unknown_recipient_domain, reject_unverified_recipient, check_sender_access hash:$allowed_senders, reject"
else
	postconf -# "smtpd_restriction_classes"
	postconf -e "smtpd_recipient_restrictions=reject_non_fqdn_recipient,reject_unknown_recipient_domain,reject_unverified_recipient"
fi

# Use 587 (submission)
sed -i -r -e 's/^#submission/submission/' /etc/postfix/master.cf
}

## application hooks
hooks_always() {
echo "=> Executing $APP_DESCRIPTION configuration hooks 'always'..."

# save docker variables for later usage
for var in APP_NAME APP_DESCRIPTION APP_CHART APP_RELEASE APP_NAMESPACE; do eval echo $var='\"$(eval echo \$$var)\"' ; done >> /.dockerenv

## docker init commands
# reset root user .ssh directory permissions
[ -e "/root/.ssh" ] && chmod 750 "/root/.ssh"
# rename default /etc/skel/.bashrc file because we override it via /etc/profile.d/iz.sh
[ -e "/etc/skel/.bashrc" ] && mv "/etc/skel/.bashrc" "/etc/skel/.bashrc-${OS_RELEASE}"

# customize vim
echo "set paste
syntax on
set mouse-=a" >> /etc/vim/vimrc.local

# configure dynamic motd with colors
rm -f /etc/motd /etc/update-motd.d/10-uname
echo -E '#!/bin/sh
. /.dockerenv
export TERM=xterm-256color
echo "$(tput setaf 214)$APP_DESCRIPTION$(tput sgr0) :: $([ -n "$APP_CHART" ] && echo chart:[$(tput setaf 14)$APP_CHART$(tput sgr0)]) $([ -n "$APP_RELEASE" ] && echo release:[$(tput setaf 14)$APP_RELEASE$(tput sgr0)]) $([ -n "$APP_NAMESPACE" ] && echo namespace:[$(tput setaf 14)$APP_NAMESPACE$(tput sgr0)])"' > /etc/update-motd.d/10-server-manager && chmod 755 /etc/update-motd.d/10-server-manager;

# colorize bash prompt and vars
echo -E '## initZero customizations
export PATH=$PATH:~/bin

HISTSIZE=1000000
HISTFILESIZE=2000000

# no language files are installed, force to C
export LC_ALL=C

# misc useful aliases
alias d="ls -al"

# /etc/vim/vimrc is ignored if not exist ~/.vimrc
if [ ! -e ~/.vimrc ]; then touch ~/.vimrc; fi

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls="ls --color=auto"
fi

# InitZero deploy namespace management
domain="$(cat /etc/resolv.conf | grep ^search | cut -d" " -f2)"
namespace="${domain%%.*}"

case $namespace in
  prod) nm="\[\e[1;31m\].$namespace\[\e[m\]" ;;
  test) nm="\[\e[1;32m\].$namespace\[\e[m\]" ;;
  *)    nm="\[\e[1;36m\].$namespace\[\e[m\]" ;;
esac

# colors management: more info from https://wiki.archlinux.org/index.php/Bash/Prompt_customization_(Italiano)
case "$TERM" in
    xterm-color|*-256color)
      color_prompt=yes
      if [ $(id -u) -eq 0 ];then
        export PS1="\[\e[32m\][\[\e[m\]\[\e[0;31m\]\u\[\e[m\]\[\e[33m\]@\[\e[m\]\[\e[0;36m\]\h\[\e[m\]$nm \[\e[0;33m\]\w\[\e[m\]\[\e[32m\]]\[\e[m\]\[\e[0;31m\]\\$\[\e[m\] "
       else
        export PS1="\[\e[32m\][\[\e[m\]\[\e[1;32m\]\u\[\e[m\]\[\e[33m\]@\[\e[m\]\[\e[0;36m\]\h\[\e[m\]$nm \[\e[0;33m\]\w\[\e[m\]\[\e[32m\]]\[\e[m\]\[\e[1;32m\]\\$\[\e[m\] "
      fi
    ;;
esac
' > /etc/profile.d/iz.sh

# configure supervisord
if [ "$OS_RELEASE" = "debian" ]; then
  echo "=> Fixing supervisord config file..."
  sed 's|^files = .*|files = /etc/supervisor/conf.d/*.ini|' -i /etc/supervisor/supervisord.conf
  mkdir -p /var/log/supervisor /var/log/proftpd /var/log/dbconfig-common /var/log/apt/ /var/log/apache2/ /var/run/nagios/
  touch /var/log/wtmp /var/log/lastlog
  [ ! -e /sbin/nologin ] && ln -s /usr/sbin/nologin /sbin/nologin
fi

# configure /etc/aliases
[ ! -f /etc/aliases ] && echo "postmaster: root" > /etc/aliases
[ ${ROOT_MAILTO} ] && echo "root: ${ROOT_MAILTO}" >> /etc/aliases

# enable/disable and configure services
chkService SYSLOG_ENABLED
chkService CRON_ENABLED
chkService SSH_ENABLED
chkService FTP_ENABLED
chkService NRPE_ENABLED
chkService ZABBIX_ENABLED
chkService OPENVPN_ENABLED
chkService HTTPD_ENABLED
chkService POSTFIX_ENABLED
[ "${MTA_ENABLED}" = "true" ] && cfgService_mta
[ "${PMA_ENABLED}" = "true" ] && cfgService_pma
[ "${CERTBOT_ENABLED}" = "true" ] && cfgService_certbot

## rc.local compatibility script
[ -e "/etc/rc.local" ] && echo "=> Executing /etc/rc.local" && /etc/rc.local

if [ "$CSV_IMPORT" = "true" ]; then
  # if the CSV files are created on container startup (like Kubernetes PostStart Hook) the files can be written after some time, so manage this behavior
  [ ! -e "$CSV_GROUPS" ] && echo "=> INFO: The groups CSV file '$CSV_GROUPS' doesn't exist... waiting 30 seonds before continue" && sleep 30
  [ ! -e "$CSV_USERS" ] && echo "=> INFO: The users CSV file '$CSV_USERS' doesn't exist... waiting 30 seonds before continue" && sleep 30

  ## create users and groups if import file exist
  if [ -e "$CSV_GROUPS" ];then
      echo "=> Importing system groups via CSV '$CSV_GROUPS'"
      addCSVGroups "$CSV_GROUPS"
      [ "$CSV_REMOVE" = "true" ] && (echo "--> Removing imported CSV file '$CSV_GROUPS'" && rm -f "$CSV_GROUPS") || (echo "--> Keeping imported CSV '$CSV_GROUPS'")
    else
      echo "=> INFO: The groups CSV file '$CSV_GROUPS' doesn't exist... not importing"
  fi

  if [ -e "$CSV_USERS" ];then
      echo "=> Importing system users via CSV '$CSV_USERS'"
      addCSVUsers "$CSV_USERS"
      addCSVUsers2Groups "$CSV_USERS"
      [ "$CSV_REMOVE" = "true" ] && (echo "--> Removing imported CSV file '$CSV_USERS'" && rm -f "$CSV_USERS") || (echo "--> Keeping imported CSV '$CSV_USERS'")
    else
      echo "=> INFO: The users CSV file '$CSV_USERS' doesn't exist... not importing"
  fi
fi

## final messages
echo "========================================================================"
echo "=> Setting root user with a ${PASSWORD_TYPE} password in ${APP_DESCRIPTION}"
echo "root:${ROOT_PASSWORD}" | chpasswd
echo "=> Done!"
if [ "$PASSWORD_TYPE" = "random" ]; then
  echo "========================================================================"
  echo "You can now connect to $APP_DESCRIPTION appliance using the following ssh root password:"
  echo "  ${ROOT_PASSWORD}"
fi
}

hooks_oneshot() {
echo "=> Executing $APP_DESCRIPTION configuration hooks 'oneshot'..."

# save the configuration status for later usage with persistent volumes
touch "${CONF_DEFAULT}/.configured"
}

hooks_always
#[ ! -f "${CONF_DEFAULT}/.configured" ] && hooks_oneshot || echo "=> Detected $APP_DESCRIPTION configuration files already present in ${CONF_DEFAULT}... skipping automatic configuration"
