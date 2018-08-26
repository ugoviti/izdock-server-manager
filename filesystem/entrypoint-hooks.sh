#!/bin/sh

# tomcat hooks
hooks_always() {
echo "=> Executing $APP configuration hooks 'always'..."
PASSWORD_TYPE=$([ ${APP_ADMIN_PASSWORD} ] && echo "preset" || echo "random")
APP_ADMIN_PASSWORD="${APP_ADMIN_PASSWORD:-$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 13 ; echo '')}"


echo "=> Configuring rsyslog logging server..."

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

echo "=> Configuring crond..."
echo "--> Fixing /var/spool/cron/crontabs/root permissions..."
chown root:root /var/spool/cron/crontabs/root

echo "=> Configuring SSH server..."
[ "$APP_SSH_ENABLE" = "YES" ] && sed "s/autostart=.*/autostart=true/" -i /etc/supervisor.d/sshd.ini
[ "$APP_SSH_ENABLE" = "NO" ] && sed "s/autostart=.*/autostart=false/" -i /etc/supervisor.d/sshd.ini
sed "s/#PermitRootLogin.*/PermitRootLogin ${APP_SSH_PERMIT_ROOT:-no}/" -i /etc/ssh/sshd_config
sed "s/#Port.*/Port ${APP_SSH_PORT:-22}/" -i /etc/ssh/sshd_config

# replace rsa key if needed
if [ -n "$APP_SSH_HOST_KEYS_DIR" ];then
 rm -f /etc/ssh/ssh_host_*
 if [ ! -e "$APP_SSH_HOST_KEYS_DIR/ssh_host_rsa_key" ];then
  mkdir -p "$APP_SSH_HOST_KEYS_DIR"
  ssh-keygen -f "$APP_SSH_HOST_KEYS_DIR/ssh_host_rsa_key" -N '' -t rsa
 fi
 sed "s|#HostKey \/etc\/ssh\/ssh_host_rsa_key|HostKey $APP_SSH_HOST_KEYS_DIR/ssh_host_rsa_key|" -i /etc/ssh/sshd_config
fi

echo "=> Configuring FTP server..."
[ "$APP_FTP_ENABLE" = "YES" ] && sed "s/autostart=.*/autostart=true/" -i /etc/supervisor.d/vsftpd.ini
[ "$APP_FTP_ENABLE" = "NO" ] && sed "s/autostart=.*/autostart=false/" -i /etc/supervisor.d/vsftpd.ini
# vsftpd config
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
pasv_enable=YES
pasv_min_port=${APP_FTP_PASV_MIN:-21000}
pasv_max_port=${APP_FTP_PASV_MAX:-21100}
pasv_promiscuous=YES
listen_ipv6=NO
hide_ids=YES

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
ssl_enable=${APP_FTP_SSL:-NO}
#rsa_cert_file=/etc/ssl/private/vsftpd.pem
#rsa_private_key_file=/etc/ssl/private/vsftpd.pem
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
print_vsftp_config > /etc/vsftpd/vsftpd.conf


if [ -w "/etc/nrpe.cfg" ]; then
echo "=> Configuring NRPE server..."
[ "$APP_NRPE_ENABLE" = "YES" ] && sed "s/autostart=.*/autostart=true/" -i /etc/supervisor.d/nrpe.ini || sed "s/autostart=.*/autostart=false/" -i /etc/supervisor.d/nrpe.ini
#sed 's/log_facility=/#log_facility=/g' -i /etc/nrpe.cfg
sed 's/allowed_hosts=.*/allowed_hosts=127.0.0.1,10.0.0.0\/8,172.16.0.0\/12,192.168.0.0\/16/g' -i /etc/nrpe.cfg
sed 's/#nrpe_user=/nrpe_user=/g' -i /etc/nrpe.cfg
sed 's/#nrpe_group=/nrpe_group=/g' -i /etc/nrpe.cfg
sed 's/dont_blame_nrpe=.*/dont_blame_nrpe=1/g' -i /etc/nrpe.cfg
sed 's/#allow_bash_command_substitution=.*/allow_bash_command_substitution=1/g' -i /etc/nrpe.cfg
sed 's/#command/command/g' -i /etc/nrpe.cfg
fi


echo "=> Configuring OpenVPN server..."
[ "$APP_OPENVPN_ENABLE" = "YES" ] && sed "s/autostart=.*/autostart=true/" -i /etc/supervisor.d/openvpn.ini
[ "$APP_OPENVPN_ENABLE" = "NO" ] && sed "s/autostart=.*/autostart=false/" -i /etc/supervisor.d/openvpn.ini

#openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem

if [ -w "/etc/phpmyadmin/config.inc.php" ]; then
echo "=> Configuring PHPMyAdmin..."
sed "s/\$cfg\['blowfish_secret'\] =.*;/\$cfg\['blowfish_secret'\] = '$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)';/" -i /etc/phpmyadmin/config.inc.php
sed 's/localhost/127.0.0.1/g' -i /etc/phpmyadmin/config.inc.php
sed 's@Alias /phpmyadmin@Alias /admin/pma@' -i /etc/apache2/conf.d/phpmyadmin.conf
sed 's/Order allow,deny/#Order allow,deny/' -i /etc/apache2/conf.d/phpmyadmin.conf
sed 's/Allow from all/Require all granted/' -i /etc/apache2/conf.d/phpmyadmin.conf
sed 's/Require .*/Require ip ::1\nRequire ip 127.0.0.1\/8\nRequire ip 192.168.0.0\/16\nRequire ip 10.0.0.0\/8\nRequire ip 172.16.0.0\/12\n/' -i /etc/apache2/conf.d/phpmyadmin.conf
chown apache:apache /etc/phpmyadmin/config.inc.php
fi

echo "=> Configuring Let's Encrypt SSL..."
if [[ ! -z "$CERT_DOMAIN" && ! -z "$CERT_MAIL" && ! -z "$CERT_WEBROOT" ]]; then
  echo "Generating SSL certificate for '$CERT_DOMAIN' domain using '$CERT_WEBROOT' as webroot"
  certbot certonly -n --agree-tos --webroot -m $CERT_MAIL -w $CERT_WEBROOT -d $CERT_DOMAIN
else
  echo "No CERT_DOMAIN variable found, skipping ssl certificate creation"
fi


# SMTP variables
local domain="${domain:-$HOSTNAME}"
local from="${from:-root@localhost.localdomain}"
local host="${host:-localhost}"
local port="${port:-25}"
local tls="${tls:-off}"
local starttls="${starttls:-off}"
local username="${username:-}"
local password="${password:-}"
local timeout="${timeout:-3600}"

if [ -e "/usr/sbin/ssmtp" ]; then
 echo "=> Configuring SSMTP MTA..."
 print_ssmtp_conf() {
  #echo "rewriteDomain=$domain"
  #echo "FromLineOverride=$from"
  echo "hostname=$domain"
  echo "root=$from"
  echo "mailhub=$host"
  echo "UseTLS=$tls"
  echo "UseSTARTTLS=$starttls"
  if [[ -n "$username" && -n "$password" ]]; then
   echo "auth on"
   echo "AuthUser=$username"
   echo "AuthPass=$password"
  fi
 }
 print_ssmtp_conf > /etc/ssmtp/ssmtp.conf
fi

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
  if [[ -n "$username" && -n "$password" ]]; then
    echo "auth on"
    echo "user $username"
    echo "password $password"
    #passwordeval gpg2 --no-tty -q -d /etc/msmtp-password.gpg
  fi
 }
 print_msmtp_conf > /etc/msmtp.conf
fi

echo -n "--> forwarding all emails to: $host"
[ -n "$username" ] && echo -n " using username: $username"
echo

# izdsendmail config
mv /usr/sbin/sendmail /usr/sbin/sendmail.ssmtp && ln -s /usr/local/sbin/izsendmail /usr/sbin/sendmail
if [ -w "/etc/php/php.ini" ]; then
 sed "s/;sendmail_path =.*/sendmail_path = \/usr\/local\/sbin\/izsendmail -t -i/" -i /etc/php/php.ini
 sed "s/auto_prepend_file =.*/auto_prepend_file = \/usr\/local\/share\/izsendmail-env.php/" -i /etc/php/php.ini
fi

if [ -e "/usr/sbin/postconf" ]; then
echo "=> Configuring Postfix MTA..."
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

# Split with space
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
fi


echo "========================================================================"
echo "=> Setting root user with a ${PASSWORD_TYPE} password in ${APP}"
echo "root:${APP_ADMIN_PASSWORD}" | chpasswd
echo "=> Done!"
if [ "$PASSWORD_TYPE" = "random" ]; then
  echo "========================================================================"
  echo "You can now connect to $APP appliance using the following ssh root password:"
  echo "  ${APP_ADMIN_PASSWORD}"
fi

[ -e "/etc/rc.local" ] && echo && echo "=> Executing /etc/rc.local" && /etc/rc.local
}

hooks_oneshot() {
echo "=> Executing $APP configuration hooks 'oneshot'..."

# save the configuration status for later usage with persistent volumes
touch "${APP_CONF_DEFAULT}/.configured"
}

hooks_always
#[ ! -f "${APP_CONF_DEFAULT}/.configured" ] && hooks_oneshot || echo "=> Detected $APP configuration files already present in ${APP_CONF_DEFAULT}... skipping automatic configuration"
