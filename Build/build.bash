#!/bin/bash
# +--------------------------------------------------------------------+
# EFA 2.0.0.1 build script version 201308
# +--------------------------------------------------------------------+
# Copyright (C) 2012~2013  http://www.efa-project.org
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# +--------------------------------------------------------------------+
#
# +---------------------------------------------------+
# (Pre requirements for bare bone install)
# +---------------------------------------------------+
# - Configure Hardware
# - Install Ubuntu minimal with following disk layout
#     / 		( 6GB)
#     /tmp 		( 1GB)
#     /var		(12GB)
#     swap		( 1GB)
# - Set /tmp "noexec,nosuid" in /etc/fstab
# - Configure IP settings
# - Create user efaadmin
# +---------------------------------------------------+

# +---------------------------------------------------+
# Variables
# +---------------------------------------------------+
version="2.0.0.1"										# E.F.A. Version
osv="12.04"												# Required Ubuntu Version
dlurl="http://dl.efa-project.org/build/$version"		# URL for file downloads
builddir="/usr/src/EFA"									# E.F.A. Build dir
logdir="/var/log/EFA"									# E.F.A. Log dir
home="/home/baruwa"										# Baruwa home
pythonv="2.7"											# Python version to use
password="EfaPr0j3ct"									# Default password (should not be changed!)
debug="1"												# Enable/Disable Debug
# +---------------------------------------------------+

# +---------------------------------------------------+
# Check OS
# +---------------------------------------------------+
func_checkos () {

echo "[EFA] Checking Ubuntu Version"
if [ ! `lsb_release -r -s` == "$osv" ]
	then
		echo "[EFA] Error you do not seem to be running Ubuntu $osv."
		echo "[EFA] Ubuntu ]$osv is required to continue this build."
		echo "[EFA] Please see http://www.efa-project.org for more info."
		if [ $debug == "1" ]; then pause; fi
		exit 0
fi

if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+

# +---------------------------------------------------+
# Disclaimer
# +---------------------------------------------------+
func_disclaimer () {
echo "Build for E.F.A. v$version"
echo "TODO TODO TODO TODO TODO TODO TODO"
echo "TODO TODO TODO TODO TODO TODO TODO"
echo "TODO TODO TODO TODO TODO TODO TODO"
echo "TODO TODO TODO TODO TODO TODO TODO"
echo "TODO TODO TODO TODO TODO TODO TODO"

if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+

# +---------------------------------------------------+
# Install and configure dependencies
# +---------------------------------------------------+
func_dependencies () {

echo "[EFA] Install and configuring dependencies"
export DEBIAN_FRONTEND='noninteractive'

echo "[EFA] Installing Baruwa repo for mailscanner."
wget -cq -O - http://apt.baruwa.org/baruwa-apt-keys.gpg | apt-key add - &> /dev/null
echo "deb http://apt.baruwa.org/ubuntu precise main" >> /etc/apt/sources.list

apt-get update
apt-get -y install gcc g++ git subversion curl patch sudo apparmor dnsmasq rabbitmq-server \
mailscanner exim4-daemon-heavy nginx uwsgi uwsgi-plugin-python razor pyzor libjpeg62-dev \
libxml2-dev libxslt1-dev cython libpq-dev libfreetype6-dev libldap2-dev libssl-dev swig \
libcrack2-dev libgeoip-dev python-dev libsasl2-dev libmysqlclient-dev libcloog-ppl0 \
libmemcached-dev zlib1g-dev libssl-dev python-dev build-essential liblocal-lib-perl \
libanyevent-perl libaprutil1-dbd-sqlite3 libaprutil1-ldap libart-2.0-2 libauthen-dechpwd-perl \
libauthen-passphrase-perl libcap2 libclass-mix-perl libcrypt-des-perl libcrypt-eksblowfish-perl \
libcrypt-mysql-perl libcrypt-passwdmd5-perl libcrypt-rijndael-perl libcrypt-unixcrypt-xs-perl \
libdata-entropy-perl libdata-float-perl libdata-integer-perl libdbd-mysql-perl libdbd-pg-perl \
libdigest-crc-perl libdigest-md4-perl libelf1 libev-perl libhttp-lite-perl liblcms1 liblua5.1-0 \
liblzo2-2 libmodule-runtime-perl libnspr4 libnss3 libopts25 libparams-classify-perl libscalar-string-perl \
libstring-crc32-perl libdigest-sha-perl python-setuptools python-virtualenv postgresql postgresql-plpython-9.1 \
sphinxsearch memcached clamav-daemon clamav-unofficial-sigs  libjs-dojo-core libjs-dojo-dijit libjs-dojo-dojox \
arj cabextract expect htop lzop nomarch ntp p7zip ripole tcl8.5 unrar-free zoo vim libconvert-tnef-perl \
libdbd-sqlite3-perl libfilesys-df-perl libmailtools-perl libmime-tools-perl libmime-perl libnet-cidr-perl \
libsys-syslog-perl libio-stringy-perl libfile-temp-perl libole-storage-lite-perl libarchive-zip-perl \
libsys-hostname-long-perl libnet-cidr-lite-perl libhtml-parser-perl libdb-file-lock-perl libnet-dns-perl \
libncurses5-dev libdigest-hmac-perl libnet-ip-perl liburi-perl libfile-spec-perl spamassassin libnet-ident-perl \
libmail-spf-perl libmail-dkim-perl dnsutils libio-socket-ssl-perl libtest-pod-perl libbusiness-isbn-perl \
libdata-dump-perl libinline-perl libnet-dns-resolver-programmable-perl
if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+


# +---------------------------------------------------+
# Pre requirements
# +---------------------------------------------------+
func_prerequirements () {

echo "[EFA] Checking Pre-Requirements"
# Apt settings for noexec /tmp dir
echo 'DPkg:Pre-Invoke{"mount -o remount,exec /tmp";};' >> /etc/apt/apt.conf
echo 'DPkg:Post-Invoke {"mount -o remount /tmp";};' >> /etc/apt/apt.conf

# Stop unneeded services
update-rc.d -f whoopsie remove

# Secure SSH
sed -i '/^PermitRootLogin/ c\PermitRootLogin no' /etc/ssh/sshd_config

if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+

# +---------------------------------------------------+
# E.F.A requirements
# +---------------------------------------------------+
func_efarequirements () {

echo "[EFA] Configuring E.F.A Requirements"
echo "EFA-$version" >> /etc/EFA-Version
cd /usr/local/sbin
wget -N $dlurl/EFA/EFA-Init
chmod 700 EFA-Init
wget -N $dlurl/EFA/EFA-Configure
chmod 700 EFA-Configure
wget -N $dlurl/EFA/EFA-Update
chmod 700 EFA-Update

mkdir $builddir
mkdir $logdir
mkdir /var/EFA
mkdir /var/EFA/update
mkdir /etc/network/interfaces.d

echo "" > /etc/issue
echo "------------------------------" >> /etc/issue
echo "--- Welcome to EFA $version ---" >> /etc/issue
echo "------------------------------" >> /etc/issue
echo "  http://www.efa-project.org  " >> /etc/issue
echo "------------------------------" >> /etc/issue
echo "" >> /etc/issue
echo "First time login: efaadmin/EfaPr0j3ct" >> /etc/issue

# Set EFA-Init to run at first root login:
sed -i '1i\\/usr\/local\/sbin\/EFA-Init' /root/.bashrc

# Monthly check for update
cd /etc/cron.monthly
wget -N $dlurl/EFA/EFA-Monthly-cron
chmod 700 EFA-Monthly-cron

if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+


# +---------------------------------------------------+
# Configure dnsmasq
# +---------------------------------------------------+
func_dnsmasq (){
echo "[EFA] Configure dnsmasq"
sed -i s/"#listen-address="/"listen-address=127.0.0.1"/ /etc/dnsmasq.conf
echo -e "# IPv6 \nnet.ipv6.conf.all.disable_ipv6 = 1 \nnet.ipv6.conf.default.disable_ipv6 = 1 \nnet.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -q -p
service dnsmasq restart
if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+


# +---------------------------------------------------+
# Install baruwa
# +---------------------------------------------------+
func_baruwa (){

echo "[EFA] Installing Baruwa"
mkdir -p $home && cd $home
virtualenv -p /usr/bin/python$pythonv  --distribute px
source px/bin/activate
export SWIG_FEATURES="-cpperraswarn -includeall -D__`uname -m`__ -I/usr/include/openssl"
wget -N $dlurl/Baruwa/requirements.txt
pip install distribute
pip install -U distribute
pip install --timeout 60 -r requirements.txt
if [ $debug == "1" ]; then pause; fi

cd $home
curl $dlurl/Sphinx/sphinxapi.py -o px/lib/python$pythonv/site-packages/sphinxapi.py
wget -N $dlurl/Patches/repoze.who-friendly-form.patch
wget -N $dlurl/Patches/repoze-who-fix-auth_tkt-tokens.patch

cd px/lib/python$pythonv/site-packages/repoze/who/plugins/
patch -p3 -i $home/repoze.who-friendly-form.patch
patch -p4 -i $home/repoze-who-fix-auth_tkt-tokens.patch
cd $home

wget -N $dlurl/m2crypto/m2crypto.sh
chmod +x m2crypto.sh
./m2crypto.sh
if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+


# +---------------------------------------------------+
# Configure postgresql
# +---------------------------------------------------+
func_postgresql () {

echo "[EFA] Configuring Postgresql"
cat > /etc/postgresql/9.1/main/pg_hba.conf << 'EOF'
# TYPE  DATABASE    USER        CIDR-ADDRESS          METHOD
local   all         postgres                          trust
local   all         sa_user                           trust
host    all         all         127.0.0.1/32          md5
host    all         all         ::1/128               md5
EOF

sed -e "s/^#timezone = \(.*\)$/timezone = 'UTC'/" -i /etc/postgresql/9.1/main/postgresql.conf
service postgresql restart

cd $home
su - postgres -c "psql postgres -c \"CREATE ROLE baruwa WITH LOGIN PASSWORD '$password';\""
su - postgres -c 'createdb -E UTF8 -O baruwa -T template1 baruwa'
su - postgres -c "psql baruwa -c \"CREATE LANGUAGE plpythonu;\""
wget -N $dlurl/postgresql/admin-functions.sql
su - postgres -c 'psql baruwa -f '$home'/admin-functions.sql'
service postgresql restart
if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+


# +---------------------------------------------------+
# Configure SphinxSearch
# +---------------------------------------------------+
func_sphinxsearch () {
sed -i -e 's:START=no:START=yes:' /etc/default/sphinxsearch
cd /etc/sphinxsearch/
wget -N $dlurl/Sphinx/sphinx.conf

service sphinxsearch start
cd $home
if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+


# +---------------------------------------------------+
# Configure RabbitMQ
# +---------------------------------------------------+
func_rabbitmq () {

echo "[EFA] Configuring RabbitMQ"
rabbitmqctl delete_user guest
rabbitmqctl add_user baruwa $password
rabbitmqctl add_vhost baruwa
rabbitmqctl set_permissions -p baruwa baruwa ".*" ".*" ".*"
if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+


# +---------------------------------------------------+
# Install and Configure Mailscanner
# +---------------------------------------------------+
func_mailscanner () {

echo "[EFA] configuring Mailscanner"
cd $home
wget -N $dlurl/MailScanner/mailscanner-baruwa-iwantlint.patch
wget -N $dlurl/MailScanner/mailscanner-baruwa-sql-config.patch
cd /usr/sbin
patch -i $home/mailscanner-baruwa-iwantlint.patch
cd /usr/share/MailScanner/MailScanner
patch -p3 -i $home/mailscanner-baruwa-sql-config.patch
cd $home
wget -N $dlurl/MailScanner/BS.pm
mv BS.pm /etc/MailScanner/CustomFunctions/
cd /etc/MailScanner
mv MailScanner.conf MailScanner.conf.orig
cd $home
wget -N $dlurl/MailScanner/MailScanner.conf
wget -N $dlurl/MailScanner/scan.messages.rules
wget -N $dlurl/MailScanner/nonspam.actions.rules
wget -N $dlurl/MailScanner/filename.rules
wget -N $dlurl/MailScanner/filetype.rules
wget -N $dlurl/MailScanner/filename.rules.allowall.conf
wget -N $dlurl/MailScanner/filetype.rules.allowall.conf
mv /etc/MailScanner/spam.assassin.prefs.conf /etc/MailScanner/spam.assassin.prefs.conf.orig
wget -N $dlurl/MailScanner/spam.assassin.prefs.conf
mv *.rules /etc/MailScanner/rules/
mv *.conf /etc/MailScanner/
chmod -R 777 /var/spool/MailScanner/
ln -s /etc/MailScanner/spam.assassin.prefs.conf /etc/mail/spamassassin/mailscanner.cf
mkdir -p /var/lib/spamassassin/3.003001

sed -i 's:/usr/local:/usr/:' /etc/MailScanner/autoupdate/clamav-autoupdate
sed -i s/"#run_mailscanner"/"run_mailscanner"/ /etc/default/mailscanner
sed -i s/"\/var\/lock\/MailScanner.off"/"\/var\/lock\/MailScanner\/MailScanner.off"/ /etc/init.d/mailscanner
sed -i s/"\/var\/lock\/subsys\/mailscanner"/"\/var\/lock\/MailScanner\/mailscanner"/ /etc/init.d/mailscanner

mkdir -p /var/spool/exim.in/input
chown -R Debian-exim:Debian-exim /var/spool/exim.in
sed -i '20i{clamd}\         /bin/false\                              /usr/local ' /etc/MailScanner/virus.scanners.conf

su - postgres -c "psql -c\"create role sa_user login;\""
su - postgres -c "psql -c\"alter role sa_user password '$password';\""
su - postgres -c "psql -c\"create database sa_bayes owner sa_user;\""
su - postgres -c "psql -d sa_bayes -U sa_user -c \"\i /usr/share/doc/spamassassin/sql/bayes_pg.sql;\""
su - postgres -c "psql -c\"create user efaadmin superuser;\""
su - postgres -c "psql -c\"alter user efaadmin password '$password';\""
	
service postgresql restart
if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+


# +---------------------------------------------------+
# Install Perl Modules
# +---------------------------------------------------+
func_perl () {
echo "[EFA] Installing Perl Modules"
yes, local::lib, yes | perl -MCPAN -e "CPAN::Shell->force(qw(install Mail::SPF::Query Digest::SHA1 Parse::RecDescent SAVI Test::Manifest YAML Business::ISBN Data::Dump Encoding::FixLatin AnyEvent::Handle EV IP::Country::Fast Encode::Detect Crypt::OpenSSL::RSA));"
if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+


# +---------------------------------------------------+
# Configure Exim
# +---------------------------------------------------+
func_exim () {

echo "[EFA] Configuring Exim"
cat > /etc/sudoers.d/baruwa << 'EOF'
Defaults:baruwa   !requiretty, visiblepw

baruwa ALL=(exim) NOPASSWD: /usr/sbin/exim -C /etc/exim4/exim_out.conf -M *, \
        /usr/sbin/exim -C /etc/exim4/exim_out.conf -Mf *, \
        /usr/sbin/exim -C /etc/exim4/exim_out.conf -Mrm *, \
        /usr/sbin/exim -C /etc/exim4/exim_out.conf -Mg *, \
        /usr/sbin/exim -C /etc/exim4/exim_out.conf -Mar *, \
        /usr/sbin/exim -C /etc/exim4/exim_out.conf -qff, \
                /usr/sbin/exim -Mrm *, \
                /usr/sbin/exim -Mg *, \
                /usr/sbin/exim -Mar *

baruwa ALL = NOPASSWD: /bin/kill -s HUP *
EOF
chmod 0440 /etc/sudoers.d/baruwa

cd /etc/exim4
wget -N $dlurl/exim/exim4.conf
wget -N $dlurl/exim/exim_out.conf
wget -N $dlurl/exim/macros.conf
wget -N $dlurl/exim/trusted-configs
       
mkdir /etc/exim4/baruwa
cd /etc/exim4/baruwa
wget -N $dlurl/exim/exim-bcrypt.pl

usermod -a -G Debian-exim clamav
service exim4 start
if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+


# +---------------------------------------------------+
# Configure Baruwa
# +---------------------------------------------------+
func_baruwa_config (){

echo "[EFA] Configuring Baruwa"
cd $home
virtualenv -p /usr/bin/python$pythonv --distribute px
source px/bin/activate
export SWIG_FEATURES="-cpperraswarn -includeall -D__`uname -m`__ -I/usr/include/openssl"
pip install -U distribute
pip install baruwa

px/bin/paster make-config baruwa production.ini
mkdir /etc/baruwa
mv $home/production.ini /etc/baruwa/production.ini
sed -i -e 's/exim/Debian-exim/' /etc/baruwa/production.ini
sed -i -e 's/sqlalchemy.url/#sqlalchemy.url/' /etc/baruwa/production.ini
sed -i "72i sqlalchemy.url = postgresql://baruwa:$password@127.0.0.1:5432/baruwa" /etc/baruwa/production.ini
sed -i -e 's:broker.password =:broker.password = '$password':' \
       -e "s:snowy.local:$(hostname):g" \
       -e 's:^#celery.queues:celery.queues:' /etc/baruwa/production.ini
	   
mkdir -p /var/log/baruwa /var/run/baruwa /var/lib/baruwa/data/{cache,sessions,uploads,templates} /var/lock/baruwa /etc/MailScanner/baruwa/signatures /etc/MailScanner/baruwa/dkim /etc/MailScanner/baruwa/rules /var/lib/baruwa/data/templates/{general,accounts} 

getent group baruwa >/dev/null || addgroup --system baruwa
getent passwd baruwa >/dev/null || adduser --system --ingroup baruwa --home /var/lib/baruwa --no-create-home --gecos "Baruwa user" --disabled-login baruwa
chown baruwa.baruwa -R /var/lib/baruwa /var/run/baruwa /var/log/baruwa /var/lock/baruwa /etc/MailScanner/baruwa
usermod -a -G Debian-exim baruwa

cat > /etc/default/baruwa << 'EOF'
CELERYD_CHDIR="/home/baruwa"
CELERYD="$CELERYD_CHDIR/px/bin/paster celeryd /etc/baruwa/production.ini"
CELERYD_LOG_LEVEL="INFO"
CELERYD_LOG_FILE="/var/log/baruwa/celeryd.log"
CELERYD_PID_FILE="/var/run/baruwa/celeryd.pid"
CELERYD_USER="baruwa"
CELERYD_GROUP="baruwa"
EOF

cd $home
wget -N $dlurl/Baruwa/baruwa.init
mv baruwa.init /etc/init.d/baruwa
chmod +x /etc/init.d/baruwa
update-rc.d baruwa defaults
service baruwa start

N | $home/px/bin/paster setup-app /etc/baruwa/production.ini
indexer --all --rotate
$home/px/bin/paster create-admin-user -u "root" -p "$password" -e "root@efa-project.org" -t UTC /etc/baruwa/production.ini

cd $home/px/lib/python$pythonv/site-packages/baruwa/controllers/
wget -N $dlurl/Baruwa/taskids.sh
chmod +x taskids.sh
./taskids.sh
if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+


# +---------------------------------------------------+
# Configure nginx
# +---------------------------------------------------+
func_nginx () {
echo "[EFA] configure nginx"
cd $home
wget -N $dlurl/nginx/nginx.conf
mv nginx.conf /etc/nginx/sites-enabled/baruwa
rm -r /etc/nginx/sites-enabled/default
sed -i '/daemonize/ahome = /home/baruwa/px' /etc/baruwa/production.ini
sed -i '/home/apaste = config:/etc/baruwa/production.ini' /etc/baruwa/production.ini
sed -i '/paste/achmod-socket = 666' /etc/baruwa/production.ini
ln -s /etc/baruwa/production.ini /etc/uwsgi/apps-enabled/
if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+


# +---------------------------------------------------+
# Configure Pyzor, Razor and DCC
# +---------------------------------------------------+
func_pyzor_razor_dcc () {

echo "[EFA] Configure Pyzor, Razor and DCC"
pyzor --homedir=/var/lib/MailScanner discover
pyzor ping

cd && rm -r /etc/razor/razor-agent.conf
mkdir /var/lib/MailScanner/.razor
razor-admin -home=/var/lib/MailScanner/.razor -create
razor-admin -home=/var/lib/MailScanner/.razor -discover
razor-admin -home=/var/lib/MailScanner/.razor -register
sed -i '/razor-whitelist/arazorhome\              = /var/lib/MailScanner/.razor/' /var/lib/MailScanner/.razor/razor-agent.conf
sed -i 's:= 3:= 0:' /var/lib/MailScanner/.razor/razor-agent.conf
sa-learn --sync

cd $home
wget -N $dlurl/DCC/dcc.tar.Z
tar xvzf dcc.tar.Z
cd dcc-1.3.147/
./configure
make
make install

# Configure DCC and run as daemon for better performance
ln -s /var/dcc/libexec/cron-dccd /usr/bin/cron-dccd
ln -s /var/dcc/libexec/cron-dccd /etc/cron.monthly/cron-dccd
echo "dcc_home /var/dcc" >> /etc/MailScanner/spam.assassin.prefs.conf
sed -i '/^dcc_path / c\dcc_path /usr/local/bin/dccproc' /etc/MailScanner/spam.assassin.prefs.conf
sed -i '/^DCCIFD_ENABLE=/ c\DCCIFD_ENABLE=on' /var/dcc/dcc_conf
sed -i '/^DBCLEAN_LOGDAYS=/ c\DBCLEAN_LOGDAYS=1' /var/dcc/dcc_conf
sed -i '/^DCCIFD_LOGDIR=/ c\DCCIFD_LOGDIR="/var/dcc/log"' /var/dcc/dcc_conf
chown Debian-exim:Debian-exim /var/dcc
sed -i "s/#loadplugin Mail::SpamAssassin::Plugin::DCC/loadplugin Mail::SpamAssassin::Plugin::DCC/g" /etc/mail/spamassassin/v310.pre
sed -i "s/# loadplugin Mail::SpamAssassin::Plugin::RelayCountry/loadplugin Mail::SpamAssassin::Plugin::RelayCountry/g" /etc/mail/spamassassin/init.pre
curl $dlurl/DCC/DCC.init -o /etc/init.d/DCC
chmod 755 /etc/init.d/DCC
update-rc.d DCC defaults
service DCC start
if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+


# +---------------------------------------------------+
# Cron settings
# +---------------------------------------------------+
func_cron () {

echo "[EFA] Setting Cron Jobs"
curl $dlurl/cron/cron.baruwa-updateindex -o /etc/cron.hourly/baruwa-updateindex 
chmod +x /etc/cron.hourly/baruwa-updateindex
curl $dlurl/cron/cron.baruwa -o /etc/cron.d/baruwa
chmod +x /etc/cron.d/baruwa
curl $dlurl/cron/cron.mailscanner -o /etc/cron.d/mailscanner
chmod +x /etc/cron.d/mailscanner
curl $dlurl/cron/check_mailscanner -o /usr/sbin/check_mailscanner
chmod +x /usr/sbin/check_mailscanner
curl $dlurl/cron/update_bad_phishing_sites -o /usr/sbin/update_bad_phishing_sites
chmod +x /usr/sbin/update_bad_phishing_sites
curl $dlurl/cron/update_bad_phishing_emails -o /usr/sbin/update_bad_phishing_emails
chmod +x /usr/sbin/update_bad_phishing_emails
if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+

# +---------------------------------------------------+
# Post-Config
# +---------------------------------------------------+
func_postconfig () {

echo "/var/spool/MailScanner/** rw," >> /etc/apparmor.d/local/usr.sbin.clamd
echo "/var/spool/MailScanner/incoming/** rw," >> /etc/apparmor.d/local/usr.sbin.clamd
sed -i '/exim4/a/var/spool/exim.in/** rw,' /etc/apparmor.d/usr.sbin.clamd
service apparmor restart &> /dev/null

indexer --all --rotate
#freshclam
#service clamav-daemon restart
#/usr/sbin/clamav-unofficial-sigs

cd $home
mv /home/baruwa/px/lib/python2.7/site-packages/baruwa/public/imgs/logo.png /home/baruwa/px/lib/python2.7/site-packages/baruwa/public/imgs/logo-baruwa.png
wget $dlurl/EFA/logo.png
mv logo.png /home/baruwa/px/lib/python2.7/site-packages/baruwa/public/imgs/logo.png

#su - postgres -c "psql -d baruwa -c\"select * from configurations;\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('%web-site%','%web-site%','www.efa-project.org','1','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('webbugurl','WebBugReplacement','http://dl.efa-project.org/static/1x1spacer.gif','4','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('%org-name%','%org-name%','EFA Project','1','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('%org-long-name%','%org-long-name%','EFA Project MAIL GATEWAY','1','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('envfromheader','EnvelopeFromHeader','X-EFA-Envelope-From:','2','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('envtoheader','EnvelopeToHeader','X-EFA-Envelope-To:','2','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('idheader','IDHeader','X-EFA-ID:','2','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('ipverheader','IPProtocolVersionHeader',' X-EFA-IP-Protocol:','2','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('hostname','Hostname','the %org-name% ($HOSTNAME) EFA','2','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('spamvirusheader','SpamVirusHeader','X-EFA-SpamVirus-Report:','3','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('virusscanners','VirusScanners','{clamd}','3','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('noticesignature','NoticeSignature','-- E.F.A. Project Email Security %website%','6','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('noticesfrom','NoticesFrom','EFA','6','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('spamheader','SpamHeader','X-EFA-SpamCheck:','7','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('spamstarsheader','SpamScoreHeader','X-EFA-SpamScore:','7','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('mshmacheader','WatermarkHeader','X-%org-name%-EFA-Watermark:','7','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('mailheader','MailHeader','X-EFA:','2','1');\""
su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('infoheader','InformationHeader','X-EFA-Information:','2','1');\""
#su - postgres -c "psql -d baruwa -c\"INSERT INTO configurations (internal,external,value,section,server_id) VALUES('','','','','1');\""
}
# +---------------------------------------------------+
# Cleanup
# +---------------------------------------------------+
func_cleanup () {

echo "[EFA] Starting Cleanup"
# Clean SSH keys (gererate at first boot)
/bin/rm /etc/ssh/ssh_host_*

# Clean network configs
rm /var/cache/apt/archives/*
echo "auto lo" > /etc/network/interfaces
echo "iface lo inet loopback" >> /etc/network/interfaces
echo " " >> /etc/network/interfaces
echo "source /etc/network/interfaces.d/*" >> /etc/network/interfaces
echo "nameserver 8.8.8.8" > /etc/resolv.
echo "nameserver 8.8.4.4" >> /etc/resolv.conf
echo "127.0.0.1               localhost efa" > /etc/hosts

echo "auto eth0" > /etc/network/interfaces.d/eth0
echo "iface eth0 inet dhcp" >> /etc/network/interfaces.d/eth0

# Clean history
rm /home/efaadmin/.bash_history
rm /root/.bash_history

# Clean logs
rm -r /var/log/exim4/*

if [ $debug == "1" ]; then pause; fi
}
# +---------------------------------------------------+


# +---------------------------------------------------+
# Generate Key's
# +---------------------------------------------------+
func_generate_key () {
        openssl req -x509 -newkey rsa:2048 -days 9999 -nodes -x509 -subj "/C=$sslcountry/ST=$sslprovince/L=$sslcity/O=$orgname/CN=$baruwadomain" -keyout baruwa.key -out baruwa.pem -nodes
        mkdir /etc/pki && mkdir /etc/pki/baruwa && mv baruwa.* /etc/pki/baruwa/
}
# +---------------------------------------------------+

# +---------------------------------------------------+
# Pause
# +---------------------------------------------------+
pause(){
	read -p "Press [Enter] key to continue..." fackEnterKey
}
# +---------------------------------------------------+


# +---------------------------------------------------+
# Main logic
# +---------------------------------------------------+
if [ `whoami` == root ]
	then
		func_checkos
		func_disclaimer
		func_dependencies
		func_prerequirements
		func_efarequirements
		func_dnsmasq
		func_baruwa
		func_postgresql
		func_sphinxsearch
		func_rabbitmq
		func_mailscanner
		func_perl
		func_exim
		func_baruwa_config
		func_nginx
		func_pyzor_razor_dcc
		func_cron
		func_postconfig
		func_cleanup
		#reboot
	else
		echo "[EFA] ERROR: Please become root."
		exit 0
	fi
# +---------------------------------------------------+