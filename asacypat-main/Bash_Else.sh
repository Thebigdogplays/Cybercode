#!/bin/bash

#Run as root; confirm forensics complete.
touch debug_output.log
exec 5> debug_output.log
BASH_XTRACEFD="5"
PS4='$LINENO: '

apt-get update -y
apt-get upgrade -y
apt-get dist-upgrade -y

#Installs Lynis, writes scan results to lynis.log
#cd /usr/local
#git clone https://github.com/CISOfy/lynis
#cd lynis
#./lynis audit system
#cd

#Unnecessary
#cat /var/log/lynis-report.dat | grep "suggestion" >> lynis.log
#cat /var/log/lynis-report.dat | grep "warning" >> lynis.log
#cat /var/log/lynis-report.dat | grep "vulnerable" >> lynis.log
#cat /var/log/lynis-report.dat | grep "network_listen" >> lynis.log
#cat /var/log/lynis-report.dat | grep "manual" >> lynis.log

#FTP Removal
apt-get remove ftp
apt-get remove pure-ftp



#Removing unwanted programs/services
#reqs
apt-get remove ftp -y
apt-get remove pure-ftpd -y
apt-get remove nmap -y
apt-get remove zenmap -y
apt-get remove john -y
apt-get remove john-data -y
apt-get remove wireshark -y
apt-get remove ophcrack -y
apt-get remove ophcrack-cli -y
apt-get remove netcat -y 
apt-get remove netcat-openbsd -y 
apt-get remove netcat-traditional -y 
apt-get remove ncat -y 
apt-get remove pnetcat -y 
apt-get remove socat -y 
apt-get remove sock -y 
apt-get remove socket -y 
apt-get remove sbd -y 
apt-get remove hydra -y
apt-get remove hydra-gtk -y
apt-get remove aircrack-ng -y
apt-get remove fcrackzip -y
apt-get remove lcrack -y
apt-get remove pdfcrack -y
apt-get remove pyrit -y
apt-get remove rarcrack -y
apt-get remove sipcrack -y
apt-get remove irpas -y
apt-get remove logkeys -y
apt-get remove zeitgeist-core -y 
apt-get remove zeitgeist-datahub -y 
apt-get remove python-zeitgeist -y 
apt-get remove rhythmbox-plugin-zeitgeist -y 
apt-get remove zeitgeist -y 
apt-get remove nfs-kernel-server -y 
apt-get remove nfs-common -y 
apt-get remove portmap -y 
apt-get remove rpcbind -y 
apt-get remove autofs -y 
apt-get remove nginx -y 
apt-get remove nginx-common -y 
apt-get remove inetd -y 
apt-get remove openbsd-inetd -y 
apt-get remove xinetd -y 
apt-get remove inetutils-ftp -y 
apt-get remove inetutils-ftpd -y 
apt-get remove inetutils-inetd -y 
apt-get remove inetutils-ping -y 
apt-get remove inetutils-syslogd -y 
apt-get remove inetutils-talk -y 
apt-get remove inetutils-talkd -y 
apt-get remove inetutils-telnet -y 
apt-get remove inetutils-telnetd -y 
apt-get remove inetutils-tools -y 
apt-get remove inetutils-traceroute -y 
apt-get remove vnc4server -y 
apt-get remove vncsnapshot -y 
apt-get remove vtgrab -y 
apt-get remove snmp -y 
rm -rf /usr/bin/nc
#telnet stuff
apt-get remove telnet -y
apt-get remove telnetd -y
apt-get remove inetutils-telnetd -y
apt-get remove telnetd-ssl -y
#remote stuff
apt-get remove remote-login-service vino remmina remmina-common -y
apt-get remove rstatd -y
apt-get remove .*samba.* .*smb.* -y
apt-get remove vsftpd -y
apt-get remove openssh-server -y
apt-get remove samba -y
apt-get remove samba-common -y
apt-get remove samba-common-bin -y
apt-get remove samba4 -y
#db stuff
apt-get remove mysql-client-core-5.5 -y 
apt-get remove mysql-client-core-5.6 -y 
apt-get remove mysql-common-5.5 -y 
apt-get remove mysql-common-5.6 -y 
apt-get remove mysql-server -y 
apt-get remove mysql-server-5.5 -y 
apt-get remove mysql-server-5.6 -y 
apt-get remove mysql-client-5.5 -y 
apt-get remove mysql-client-5.6 -y 
apt-get remove mysql-server-core-5.6 -y
#http/apache stuff
apt-get remove apache2 -y
rm -rf /var/www/*
#dns stuff
apt-get remove bind9 -y

#Password settings, minimum days-10, max-90, warning-7
 unalias -a
  PASSMAX="$(grep -n 'PASS_MAX_DAYS' /etc/login.defs | grep -v '#' | cut -f1 -d:)"
    sed -e "${PASSMAX}s/.*/PASS_MAX_DAYS	90/" /etc/login.defs > /var/local/temp1.txt
    PASSMIN="$(grep -n 'PASS_MIN_DAYS' /etc/login.defs | grep -v '#' | cut -f1 -d:)"
    sed -e "${PASSMIN}s/.*/PASS_MIN_DAYS	10/" /var/local/temp1.txt > /var/local/temp2.txt
    PASSWARN="$(grep -n 'PASS_WARN_AGE' /etc/login.defs | grep -v '#' | cut -f1 -d:)"
    sed -e "${PASSWARN}s/.*/PASS_WARN_AGE	7/" /var/local/temp2.txt > /var/local/temp3.txt
    mv /etc/login.defs /etc/login.defs.old
    mv /var/local/temp3.txt /etc/login.defs
    rm /var/local/temp1.txt /var/local/temp2.txt

#Account lockouts
	cp /etc/pam.d/common-auth /etc/pam.d/common-auth.old
    echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" >> /etc/pam.d/common-auth
	
#Disable ALL remote logons through ssh and all for root as a whole
cat > /etc/ssh/sshd_config <<"__EOF__"
Authentication:
LoginGraceTime 2m
PermitRootLogin no
StrictModes yes
MaxAuthTries 0
MaxSessions 0
PubkeyAuthentication yes
__EOF__

systemctl reload sshd.service

cat> /etc/security/access.conf <<"__EOF__"
-:ALL:ALL EXCEPT LOCAL
__EOF__

#Configure auto-logout
cat > /etc/profile.d/autologout.sh <<"__EOF__"
TMOUT=300
readonly TMOUT
export TMOUT
__EOF__

chmod +x /etc/profile.d/autologout.sh

#Install AVG/Scan outputs to /etc/avgscan.log
wget -c http://download.avgfree.com/filedir/inst/avg85flx-r874-a3473.i386.deb
dpkg -i avg85flx-r874-a3473.i386.deb
avgctl --start
avgupdate
cd /etc
touch avgscan.log
avgscan / > avgscan.log
cd


#Rootkit Scans-Write to /etc/rootkits.log--rootkits2.log
apt-get install chkrootkit -y
cd /etc
touch rootkits.log
chkrootkit -q > rootkits.log
cd
apt-get install rkhunter -y
rkhunter --update
cd /etc
touch rootkits2.log
rkhunter --check > rootkits2.log
cd

sudo apt install firefox -y

#Configures ufw
apt-get install ufw -y
ufw enable
ufw deny 23
ufw deny 2049
ufw deny 515
ufw deny 111
ufw deny ssh
#Samba stuff, delete if samba allowed
ufw deny netbios-ns
ufw deny netbios-dgm
ufw deny netbios-ssn
ufw deny microsoft-ds
#ftp stuff
ufw deny ftp 
ufw deny sftp 
ufw deny saft 
ufw deny ftps-data 
ufw deny ftps
#telnet stuff, delete if allowed
ufw deny telnet
ufw deny rtelnet
ufw deny telnets
#mail protocol stuff, delete if allowed
ufw deny smtp
ufw deny pop2
ufw deny pop3
ufw deny imap2
ufw deny imaps
ufw deny pop3s
#print stuff, delete if allowed
ufw deny ipp
ufw deny printer
ufw deny cups
#database stuff, delete if allowed
ufw deny ms-sql-s
ufw deny ms-sql-m
ufw deny mysql
ufw deny mysql-proxy
#http/apache stuff, alter if allowed
ufw deny http
#dns stuff
ufw deny domain

#Clears any unwanted dns connections
cd /etc/init.d/dnsmasq
restart
cd /etc/init.d/nscd
-i hosts
cd /etc/init.d/nscd
reload
rndc flush
cd 

#clears hosts file to block potential mslicious network connections, copios to 'hosts', in case needed
cp /etc/hosts hosts
echo 127.0.0.1	localhost > /etc/hosts
echo 127.0.1.1	ubuntu  >> /etc/hosts
echo ::1     ip6-localhost ip6-loopback >> /etc/hosts
echo fe00::0 ip6-localnet >> /etc/hosts
echo ff00::0 ip6-mcastprefix >> /etc/hosts
echo ff02::1 ip6-allnodes >> /etc/hosts
echo ff02::2 ip6-allrouters >> /etc/hosts

#Checks for users with root privileges (UID 0), and checks root group... writes to /etc/rootusers.log
cd /etc
touch rootusers.log
grep 'x:0:' /etc/passwd >> rootusers.log
echo root user group-- >> rootusers.log 
grep root /etc/group >> rootusers.log
cd

#checks for active netcat backdoors, write them to /etc/backdoors.log
cd /etc
touch backdoors.log
netstat -ntlup | grep -e "netcat" -e "nc" -e "ncat" >> /etc/backdoors.log

#Delete personal file types
find / -name '*.mp3' -type f -delete
find / -name '*.mov' -type f -delete
find / -name '*.mp4' -type f -delete
find / -name '*.avi' -type f -delete
find / -name '*.mpg' -type f -delete
find / -name '*.mpeg' -type f -delete
find / -name '*.flac' -type f -delete
find / -name '*.m4a' -type f -delete
find / -name '*.flv' -type f -delete
find / -name '*.ogg' -type f -delete
find / -name '*.midi' -type f -delete
find / -name '*.mid' -type f -delete
find / -name '*.mod' -type f -delete
find / -name '*.mp3' -type f -delete
find / -name '*.mp2' -type f -delete	
find / -name '*.mpa' -type f -delete
find / -name '*.abs' -type f -delete
find / -name '*.mpega' -type f -delete
find / -name '*.au' -type f -delete
find / -name '*.snd' -type f -delete
find / -name '*.wav' -type f -delete
find / -name '*.aiff' -type f -delete
find / -name '*.aif' -type f -delete
find / -name '*.sid' -type f -delete
find / -name '*.flac' -type f -delete
find / -name '*.ogg' -type f -delete
find / -name '*.mpeg' -type f -delete
find / -name '*.mpg' -type f -delete
find / -name '*.mpe' -type f -delete
find / -name '*.dl' -type f -delete
find / -name '*.movie' -type f -delete
find / -name '*.movi' -type f -delete
find / -name '*.mv' -type f -delete
find / -name '*.iff' -type f -delete
find / -name '*.anim5' -type f -delete
find / -name '*.anim3' -type f -delete
find / -name '*.anim7' -type f -delete
find / -name '*.avi' -type f -delete
find / -name '*.vfw' -type f -delete
find / -name '*.avx' -type f -delete
find / -name '*.fli' -type f -delete
find / -name '*.flc' -type f -delete
find / -name '*.mov' -type f -delete
find / -name '*.qt' -type f -delete
find / -name '*.spl' -type f -delete
find / -name '*.swf' -type f -delete
find / -name '*.dcr' -type f -delete
find / -name '*.dir' -type f -delete
find / -name '*.dxr' -type f -delete
find / -name '*.rpm' -type f -delete
find / -name '*.rm' -type f -delete
find / -name '*.smi' -type f -delete
find / -name '*.ra' -type f -delete
find / -name '*.ram' -type f -delete
find / -name '*.rv' -type f -delete
find / -name '*.wmv' -type f -delete
find / -name '*.asf' -type f -delete
find / -name '*.asx' -type f -delete
find / -name '*.wma' -type f -delete
find / -name '*.wax' -type f -delete
find / -name '*.wmv' -type f -delete
find / -name '*.wmx' -type f -delete
find / -name '*.3gp' -type f -delete
find / -name '*.mov' -type f -delete
find / -name '*.mp4' -type f -delete
find / -name '*.avi' -type f -delete
find / -name '*.swf' -type f -delete
find / -name '*.flv' -type f -delete
find / -name '*.m4v' -type f -delete
find / -name '*.tiff' -type f -delete
find / -name '*.tif' -type f -delete
find / -name '*.rs' -type f -delete
find / -name '*.im1' -type f -delete
find / -name '*.gif' -type f -delete
find / -name '*.jpeg' -type f -delete
find / -name '*.jpg' -type f -delete
find / -name '*.jpe' -type f -delete
find / -name '*.png' -type f -delete
find / -name '*.rgb' -type f -delete
find / -name '*.xwd' -type f -delete
find / -name '*.xpm' -type f -delete
find / -name '*.ppm' -type f -delete
find / -name '*.pbm' -type f -delete
find / -name '*.pgm' -type f -delete
find / -name '*.pcx' -type f -delete
find / -name '*.ico' -type f -delete
find / -name '*.svg' -type f -delete
find / -name '*.svgz' -type f -delete

#Changes perms of files that are commonly exploited
chown root:root /etc/securetty
chmod 0600 /etc/securetty
chmod 644 /etc/crontab
chmod 640 /etc/ftpusers
chmod 440 /etc/inetd.conf
chmod 440 /etc/xinetd.conf
chmod 400 /etc/inetd.d
chmod 644 /etc/hosts.allow
chmod 440 /etc/sudoers
chmod 640 /etc/shadow
chown root:root /etc/shadow

#Lists all files with perms 700-777 in fileperms.log
cd /etc
touch fileperms.log
cd
find / -type f -perm 777 >> /etc/fileperms.log
find / -type f -perm 776 >> /etc/fileperms.log
find / -type f -perm 775 >> /etc/fileperms.log
find / -type f -perm 774 >> /etc/fileperms.log
find / -type f -perm 773 >> /etc/fileperms.log
find / -type f -perm 772 >> /etc/fileperms.log
find / -type f -perm 771 >> /etc/fileperms.log
find / -type f -perm 770 >> /etc/fileperms.log
find / -type f -perm 767 >> /etc/fileperms.log
find / -type f -perm 766 >> /etc/fileperms.log
find / -type f -perm 765 >> /etc/fileperms.log
find / -type f -perm 764 >> /etc/fileperms.log
find / -type f -perm 763 >> /etc/fileperms.log
find / -type f -perm 762 >> /etc/fileperms.log
find / -type f -perm 761 >> /etc/fileperms.log
find / -type f -perm 760 >> /etc/fileperms.log
find / -type f -perm 757 >> /etc/fileperms.log
find / -type f -perm 756 >> /etc/fileperms.log
find / -type f -perm 755 >> /etc/fileperms.log
find / -type f -perm 754 >> /etc/fileperms.log
find / -type f -perm 753 >> /etc/fileperms.log
find / -type f -perm 752 >> /etc/fileperms.log
find / -type f -perm 751 >> /etc/fileperms.log
find / -type f -perm 750 >> /etc/fileperms.log
find / -type f -perm 747 >> /etc/fileperms.log
find / -type f -perm 746 >> /etc/fileperms.log
find / -type f -perm 745 >> /etc/fileperms.log
find / -type f -perm 744 >> /etc/fileperms.log
find / -type f -perm 743 >> /etc/fileperms.log
find / -type f -perm 742 >> /etc/fileperms.log
find / -type f -perm 741 >> /etc/fileperms.log
find / -type f -perm 740 >> /etc/fileperms.log
find / -type f -perm 737 >> /etc/fileperms.log
find / -type f -perm 736 >> /etc/fileperms.log
find / -type f -perm 735 >> /etc/fileperms.log
find / -type f -perm 734 >> /etc/fileperms.log
find / -type f -perm 733 >> /etc/fileperms.log
find / -type f -perm 732 >> /etc/fileperms.log
find / -type f -perm 731 >> /etc/fileperms.log
find / -type f -perm 730 >> /etc/fileperms.log
find / -type f -perm 727 >> /etc/fileperms.log
find / -type f -perm 726 >> /etc/fileperms.log
find / -type f -perm 725 >> /etc/fileperms.log
find / -type f -perm 724 >> /etc/fileperms.log
find / -type f -perm 723 >> /etc/fileperms.log
find / -type f -perm 722 >> /etc/fileperms.log
find / -type f -perm 721 >> /etc/fileperms.log
find / -type f -perm 720 >> /etc/fileperms.log
find / -type f -perm 717 >> /etc/fileperms.log
find / -type f -perm 716 >> /etc/fileperms.log
find / -type f -perm 715 >> /etc/fileperms.log
find / -type f -perm 714 >> /etc/fileperms.log
find / -type f -perm 713 >> /etc/fileperms.log
find / -type f -perm 712 >> /etc/fileperms.log
find / -type f -perm 711 >> /etc/fileperms.log
find / -type f -perm 710 >> /etc/fileperms.log
find / -type f -perm 707 >> /etc/fileperms.log
find / -type f -perm 706 >> /etc/fileperms.log
find / -type f -perm 705 >> /etc/fileperms.log
find / -type f -perm 704 >> /etc/fileperms.log
find / -type f -perm 703 >> /etc/fileperms.log
find / -type f -perm 702 >> /etc/fileperms.log
find / -type f -perm 701 >> /etc/fileperms.log
find / -type f -perm 700 >> /etc/fileperms.log
cd

#lists all php files in /etc/phpfiles.log ('/var/cache/dictionaries-common/sqspell.php' is a system PHP file)
find / -name "*.php" -type f >> /etc/phpfiles.log

#Drops unwanted service-related ports and bogons
apt-get install -y iptables
mkdir /iptables/
touch /iptables/rules.v4.bak
touch /iptables/rules.v6.bak
iptables-save > /iptables/rules.v4.bak
ip6tables-save > /iptables/rules.v6.bak
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 2049 -j DROP
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 515 -j DROP
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 111 -j DROP
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP
iptables -A INPUT -p all -s localhost  -i eth0 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -i $interface -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -s 100.64.0.0/10 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 192.0.0.0/24 -j DROP
iptables -A INPUT -s 192.0.2.0/24 -j DROP
iptables -A INPUT -s 198.18.0.0/15 -j DROP
iptables -A INPUT -s 198.51.100.0/24 -j DROP
iptables -A INPUT -s 203.0.113.0/24 -j DROP
iptables -A INPUT -s 224.0.0.0/3 -j DROP
iptables -A OUTPUT -d 127.0.0.0/8 -o $interface -j DROP
iptables -A OUTPUT -d 0.0.0.0/8 -j DROP
iptables -A OUTPUT -d 100.64.0.0/10 -j DROP
iptables -A OUTPUT -d 169.254.0.0/16 -j DROP
iptables -A OUTPUT -d 192.0.0.0/24 -j DROP
iptables -A OUTPUT -d 192.0.2.0/24 -j DROP
iptables -A OUTPUT -d 198.18.0.0/15 -j DROP
iptables -A OUTPUT -d 198.51.100.0/24 -j DROP
iptables -A OUTPUT -d 203.0.113.0/24 -j DROP
iptables -A OUTPUT -d 224.0.0.0/3 -j DROP
iptables -A OUTPUT -s 127.0.0.0/8 -o $interface -j DROP
iptables -A OUTPUT -s 0.0.0.0/8 -j DROP
iptables -A OUTPUT -s 100.64.0.0/10 -j DROP
iptables -A OUTPUT -s 169.254.0.0/16 -j DROP
iptables -A OUTPUT -s 192.0.0.0/24 -j DROP
iptables -A OUTPUT -s 192.0.2.0/24 -j DROP
iptables -A OUTPUT -s 198.18.0.0/15 -j DROP
iptables -A OUTPUT -s 198.51.100.0/24 -j DROP
iptables -A OUTPUT -s 203.0.113.0/24 -j DROP
iptables -A OUTPUT -s 224.0.0.0/3 -j DROP
iptables -A INPUT -d 127.0.0.0/8 -i $interface -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 100.64.0.0/10 -j DROP
iptables -A INPUT -d 169.254.0.0/16 -j DROP
iptables -A INPUT -d 192.0.0.0/24 -j DROP
iptables -A INPUT -d 192.0.2.0/24 -j DROP
iptables -A INPUT -d 198.18.0.0/15 -j DROP
iptables -A INPUT -d 198.51.100.0/24 -j DROP
iptables -A INPUT -d 203.0.113.0/24 -j DROP
iptables -A INPUT -d 224.0.0.0/3 -j DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -P OUTPUT DROP

#Searches all installed packages for common keywords used in low-level malware, writes to /etc/avgscanremainingmalware.log
cd /etc
touch remainingmalware.log
dpkg-query --list | grep -e "game" -e "freeciv" -e "minetest" -e "nmap" -e "crack" -e "john" -e "logkey" -e "hydra" -e "fakeroot" -e "medusa" -e "nikto" -e "tightvnc" -e "bind9" -e "avahi" -e "cupsd" -e "nginx" -e "wireshark" -e "frostwire" -e "vuze" -e "weplab" -e "pyrit" -e "mysql" -e "php" -e "ftp" -e "filezilla" -e "postgresql" -e "irssi" -e "telnet" -e "samba" -e "apache" -e "netcat" -e "ssh" -e "password" -e "trojan" -e "Trojan" -e "Hack" -e "hack" -e "server" >> /etc/remainingmalware.log
cd

#Cron activities outputted to /var/local/cronjoblist --proccesses to /var/local/pslist
chmod 604 /etc/shadow
crontab -l >> /var/local/cronjoblist.log
ss -an4 > /var/local/netstat.log
ps axk start_time -o start_time,pid,user,cmd >> /var/local/pslist.log

#Installation and first run of ClamAV
apt-get install clamav -y
freshclam
clamscan -r /*

apt-get autoremove -y
apt-get autoclean -y
apt-get clean -y



#Order of Operations (Take notes throughout)
#1.Read readme
#2.answer forensics
#	-apt install git
#3.git clone https://github.com/Adamapb/asacypat.git
#	chmod +x <file name>
#./<file name>
#4.Check scoring
#5.do user tasks (Perms, acct types, passwords, super users)
#6.Check output populated earlier in script (in comments)
#7.check scoring
#8.Review readme **CAREFULLY**
#9.View running services/daemons
#10.view active ports
#11.check system spec utilization
#	-Run Lynis. Commands near top of script
#12.check scoring
#13.review readme, double check update status on named applications
#14.If not 100, **brainstorm**, review config files, review running services
#15.Check netplan?
#16.Check sudoers.d?
#17.Check package repositories?
#18. Enable auto-updates?
#19.LOG OUT AND LOCK ROOT
#20.Disable guest user
#21.Review Local Policies
#22.Cross-reference CP XIII R3 vulnerability categories. (In Adam's repo)