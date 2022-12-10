#!/bin/bash

#Run as root; confirm forensics complete.
touch debug_output.log
exec 5> debug_output.log
BASH_XTRACEFD="5"
PS4='$LINENO: '

apt-get update -y
apt-get upgrade -y
apt-get dist-upgrade -y

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

apt-get autoremove -y
apt-get autoclean -y


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
