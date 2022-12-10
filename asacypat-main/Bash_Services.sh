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