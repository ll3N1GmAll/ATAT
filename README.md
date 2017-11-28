# ATAT
Attack Team Automation Tool for automating penetration testing operations. Based on ezsploit by rand0m1ze.
v1.3 Changelog:
Added support for linux post exploitation,
Added support for Apache Struts exploits,
Added support for Java JMX exploitation,
Added support for Java RMI exploitation,
Added fully automated MSF Post Exploitation on all sessions acquired for the following post ex activities:
- enumerate hosts
- dump cached domain creds
- verify if you are on a vm
- group policy preferences (dump local admin creds if pushed via GPO)
- steal SVN creds (code repository)
- steal scp creds
- enumerate internal sites the user visits
- all apps installed on target
- Chrome, dump cookies, and saved creds
- IE, dump cookies, and saved creds
- Firefox, dump cookies, and saved creds
- grab RDP sessions
- grab local settings and local accounts
- dumps WPA PSK & WEP passwords
- dumps passwords on the local windows system including domain accounts
- dump .ssh directory for known hosts
- gather OS environment variables
- dump /etc/shadow
- dump user list plus bash/mysql/vim/lastlog/sudoers history
- enum packages, services, mounts, user list, bash
- check for AV, rootkit, HIDS/HIPS, firewalls, etc
- dump IPTables, interfaces, wifi info, open ports
- collect config files for commonly installed apps and services

The ATAT folder must be duplicated in /root & ~/ to run properly (this only needs to be done once and does not need to be updated).
You can have the ATAT folder in /root only if you wish; and you can run it from there.
You do not have to run the script from /root if you place one copy of the ATAT folder in ~/ and one copy in /root.

For post exploitation, you must enter each module (one per line) that you wish to run through any meterpreter shells spawned in the postex.rc file

usage:
chmod +x ~/ATAT/ATAT.sh
cd ATAT
sudo ./ATAT.sh

You MUST load your PORTS or IPs into their appropriate TXT files for options 6, 7, & 8 to work (one per line)!

OPTION 6:
/root/ATAT/MSF_targets.txt

OPTION 7:
/root/ATAT/MSF_target_ports.txt

OPTION 8:
/root/ATAT/MSF_AUX_target_ports.txt

OPTION 9:
/root/ATAT/MSF_targets.txt

OPTION 10:
/root/ATAT/MSF_targets.txt
