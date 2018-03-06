# ATAT
Attack Team Automation Tool for automating penetration testing operations. Based on ezsploit by rand0m1ze. Durandal backdoor builder created by Travis Weathers (Skysploit).
v1.5.1
Added support for Apache Struts exploits,
Added support for Java JMX exploitation,
Added support for Java RMI exploitation,
Added support for linux post exploitation,
Added support for load balancer detection,
Added support for SSLScan,
Added support for Masscan of all TCP ports,
Added Android persistenct reverse Meterpreter APK builder,
Added DBD persistent backdoor builder by Skysploit,
Added dependency checker by Skysploit,
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
- grab arp table from target
- enumerate the domain, domain users, and domain tokens
- grab the host file
- dump logged on users
- dump MS product keys
- steal VNC creds
- enumerate services & shares on target
- steal SNMP inforamtion
- dump DNS cache
- steal GPG credentials/certificates
- grab the history of mounted USB devices
- assess the target and suggest local exploits for privilege escalation or other operations

--- INSTRUCTIONS TO RUN THIS FROM /home/<profile>/ instead of running as root ---
The ATAT folder must be duplicated in /root & ~/ to run properly unless you are on Kali (logged in as root) or you are running
another distro logged in as root (duplicating this folder only needs to be done once and does not need to be updated ever).
You then do not have to run the script from /root if you place one copy of the ATAT folder in ~/ and one copy in /root.
Placing a copy of the ATAT folder in /root/ in this circumstance is only so you have the TXT files 
accessible by ATAT when it run as sudo. Then you simply run ATAT via sudo ./ATAT.sh from ~/ATAT.
All targets and/or ports must be added into their respective TXT files in /root/ as referenced above and detailed below.
Adding your targets/ports to the TXT files in ~/ATAT will not work under this setup
*You can have the ATAT folder in /root only if you wish; and you can run it from there and disregard all of these instructions.*

usage:
chmod +x ~/ATAT/ATAT.sh
cd ATAT
sudo ./ATAT.sh

You MUST load your PORTS or IPs into their appropriate TXT files for options listed below to work! (one per line)

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

OPTION 11:
/root/ATAT/MSF_targets.txt

OPTION 12:
/root/ATAT/MSF_targets.txt

OPTION 13:
/root/ATAT/MSF_targets.txt
Results output to screen and the ATAT folder in LBD_Results.txt.
OUTPUT FILES APPEND DATA DUE TO THE NATURE OF THESE LOOPED OPERATIONS; THEREFORE, ALL OUTPUT FILES MUST BE DELETED OR CLEANED OUT PERIODICALLY TO GET RID OF PREVIOUS SCANS' RESULTS

OPTION 14:
/root/ATAT/MSF_targets.txt
Results output to screen and the ATAT folder in SSLScan_Results.txt. All output is further processed and grouped into the following categories:
RC4 findings in rc4.txt
SSLv2 findings in sslv2.txt
Heartbleed Findings in heartbleed_targets.txt
Freak vuln findings in freak.txt
Weak Cipher Findings in weak_ciphers.txt
Expired Certificate Findings in expired_certs.txt
SSL Certificate Details in ssl_certs.txt
OUTPUT FILES APPEND DATA DUE TO THE NATURE OF THESE LOOPED OPERATIONS; THEREFORE, ALL OUTPUT FILES MUST BE DELETED OR CLEANED OUT PERIODICALLY TO GET RID OF PREVIOUS SCANS' RESULTS

OPTION 15:
/root/ATAT/MSF_targets.txt
This masscans all TCP ports for all targets at a reasonable rate (--rate 1000)
Results output to screen and the ATAT folder in Open_Ports.txt.
OUTPUT FILES APPEND DATA DUE TO THE NATURE OF THESE LOOPED OPERATIONS; THEREFORE, ALL OUTPUT FILES MUST BE DELETED OR CLEANED OUT PERIODICALLY TO GET RID OF PREVIOUS SCANS' RESULTS

OPTION 16:
Dependencies option will attempt to install the required dependencies for ATAT. If MingW32 fails you may need to enable Universe in your sources.list file; otherwise research how to get Mingw32 properly installed on your particular distro.
DBD Installer option must be run on your attacker box in order to receive DBD reverse shells.

For post exploitation,

METHOD 1: 
Launch your listener with menu option 2. The default post modules from postex.rc will run againt each meterpreter session you receive.

METHOD 2: If your loot files only contian headers; but no other loot data, then you must do the following: From your listener window, after all of your sessions are in (after your attacks have completed) hit enter to drop down to your handler prompt and then enter the following command without double quotes: "resource '/root/ATAT/ATAT_multi_post.rc'"
