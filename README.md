# ATAT
Attack Team Automation Tool for automating penetration testing operations. Based on ezsploit by rand0m1ze.
The ATAT folder must be duplicated in /root & ~/ to run properly (this only needs to be done once and does not need to be updated).
You can have the ATAT folder in /root only if you wish; and you can run it from there.
You do not have to run the script from /root if you place one copy of the ATAT folder in ~/ and one copy in /root.

usage:chmod +x ~/ATAT/ATAT.sh
cd ATAT
sudo ./ATAT.sh

You MUST load your PORTS or IPs into their appropriate TXT files for options 6, 7, & 8 to work (one per line)!
OPTION 6:~/ATAT/Exploit/MultiTarget/MSF_targets.txt
OPTION 7:~/ATAT/Exploit/MultiPort/MSF_target_ports.txt
OPTION 8:~/ATAT/Auxiliary/MultiPort/MSF_AUX_target_ports.txt
