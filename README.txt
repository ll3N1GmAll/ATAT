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
/root/ATAT/Exploit/MultiTarget/MSF_targets.txt

OPTION 7:
/root/ATAT/Exploit/MultiPort/MSF_target_ports.txt

OPTION 8:
/root/ATAT/Auxiliary/MultiPort/MSF_AUX_target_ports.txt

OPTION 9:
/root/ATAT/Exploit/MultiTarget/MSF_targets.txt

OPTION 10:
/root/ATAT/Exploit/MultiTarget/MSF_targets.txt
