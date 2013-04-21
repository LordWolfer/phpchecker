#!/bin/bash

VERSION=3.0

FILE=suspicious_list
STATFILE=

BSCHECK=false
DOSTAT=false
CHKBASE=/
ADDLIST=
ADDCHK=false

#colors
BOLD=$(tput bold)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 6)
GREEN='\e[0;32m'
RESET=$(tput sgr0)

help() {
	cat<<EOF
This script will automatically look for signs of attacks in php web-pages.
Current version: $VERSION

Usage: $0 [<options>]

Options are:

-b		Enable checking for raw bytestreams to the browser.
-f <folder>	Only check folder instead of the whole file system.
-h		This cruft.
-l <list>	Enable additional checks from a list.
-o <file>	The output file
-s <file>	Enable statistics (will be generated in file).

EOF
	exit 0	
}

check() {
	IFS=$'\n'
	echo "Starting tests @ $(date +%Y%m%d:%H%M)...." > $FILE
	echo -e $BOLD
	for i in $(find $CHKBASE -type f -name '*.php')
	do
		echo $i
		#php.ini overrides....
		if [[ $(cat $i) == *'ini_set'* ]] ; then
			echo -e $RED"$i seems to override our php.ini settings! " >> $FILE
		fi
		if [[ $(cat $i) == *"error_reporting"* ]] || [[ $(cat $i) == *"error_log"* ]] ; then
			echo -e $RED"$i seems to tamper with the error reporting! " >> $FILE
		fi		
		if [[ $(cat $i) == *"display_error"* ]] ; then
			echo -e $RED"$i seems to set the displaying of errors! " >> $FILE
		fi
		#running code at runtime....
		if [[ $(cat $i) == *"eval"* ]] ; then
			echo -e $RED"$i seems to be calling eval on something! " >> $FILE
		fi
		if [[ $(cat $i) == *"exec"* ]] ; then
			echo -e $RED"$i seems to be running a shell code! " >> $FILE
		fi
		#checking obfu...
		if [[  $(cat $i) == *"base64_decode"* ]] ; then
			echo -e $YELLOW"$i seems to be decoding something! " >> $FILE
		fi
		if [[  $(cat $i) == *"gzinflate"* ]] ; then
			echo -e $YELLOW"$i seems to extract something gzipped! " >> $FILE
		fi
		#checking if it modifyes the file system
		if [[  $(cat $i) == *"fwrite"* ]] ; then
			echo -e $YELLOW"$i tries to write into a file! " >> $FILE
		fi
		#checking XSS
		if [[  $(cat $i) == *[I,i][F,f][R,r][A,a][M,m][E,e]* ]] ; then
			echo -e $YELLOW"$i contains an iframe! " >> $FILE
		fi
		if [[  $(cat $i) == *"redsirenwebsolutions.com"* ]] || [[  $(cat $i) == *"ha.ckers.org"* ]] ; then
			echo -e $RED"$i mentions a bad domain! " >> $FILE
		fi
		if [[  $(cat $i) == *"fromCharCode"* ]] ; then
			echo -e $RED"$i contains obfuscated javascript! " >> $FILE
		fi
		if [[  $(cat $i) == *"<"[I,i][M,m][G,g]" "[S,s][R,r][C,c]"="[\",\'][J,j][A,a][V,v][A,a][S,s][C,c][R,r][I,i][P,p][T,t]":"* ]] || [[  $(cat $i) == *"<"[I,i][M,m][G,g]" "[S,s][R,r][C,c]"="[J,j][A,a][V,v][A,a][S,s][C,c][R,r][I,i][P,p][T,t]* ]] ; then
			echo -e $RED"$i contains a javascript hidden as an image! " >> $FILE
		fi
		if [[  $(cat $i) == *"document.cookie"* ]] ; then
			echo -e $RED"$i plays with the user's cookie! " >> $FILE
		fi
		if [[  $(cat $i) == *"&#"[0-9]* ]] || [[  $(cat $i) == *"&#x"[0-9]* ]] ; then
			echo -e $RED"$i contains someting obfuscated (utf-8 encoded)! " >> $FILE
		fi
		#checking if it sends raw data to the browser
		if [[ "$BSCHECK" == "true" ]] && [[ $(cat $i) == *'passthru'* ]] ; then
			echo -e $YELLOW"$i seems to be opening a byte-stream to the browser! " >> $FILE
		fi
		#additional checks....
		if [[ "$ADDCHK" == "true" ]] ; then
			for j in $(cat $ADDLIST)
			do
				if [[ $(cat $i) == *"$j"* ]] ; then
					echo -e $GREEN"$i valideted true when checking $j from an user supplied list! " >> $FILE
				fi
			done
		fi
	done
	echo -en $RESET >> $FILE
	echo "Finished successfully."
	unset IFS
	echo -en $RESET
}

statistics(){
	if [[ "$DOSTAT" == "true" ]] ; then
		cat $FILE | grep -v ^""$ | cut -d" " -f1 | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" | uniq -c | sort -r -n -t" " -k 1 > $STATFILE
	fi
}

while getopts bhs:f:o:l: OPTION
do
	case $OPTION in
		h)
			help
			;;
		b)
			BSCHECK=true
			;;
		s)
			#echo "$OPTION triggered with $OPTARG"
			DOSTAT=true
			STATFILE=$OPTARG
			;;
		f)
			#echo "$OPTION triggered with $OPTARG"
			CHKBASE=$OPTARG
			;;
		o)
			FILE=$OPTARG
			;;
		l)
			ADDLIST=$OPTARG
			ADDCHK=true
			;;
		?)
			help
			;;
	esac
done
echo -n "Checking files on $CHKBASE"
if [[ "$DOSTAT" == "true" ]] ; then
	echo -n " with statistics in: $STATFILE"
fi
echo "."
check
statistics

