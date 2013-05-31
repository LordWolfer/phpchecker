#!/bin/bash

#            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#                    Version 2, December 2004
#
# Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>
#
# Everyone is permitted to copy and distribute verbatim or modified
# copies of this license document, and changing it is allowed as long
# as the name is changed.
#
#            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
#
#  0. You just DO WHAT THE FUCK YOU WANT TO.

VERSION=3.1

FILE=suspicious_list
STATFILE=

BSCHECK=false
DOSTAT=false
CHKBASE=/
ADDLIST=
ADDCHK=false
SILENT=false
TERMWARN=false

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

When called withouth options the script will start checking the whole filesystem (which can take a while).

Options are:

-b		Enable checking for raw bytestreams to the browser.
-f <folder>	Only check folder instead of the whole file system.
-h		This cruft.
-l <list>	Enable additional checks from a list.
-o <file>	The output file
-s <file>	Enable statistics (will be generated in file).
-q		Quiet mode. Dont write filenames to terminal.
-w		Enable warnings to terminal about the most suspicious files. (Requires quiet mode to be set.)

EOF
	exit 0	
}

fcheck(){
	IFS=$'\n'
	for l in $(cat $1)
	do
		#php.ini overrides....
		if [[ "$l" == *"ini_set"* ]] ; then
			echo -e $RED"$1 seems to override our php.ini settings! "
		fi
		if [[ "$l" == *"error_reporting"* ]] || [[ "$l" == *"error_log"* ]] ; then
			echo -e $RED"$1 seems to tamper with the error reporting! "
		fi		
		if [[ "$l" == *"display_error"* ]] ; then
			echo -e $RED"$1 seems to set the displaying of errors! "
		fi
		#running code at runtime....
		if [[ "$l" == *"eval"* ]] ; then
			echo -e $RED"$1 seems to be calling eval on something! "
		fi
		if [[ "$l" == *"exec"* ]] ; then
			echo -e $RED"$1 seems to be running a shell code! "
		fi
		#checking obfu...
		if [[ "$l" == *"base64_decode"* ]] ; then
			echo -e $YELLOW"$1 seems to be decoding something! "
		fi
		if [[ "$l" == *"gzinflate"* ]] ; then
			echo -e $YELLOW"$1 seems to extract something gzipped! "
		fi
		#checking if it modifyes the file system
		if [[ "$l" == *"fwrite"* ]] ; then
			echo -e $YELLOW"$1 tries to write into a file! "
		fi
		#checking XSS
		if [[ "$l" == *[I,i][F,f][R,r][A,a][M,m][E,e]* ]] ; then
			echo -e $YELLOW"$1 contains an iframe! "
		fi
		if [[ "$l" == *"redsirenwebsolutions.com"* ]] || [[  "$l" == *"ha.ckers.org"* ]] ; then
			echo -e $RED"$1 mentions a bad domain! "
		fi
		if [[ "$l" == *"fromCharCode"* ]] ; then
			echo -e $RED"$1 contains obfuscated javascript! "
		fi
		if [[ "$l" == *"<"[I,i][M,m][G,g]" "[S,s][R,r][C,c]"="[\",\'][J,j][A,a][V,v][A,a][S,s][C,c][R,r][I,i][P,p][T,t]":"* ]] || [[  "$l" == *"<"[I,i][M,m][G,g]" "[S,s][R,r][C,c]"="[J,j][A,a][V,v][A,a][S,s][C,c][R,r][I,i][P,p][T,t]* ]] ; then
			echo -e $RED"$1 contains a javascript hidden as an image! "
		fi
		if [[ "$l" == *"document.cookie"* ]] ; then
			echo -e $RED"$1 plays with the user's cookie! "
		fi
		if [[ "$l" == *"&#"[0-9]* ]] || [[ "$l" == *"&#x"[0-9]* ]] ; then
			echo -e $RED"$1 contains someting obfuscated (utf-8 encoded)! "
		fi
		#checking if it sends raw data to the browser
		if [[ "$BSCHECK" == "true" ]] && [[ "$l" == *"passthru"* ]] ; then
			echo -e $YELLOW"$1 seems to be opening a byte-stream to the browser! "
		fi
		#additional checks....
		if [[ "$ADDCHK" == "true" ]] ; then
			for j in $(cat $ADDLIST)
			do
				if [[ "$l" == *"$j"* ]] ; then
					echo -e $GREEN"$1 valideted true when checking $j from an user supplied list! "
				fi
			done
		fi
	done
	unset IFS
}

check() {
	IFS=$'\n'
	echo "Starting tests @ $(date --rfc-3339=seconds)...." > $FILE
	if [[ "$SILENT" == "false" ]] ; then
		echo -e $BOLD
	fi
	for i in $(find $CHKBASE -type f -name '*.php')
	do
		if [[ "$SILENT" == "false" ]] ; then
			echo $i
		fi
	fcheck $i >> $FILE
	done
	echo -en $RESET >> $FILE
	if [[ "$SILENT" == "false" ]] ; then
		echo "Finished successfully."
		echo -en $RESET
	fi
	unset IFS
}

statistics(){
	if [[ "$DOSTAT" == "true" ]] ; then
		cat $FILE | grep -v ^""$ | grep -v "Starting tests @" | cut -d" " -f1 | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" | uniq -c | sort -r -n -t" " -k 1 > $STATFILE
	fi
}

terminalwarning(){
	if [[ "$TERMWARN" == "true" ]] && [[ "$SILENT" == "true" ]] ; then
		echo $BOLD$RED
		cat $STATFILE | awk '$1 >= 4'
		echo $RESET
	fi
}

while getopts bhs:f:o:l:qw OPTION
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
		q)
			SILENT=true
			;;
		w)
			TERMWARN=true
			;;
		?)
			help
			;;
	esac
done
if [[ "$SILENT" == "false" ]] ; then
	echo -n "Checking files on $CHKBASE"
	if [[ "$DOSTAT" == "true" ]] ; then
		echo -n " with statistics in: $STATFILE"
	fi
	echo "."
fi
check
statistics
terminalwarning

