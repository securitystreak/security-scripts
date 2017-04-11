#!/bin/bash
HOST=$1
SSL_PORT=$2
KEY_LEN_LIMIT=$3
VULN_SUIT_LIST=$4
echo -e "[*] assessing host \e[3;36m $HOST:$SSL_PORT\e[0m"
for cipher in `sslyze --regular $HOST:$SSL_PORT | awk -F\  '/[0-9]* bits/ { print $1"_"$2"_"$3 }'`
do
		suit=`echo $cipher | awk -F\_ '{ print $1 }' | sed 's/ //g'`
		keylen=`echo $cipher | awk -F\_ '{ print $2 }' | sed 's/ //g'`
		for bad_suit in `cat $VULN_SUIT_LIST`
		do
				BAD_SUIT="0"
				if [ "$suit" = "`echo $bad_suit | sed 's/ //g'`" ]
				then
						suit=`echo -e "\e[1;31m*$suit\e[0m"` #make it red for bad
						BAD_SUIT="1"
				fi
		done
		if [ "$keylen" -lt "$KEY_LEN_LIMIT" ]
		then
			keylen=`echo -e "\e[1;31m*$keylen\e[0m"` #make it red for bad
		fi
		echo -e "\t[+]$suit : $keylen" 
done | column -t -s:
