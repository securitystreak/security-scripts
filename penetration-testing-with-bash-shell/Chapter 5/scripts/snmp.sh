#!/bin/bash
if [ $# != 1 ]
then
	echo "USAGE: . snmp [HOST]"
	exit 1
fi
TARGET=$1
echo "[*] Running SNMP enumeration on '$TARGET'"
for comm_string in \
`msfcli auxiliary/scanner/snmp/snmp_login RHOSTS=$TARGET E 2> /dev/null\
 | awk -F\' '/access with community/ { print $2 }'`; 
do 
		echo "[*] found community string '$comm_string' ...running enumeration"; 
		msfcli auxiliary/scanner/snmp/snmp_enum RHOSTS=$TARGET COMMUNITY=$comm_string E 2> /dev/null;
done
