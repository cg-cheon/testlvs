#! /bin/sh

iface="$1"

function get_packets() {
	cat /proc/net/dev | sed -n "s/.*${iface}:\(.*\)/\1/p" | \
	awk '{ packets += $2} ; END { print packets }'
}

p0="`get_packets "$iface"`"
to=10

while true
do
	sleep $to
	p1="`get_packets "$iface"`"
	echo "$((($p1-$p0)/$to)) packets/sec"
	p0="$p1"
done

