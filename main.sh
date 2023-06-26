#!/bin/bash

traffic_stat()
{
	echo "----------------------------"
	num_packets=`sudo tshark -r $1 2> /dev/null | wc -l` 
	time=`sudo tshark -r $1 2> /dev/null | tail -n 1 | tr -s " " | cut -f3 -d" "`
	total_size=$(sudo tshark -r $1 -T fields -e frame.len 2> /dev/null | awk '{s+=$1} END {print s}')
	echo "$total_size"
	
	vol_packets=$(echo "scale=2; $num_packets / $time" | bc -l || echo "error: time=0")
	echo "Packets/sec = $vol_packets"
	
	vol_bytes=$(echo "scale=2; $total_size / $time" | bc -l || echo "error: time=0")
	echo "Bytes/sec = $vol_bytes"
	
	src_ips=`sudo tshark -r $1 -T fields -e ip.src -e ipv6.src 2> /dev/null | sort | uniq | wc -l`
	dest_ips=`sudo tshark -r $1 -T fields -e ip.dst -e ipv6.dst  2> /dev/null | sort | uniq | wc -l`
	
	echo "Nr. source ip = $src_ips"
	echo "Nr. destination ip = $dest_ips"
	
	src_ports=`sudo tshark -r $1 -T fields -e ip.src -e ipv6.src -e tcp.srcport -e udp.srcport 2> /dev/null | sort | uniq | wc -l`
	dest_ports=`sudo tshark -r $1 -T fields -e ip.dst -e ipv6.dst -e tcp.srcport -e udp.srcport 2> /dev/null | sort | uniq | wc -l`
	
	echo "Nr. source ports = $src_ports"
	echo "Nr. destination ports = $dest_ports"
	echo "----------------------------"
}

ip_source()
{
	echo "----------------------------"
	read -p "Introduce ip: " ip
	sudo tshark -r $1 -Y "ip.src == $ip" -w $1 2> /dev/null || sudo tshark -r $1 -Y "ipv6.src == $ip" -w $1 2> /dev/null
	sudo tshark -r $1 2> /dev/null | egrep "$ip → "
	echo "----------------------------"
}

ip_destination()
{
	echo "----------------------------"
	read -p "Introduce ip: " ip
	sudo tshark -r $1 -Y "ip.dst == $ip" -w $1 2> /dev/null || sudo tshark -r $1 -Y "ipv6.dst == $ip" -w $1 2> /dev/null
	sudo tshark -r $1 2> /dev/null | egrep "→ $ip"
	echo "----------------------------"
}

protocol()
{
	echo "----------------------------"
	read -p "Introduce protocol: " prot
	sudo tshark -r $1 -Y "$prot" -w $1 2> /dev/null
	sudo tshark -r $1
	echo "----------------------------"
}

word_alert()
{
	echo "----------------------------"
	read -p "Introduce suspect word: " word
	sudo tshark -r $1 -Y "frame contains \"$word\"" -w $2 2> /dev/null
	sudo tchark -r $2 2> /dev/null
	echo "----------------------------"
}

evidence()
{
	echo "$1 $2" >> levels

}

online_ip_source()
{
	#sudo pkill -SIGTERM tshark
	read -p "Introduce ip: " ip
	touch filtering$1
	let pv=$1-1
	(sudo tshark -Y "ip.src == $ip" -r <(tail -f filtering$pv) -w filtering$1
 2>/dev/null & disown) || (sudo tshark -Y "ipv6.src == $ip"-r <(tail -f filtering$pv) -w filtering$1 2>/dev/null & disown)
	pid=$!
	evidence $1 $pid
}



if [[ $# -eq 0 ]]
then
	echo "IN LINE"
	touch filtering0
	touch levels
	sudo tcpdump -i ens33 -w filtering0 & 2> /dev/null
	
	PS3="Choose an option:"
	select ITEM in "Statistics" "Alerts" "Exit"
	do
	case $REPLY in
	1)
		let nr=1
		while true 
		do
		
		read -p "Enter a filter: " filter
		#echo "$filter"
		if [[ -z $filter ]]
		then
			break
		fi
		PS3="Next: "
		select ITEM in "Add filter" "Erase existing filters"
		do
			case $REPLY in
				1)
				break
				;;
				2) 
				let nr=1
				break
				;;
				*) 
				echo "Invalid option - eracing filters"
				let nr=1
				break
			esac
			done
		
		case $filter in
			ts)
			
			;;
			ips) 
			online_ip_source $nr
			let nr=nr+1
			;;
			ipd)
			
			;;
			prot)
			
			;;
			pck)
			
			;;
			dsp)
			sudo tshark -r filtering$nr -l -F pcapng
			;;
			*) 
			echo "Invalid option"
			break
		esac
		
		done
		PS3="Choose an option:"
	;;
	2) 
		while true 
		do
		
		read -p "Enter a rule: " rule
		#echo "$filter"
		if [[ -z $rule ]]
		then
			break
		fi
		
		case $rule in
			wd)
			word_alert "temp" "alerts"
			;;
			*) 
			echo "Invalid option"
			break
		esac
		
		done
	;;
	3) exit 0 ;;
	*) echo "Invalid option"
	esac
	done
	
	
else
	echo "OUT OF LINE file: $1"
	cp $1 temp
	PS3="Choose an option:"
	select ITEM in "Statistics" "Alerts" "Exit"
	do
	case $REPLY in
	1)
		while true 
		do
		
		read -p "Enter a filter: " filter
		#echo "$filter"
		if [[ -z $filter ]]
		then
			break
		fi
		PS3="Next: "
		select ITEM in "Add filter" "Erase existing filters"
		do
			case $REPLY in
				1)
				break
				;;
				2) 
				cp $1 temp
				break
				;;
				*) 
				echo "Invalid option - eracing filters"
				cp $1 temp
				break
			esac
			done
		
		case $filter in
			ts)
			traffic_stat "temp"
			;;
			ips) 
			ip_source "temp"
			;;
			ipd)
			ip_destination "temp"
			;;
			prot)
			protocol "temp"
			;;
			pck)
			sudo tshark -r temp -x
			;;
			*) 
			echo "Invalid option"
			break
		esac
		
		done
		PS3="Choose an option:"
	;;
	2) 
		while true 
		do
		
		read -p "Enter a rule: " rule
		#echo "$filter"
		if [[ -z $rule ]]
		then
			break
		fi
		
		case $rule in
			wd)
			word_alert "temp" "alerts"
			;;
			*) 
			echo "Invalid option"
			break
		esac
		
		done
	;;
	3) exit 0 ;;
	*) echo "Invalid option"
	esac
	done
fi
