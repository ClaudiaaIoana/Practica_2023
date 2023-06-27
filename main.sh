#!/bin/bash

traffic_stat()
{
	echo "----------------------------"
	
	let lvl=$1-1
	
	num_packets=`sudo tshark -r filtering$lvl 2> /dev/null | wc -l` 
	time=`sudo tshark -r filtering$lvl 2> /dev/null | tail -n 1 | tr -s " " | cut -f3 -d" "`
	total_size=$(sudo tshark -r filtering$1 -T fields -e frame.len 2> /dev/null | awk '{s+=$1} END {print s}')
	echo "$total_size"
	
	vol_packets=$(echo "scale=2; $num_packets / $time" | bc -l || echo "error: time=0")
	echo "Packets/sec = $vol_packets"
	
	vol_bytes=$(echo "scale=2; $total_size / $time" | bc -l || echo "error: time=0")
	echo "Bytes/sec = $vol_bytes"
	
	src_ips=`sudo tshark -r filtering$lvl -T fields -e ip.src -e ipv6.src 2> /dev/null | sort | uniq | wc -l`
	dest_ips=`sudo tshark -r filtering$lvl -T fields -e ip.dst -e ipv6.dst  2> /dev/null | sort | uniq | wc -l`
	
	echo "Nr. source ip = $src_ips"
	echo "Nr. destination ip = $dest_ips"
	
	src_ports=`sudo tshark -r filtering$lvl -T fields -e ip.src -e ipv6.src -e tcp.srcport -e udp.srcport 2> /dev/null | sort | uniq | wc -l`
	dest_ports=`sudo tshark -r filtering$lvl -T fields -e ip.dst -e ipv6.dst -e tcp.srcport -e udp.srcport 2> /dev/null | sort | uniq | wc -l`
	
	echo "Nr. source ports = $src_ports"
	echo "Nr. destination ports = $dest_ports"
	echo "----------------------------"
}

ip_source()
{
	echo "----------------------------"
	
	let lvl=$1-1
	touch filtering$1
	
	read -p "Introduce ip: " ip
	sudo tshark -r filtering$lvl -Y "ip.src == $ip" -w filtering$1 2> /dev/null || sudo tshark -r filtering$lvl -Y "ipv6.src == $ip" -w filtering$1 2> /dev/null
	sudo tshark -r filtering$1 2> /dev/null | egrep "$ip → "
	echo "----------------------------"
}

ip_destination()
{
	echo "----------------------------"
	
	let lvl=$1-1
	touch filtering$1
	
	read -p "Introduce ip: " ip
	sudo tshark -r filtering$lvl -Y "ip.dst == $ip" -w filtering$1 2> /dev/null || sudo tshark -r filtering$lvl -Y "ipv6.dst == $ip" -w filtering$1 2> /dev/null
	sudo tshark -r filtering$1 2> /dev/null | egrep "→ $ip"
	echo "----------------------------"
}

protocol()
{
	echo "----------------------------"
	
	let lvl=$1-1
	touch filtering$1
	
	read -p "Introduce protocol: " prot
	sudo tshark -r filtering$lvl -Y "$prot" -w filtering$1 2> /dev/null
	sudo tshark -r filtering$1
	echo "----------------------------"
}

interaction()
{
	let lvl=$1-1
	touch filtering$1
	
	read -p "Introduce ip source: " ip
	sudo tshark -r filtering$lvl -Y "ip.dst == $ip" -w filtering$1 2> /dev/null || sudo tshark -r filtering$lvl -Y "ipv6.dst == $ip" -w filtering$1 2> /dev/null
	
	read -p "Introduce ip destination: " ip
	sudo tshark -r filtering$1 -Y "ip.dst == $ip" -w filtering$1 2> /dev/null || sudo tshark -r filtering$1 -Y "ipv6.dst == $ip" -w filtering$1 2> /dev/null
	
	tshark -r filtering$1
	
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
	cp $1 filtering0
	let nr=1
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
				echo "Current level: $nr"
				read -p "Introduce desired level: " new_nr
				if [[ $new_nr -lt 0 ]]
				then
					echo $new_nr
					echo "Invalid level"
				else
				
				while [[ $nr -gt $new_nr ]]
				do
					rm filtering$nr 2> /dev/null
					let nr=nr-1
					echo $nr $new_nr
				done
				fi
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
			traffic_stat $nr
			;;
			ips) 
			ip_source $nr
			let nr=nr+1
			;;
			ipd)
			ip_destination $nr
			let nr=nr+1
			;;
			prot)
			protocol $nr
			let nr=nr+1
			;;
			intr)
			interaction $nr
			;;
			pck)
			let lvl=nr-1
			sudo tshark -r filtering$lvl -x
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
