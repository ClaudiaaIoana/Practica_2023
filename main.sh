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

port_source()
{
	echo "----------------------------"
	
	let lvl=$1-1
	touch filtering$1
	
	read -p "Source port: " pr
	sudo tshark -r filtering$lvl -Y "tcp.srcport == $pr or udp.srcport == $pr" -w filtering$1 2> /dev/null
	sudo tshark -r filtering$1 2> /dev/null | egrep "$ip → "
	echo "----------------------------"
}

port_destination()
{
	echo "----------------------------"
	
	let lvl=$1-1
	touch filtering$1
	
	read -p "Source port: " pr
	sudo tshark -r filtering$lvl -Y "tcp.dstort == $pr or udp.dstport == $pr" -w filtering$1 2> /dev/null
	sudo tshark -r filtering$1 2> /dev/null | egrep "$ip → "
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
	
	read -p "Introduce ip1: " ip1
	read -p "Introduce ip2: " ip2
	sudo tshark -r filtering$lvl -Y "ip.dst == $ip1 or ips.rc=$ip1" -w filtering$1 2> /dev/null || sudo tshark -r filtering$lvl -Y "ipv6.dst == $ip1 or ipv6.src=$ip1" -w filtering$1 2> /dev/null
	
	sudo tshark -r filtering$lvl -Y "ip.dst == $ip2 or ips.rc=$ip2" -w filtering$1 2> /dev/null || sudo tshark -r filtering$lvl -Y "ipv6.dst == $ip2 or ipv6.src=$ip2" -w filtering$1 2> /dev/null
	
	
	tshark -r filtering$1 | sort -h
	
}

word_alert()
{
	echo "----------------------------"
	read -p "Introduce suspect word: " word
	sudo tshark -r $1 -Y "frame contains \"$word\"" -w $2 2> /dev/null
	
	if [[ -n $(sudo tshark -r $2 2> /dev/null) ]]
	then
		echo "Word alert found !"
		read -p "Print the packets: y/n " chk
		if [[ $chk = "y" ]]
		then
			sudo tshark -r $2 2> /dev/null
		fi
	else
		echo "No alerts found !"
	fi
	
	echo "----------------------------"
}

online_filtering()
{
	if [[ -n $2 ]]
	then
		if [[ -n $(ps $2 | egrep -o $2) ]]
		then
			echo "killing the prev procces"
			sudo kill -9 $2
		fi
	fi
	
	sed -i '/^$/d' filters
	filt=""
	
	while read -r line
	do
	  	filt+="and $line "
	done <$1
	
	filt=`echo $filt | sed "s/^and//"`
	
	tshark -qQ -i ens33 -f "$filt" -w online_fcaptures &
	sleep 2
}

online_word_alert()
{
	read -p "Introduce suspect word: " word
	sudo tshark -i ens33 -f "frame contains \"$word\"" -w $1 2> /dev/null
}


if [[ $# -eq 0 ]]
then
	echo "IN LINE"
	
	PS3="Choose an option:"
	select ITEM in "Statistics" "Alerts" "Exit"
	do
	case $REPLY in
	1)
		touch online_fcaptures
		touch filters
		chmod 666 online_fcaptures
		let nr=1
		filters=""
		
		while true 
		do
		
		read -p "Enter a filter: " filter
		
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
					echo "Invalid level"
				else
				
				while [[ $nr -gt $new_nr  ]]
				do
					aux=`head -n -1 filters`
					echo $aux > filters
					let nr=nr-1
				done
				fi
				break
				;;
				*) 
				echo "Invalid option - eracing filters"
				let nr=1
				truncate -s 0 filters
				break
			esac
			done
		
		case $filter in
			ts)
			
			;;
			ips) 
			read -p "Introduce ip: " ip
			echo "src host $ip" >> filters
			online_filtering "filters" $pid
			pid=$!
			let nr=nr+1
			;;
			ipd)
			read -p "Introduce ip: " ip
			echo "dst host $ip" >> filters
			online_filtering "filters" $pid
			pid=$!
			let nr=nr+1
			;;
			prs)
			read -p "Introduce port: " pr
			echo "tcp.srcport == $pr or udp.srcport == $pr" >> filters
			online_filtering "filters" $pid
			pid=$!
			let nr=nr+1
			;;
			prd)
			read -p "Introduce port: " pr
			echo "tcp.dstport == $pr or udp.dstport == $pr" >> filters
			online_filtering "filters" $pid
			pid=$!
			let nr=nr+1
			;;
			prot)
			read -p "Introduce protocol: " prot
			echo "$prot" >> filters
			online_filtering "filters" $pid
			pid=$!
			let nr=nr+1
			;;
			*) 
			echo "Invalid option"
			break
		esac
		
		done
		rm filters
		PS3="Choose an option:"
	;;
	2) 
		while true 
		do
		
		read -p "Enter a rule: " rule
		if [[ -z $rule ]]
		then
			break
		fi
		
		case $rule in
			wd)
			online_word_alert "online_alerts"
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
	
	let nr=1
	PS3="Choose an option:"
	select ITEM in "Statistics" "Alerts" "Exit"
	do
	case $REPLY in
	1)
		cp $1 filtering0
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
				
				while [[ $nr -gt $new_nr  ]]
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
		cp $1 filtering0
		while true 
		do
		
		echo "" > alerts
		
		read -p "Enter a rule: " rule
		
		if [[ -z $rule ]]
		then
			break
		fi
		
		case $rule in
			wd)
			word_alert "filtering0" "alerts"
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
