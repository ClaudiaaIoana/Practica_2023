#!/bin/bash
while true
do
	if [[ -f ~/Documents/GitHub/Practica_2023/filters ]]
	then
	filt=`tail -n 1 ~/Documents/GitHub/Practica_2023/filters`
	if [[ ! $filt = $ant_filt ]]
	then
		if [[ -n $pid ]]
		then
			kill -9 $pid
		fi
		
		level=`wc -l ~/Documents/GitHub/Practica_2023/filters | egrep -o "\b[0-9]+\b"`
		echo "----------------------------------------------------------------"
		echo "----------------------------------------------------------------"
		echo "LEVEL $level"
		echo "----------------------------------------------------------------"
		echo "----------------------------------------------------------------"
		tail -f ~/Documents/GitHub/Practica_2023/online_fcaptures | tshark -r - -l 2> /dev/null &
		pid=$!
	fi
	ant_filt=$filt
	else 
		exit 1
	fi
done
