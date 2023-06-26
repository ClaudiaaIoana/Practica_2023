#!/bin/bash
cat levels
while true
do
	level=`tail -n 1 levels | cut -f1 -d" "`
	if [[ $level -ne $ant_level ]]
	then
		kill -9 $pid
		echo "----------------------------------------------------------------"
		echo "LEVEL $level"
		echo "----------------------------------------------------------------"
		tail -f filtering$level | sudo tshark 2> /dev/null &
		pid=$!
	fi
	ant_level=$level
done
