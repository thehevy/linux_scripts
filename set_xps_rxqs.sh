#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2019 - 2024 Intel Corporation
#
# Script to setup mechanism for Tx queue selection based on Rx queue(s) map.
# This is done by configuring Rx queue(s) map per Tx queue via sysfs. This
# Rx queue(s) map is used during selection of Tx queue in
# data path (net/core/dev.c:get_xps_queue).
#
# typical usage is (as root):
# set_xps_rxqs <interface> <none> (to set XPS to RX queues)
# set_xps_rxqs <interface> reset (to reset all XPS RX queues to 0)
# to get help:
# set_xps_rxqs


iface=$1
task=$2

if [ -z "$iface" ]; then
	echo "Usage: $0 <interface> <reset|<none>>"
	exit 1
fi

CHECK () {
	"$@"
	if ! mycmd; then
		echo "Error in command ${1}, execution aborted, but some changes may have already been made!" >&2
		exit 1
	fi
}

# Function: CPUMASK
# Description: This function calculates the CPU mask based on the input CPU number.
# Parameters:
#   - cpu: The CPU number for which the mask needs to be calculated.
# Returns:
#   - The calculated CPU mask.
CPUMASK () {
	cpu=$1
	if [ "$cpu" -ge 32 ]; then
		mask_fill=""
		mask_zero="00000000"
		((pow = cpu / 32))
		for ((i=1; i<=pow; i++)); do
			mask_fill="${mask_fill},${mask_zero}"
		done

		((cpu -= 32 * pow))
		mask_tmp=$((1 << cpu))
		mask=$(printf "%X%s" $mask_tmp $mask_fill)
	else
		mask_tmp=$((1 << cpu))
		mask=$(printf "%X" $mask_tmp)
	fi
	echo "$mask"
}


# This script sets the XPS (Transmit Packet Steering) receive queues for a given network interface.
# It iterates over the "/sys/class/net/$iface/queues/tx-"* directories and sets the XPS receive queues to a mask of 0.
# The mask is written to the "xps_rxqs" file in each directory.

if [ "$task" = "reset" ]; then
	for i in "/sys/class/net/$iface/queues/tx-"*/xps_rxqs; do
		j=$(echo "$i" | cut -d'/' -f7 | cut -d'-' -f2)
		mask=0
		echo "${mask}" > "$i"
		CHECK echo "${mask}" > "$i"
	done
else
	# This script sets the XPS (Transmit Packet Steering) RX queues for a given network interface.
	# It iterates over the "/sys/class/net/$iface/queues/tx-"* directories, where $iface is the network interface name.
	# For each directory, it extracts the queue number and sets the corresponding XPS RX queue mask using the CPUMASK command.
	# The mask is then written to the "xps_rxqs" file in the directory.

	for i in "/sys/class/net/$iface/queues/tx-"*/xps_rxqs; do
		j=$(echo "$i" | cut -d'/' -f7 | cut -d'-' -f2)
		mask=$(CPUMASK "$j")
		echo "${mask}" > "$i"
		CHECK echo "${mask}" > "$i"
	done
fi
