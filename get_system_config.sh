#!/bin/bash
current_time=$(date "+%b-%d-%Y_%I_%M_%S")
tasks=(version meminfo Intel800Series drivers DDP NUMA IRQ CPU CPU_Power CPU_Freq CPU_Topology System_info TUNED_status IRQ_Balance_status)
drivers_list=(ice idpf i40e iavf) #idpf

ls setup_parameters.sh > /dev/null 2>&1
status=$?
if [[ "$status" == 0 ]]; then
	echo "using parameters in setup_parameters.sh"
	source setup_parameters.sh
fi
iface=ens11f0
if [[ -z $iface ]]; then 
	readarray interfaces < <(find /sys/class/net -mindepth 1 -maxdepth 1 ! -name "br*" ! -name "eno*" ! -name "enx*" ! -name "cal*" ! -name "tun*"  ! -name "docker*" ! -name "lo" ! -name "vir*" -printf "%P " -execdir cat {}/device/device \;  | awk '{ print $1 }')
else
	interfaces=("$iface")
fi
#echo "Reporting configurations for interface(s) " "${interfaces[@]// /}" 

# Function: version
# Function to retrieve system configuration information
# This function prints the Linux version, current time, uname output, and the contents of /proc/cmdline
# The output is appended to the specified outfile
version(){
	{ 
		echo "************************************************************"
		echo linux_version
		echo "updated=$current_time"
		echo "************************************************************"
		uname -a 
		echo 
		echo "cmdline" 
		echo "cmdline=""$(cat /proc/cmdline)" 
		echo 
	} >> "${outfile}"
}

# Function: meminfo
# Description: This function retrieves information about the system's memory and appends it to the specified output file.
# Parameters: None
# Returns: None
meminfo(){
	{
		echo "************************************************************"
		echo meminfo
		echo updated="$current_time"
		echo "************************************************************"
		awk -F: '{gsub(" ",""); print $1 "=" $2}' /proc/meminfo
		echo 
	} >> "${outfile}"
}

# Function: Intel800Series
# Description: This function retrieves system configuration details for Intel 800 Series devices.
# It iterates through the list of network interfaces and collects information such as device ID,
# firmware version, PCI address, MAC address, NUMA node, IP address, ADQ flag status, IRQ count,
# IRQ start, link status, and tc qdisc show information. It also retrieves bus status information
# for devices with PCIe connections. The collected information is appended to the specified output file.
# Parameters:
#   - None
# Returns:
#   - None

Intel800Series(){
	{ 
		# Print header information
		echo "************************************************************"
		echo Intel800Series
		echo "updated=$current_time"
		echo "************************************************************"
	} >> "${outfile}"

	# Iterate through the list of interfaces
	for i in "${interfaces[@]// /}" ; do
		echo "$i"
		{
			# Print details for the current interface
			echo "Details for \"$i\""
			find /sys/class/net -mindepth 1 -maxdepth 1 -name "$i" -printf "%P.device_id=" -execdir cat {}/device/device \; 
			echo -n "$i" 
			ethtool -i "$i" | grep firmware-version | awk '{ print ".firmware="$3 }'	
			echo -n "$i" 
			ethtool -i "$i" | grep bus-info | awk '{ print ".pci_address="$2 }'
			find /sys/class/net -mindepth 1 -maxdepth 1 -name "$i" -printf "%P.mac_address=" -execdir cat {}/address \; 
			find /sys/class/net -mindepth 1 -maxdepth 1 -name "$i" -printf "%P.numa_node=" -execdir cat {}/device/numa_node \; 
		} >> "${outfile}"

		# Get IP address for the interface
		ipaddr=$(ip -f inet -o addr show dev "$i"|cut -d\  -f7|cut -d/ -f1)
		if [ -z "$ipaddr" ]
		then
			# If IP address is not available, write NA to the output file
			echo -n "$i" >> "${outfile}"; echo ".ip_address=NA" >> "${outfile}"
		else
			# Write the IP address to the output file
			echo -n "$i" >> "${outfile}";  echo ".ip_address=${ipaddr}" >> "${outfile}"
		fi
		echo >> "${outfile}"

		# Check if the ice driver is compiled with ADQ flag
		ethtool -S "${i}" | grep "pkts_bp_stop_budget" > /dev/null 2>&1
		status=$?
		if [[ "$status" == 0 ]]; then
			echo "ice driver COMPILED with ADQ flag. ADQ statitics enabled."  >> "${outfile}"
		else 
			echo "ice driver NOT COMPILED with ADQ flag" >> "${outfile}"
		fi
		echo >> "${outfile}"

		# Get IRQ information for the interface
		irqs=""
		mapfile -t irqs < <(grep "$i" /proc/interrupts | cut -f1 -d:)
		if [ -n "${irqs[0]}" ]; then 
			{
				# Write IRQ count and start information to the output file
				echo "$i"".irq.count=""${#irqs[@]}" | sed -r 's/\s+//g' 
				echo "$i"".irq.start=""${irqs[0]}" | sed -r 's/\s+//g' 
				echo "$i"".irq.start=""${irqs[-1]}" | sed -r 's/\s+//g' 
			} >> "${outfile}"
		fi

		{
			echo
			echo "ip link show information"
		} >> "${outfile}"
		
		interface=$i
		linkstatus=$(ip link show "$i" | sed 's/^.*\: //' | awk '$1=$1')
		{
			# Write link status information to the output file
			echo "$interface.linkstatus = $linkstatus"
			echo
			echo "tc qdisc show information for $i" 
		} >> "${outfile}"
		counter=1
		tc qdisc show dev "$i" | while read -r line ; do
			# Write tc qdisc show information to the output file
			echo "$interface"_tc_qdisc_entry.$counter="$line" >> "${outfile}"
			counter=$((counter+1))
		done 

		echo >> "${outfile}"
		echo >> "${outfile}"
	done

	{
		# Print footer information
		echo "************************************************************" 
		echo 'All devices should report the following -- 126.016 Gb/s available PCIe bandwidth, limited by 8 GT/s x16 link' 
	} >> "${outfile}"

	# Get bus status information for devices with PCIe connections
	dmesg | grep 'ice 000' | grep PCIe | sed 's/\[[^]]*\] ice //g' | sort | uniq | while read -r line ; do
		currentbus=$(dmesg | grep 'ice 000' | grep PCIe | sed 's/\[[^]]*\] ice //g' | sort | uniq | awk '{print substr($1, 1, length($1)-1)}' | sed -n "${counter}"p)
		echo "bus_status.$currentbus=$line" >> "${outfile}"
	done 
	echo >> "${outfile}"
}

#drivers
# This function retrieves information about the loaded drivers on the system.
# It appends the driver information to the specified output file.
# Parameters:
#   - None
# Returns:
#   - None
drivers(){
	{ 
		echo "************************************************************"
		echo drivers
		echo updated="$current_time"
		echo "************************************************************"
	} >> "${outfile}"

	for driver in "${drivers_list[@]}"; do
		lsmod | grep "${driver}" > /dev/null 2>&1
		status=$?
		if [[ "$status" == 0 ]]; then
			{
				echo "************************************************************"
				echo "$driver""_driver_info.updated=$current_time"
				echo "************************************************************"
				modinfo "$driver"
				echo 
			} >> "${outfile}"
		else
			echo "${driver} not loaded"
		fi
	done
}

# DDP Package
# Function to retrieve DDP (Data Plane Development Kit) information and write it to an output file.
# The function appends DDP information to the specified output file.
# Parameters:
#   - outfile: The path to the output file.
# Returns: None
DDP(){
	{ 
		echo "************************************************************"
		echo ice_DDP 
		echo updated="$current_time" 
		echo "************************************************************" 
	} >> "${outfile}"

	# Retrieve DDP package status for each bus and write it to the output file.
	dmesg | grep ice.pkg | sed 's/\[[^]]*\] ice //g' | sort | uniq | while read -r line ; do
	  	currentbus=$(dmesg | grep ice.pkg | sed 's/\[[^]]*\] ice //g' | sort | uniq | awk '{print substr($1, 1, length($1)-1)}' | sed -n "${counter}"p)
		echo "DDP_pkg_status.$currentbus=$line" >> "${outfile}"
	done 

	{	
		echo
		echo "DDP_Updates_pkg=/lib/firmware/updates/intel/ice/ddp/ice.pkg" 
	} >> "${outfile}"

	updates_ddp_pkg=/lib/firmware/updates/intel/ice/ddp/ice.pkg

	# Check if DDP updates package exists and write its information to the output file.
	if [[ -f "$updates_ddp_pkg" ]]; then
		{
			echo DDP_Updates_pkg_date="$(stat -c '%.10y ' /lib/firmware/updates/intel/ice/ddp/ice.pkg)"
			echo DDP_Updates_pkg_size="$(du -sh --apparent-size /lib/firmware/updates/intel/ice/ddp/ice.pkg) | awk '{print $1}'"
			echo 
		} >> "${outfile}"
	else
		{
			echo DDP_Updates_pkg_error=$updates_ddp_pkg " does not exist. The adapters may be running in Safe Mode and will not be fully featured."
			echo 
		} >> "${outfile}"
	fi
	
	# Count the number of DDP updates packages and write the count to the output file.
	DPP_Updates_pkg_count=$(find /lib/firmware/updates/intel/ice/ddp/ -name '*.pkg' | wc -l)
	echo "DPP_Updates_pkg_count=$DPP_Updates_pkg_count" >> "${outfile}"
	updatespkgcounter=1

	# Write the names of DDP updates packages to the output file.
	find /lib/firmware/updates/intel/ice/ddp/ -name '*.pkg' -exec basename {} \; | while read -r i ; do
		echo DDP_Updates_pkg_file.$updatespkgcounter="$i" >> "${outfile}"
		updatespkgcounter=$((updatespkgcounter+1))
	done

	ddp_pkg=/lib/firmware/intel/ice/ddp/ice.pkg
	{
		echo
		echo "DDP_pkg=$ddp_pkg" 
	} >> "${outfile}"

	# Check if DDP package exists and write its information to the output file.
	if [[ -f "$ddp_pkg" ]]; then
		{
		echo DDP_pkg_date="$(stat -c '%.10y ' $ddp_pkg)"
		echo DDP_pkg_size="$(du -sh --apparent-size $ddp_pkg) | awk '{print $1}'"
		echo
		} >> "${outfile}"
	else
		{
		echo DDP_pkg_error=$ddp_pkg " does not exist. DPDK may not work correctly." >> "${outfile}"
		echo
		} >> "${outfile}"
	fi

	# Count the number of DDP packages and write the count to the output file.
	echo DPP_pkg_count="$(find /lib/firmware/intel/ice/ddp -type f -name '*.pkg' | wc -l)" >> "${outfile}"
	pkgcounter=1

	# Write the names of DDP packages to the output file.
	find /lib/firmware/intel/ice/ddp/ -name '*.pkg' -exec basename {} \; | while read -r i ; do
		echo "DDP_pkg_file.$pkgcounter=$i" >> "${outfile}"
		pkgcounter=$((pkgcounter+1))
	done

	echo >> "${outfile}"
}

#NUMA
# Function: NUMA
# Description: This function retrieves NUMA (Non-Uniform Memory Access) information from the system and appends it to the specified output file.
# Parameters: None
# Output: The NUMA information is appended to the output file specified by the 'outfile' variable.
NUMA(){
	{ 
		echo "************************************************************"
		echo NUMA
		echo updated="$current_time"
		echo "************************************************************"
	} >> "${outfile}"
	lscpu | grep NUMA | while read -r line ; do
		echo "$line" | sed -e 's/[)(]//g' -e 's/: /=/g' -e 's/ /_/g' >> "${outfile}"
	done
	echo >> "${outfile}"
}

#IRQ
# Function to retrieve IRQ information and write it to a file
IRQ(){
	{ 
		echo "************************************************************"
		echo IRQ
		echo updated="$current_time"
		echo "************************************************************"
	} >> "${outfile}"
	
	folder_path="/proc/irq/*/smp_affinity"
	# Check if the folder path is not empty
	if [[ -n $folder_path ]]; then
		echo "Values in ""$folder_path"" folder" >> "${outfile}"
		
		# Get the list of files in the folder
		folder_files=$(ls $folder_path)
		
		# Iterate through each file in the folder
		for file in $folder_files; do 
			irqnumber=${file////.}
			
			# Write the IRQ number and its corresponding value to the output file
			echo "${irqnumber}""="$(cat $file) | sed 's/.proc.//g' >> "${outfile}"
		done
	fi
	
	echo >> "${outfile}"
}

#CPU
# Function to retrieve CPU information and write it to a file
CPU(){
	{ 
		echo "************************************************************"
		echo CPU
		echo updated="$current_time"
		echo "************************************************************"
	} >> "${outfile}"		

    # Path to the parent directory containing CPU information
    parent_path="/sys/devices/system/cpu/"

    # Loop through each folder in the parent directory
	for folder in ${parent_path}; do 
        folder_path=${folder} ; 
        
        # Check if the folder is a directory
        if [[ -d $folder_path ]]; then
            echo "Values in ""${folder_path}"" folder" >> "${outfile}"
            
            # Get the list of files in the folder
            folder_files=$(ls "$folder_path")
            
            # Loop through each file in the folder
            for file in ${folder_files}; do 
				# Check if the file is a directory
				if [ -d "$folder_path"/"${file}" ]; then
					skip=1
				else
					# Write the file name and its contents to the output file
					echo "${file}""=""$(cat "${folder_path}"/"${file}")" >> "${outfile}" 
				fi
			done
            echo >> "${outfile}" 
		fi
	done
    echo >> "${outfile}"
}

#CPU_Power
# Function to retrieve CPU power information and write it to a file
CPU_Power(){
	{ 
		echo "************************************************************"
		echo CPU_Power
		echo updated="$current_time"
		echo "************************************************************"
	} >> "${outfile}"	
	folder_path="/sys/devices/system/cpu/intel_pstate/"
	if [[ -d ${folder_path} ]]; then
		echo "Values in ""${folder_path}"" folder" >> "${outfile}"
		folder_files=$(ls "$folder_path")
		for file in $folder_files; do echo "${file}""=""$(cat "${folder_path}"/"${file}")" >> "${outfile}"; done
	fi
	echo >> "${outfile}"
}

#CPU_Freq
# CPU_Freq function retrieves and logs the CPU frequency information.
# It appends the CPU frequency details to the specified output file.
CPU_Freq(){	
	{ 
		echo "************************************************************"
		echo CPU_Freq
		echo updated="$current_time"
		echo "************************************************************"
	} >> "${outfile}"
	folder_path="/sys/devices/system/cpu/cpu0/cpufreq/"
	if [[ -d $folder_path ]]; then
		echo "Values in ""${folder_path}"" folder" >> "${outfile}"
		folder_files=$(ls $folder_path)
		for file in $folder_files; do echo "${file}""=""$(cat ${folder_path}/"${file}")" >> "${outfile}" ; done
	fi
	echo >> "${outfile}"
}

#CPU_Topology
CPU_Topology(){	
	{
		echo
		echo "************************************************************"
		echo CPU_Topology
		echo updated="$current_time"
		echo "************************************************************"
	} >> "${outfile}"
	folder_path="/sys/devices/system/cpu/cpu0/topology/"
	if [[ -d $folder_path ]]; then
		echo "Values in ""${folder_path}"" folder" >> "${outfile}"
		folder_files=$(ls $folder_path)
		for file in $folder_files; do echo "${file}""=""$(cat $folder_path/"${file}")" >> "${outfile}" ; done
	fi
	{
		echo
		echo "************************************************************" 
		echo CPU_0_thermal_throttle_information.updated="$current_time" 
		echo "************************************************************"
	} >> "${outfile}"

	folder_path="/sys/devices/system/cpu/cpu0/thermal_throttle/"
	if [[ -d $folder_path ]]; then
		echo "Values in ""${folder_path}"" folder" >> "${outfile}"
		folder_files=$(ls "$folder_path")
		for file in $folder_files; do echo "$file""=""$(cat $folder_path/"${file}")" >> "${outfile}" ; done
	fi
	{
		echo
		echo "************************************************************" 
		echo CPU_cpuidle_information.updated="$current_time" >> "${outfile}"
		echo "************************************************************"
	} >> "${outfile}"

	folder_path="/sys/devices/system/cpu/cpuidle/"
	if [[ -d $folder_path ]]; then
		echo "Values in ""${folder_path}"" folder" >> "${outfile}"
		folder_files=$(ls "$folder_path")
		for file in $folder_files; do echo "$file""=""$(cat $folder_path/"${file}")" >> "${outfile}" ; done
	fi
	{
		echo
		echo "************************************************************" 
		echo CPU_0_cpuidle_information.updated="$current_time" 
		echo "************************************************************"
	} >> "${outfile}"

        parent_path="/sys/devices/system/cpu/cpu0/cpuidle/state*/"
	for folder in $parent_path; do folder_path=$folder ; 
        if [[ -d $folder_path ]]; then
                echo "Values in ""${folder_path}"" folder" >> "${outfile}"
				statefolder=$(basename "${folder_path}")
                folder_files=$(ls "$folder_path")
                for file in $folder_files; do 
					if [ -d "${folder_path}"/"${file}" ]; then
						echo "$file" is a directory >> "${outfile}"
					else
						echo "$statefolder"."$file""=""$(cat "${folder_path}"/"${file}")" >> "${outfile}" 
					fi
				done
        echo >> "${outfile}" 
		fi
	done
        echo >> "${outfile}"
}

#System_info
# Function to retrieve system configuration information and append it to an output file.
# The function retrieves various system configuration parameters using sysctl and stores them in the output file.
# It also retrieves specific parameters related to network core and IPv4 settings.
# Additionally, it retrieves specific parameters related to virtual memory, kernel scheduling, performance events, and file system usage.
# The retrieved parameters are formatted and appended to the output file.

System_info(){
	{ 
		echo "************************************************************"
		echo system_level_config
		echo "updated=$current_time"
		echo "************************************************************"
	} >> "${outfile}"	

	sysctl_outfile=configuration_sysctl.ALL.$(hostname).conf
	sysctl -a > "${sysctl_outfile}"
	net_core_list=(somaxconn netdev_max_backlog rmem_default wmem_default rmem_max wmem_max optmem_max rps_sock_flow_entries netdev_rss_key netdev_budget netdev_budget_usecs dev_weight_rx_bias dev_weight_tx_bias busy_poll busy_read max_skb_frags default_qdisc)
	for item in "${net_core_list[@]}"; do
		grep net.core."$item" "${sysctl_outfile}" | sed -r 's/ = /=/g' >> "${outfile}"
	done
	
	net_ipv4_list=(tcp_available_congestion_control tcp_congestion_control tcp_moderate_rcvbuf tcp_notsent_lowat tcp_max_syn_backlog tcp_mem tcp_rmem tcp_wmem tcp_limit_output_bytes tcp_slow_start_after_idle tcp_tw_reuse tcp_timestamps tcp_window_scaling tcp_autocorking tcp_early_retrans tcp_ecn tcp_dsack tcp_sack tcp_fack tcp_fastopen tcp_no_metrics_save tcp_mtu_probing tcp_low_latency tcp_max_orphans tcp_synack_retries tcp_syncookies tcp_fin_timeout tcp_keepalive_intvl tcp_keepalive_probes)
	
	for item in "${net_ipv4_list[@]}"; do
		grep net.ipv4."$item" "${sysctl_outfile}" | sed -r 's/ = /=/g' >> "${outfile}"
	done

	{
		grep "vm.dirty_ratio" "${sysctl_outfile}"
		grep "vm.dirty_background_ratio" "${sysctl_outfile}"
		grep "vm.swappiness" "${sysctl_outfile}"
		grep "vm.min_free_kbytes" "${sysctl_outfile}"
		grep "vm.zone_reclaim_mode" "${sysctl_outfile}"
		grep "kernel.sched_migration_cost_ns" "${sysctl_outfile}"
		grep "kernel.sched_min_granularity_ns" "${sysctl_outfile}"
		grep "kernel.sched_wakeup_granularity_ns" "${sysctl_outfile}"
		grep "kernel.perf_event_max_sample_rate" "${sysctl_outfile}"
		grep "kernel.perf_cpu_time_max_percent" "${sysctl_outfile}"
		grep "fs.file-nr" "${sysctl_outfile}"
	} | sed -r 's/ = /=/g' >> "${outfile}"

	echo >> "${outfile}"
}

System_info_sysctl(){	
	{ 
		echo "************************************************************"
		echo system_level_config
		echo "updated=$current_time"
		echo "************************************************************"
	} >> "${outfile}"

	net_core_list=(somaxconn netdev_max_backlog rmem_default wmem_default rmem_max wmem_max optmem_max rps_sock_flow_entries netdev_rss_key netdev_budget netdev_budget_usecs dev_weight_rx_bias dev_weight_tx_bias busy_poll busy_read max_skb_frags default_qdisc)
	for item in "${net_core_list[@]}"; do
		sysctl net.core."$item" | sed -r 's/ = /=/g' >> "${outfile}"
	done
	
	net_ipv4_list=(tcp_available_congestion_control tcp_congestion_control tcp_moderate_rcvbuf tcp_notsent_lowat tcp_max_syn_backlog tcp_mem tcp_rmem tcp_wmem tcp_limit_output_bytes tcp_slow_start_after_idle tcp_tw_reuse tcp_timestamps tcp_window_scaling tcp_autocorking tcp_early_retrans tcp_ecn tcp_dsack tcp_sack tcp_fack tcp_fastopen tcp_no_metrics_save tcp_mtu_probing tcp_low_latency tcp_max_orphans tcp_synack_retries tcp_syncookies tcp_fin_timeout tcp_keepalive_intvl tcp_keepalive_probes)
	
	for item in "${net_ipv4_list[@]}"; do
		sysctl net.ipv4."$item" | sed -r 's/ = /=/g' >> "${outfile}"
	done

	{
		sysctl vm.dirty_ratio | sed -r 's/ = /=/g' 
		sysctl vm.dirty_background_ratio | sed -r 's/ = /=/g'
		sysctl vm.swappiness | sed -r 's/ = /=/g'
		sysctl vm.min_free_kbytes | sed -r 's/ = /=/g' 
		sysctl vm.zone_reclaim_mode | sed -r 's/ = /=/g' 

		sysctl kernel.sched_migration_cost_ns | sed -r 's/ = /=/g' 
		sysctl kernel.sched_min_granularity_ns | sed -r 's/ = /=/g'
		sysctl kernel.sched_wakeup_granularity_ns | sed -r 's/ = /=/g'
		sysctl kernel.perf_event_max_sample_rate | sed -r 's/ = /=/g' 
		sysctl kernel.perf_cpu_time_max_percent | sed -r 's/ = /=/g'
		sysctl fs.file-nr | sed -r 's/ = /=/g' 
	} >> "${outfile}"
}

# Function to get the status of the tuned service and write it to an output file.
# The function prints a header with the current time, followed by the status of the tuned service.
# If the tuned service is running, it also prints the active tuning profile.
# The output is appended to the specified output file.

TUNED_status(){
	{
		echo
		echo "************************************************************"
		echo tuned_service_status
		echo updated="$current_time"
		echo "************************************************************"
		systemctl status tuned
		if systemctl status tuned | grep -q running; then
			tuned-adm active
		fi
		echo
	} >> "${outfile}"
}

#IRQ_Balance_status
# Function: IRQ_Balance_status
# Description: This function checks the status of the irqbalance service and appends the result to the specified output file.
# Parameters: None
# Returns: None

IRQ_Balance_status(){
	{
		echo
		echo "************************************************************"
		echo irqbalance_service_status
		echo updated="$current_time"
		echo "************************************************************"
	} >> "${outfile}"

	IRQBALANCE_ON=$(pgrep -c irqbalance)
		if [ "$IRQBALANCE_ON" == "0" ] ; then
			echo "irqbalance=running"  >> "${outfile}"
		else
			echo "irqbalance=not running"  >> "${outfile}"
		fi
	echo >> "${outfile}"
}

#Run all Tasks
# Function: ALL
# Description: This function generates a configuration report for the system by running a series of tasks.
#              The output is saved to a file named configuration_details.ALL.`hostname`.txt.
#              The function also logs the date and time of the report generation.
# Parameters: None
# Returns: None

ALL(){
	outfile="configuration_details.ALL.$(hostname).txt"
	touch "${outfile}"
	date > "${outfile}"
	echo >> "${outfile}"
	for item in "${tasks[@]}"; do
		echo "Running $item tasks"
		$item
	done
	echo >> "${outfile}"
}

# This script is used to generate system configuration details and save them to a file.
# If no argument is provided, it will generate configuration details for all components.
# If an argument is provided, it will generate configuration details for the specified component.

# Usage: ./get_system_config.sh [component]

# Parameters:
#   - component: Optional. The component for which to generate configuration details.

# Example usage:
#   - Generate configuration details for all components:
#     ./get_system_config.sh

#   - Generate configuration details for a specific component:
#     ./get_system_config.sh cpu

# The script creates a file named "configuration_details.<component>.<hostname>.txt" and appends the configuration details to it.
# The file is created in the same directory as the script.

# Dependencies:
#   - None

# Exit codes:
#   - None

# Note: This script requires write permissions in the directory where it is executed.

if [ -z "$1" ]
	then
		ALL
	else
outfile="configuration_details.$1.$(hostname).txt"
touch "${outfile}"
date > "${outfile}"
	echo >> "${outfile}"
	$1
fi
