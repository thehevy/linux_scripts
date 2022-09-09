#!/bin/bash
current_time=`date "+%b-%d-%Y_%I_%M_%S"`
tasks=(version meminfo Intel800Series drivers DDP NUMA IRQ CPU CPU_Power CPU_Freq CPU_Topology System_info TUNED_status IRQ_Balance_status)
drivers_list=(ice idpf i40e iavf) #idpf

ls setup_parameters.sh > /dev/null 2>&1
status=$?
if [[ "$status" == 0 ]]; then
	echo "using parameters in setup_parameters.sh"
	source setup_parameters.sh
fi

if [[ -z $iface ]]; then 
	readarray interfaces < <(find /sys/class/net -mindepth 1 -maxdepth 1 ! -name br* ! -name eno* ! -name enx* ! -name cal* ! -name tun*  ! -name docker* ! -name lo ! -name vir* ! -name br -printf "%P " -execdir cat {}/device/device \;  | awk '{ print $1 }')
else
	interfaces=($iface)
fi
echo "Reporting configurations for interface(s) "${interfaces[@]// /} 
#echo "Reporting configurations for interface(s) "${interfaces[@]// /} >> $outfile

#OS Version
version(){
echo "************************************************************" >> $outfile
echo linux_version >> $outfile
echo updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
	uname -a >> $outfile
	echo >> $outfile
	echo "cmdline" >> $outfile
	echo "cmdline="`cat /proc/cmdline` >> $outfile
	echo >> $outfile
}

#meminfo
meminfo(){
echo "************************************************************" >> $outfile
echo meminfo >> $outfile
echo updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
  cat /proc/meminfo | while read line; do
	  echo $line | awk '{gsub(":","="); gsub(" ",""); print $0}' >> $outfile
	done
	echo >> $outfile
}
#Intel800Series
Intel800Series(){
echo "************************************************************" >> $outfile
echo Intel800Series >> $outfile
echo updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
	for i in "${interfaces[@]// /}" ; do
		echo "Details for "$i >> $outfile
		find /sys/class/net -mindepth 1 -maxdepth 1 -name $i -printf "%P.device_id=" -execdir cat {}/device/device \; >> $outfile
		echo -n $i >> $outfile; ethtool -i $i | grep firmware-version | awk '{ print ".firmware="$3 }'>> $outfile	
		echo -n $i >> $outfile; ethtool -i $i | grep bus-info | awk '{ print ".pci_address="$2 }'>> $outfile	
		find /sys/class/net -mindepth 1 -maxdepth 1 -name $i -printf "%P.mac_address=" -execdir cat {}/address \; >> $outfile
		find /sys/class/net -mindepth 1 -maxdepth 1 -name $i -printf "%P.numa_node=" -execdir cat {}/device/numa_node \; >> $outfile
		ipaddr=$(ip -f inet -o addr show dev $i|cut -d\  -f7|cut -d/ -f1)
		if [ -z "$ipaddr" ]
				then
				echo -n $i >> $outfile; echo ".ip_address=NA" >> $outfile
			else
							echo -n $i >> $outfile;  echo ".ip_address="$ipaddr >> $outfile
				#			echo -n $i >> $outfile; echo -n ".ip_address=" >> $outfile; ip -f inet -o addr show dev $i|cut -d\  -f7|cut -d/ -f1 >> $outfile
		fi
		echo >> $outfile

		ethtool -S ${i} | grep "pkts_bp_stop_budget" > /dev/null 2>&1
		status=$?
		if [[ "$status" == 0 ]]; then
			echo "ice driver COMPILED with ADQ flag. ADQ statitics enabled."  >> $outfile
		else 
			echo "ice driver NOT COMPILED with ADQ flag" >> $outfile
		fi
		echo >> $outfile

		irqs=""
		irqs=(`grep $i /proc/interrupts | cut -f1 -d:`)
		if [ ! -z ${irqs[0]} ]; then echo $i".irq.count="${#irqs[@]} | sed -r 's/\s+//g' >> $outfile ; echo $i".irq.start="${irqs[0]} | sed -r 's/\s+//g' >> $outfile ; echo $i".irq.start="${irqs[-1]} | sed -r 's/\s+//g' >> $outfile; fi
		echo >> $outfile
		echo "ip link show information" >> $outfile
		interface=`echo $i`
		linkstatus=`ip link show $i | sed 's/^.*\: //' | awk '$1=$1'`
		echo $interface.linkstatus=$linkstatus >> $outfile
		echo >> $outfile
		echo "tc qdisc show information for $i" >> $outfile
		counter=1
		tc qdisc show dev $i | while read line ; do
		  echo "$interface"_tc_qdisc_entry.$counter=$line >> $outfile
		  counter=$[$counter+1]
		done 

		echo >> $outfile
		echo >> $outfile
	done
	echo "************************************************************" >> $outfile
	echo 'All devices should report the following -- 126.016 Gb/s available PCIe bandwidth, limited by 8 GT/s x16 link' >> $outfile
	dmesg | grep 'ice 000' | grep PCIe | sed 's/\[[^]]*\] ice //g' | sort | uniq | while read line ; do
	  currentbus=$(dmesg | grep 'ice 000' | grep PCIe | sed 's/\[[^]]*\] ice //g' | sort | uniq | awk '{print substr($1, 1, length($1)-1)}' | sed -n ${counter}p)
	  echo "bus_status.$currentbus=$line" >> $outfile
	done 
	echo >> $outfile
}

#drivers
drivers(){
echo "************************************************************" >> $outfile
echo drivers >> $outfile
echo updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
for driver in ${drivers_list[@]}; do
	lsmod | grep ${driver} > /dev/null 2>&1
	status=$?
	if [[ "$status" == 0 ]]; then
		echo "************************************************************" >> $outfile
		echo $driver"_driver_info.updated="$current_time >> $outfile
		echo "************************************************************" >> $outfile
		modinfo $driver >>$outfile
		echo >> $outfile
	else
		echo "${driver} not loaded"
	fi
done
}
#DDP Package
DDP(){
echo "************************************************************" >> $outfile
echo ice_DDP >> $outfile
echo updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
	dmesg | grep ice.pkg | sed 's/\[[^]]*\] ice //g' | sort | uniq | while read line ; do
	  currentbus=$(dmesg | grep ice.pkg | sed 's/\[[^]]*\] ice //g' | sort | uniq | awk '{print substr($1, 1, length($1)-1)}' | sed -n ${counter}p)
	  echo "DDP_pkg_status.$currentbus=$line" >> $outfile
	done 
	echo >> $outfile
	updates_ddp_pkg=/lib/firmware/updates/intel/ice/ddp/ice.pkg
	echo "DDP_Updates_pkg=/lib/firmware/updates/intel/ice/ddp/ice.pkg" >> $outfile
	if [[ -f "$updates_ddp_pkg" ]]; then
		echo DDP_Updates_pkg_date=`stat -c '%.10y ' /lib/firmware/updates/intel/ice/ddp/ice.pkg`  >> $outfile
		echo DDP_Updates_pkg_size=`du -sh --apparent-size /lib/firmware/updates/intel/ice/ddp/ice.pkg` | awk '{print $1}' >> $outfile
		echo >> $outfile
	else
		echo DDP_Updates_pkg_error=$updates_ddp_pkg " does not exisit. The adapters maybe running in Safe Mode and will not be fully featured." >> $outfile
		echo >> $outfile
	fi
	
	echo DPP_Updates_pkg_count=`ls /lib/firmware/updates/intel/ice/ddp/*.pkg | wc -l`  >> $outfile
	updatespkgcounter=1
	for i in `find /lib/firmware/updates/intel/ice/ddp/ -name '*.pkg' -exec basename {} \;` ; do
	 echo DDP_Updates_pkg_file.$updatespkgcounter=$i >> $outfile
	 updatespkgcounter=$[$updatespkgcounter+1]
	done
	echo >> $outfile

	ddp_pkg=/lib/firmware/intel/ice/ddp/ice.pkg
	echo "DDP_pkg=/lib/firmware/intel/ice/ddp/ice.pkg" >> $outfile
	if [[ -f "$ddp_pkg" ]]; then
		echo DDP_pkg_date=`stat -c '%.10y ' /lib/firmware/intel/ice/ddp/ice.pkg`  >> $outfile
		echo DDP_pkg_size=`du -sh --apparent-size /lib/firmware/intel/ice/ddp/ice.pkg` | awk '{print $1}' >> $outfile
		echo >> $outfile
	else
		echo DDP_pkg_error=$ddp_pkg " does not exisit. DPDK may not work correctly." >> $outfile
		echo >> $outfile
	fi
	echo DPP_pkg_count=`ls /lib/firmware/intel/ice/ddp/*.pkg | wc -l`  >> $outfile
	pkgcounter=1
	for i in `find /lib/firmware/intel/ice/ddp/ -name '*.pkg' -exec basename {} \;` ; do
	 echo DDP_pkg_file.$pkgcounter=$i  >> $outfile
	 pkgcounter=$[$pkgcounter+1]
	done
	echo >> $outfile
}
#NUMA
NUMA(){
echo "************************************************************" >> $outfile
echo NUMA >> $outfile
echo updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
	lscpu | grep NUMA | while read line ; do
	 echo $line | sed -e 's/[)(]//g' -e 's/: /=/g' -e 's/ /_/g' >> $outfile
	done
	echo >> $outfile
}

#IRQ
IRQ(){
echo "************************************************************" >> $outfile
echo IRQ >> $outfile
echo updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
	folder_path="/proc/irq/*/smp_affinity"
		if [[ -n $folder_path ]]; then
		echo "Values in "$folder_path" folder" >> $outfile
		folder_files=`ls $folder_path`
		for file in $folder_files; do 
		  irqnumber=${file////.}
		  echo $irqnumber"="`cat $file` | sed 's/.proc.//g' >> $outfile
		done
	fi
	echo >> $outfile
}

#CPU
CPU(){		
echo "************************************************************" >> $outfile
echo CPU >> $outfile
echo updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
     parent_path="/sys/devices/system/cpu/"
	for folder in $parent_path; do folder_path=$folder ; 
        if [[ -d $folder_path ]]; then
                echo "Values in "$folder_path" folder" >> $outfile
                folder_files=`ls $folder_path`
                for file in $folder_files; do 
					if [ -d $folder_path/$file ]; then
						skip=1
					else
						echo $file"="`cat $folder_path/$file` >> $outfile 
					fi
				done
        echo >> $outfile 
		fi
	done
        echo >> $outfile
}

#CPU_Power
CPU_Power(){	
echo "************************************************************" >> $outfile
echo CPU_Power >> $outfile
echo updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
	folder_path="/sys/devices/system/cpu/intel_pstate/"
		if [[ -d $folder_path ]]; then
		echo "Values in "$folder_path" folder" >> $outfile
		folder_files=`ls $folder_path`
		for file in $folder_files; do echo $file"="`cat $folder_path/$file` >> $outfile; done
	fi
	echo >> $outfile
}
#CPU_Freq
CPU_Freq(){	
echo "************************************************************" >> $outfile
echo CPU_0_cpufreq >> $outfile
echo updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
	folder_path="/sys/devices/system/cpu/cpu0/cpufreq/"
	if [[ -d $folder_path ]]; then
		echo "Values in "$folder_path" folder" >> $outfile
		folder_files=`ls $folder_path`
		for file in $folder_files; do echo $file"="`cat $folder_path/$file` >> $outfile ; done
	fi
	echo >> $outfile
}
#CPU_Topology
CPU_Topology(){	
echo "************************************************************" >> $outfile
echo CPU_0_topology >> $outfile
echo updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
	folder_path="/sys/devices/system/cpu/cpu0/topology/"
	if [[ -d $folder_path ]]; then
		echo "Values in "$folder_path" folder" >> $outfile
		folder_files=`ls $folder_path`
		for file in $folder_files; do echo $file"="`cat $folder_path/$file` >> $outfile ; done
	fi
	echo >> $outfile

echo "************************************************************" >> $outfile
echo CPU_0_thermal_throttle_information.updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
	folder_path="/sys/devices/system/cpu/cpu0/thermal_throttle/"
	if [[ -d $folder_path ]]; then
		echo "Values in "$folder_path" folder" >> $outfile
		folder_files=`ls $folder_path`
		for file in $folder_files; do echo $file"="`cat $folder_path/$file` >> $outfile ; done
	fi
	echo >> $outfile

echo "************************************************************" >> $outfile
echo CPU_cpuidle_information.updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
	folder_path="/sys/devices/system/cpu/cpuidle/"
	if [[ -d $folder_path ]]; then
		echo "Values in "$folder_path" folder" >> $outfile
		folder_files=`ls $folder_path`
		for file in $folder_files; do echo $file"="`cat $folder_path/$file` >> $outfile ; done
	fi
	echo >> $outfile

echo "************************************************************" >> $outfile
echo CPU_0_cpuidle_information.updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
        parent_path="/sys/devices/system/cpu/cpu0/cpuidle/state*/"
	for folder in $parent_path; do folder_path=$folder ; 
        if [[ -d $folder_path ]]; then
                echo "Values in "$folder_path" folder" >> $outfile
				statefolder=$(basename $folder_path)
                folder_files=`ls $folder_path`
                for file in $folder_files; do 
					if [ -d $folder_path/$file ]; then
						echo $file is a directory >> $outfile
					else
						echo $statefolder.$file"="`cat $folder_path/$file` >> $outfile 
					fi
				done
        echo >> $outfile 
		fi
	done
        echo >> $outfile
}
#System_info
System_info(){	
echo "************************************************************" >> $outfile
echo system_level_config >> $outfile
echo updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
	sysctl_outfile=configuration_sysctl.ALL.`hostname`.conf
	sysctl -a > ${sysctl_outfile}
	net_core_list=(somaxconn netdev_max_backlog rmem_default wmem_default rmem_max wmem_max optmem_max rps_sock_flow_entries netdev_rss_key netdev_budget netdev_budget_usecs dev_weight_rx_bias dev_weight_tx_bias busy_poll busy_read max_skb_frags default_qdisc)
	for item in ${net_core_list[@]}; do
		grep net.core.$item ${sysctl_outfile} | sed -r 's/ = /=/g' >> $outfile
	done
	
	net_ipv4_list=(tcp_available_congestion_control tcp_congestion_control tcp_moderate_rcvbuf tcp_notsent_lowat tcp_max_syn_backlog tcp_mem tcp_rmem tcp_wmem tcp_limit_output_bytes tcp_slow_start_after_idle tcp_tw_reuse tcp_timestamps tcp_window_scaling tcp_autocorking tcp_early_retrans tcp_ecn tcp_dsack tcp_sack tcp_fack tcp_fastopen tcp_no_metrics_save tcp_mtu_probing tcp_low_latency tcp_max_orphans tcp_synack_retries tcp_syncookies tcp_fin_timeout tcp_keepalive_intvl tcp_keepalive_probes)
	
	for item in ${net_ipv4_list[@]}; do
		grep net.ipv4.$item ${sysctl_outfile} | sed -r 's/ = /=/g' >> $outfile
	done

	grep vm.dirty_ratio ${sysctl_outfile} | sed -r 's/ = /=/g' >> $outfile
	grep vm.dirty_background_ratio ${sysctl_outfile} | sed -r 's/ = /=/g' >> $outfile
	grep vm.swappiness ${sysctl_outfile} | sed -r 's/ = /=/g' >> $outfile
	grep vm.min_free_kbytes ${sysctl_outfile} | sed -r 's/ = /=/g' >> $outfile
	grep vm.zone_reclaim_mode ${sysctl_outfile} | sed -r 's/ = /=/g' >> $outfile

	grep kernel.sched_migration_cost_ns ${sysctl_outfile} | sed -r 's/ = /=/g' >> $outfile
	grep kernel.sched_min_granularity_ns ${sysctl_outfile} | sed -r 's/ = /=/g' >> $outfile
	grep kernel.sched_wakeup_granularity_ns ${sysctl_outfile} | sed -r 's/ = /=/g' >> $outfile
	grep kernel.perf_event_max_sample_rate ${sysctl_outfile} | sed -r 's/ = /=/g' >> $outfile
	grep kernel.perf_cpu_time_max_percent ${sysctl_outfile} | sed -r 's/ = /=/g' >> $outfile

	grep fs.file-nr ${sysctl_outfile} | sed -r 's/ = /=/g' >> $outfile

	echo >> $outfile
}
System_info_sysctl(){	
echo "************************************************************" >> $outfile
echo system_level_config >> $outfile
echo updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
	net_core_list=(somaxconn netdev_max_backlog rmem_default wmem_default rmem_max wmem_max optmem_max rps_sock_flow_entries netdev_rss_key netdev_budget netdev_budget_usecs dev_weight_rx_bias dev_weight_tx_bias busy_poll busy_read max_skb_frags default_qdisc)
	for item in ${net_core_list[@]}; do
		sysctl net.core.$item | sed -r 's/ = /=/g' >> $outfile
	done
	
	net_ipv4_list=(tcp_available_congestion_control tcp_congestion_control tcp_moderate_rcvbuf tcp_notsent_lowat tcp_max_syn_backlog tcp_mem tcp_rmem tcp_wmem tcp_limit_output_bytes tcp_slow_start_after_idle tcp_tw_reuse tcp_timestamps tcp_window_scaling tcp_autocorking tcp_early_retrans tcp_ecn tcp_dsack tcp_sack tcp_fack tcp_fastopen tcp_no_metrics_save tcp_mtu_probing tcp_low_latency tcp_max_orphans tcp_synack_retries tcp_syncookies tcp_fin_timeout tcp_keepalive_intvl tcp_keepalive_probes)
	
	for item in ${net_ipv4_list[@]}; do
		sysctl net.ipv4.$item | sed -r 's/ = /=/g' >> $outfile
	done

	sysctl vm.dirty_ratio | sed -r 's/ = /=/g' >> $outfile
	sysctl vm.dirty_background_ratio | sed -r 's/ = /=/g' >> $outfile
	sysctl vm.swappiness | sed -r 's/ = /=/g' >> $outfile
	sysctl vm.min_free_kbytes | sed -r 's/ = /=/g' >> $outfile
	sysctl vm.zone_reclaim_mode | sed -r 's/ = /=/g' >> $outfile

	sysctl kernel.sched_migration_cost_ns | sed -r 's/ = /=/g' >> $outfile
	sysctl kernel.sched_min_granularity_ns | sed -r 's/ = /=/g' >> $outfile
	sysctl kernel.sched_wakeup_granularity_ns | sed -r 's/ = /=/g' >> $outfile
	sysctl kernel.perf_event_max_sample_rate | sed -r 's/ = /=/g' >> $outfile
	sysctl kernel.perf_cpu_time_max_percent | sed -r 's/ = /=/g' >> $outfile

	sysctl fs.file-nr | sed -r 's/ = /=/g' >> $outfile

	echo >> $outfile
}

TUNED_status(){
echo "************************************************************" >> $outfile
echo tuned_service_status >> $outfile
echo updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
	systemctl status tuned >> $outfile
	if [[ -n `systemctl status tuned | grep running` ]]; then
		tuned-adm active >> $outfile
	fi
	echo >> $outfile
}

#IRQ_Balance_status
IRQ_Balance_status(){
echo "************************************************************" >> $outfile
echo irqbalance_service_status >> $outfile
echo updated=$current_time >> $outfile
echo "************************************************************" >> $outfile
	IRQBALANCE_ON=`ps ax | grep -v grep | grep -q irqbalance; echo $?`
		if [ "$IRQBALANCE_ON" == "0" ] ; then
			echo "irqbalance=running"  >> $outfile
		else
			echo "irqbalance=not running"  >> $outfile
		fi
	echo >> $outfile
}
#Run all Tasks
ALL(){
	outfile=configuration_details.ALL.`hostname`.txt
	touch $outfile
	echo `date` > $outfile
	echo >> $outfile
	for item in ${tasks[@]}; do
	echo "Running $item tasks"
		$item
	done
	echo >> $outfile
}

if [ -z "$1" ]
  then
    ALL
  else
  outfile=configuration_details.$1.`hostname`.txt
	touch $outfile
	echo `date` > $outfile
	echo >> $outfile
   $1
fi
