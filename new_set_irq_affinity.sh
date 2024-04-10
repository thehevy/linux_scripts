#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2015 - 2023, Intel Corporation
#
# Script to affinitize interrupts to cores.

# Display usage information
# usage() function provides information on how to use the script and its options.
# It displays the usage instructions, including the available options and examples.
# Parameters:
#   None
# Returns:
#   None
usage() {
    echo
    echo "Usage: option -s <interface> to show current settings only"
    echo "Usage: $0 [-x|-X] [all|local|remote [<node>]|one <core>|custom|<cores>] <interface> ..."
    echo "  Options: "
    echo "    -s      Shows current affinity settings"
    echo "    -x      Configure XPS as well as smp_affinity"
    echo "    -X      Disable XPS but set smp_affinity"
    echo "    [all] is the default value"
    echo "    [remote [<node>]] can be followed by a specific node number"
    echo "  Examples:"
    echo "    $0 -s eth1            # Show settings on eth1"
    echo "    $0 all eth1 eth2      # eth1 and eth2 to all cores"
    echo "    $0 one 2 eth1         # eth1 to core 2 only"
    echo "    $0 local eth1         # eth1 to local cores only"
    echo "    $0 remote eth1        # eth1 to remote cores only"
    echo "    $0 custom eth1        # prompt for eth1 interface"
    echo "    $0 0-7,16-23 eth0     # eth1 to cores 0-7 and 16-23"
    echo
    exit 1
}

# Display error when -x and -X options are used together
# usageX() - Displays an error message and exits if both options -x and -X are specified.
usageX() {
    echo "options -x and -X cannot both be specified, pick one"
    exit 1
}

# Check for required tools
# Function: check_required_tools
# Description: Checks if the required tools are available in the system.
# Parameters: None
# Returns: None
check_required_tools() {
    SED=$(which sed)
    if [[ ! -x $SED ]]; then
        echo "ERROR: sed not found in path, this script requires sed"
        exit 1
    fi
}

# Parse and validate command line arguments
parse_arguments() {
    if [ "$1" == "-x" ]; then
        XPS_ENA=1
        shift
    fi

    if [ "$1" == "-s" ]; then
        SHOW=1
        echo Show affinity settings
        shift
    fi

    if [ "$1" == "-X" ]; then
        if [ -n "$XPS_ENA" ]; then
            usageX
        fi
        XPS_DIS=2
        shift
    fi

    if [ "$1" == -x ]; then
        usageX
    fi

    if [ -n "$XPS_ENA" ] && [ -n "$XPS_DIS" ]; then
        usageX
    fi

    if [ -z "$XPS_ENA" ]; then
        XPS_ENA=$XPS_DIS
    fi

    SED=$(which sed)
    if [[ ! -x $SED ]]; then
        echo " $0: ERROR: sed not found in path, this script requires sed"
        exit 1
    fi

    num='^[0-9]+$'

    # search helpers
    NOZEROCOMMA="s/^[0,]*//"
    # Vars
    AFF=$1
    shift

    case "$AFF" in
        remote)	[[ $1 =~ $num ]] && rnode=$1 && shift ;;
        one)	[[ $1 =~ $num ]] && cnt=$1 && shift ;;
        all)	;;
        local)	;;
        custom)	;;
        [0-9]*)	;;
        -h|--help)	usage ;;
        "")		usage ;;
        *)		IFACES=$AFF && AFF=all ;;	# Backwards compat mode
    esac
    # append the interfaces listed to the string with spaces
    while [ "$#" -ne "0" ] ; do
        IFACES+=" $1"
        shift
    done

    # for now the user must specify interfaces
    if [ -z "$IFACES" ]; then
        usage
    fi
}

# Check if network interfaces exist
# Function to check if the network interfaces exist in /proc/net/dev
# Arguments:
#   None
# Returns:
#   None
check_interfaces() {
    for MYIFACE in $IFACES; do
        grep -q "$MYIFACE" /proc/net/dev || notfound
    done
}

# Build CPU mask for setting affinity
# Function: build_mask
# Description: This function builds a hexadecimal mask based on the value of the variable $core.
#              If $core is greater than or equal to 32, the mask is constructed by filling the
#              initial positions with zeros and setting the bit corresponding to $core to 1.
#              If $core is less than 32, the mask is constructed by setting the bit corresponding
#              to $core to 1.
# Parameters: None
# Returns: None
build_mask() {
    VEC=$core
    if [ "$VEC" -ge 32 ]
    then
        MASK_FILL=""
        MASK_ZERO="00000000"
        ((IDX = VEC / 32))
        for ((i=1; i<=IDX;i++))
        do
            MASK_FILL="${MASK_FILL},${MASK_ZERO}"
        done
        ((VEC -= 32 * IDX))
        MASK_TMP=$((1<<VEC))
        MASK=$(printf "%X%s" $MASK_TMP $MASK_FILL)
    else
        MASK_TMP=$((1<<VEC))
        MASK=$(printf "%X" $MASK_TMP)
    fi
}

# Show current affinity settings
# Function: show_affinity
# Description: Prints the affinity information for a given IRQ.
# Parameters:
#   - None
# Returns:
#   - None
show_affinity() 
{
    # returns the MASK variable
    build_mask

    # Get the SMP_I and HINT values from /proc/irq/<IRQ>/smp_affinity and /proc/irq/<IRQ>/affinity_hint respectively
    SMP_I=$(sed -E "${NOZEROCOMMA}" /proc/irq/"$IRQ"/smp_affinity)
    HINT=$(sed -E "${NOZEROCOMMA}" /proc/irq/"$IRQ"/affinity_hint)

    # Print the actual and hint values along with the corresponding file paths
    printf "ACTUAL\t%s %d %s <- /proc/irq/%s/smp_affinity\n" "$IFACE" "$core" "$SMP_I" "$IRQ"
    printf "HINT\t%s %d %s <- /proc/irq/%s/affinity_hint\n" "$IFACE" "$core" "$HINT" "$IRQ"

    # Check if the IRQ has a range of CPUs assigned to it
    IRQ_CHECK=$(grep '[-,]' /proc/irq/"$IRQ"/smp_affinity_list)
    if [ -n "$IRQ_CHECK" ]; then
        # Print the node, smp_affinity_list, xps_cpus, xps_rxqs, tx_maxrate, byte_queue_limits, limit_max, limit_min, rps_flow_cnt, and rps_cpus values along with the corresponding file paths
        printf "NODE\t%s %d %s <- /proc/irq/%s/node\n" "$IFACE" "$core" "$(cat /proc/irq/"$IRQ"/node)" "$IRQ"
        printf "LIST\t%s %d [%s] <- /proc/irq/%s/smp_affinity_list\n" "$IFACE" "$core" "$(cat /proc/irq/"$IRQ"/smp_affinity_list)" "$IRQ"
        printf "XPS\t%s %d %s <- /sys/class/net/%s/queues/tx-%d/xps_cpus\n" "$IFACE" "$core" "$(cat /sys/class/net/"$IFACE"/queues/tx-$((n-1))/xps_cpus)" "$IFACE" $((n-1))
        
        # Check if xps_rxqs is empty
        if [ -z "$(ls /sys/class/net/"$IFACE"/queues/tx-$((n-1))/xps_rxqs)" ]; then
            printf "XPSRXQs\t%s %d %s <- /sys/class/net/%s/queues/tx-%d/xps_rxqs\n" "$IFACE" "$core" "$(cat /sys/class/net/"$IFACE"/queues/tx-$((n-1))/xps_rxqs)" "$IFACE" $((n-1))
        fi

        printf "TX_MAX\t%s %d %s <- /sys/class/net/%s/queues/tx-%d/tx_maxrate\n" "$IFACE" "$core" "$(cat /sys/class/net/"$IFACE"/queues/tx-$((n-1))/tx_maxrate)" "$IFACE" $((n-1))
        printf "BQLIMIT\t%s %d %s <- /sys/class/net/%s/queues/tx-%d/byte_queue_limits/limit\n" "$IFACE" "$core" "$(cat /sys/class/net/"$IFACE"/queues/tx-$((n-1))/byte_queue_limits/limit)" "$IFACE" $((n-1))
        printf "BQL_MAX\t%s %d %s <- /sys/class/net/%s/queues/tx-%d/byte_queue_limits/limit_max\n" "$IFACE" "$core" "$(cat /sys/class/net/"$IFACE"/queues/tx-$((n-1))/byte_queue_limits/limit_max)" "$IFACE" $((n-1))
        printf "BQL_MIN\t%s %d %s <- /sys/class/net/%s/queues/tx-%d/byte_queue_limits/limit_min\n" "$IFACE" "$core" "$(cat /sys/class/net/"$IFACE"/queues/tx-$((n-1))/byte_queue_limits/limit_min)" "$IFACE" $((n-1))
        
        # Check if rps_flow_cnt is empty
        if [ -z "$(ls /sys/class/net/"$IFACE"/queues/rx-$((n-1))/rps_flow_cnt)" ]; then
            printf "RPSFCNT\t%s %d %s <- /sys/class/net/%s/queues/rx-%d/rps_flow_cnt\n" "$IFACE" "$core" "$(cat /sys/class/net/"$IFACE"/queues/rx-$((n-1))/rps_flow_cnt)" "$IFACE" $((n-1))
        fi

        # Check if rps_cpus is empty
        if [ -z "$(ls /sys/class/net/"$IFACE"/queues/rx-$((n-1))/rps_cpus)" ]; then
            printf "RPSCPU\t%s %d %s <- /sys/class/net/%s/queues/rx-%d/rps_cpus\n" "$IFACE" "$core" "$(cat /sys/class/net/"$IFACE"/queues/rx-$((n-1))/rps_cpus)" "$IFACE" $((n-1))
        fi
    fi
}
	echo


# Set CPU affinity
set_affinity() {
	# returns the MASK variable
	build_mask

# This script sets the SMP affinity and XPS CPUs for a given IRQ and network interface.
# It takes the following steps:
# 1. Writes the SMP affinity mask to /proc/irq/$IRQ/smp_affinity.
# 2. Prints the interface name, core number, and SMP affinity mask to the console.
# 3. Reads the SMP affinity mask from /proc/irq/$IRQ/smp_affinity.
# 4. Compares the read SMP affinity mask with the original mask. If they are different, it prints a warning.
# 5. Based on the value of XPS_ENA, it performs the following actions:
#    - If XPS_ENA is 1, it writes the SMP affinity mask to /sys/class/net/$IFACE/queues/tx-$((n-1))/xps_cpus.
#    - If XPS_ENA is 2, it sets the SMP affinity mask to 0 and writes it to /sys/class/net/$IFACE/queues/tx-$((n-1))/xps_cpus.
#    - If XPS_ENA is neither 1 nor 2, it does nothing.

# Note: This script assumes that the variables $MASK, $IRQ, $IFACE, $core, $n, and $XPS_ENA are defined before executing this script.
	printf "%s" $MASK > /proc/irq/$IRQ/smp_affinity
	printf "%s %d %s -> /proc/irq/$IRQ/smp_affinity\n" $IFACE $core $MASK
	SMP_I=$(sed -E "${NOZEROCOMMA}" /proc/irq/$IRQ/smp_affinity)
	if [ "$SMP_I" != "$MASK" ]; then
		printf " ACTUAL\t%s %d %s <- /proc/irq/$IRQ/smp_affinity\n" $IFACE $core $SMP_I
		printf " WARNING -- SMP_AFFINITY setting failed\n"
	fi
	case "$XPS_ENA" in
	1)
		printf "%s %d %s -> /sys/class/net/%s/queues/tx-%d/xps_cpus\n" $IFACE $core $MASK $IFACE $((n-1))
		printf "%s" $MASK > /sys/class/net/$IFACE/queues/tx-$((n-1))/xps_cpus
	;;
	2)
		MASK=0
		printf "%s %d %s -> /sys/class/net/%s/queues/tx-%d/xps_cpus\n" $IFACE $core $MASK $IFACE $((n-1))
		printf "%s" $MASK > /sys/class/net/$IFACE/queues/tx-$((n-1))/xps_cpus
	;;
	*)
	esac
}

# Parse CPU range input
# Function: parse_range
# Description: This function takes a range of numbers as input and converts it into a space-separated list of numbers.
# Parameters:
#   - $*: The range of numbers to be parsed. The range can be specified using commas (,) and hyphens (-).
# Returns:
#   - The space-separated list of numbers.
parse_range() {
    RANGE=${*//,/ }
    RANGE=${RANGE//-/..}
    LIST=""
    for r in $RANGE; do
        # eval lets us use vars in {#..#} range
        [[ $r =~ .. ]] && r=$(eval echo "{$r}")
        LIST+=" $r"
    done
    echo $LIST
}

# Main function to set affinity
# Function: doaff
# Description: Sets the CPU affinity for interrupt vectors associated with a network interface.
# Parameters:
#   - CORES: A range of CPU cores to assign the interrupt vectors to.
#   - IFACE: The network interface name.
#   - SHOW: Flag indicating whether to show the current CPU affinity or set a new one.
# Returns: None

doaff()
{
    CORES=$(parse_range $CORES)  # Parse the range of CPU cores
    ncores=$(echo $CORES | wc -w)  # Count the number of CPU cores
    n=1  # Initialize the counter

    # This script only supports interrupt vectors in pairs,
    # modification would be required to support a single Tx or Rx queue
    # per interrupt vector

    queues="${IFACE}-.*TxRx"

    irqs=$(grep "$queues" /proc/interrupts | cut -f1 -d:)  # Get the interrupt vectors associated with the queues
    [ -z "$irqs" ] && irqs=$(grep $IFACE /proc/interrupts | cut -f1 -d:)  # If no vectors found, get the interrupt vectors associated with the interface
    [ -z "$irqs" ] && irqs=$(find /sys/class/net/"${IFACE}"/device/msi_irqs -maxdepth 1 -type f -printf "%f\n" | sort -n | while IFS= read -r i; do grep -w "$i:" /proc/interrupts | grep -E -v 'fdir|async|misc|ctrl' | cut -f 1 -d :; done)  # If still no vectors found, search for MSI IRQs associated with the interface
    [ -z "$irqs" ] && echo "Error: Could not find interrupts for $IFACE"  # If no vectors found, display an error message

    if [ "$SHOW" == "1" ] ; then
        echo "TYPE IFACE CORE MASK -> FILE"
        echo "============================"
    else
        echo "IFACE CORE MASK -> FILE"
        echo "======================="
    fi

    for IRQ in $irqs; do
        [ "$n" -gt "$ncores" ] && n=1  # Reset the counter if it exceeds the number of CPU cores
        j=1
        # Much faster than calling cut for each
        for i in $CORES; do
            [ $((j++)) -ge $n ] && break
        done
        core=$i
        if [ "$SHOW" == "1" ] ; then
            show_affinity  # Show the current CPU affinity
        else
            set_affinity  # Set a new CPU affinity
        fi
        ((n++))  # Increment the counter
    done
}

# Function to set interrupt affinity for network interfaces
# Parameters:
#   - IFACES: List of network interfaces to set interrupt affinity for
#   - AFF: Affinity mode to use (local, remote, one, all, custom, or a specific core number)
# Returns: None
set_interrupt_affinity() {
    # Get the list of online CPU cores
    CORES=$(</sys/devices/system/cpu/online)
    [ "$CORES" ] || CORES=$(grep ^proc /proc/cpuinfo | cut -f2 -d:)

    # Get the core list for each node from sysfs
    node_dir=/sys/devices/system/node
    for i in "$node_dir"/node*; do
        i=${i/*node/}
        corelist[i]=$(<"$node_dir/node${i}/cpulist")
    done

    # Iterate over each network interface
    for IFACE in $IFACES; do
        dev_dir=/sys/class/net/$IFACE/device
        [ -e $dev_dir/numa_node ] && node=$(<$dev_dir/numa_node)
        [ "$node" ] && [ "$node" -gt 0 ] || node=0

        # Determine the core list based on the affinity mode
        case "$AFF" in
        local)
            CORES=${corelist[$node]}
            echo "Local Cores being used"
        ;;
        remote)
            [ "$rnode" ] || { [ $node -eq 0 ] && rnode=1 || rnode=0; }
            CORES=${corelist[$rnode]}
            echo "Remote Cores being used"
        ;;
        one)
            [ -n "$cnt" ] || cnt=0
            CORES=$cnt
            echo "${cnt} core being used"
        ;;
        all)
            CORES=$CORES
            echo "All Cores being used"
        ;;
        custom)
            echo -n "Input cores for $IFACE (ex. 0-7,15-23): "
            read -r CORES
            echo "Cores ${CORES} will be used"
        ;;
        [0-9]*)
            CORES=$AFF
            echo "Cores ${CORES} will be used"
        ;;
        *)
            usage
        ;;
        esac

        # Call the worker function to set the interrupt affinity
        doaff
    done
}

# Check if irqbalance service is running
# Function to check if irqbalance is running and may override the script's affinitization
check_irqbalance() {
    IRQBALANCE_ON=$(pgrep -x irqbalance >/dev/null; echo $?)
    if [ "$IRQBALANCE_ON" == "0" ] ; then
        echo " WARNING: irqbalance is running and will"
        echo "          likely override this script's affinitization."
        echo "          Please stop the irqbalance service and/or execute"
        echo "          'killall irqbalance'"
        exit 2
    fi
}

# Main script execution
# This script is used to set the interrupt affinity for network interfaces on a Linux system.
# It checks for the required tools, parses command line arguments, checks the available interfaces,
# sets the interrupt affinity, and checks if irqbalance is running.
main() {
    check_required_tools
    parse_arguments "$@"
    check_interfaces
    set_interrupt_affinity
    check_irqbalance
}

# main function
# This function is the entry point of the script.
# It calls the main function passing any command line arguments.
main "$@"
