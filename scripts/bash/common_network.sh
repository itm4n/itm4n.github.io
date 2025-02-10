#!/usr/bin/env bash

### BEGIN SCRIPT HEADER
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
DIR_SCRIPT=$(dirname "${SCRIPT_PATH}")
COMMON="${DIR_SCRIPT}/common.sh"
source "$COMMON" || exit
### END SCRIPT HEADER

# Global flags
FLAG_NETWORK_MANAGER_RUNNING=0
FLAG_IP_FORWARDING_ENABLED=0
FLAG_AP_INTERFACE_SET=0
FLAG_NAT_RULE_SET=0
FLAG_IP_FORWARDING_SET=0
FLAG_USE_HOSTS_FILE=0

# Hardcoded parameters
AP_DHCP_RANGE="10.0.0.10,10.0.0.100"
AP_DHCP_CIDR="24"
AP_DHCP_GW="10.0.0.1"
AP_DHCP_DNS="10.0.0.1"
CONFIG_DNSMASQ="/tmp/ap_dnsmasq.conf"
CONFIG_DNSMASQ_HOSTS="/tmp/ap_dnsmasq_hosts.txt"
CONFIG_HOSTAPD="/tmp/ap_hostapd.conf"

trap ctrl_c INT
function ctrl_c() {
	restore_network
}

function check_network_initial_state() {
    nm_name="network-manager"
    systemctl status ${nm_name} 1>/dev/null 2>&1
    if [ $? -eq 4 ]; # Service does not exist, try with name "NetworkManager"
    then
        nm_name="NetworkManager"
        systemctl status ${nm_name} 1>/dev/null 2>&1
    fi

    if [ $? -eq 0 ]; # Network Manager is installed and running
    then
        FLAG_NETWORK_MANAGER_RUNNING=1
    fi

    sysctl 'net.ipv4.ip_forward' | grep -q 'net.ipv4.ip_forward = 1'
    if [ $? -eq 0 ];
    then
        FLAG_IP_FORWARDING_ENABLED=1
    fi

    if [ -f "${CONFIG_DNSMASQ_HOSTS}" ];
    then
        print_info "Found custom hosts file: ${CONFIG_DNSMASQ_HOSTS}"
        FLAG_USE_HOSTS_FILE=1
    fi
}

function check_network_prerequisites() {
    nb_errors=0

    test_is_root || ((nb_errors=nb_errors+1))
    test_network_interface_exists $INT_AP || ((nb_errors=nb_errors+1))
    test_network_interface_exists $INT_WAN || ((nb_errors=nb_errors+1))
    test_command_exists "dnsmasq" || ((nb_errors=nb_errors+1))
    test_command_exists "hostapd" || ((nb_errors=nb_errors+1))
    test_command_exists "iptables" || ((nb_errors=nb_errors+1))
    test_command_exists "killall" || ((nb_errors=nb_errors+1))
    test_command_exists "ip" || ((nb_errors=nb_errors+1))

    if [ $FLAG_NETWORK_MANAGER_RUNNING -eq 1 ];
    then
        test_command_exists "nmcli" || ((nb_errors=nb_errors+1))
    fi

    return $nb_errors
}

function enable_ip_forwarding() {
    if [ $FLAG_IP_FORWARDING_ENABLED -eq 0 ];
    then
        sysctl -w 'net.ipv4.ip_forward=1' 1>/dev/null
        if [ $? -ne 0 ];
        then
            print_error "Failed to enable IP forwarding."
            return 1
        fi
        FLAG_IP_FORWARDING_SET=1
    fi
    return 0
}

function disable_ip_forwarding() {
    sysctl -w 'net.ipv4.ip_forward=0' 1>/dev/null
    if [ $? -ne 0 ];
    then
        print_error "Failed to disabled IP forwarding."
        return 1
    fi
    return 0
}

function add_nat_rule() {
    iptables --table nat -A POSTROUTING -o $INT_WAN -j MASQUERADE >/dev/null
    if [ $? -ne 0 ];
    then
        print_error "Failed to add NAT rule."
        return 1
    fi
    FLAG_NAT_RULE_SET=1
    return 0
}

function remove_nat_rule() {
    iptables --table nat -D POSTROUTING -o $INT_WAN -j MASQUERADE >/dev/null
    if [ $? -ne 0 ];
    then
        print_error "Failed to remove NAT rule."
        return 1
    fi
    FLAG_NAT_RULE_SET=0
    return 0
}

function configure_ap_interface() {
    nb_errors=0

    print_info "Configuring interface '${INT_AP}'."
    ip link set "${INT_AP}" down || ((nb_errors=nb_errors+1))
    ip addr flush dev "${INT_AP}" || ((nb_errors=nb_errors+1))
    ip addr add "${AP_DHCP_GW}/${AP_DHCP_CIDR}" dev "${INT_AP}" || ((nb_errors=nb_errors+1))
    ip link set "${INT_AP}" up || ((nb_errors=nb_errors+1))

    if [ $nb_errors -ne 0 ];
    then
        print_error "Failed to configure interface '${INT_AP}'."
        return $nb_errors
    fi

    FLAG_AP_INTERFACE_SET=1
    
    return $nb_errors
}

function reset_ap_interface() {
    ip link set "${INT_AP}" down
    ip addr flush dev "${INT_AP}"
    ip link set "${INT_AP}" up
}

function prepare_network() {
    nb_errors=0

    enable_ip_forwarding || ((nb_errors=nb_errors+1))
    add_nat_rule "iptables" || ((nb_errors=nb_errors+1))

    if [ $FLAG_NETWORK_MANAGER_RUNNING -eq 1 ];
    then
        print_info "Network Manager is running, setting interface '${INT_AP}' as unmanaged."
        nmcli device set "${INT_AP}" managed no >/dev/null 2>&1 || ((nb_errors=nb_errors+1))
        nmcli device set "${INT_WAN}" managed no >/dev/null 2>&1 || ((nb_errors=nb_errors+1))
    fi

    return $nb_errors
}

function generate_dnsmasq_config_file() {
    config=""
    config="${config}interface=${INT_AP}\n" # Set interface to listen on
    config="${config}dhcp-range=${AP_DHCP_RANGE}\n" # Set DHCP IP range
    config="${config}dhcp-option=3,${AP_DHCP_GW}\n" # Set default gateway in DHCP options
    config="${config}dhcp-option=6,${AP_DHCP_DNS}\n" # Set DNS server in DHCP options
    config="${config}no-hosts\n" # Do not read /etc/hosts file
    if [ $FLAG_USE_HOSTS_FILE -eq 1 ];
    then
        config="${config}addn-hosts=${CONFIG_DNSMASQ_HOSTS}\n" # Use a custom hosts file
    fi

    echo -e $config > $CONFIG_DNSMASQ

    if [ ! -f $CONFIG_DNSMASQ ];
    then
        print_error "Failed to create dnsmasq config file: ${CONFIG_DNSMASQ}"
        return 1
    fi

    print_success "Created dnsmasq config file: ${CONFIG_DNSMASQ}"
}

function print_dnsmasq_hosts_file_hint() {
    if [ $FLAG_USE_HOSTS_FILE -eq 0 ];
    then
        print_info "You can define custom DNS entries by creating the file '${CONFIG_DNSMASQ_HOSTS}' (stop and restart to apply)."
    fi
}

function start_dhcp_server_and_continue() {
    print_info "Starting dnsmasq as a daemon."
    dnsmasq -d -C "${CONFIG_DNSMASQ}" &
    print_dnsmasq_hosts_file_hint
}

function start_dhcp_server() {
    print_info "Starting dnsmasq as a daemon."
    dnsmasq -d -C "${CONFIG_DNSMASQ}"
    print_dnsmasq_hosts_file_hint
}

function restore_network() {
    print_info "Restoring initial system state."

    killall dnsmasq 2>/dev/null
    killall hostapd 2>/dev/null

    if [ $FLAG_AP_INTERFACE_SET -eq 1 ];
    then
        reset_ap_interface
    fi

    if [ -f "${CONFIG_DNSMASQ}" ];
    then
        rm -f "${CONFIG_DNSMASQ}"
    fi

    if [ -f "${CONFIG_HOSTAPD}" ];
    then
        rm -f "${CONFIG_HOSTAPD}"
    fi

    if [ $FLAG_IP_FORWARDING_SET -eq 1 ];
    then
        disable_ip_forwarding
    fi

    if [ $FLAG_NAT_RULE_SET -eq 1 ];
    then
        remove_nat_rule
    fi

    if [ $FLAG_NETWORK_MANAGER_RUNNING -eq 1 ];
    then
        nmcli device set ${INT_AP} managed yes >/dev/null 2>&1
        nmcli device set ${INT_WAN} managed yes >/dev/null 2>&1
    fi

    exit
}