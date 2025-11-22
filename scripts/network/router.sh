#!/usr/bin/env -S bash --posix

### BEGIN INCLUDE
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPT_NAME=$(basename "${SCRIPT_PATH}")
SCRIPT_DIR=$(dirname "${SCRIPT_PATH}")
source "${SCRIPT_DIR}/../common.sh" || exit
### END INCLUDE

### BEGIN CONFIG
CONFIG_DHCP_RANGE="10.0.0.10,10.0.0.100"
CONFIG_DHCP_CIDR="24"
CONFIG_DHCP_GATEWAY_IP="10.0.0.1"
CONFIG_DHCP_DNS_IP="10.0.0.1"
CONFIG_INTERFACE_IN_NAME="NO_IN_INTERFACE_SPECIFIED"
CONFIG_INTERFACE_IN_IP="${CONFIG_DHCP_GATEWAY_IP}/${CONFIG_DHCP_CIDR}"
CONFIG_INTERFACE_OUT_NAME="NO_OUT_INTERFACE_SPECIFIED"
CONFIG_AP_MODE="a" # a = IEEE 802.11a (5 GHz); b = IEEE 802.11b (2.4 GHz); g = IEEE 802.11g (2.4 GHz); ad = IEEE 802.11ad (60 GHz)
CONFIG_AP_SSID="MySecureHotspot"
CONFIG_AP_PASSPHRASE="SuperP@ss123"
### END CONFIG

### BEGIN CONST
CONST_DNSMASQ_CONFIG_FILE_PATH="/tmp/router_dnsmasq.conf"
CONST_DNSMASQ_HOSTS_FILE_PATH="/tmp/router_dnsmasq_hosts"
CONST_HOSTAPD_CONFIG_FILE_PATH="/tmp/router_hostapd.conf"
### END CONST

### BEGIN INITIAL STATE
INITIAL_STATE_NETWORK_MANAGER_RUNNING=0
INITIAL_STATE_IP_FORWARDING_ENABLED=0
INITIAL_STATE_NAT_MASQUERADE_ENABLED=0
INITIAL_STATE_INTERFACE_IN_UNMANAGED=0
INITIAL_STATE_INTERFACE_IN_FORWARDING_ENABLED=0
INITIAL_STATE_INTERFACE_OUT_FORWARDING_ENABLED=0
### END INITIAL STATE

### BEGIN ROUTER STATE
ROUTER_STATE_IP_FORWARDING_SET=0
ROUTER_STATE_NAT_MASQUERADING_ENABLED=0
ROUTER_STATE_DNSMASQ_CONFIG_FILE_CREATED=0
ROUTER_STATE_DNSMASQ_PID=0
ROUTER_STATE_HOSTAPD_CONFIG_FILE_CREATED=0
ROUTER_STATE_HOSTAPD_PID=0
ROUTER_STATE_INTERFACE_IN_UNMANAGED_SET=0
ROUTER_STATE_INTERFACE_IN_SET=0
ROUTER_STATE_INTERFACE_IN_IS_WIRELESS=0
ROUTER_STATE_INTERFACE_IN_FORWARDING_ENABLED=0
ROUTER_STATE_INTERFACE_OUT_FORWARDING_ENABLED=0
### END ROUTER STATE

function router_print_usage_and_exit() {
    print_info "Usage: ${SCRIPT_NAME} <INT_IN> <INT_OUT>"
    exit
}

trap ctrl_c INT
function ctrl_c() {
	router_restore_initial_state_and_exit
}

function router_wait_for_any_background_process() {

    pid=0
    pids=()

    if [ $ROUTER_STATE_DNSMASQ_PID -ne 0 ]; then
        pids+=( $ROUTER_STATE_DNSMASQ_PID )
    fi

    if [ $ROUTER_STATE_HOSTAPD_PID -ne 0 ]; then
        pids+=( $ROUTER_STATE_HOSTAPD_PID )
    fi

    while true; do
        for ((i=0; i<${#pids[@]}; i++)) ; do
            if ! ps ${pids[$i]} >/dev/null 2>&1; then
                pid=${pids[$i]}
                break
            fi
        done
        if [ $pid -ne 0 ]; then
            break
        fi
        sleep 1
    done

    echo -n "${pid}"
}

function router_wait_forever() {

    pid=$(router_wait_for_any_background_process)
    if [ $pid != "0" ]; then
        case ${pid} in
            "${ROUTER_STATE_DNSMASQ_PID}")
                ROUTER_STATE_DNSMASQ_PID=0
                print_error "Process with PID ${pid} (dnsamsq) exited unexpectedly"
                ;;
            "${ROUTER_STATE_HOSTAPD_PID}")
                ROUTER_STATE_HOSTAPD_PID=0
                print_error "Process with PID ${pid} (hostapd) exited unexpectedly"
                ;;
        esac
        return 1
    fi

    return 0
}

function router_check_prerequisites() {

    nb_errors=0

    for c in "dnsmasq" "hostapd" "ip" "iptables" "iwconfig" "killall" "nmcli" "sysctl"; do
        if ! util_check_command_existence "${c}"; then
            ((nb_errors=nb_errors+1))
        fi
    done

    return $nb_errors
}

function router_get_initial_state() {

    if network_test_network_manager_is_running; then
        INITIAL_STATE_NETWORK_MANAGER_RUNNING=1
        print_warning "Network Manager is installed and running"
    fi

    if network_test_interface_is_unmanaged "${CONFIG_INTERFACE_IN_NAME}"; then
        INITIAL_STATE_INTERFACE_IN_UNMANAGED=1
        print_info "Interface '${CONFIG_INTERFACE_IN_NAME}' is already 'unmanaged'"
    fi

    if network_test_ip_forward_enabled; then
        INITIAL_STATE_IP_FORWARDING_ENABLED=1
        print_info "IP forwarding is already enabled"
    fi

    if network_test_nat_masquerading_is_enabled "${CONFIG_INTERFACE_OUT_NAME}"; then
        INITIAL_STATE_NAT_MASQUERADE_ENABLED=1
        print_info "NAT masquerading is already enabled on interface '${CONFIG_INTERFACE_OUT_NAME}'"
    fi

    if network_test_interface_forwarding_is_enabled "${CONFIG_INTERFACE_IN_NAME}"; then
        INITIAL_STATE_INTERFACE_IN_FORWARDING_ENABLED=1
        print_info "Forwarding is already enabled on interface '${CONFIG_INTERFACE_IN_NAME}'"
    fi

    if network_test_interface_forwarding_is_enabled "${CONFIG_INTERFACE_OUT_NAME}"; then
        INITIAL_STATE_INTERFACE_OUT_FORWARDING_ENABLED=1
        print_info "Forwarding is already enabled on interface '${CONFIG_INTERFACE_OUT_NAME}'"
    fi
}

function router_prepare_state() {

    if [ $INITIAL_STATE_IP_FORWARDING_ENABLED -eq 0 ]; then
        if network_set_ip_forwarding 1; then
            ROUTER_STATE_IP_FORWARDING_SET=1
            print_info "Enabled IP forwarding"
        else
            print_error "Failed to enable IP forwarding"
            return 1
        fi
    fi

    if ! util_test_file_existence "${CONST_DNSMASQ_HOSTS_FILE_PATH}"; then
        print_warning "Custom hosts file '${CONST_DNSMASQ_HOSTS_FILE_PATH}' not found. Create it to set custom DNS entries and restart."
    fi

    if util_test_file_existence "${CONST_DNSMASQ_CONFIG_FILE_PATH}"; then
        print_warning "Using existing dnsmasq configuration file: ${CONST_DNSMASQ_CONFIG_FILE_PATH}"
    else
        dnsmasq_config=$(router_generate_dnsmasq_config)
        if echo "${dnsmasq_config}" > ${CONST_DNSMASQ_CONFIG_FILE_PATH}; then
            ROUTER_STATE_DNSMASQ_CONFIG_FILE_CREATED=1
            print_info "Created dnsmasq configuration file: ${CONST_DNSMASQ_CONFIG_FILE_PATH}"
        else
            print_error "Failed to create dnsmasq configuration file"
            return 1
        fi
    fi

    if network_test_interface_is_wireless "${CONFIG_INTERFACE_IN_NAME}"; then
        ROUTER_STATE_INTERFACE_IN_IS_WIRELESS=1
        print_info "Detected wireless interface: '${CONFIG_INTERFACE_IN_NAME}'"
        if util_test_file_existence "${CONST_HOSTAPD_CONFIG_FILE_PATH}"; then
            print_warning "Using existing hostapd configuration file: ${CONST_HOSTAPD_CONFIG_FILE_PATH}"
        else
            hostapd_config=$(router_generate_hostapd_config)
            if echo "${hostapd_config}" > ${CONST_HOSTAPD_CONFIG_FILE_PATH}; then
                ROUTER_STATE_HOSTAPD_CONFIG_FILE_CREATED=1
                print_info "Created hostapd configuration file: ${CONST_HOSTAPD_CONFIG_FILE_PATH}"
            else
                print_error "Failed to create hostapd configuration file"
                return 1
            fi
        fi
    fi

    if [ $INITIAL_STATE_NETWORK_MANAGER_RUNNING -eq 1 ]; then
        if [ $INITIAL_STATE_INTERFACE_IN_UNMANAGED -eq 0 ]; then
            if network_set_interface_unmanaged "${CONFIG_INTERFACE_IN_NAME}"; then
                ROUTER_STATE_INTERFACE_IN_UNMANAGED_SET=1
                print_info "Set interface '${CONFIG_INTERFACE_IN_NAME}' as 'unmanaged'"
            else
                print_error "Failed to set interface '${CONFIG_INTERFACE_IN_NAME}' as 'unmanaged'"
                return 1
            fi
        fi
    fi

    if router_configure_interface_in; then
        ROUTER_STATE_INTERFACE_IN_SET=1
        print_info "Configured interface '${CONFIG_INTERFACE_IN_NAME}' with IP address ${CONFIG_INTERFACE_IN_IP}"
    else
        print_error "Failed to configure interface '${CONFIG_INTERFACE_IN_NAME}'"
    fi

    if [ $INITIAL_STATE_NAT_MASQUERADE_ENABLED -eq 0 ]; then
        if network_set_nat_masquerading "${CONFIG_INTERFACE_OUT_NAME}"; then
            ROUTER_STATE_NAT_MASQUERADING_ENABLED=1
            print_info "Enabled NAT masquerading on interface '${CONFIG_INTERFACE_OUT_NAME}'"
        else
            print_error "Failed to enable NAT masquerading on interface '${CONFIG_INTERFACE_OUT_NAME}'"
            return 1
        fi
    fi

    if [ $INITIAL_STATE_INTERFACE_IN_FORWARDING_ENABLED -eq 0 ]; then
        if network_set_interface_forwarding "${CONFIG_INTERFACE_IN_NAME}"; then
            ROUTER_STATE_INTERFACE_IN_FORWARDING_ENABLED=1
            print_info "Enabled forwarding on interface '${CONFIG_INTERFACE_IN_NAME}'"
        else
            print_error "Failed to enable forwarding on interface '${CONFIG_INTERFACE_IN_NAME}'"
            return 1
        fi
    fi

    if [ $INITIAL_STATE_INTERFACE_OUT_FORWARDING_ENABLED -eq 0 ]; then
        if network_set_interface_forwarding "${CONFIG_INTERFACE_OUT_NAME}"; then
            ROUTER_STATE_INTERFACE_OUT_FORWARDING_ENABLED=1
            print_info "Enabled forwarding on interface '${CONFIG_INTERFACE_OUT_NAME}'"
        else
            print_error "Failed to enable forwarding on interface '${CONFIG_INTERFACE_OUT_NAME}'"
            return 1
        fi
    fi

    return 0
}

function router_generate_dnsmasq_config() {

    config=""
    config="${config}interface=${CONFIG_INTERFACE_IN_NAME}\n" # Set interface to listen on
    config="${config}dhcp-range=${CONFIG_DHCP_RANGE}\n" # Set DHCP IP range
    config="${config}dhcp-option=3,${CONFIG_DHCP_GATEWAY_IP}\n" # Set default gateway in DHCP options
    config="${config}dhcp-option=6,${CONFIG_DHCP_DNS_IP}\n" # Set DNS server in DHCP options
    config="${config}no-hosts\n" # Do not read /etc/hosts file

    if util_test_file_existence "${CONST_DNSMASQ_HOSTS_FILE_PATH}"; then
        config="${config}addn-hosts=${CONST_DNSMASQ_HOSTS_FILE_PATH}\n" # Use a custom hosts file
    fi
    
    echo -ne "${config}"
}

function router_generate_hostapd_config() {

    # https://wiki.archlinux.org/title/Software_access_point

    config=""
    config="${config}interface=${CONFIG_INTERFACE_IN_NAME}\n"
    config="${config}ssid=${CONFIG_AP_SSID}\n" # SSID to be used in IEEE 802.11 management frames
    config="${config}country_code=FR\n" # Country code (ISO/IEC 3166-1)

    if [ "${CONFIG_AP_MODE}" == "g" ]; then
        config="${config}hw_mode=g\n"
        config="${config}channel=6\n"
    fi

    if [ "${CONFIG_AP_MODE}" == "a" ]; then
        config="${config}hw_mode=a\n"
        config="${config}channel=44\n" # Channel 44 seems to be generally allowed
        config="${config}ieee80211d=1\n"
        config="${config}ieee80211n=1\n"
        config="${config}ieee80211ac=1\n"
        config="${config}wmm_enabled=1\n"
    fi

    config="${config}auth_algs=1\n" # Bit field: 1=wpa, 2=wep, 3=both
    config="${config}wpa=2\n" # Bit field: bit0 = WPA, bit1 = WPA2
    config="${config}wpa_pairwise=CCMP\n" # Set of accepted cipher suites; disabling insecure TKIP
    config="${config}wpa_passphrase=${CONFIG_AP_PASSPHRASE}\n"
    config="${config}wpa_key_mgmt=WPA-PSK SAE\n"
    config="${config}rsn_pairwise=CCMP\n" # Pairwise cipher for RSN/WPA2 (default: use wpa_pairwise value)
    config="${config}ieee80211w=2\n" # Management frame protection (0 = disabled, 1 = optional, 2 = required)
    config="${config}sae_require_mfp=1\n" # Require MFP for all associations using SAE
    config="${config}sae_groups=19 20 21 25 26\n" # SAE finite cyclic groups (default: 19) https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xml

    echo -ne "${config}"
}

function router_configure_interface_in() {

    if ! ip link set "${CONFIG_INTERFACE_IN_NAME}" down; then
        return 1
    fi

    if ! ip addr flush dev "${CONFIG_INTERFACE_IN_NAME}"; then
        return 2
    fi

    if ! ip addr add "${CONFIG_INTERFACE_IN_IP}" dev "${CONFIG_INTERFACE_IN_NAME}"; then
        return 3
    fi

    if ! ip link set "${CONFIG_INTERFACE_IN_NAME}" up; then
        return 4
    fi

    return 0
}

function router_flush_interface_in() {

    if ! ip link set "${CONFIG_INTERFACE_IN_NAME}" down; then
        return 1;
    fi

    if ! ip addr flush dev "${CONFIG_INTERFACE_IN_NAME}"; then
        return 2
    fi

    if ! ip link set "${CONFIG_INTERFACE_IN_NAME}" up; then
        return 3
    fi

    return 0
}

function router_start_dnsmasq() {

    print_info "Starting dnsmasq..."
    dnsmasq -d -C "${CONST_DNSMASQ_CONFIG_FILE_PATH}" &
    ROUTER_STATE_DNSMASQ_PID=$!
}

function router_stop_dnsmasq() {

    if [ $ROUTER_STATE_DNSMASQ_PID -ne 0 ]; then
        util_kill_process_and_wait ${ROUTER_STATE_DNSMASQ_PID}
    fi
}

function router_start_hostapd() {

    if [ $ROUTER_STATE_INTERFACE_IN_IS_WIRELESS -eq 1 ]; then
        print_info "Starting hostapd..."
        hostapd "${CONST_HOSTAPD_CONFIG_FILE_PATH}" &
        ROUTER_STATE_HOSTAPD_PID=$!
    fi
}

function router_stop_hostapd() {

    if [ $ROUTER_STATE_HOSTAPD_PID -ne 0 ]; then
        util_kill_process_and_wait ${ROUTER_STATE_HOSTAPD_PID}
    fi
}

function router_restore_initial_state_and_exit() {

    router_stop_hostapd
    router_stop_dnsmasq

    if [ $ROUTER_STATE_INTERFACE_OUT_FORWARDING_ENABLED -eq 1 ]; then
        if network_unset_interface_forwarding "${CONFIG_INTERFACE_OUT_NAME}"; then
            print_info "Disabled forwarding on interface '${CONFIG_INTERFACE_OUT_NAME}'"
        else
            print_warning "Failed to disable forwarding on interface '${CONFIG_INTERFACE_OUT_NAME}'"
        fi
    fi

    if [ $ROUTER_STATE_INTERFACE_IN_FORWARDING_ENABLED -eq 1 ]; then
        if network_unset_interface_forwarding "${CONFIG_INTERFACE_IN_NAME}"; then
            print_info "Enabled forwarding on interface '${CONFIG_INTERFACE_IN_NAME}'"
        else
            print_warning "Failed to disable forwarding on interface '${CONFIG_INTERFACE_IN_NAME}'"
        fi
    fi

    if [ $ROUTER_STATE_NAT_MASQUERADING_ENABLED -eq 1 ]; then
        if network_unset_nat_masquerading "${CONFIG_INTERFACE_OUT_NAME}"; then
            print_info "Disabled NAT masquerading on interface '${CONFIG_INTERFACE_OUT_NAME}'"
        else
            print_warning "Failed to disable NAT masquerading on interface '${CONFIG_INTERFACE_OUT_NAME}'"
        fi
    fi

    if [ $ROUTER_STATE_INTERFACE_IN_SET -eq 1 ]; then
        if router_flush_interface_in; then
            print_info "Reset interface '${CONFIG_INTERFACE_IN_NAME}'"
        else
            print_warning "Failed to reset interface '${CONFIG_INTERFACE_IN_NAME}'"
        fi
    fi

    if [ $ROUTER_STATE_INTERFACE_IN_UNMANAGED_SET -eq 1 ]; then
        network_unset_interface_unmanaged "${CONFIG_INTERFACE_IN_NAME}" "yes"
        print_info "Set interface '${CONFIG_INTERFACE_IN_NAME}' as 'managed'"
    fi

    if [ $ROUTER_STATE_IP_FORWARDING_SET -eq 1 ]; then
        network_set_ip_forwarding 0
        print_info "Disabled IP forwarding"
    fi

    if [ $ROUTER_STATE_HOSTAPD_CONFIG_FILE_CREATED -eq 1 ]; then
        if rm -f "${CONST_HOSTAPD_CONFIG_FILE_PATH}"; then
            print_info "Deleted hostapd configuration file"
        else
            print_warning "Failed to delete dnsmasq configuration file"
        fi
    fi

    if [ $ROUTER_STATE_DNSMASQ_CONFIG_FILE_CREATED -eq 1 ]; then
        if rm -f "${CONST_DNSMASQ_CONFIG_FILE_PATH}"; then
            print_info "Deleted dnsmasq configuration file"
        else
            print_warning "Failed to delete dnsmasq configuration file"
        fi
    fi

    exit
}

util_check_is_root || exit
util_check_argc $# 2 || router_print_usage_and_exit

CONFIG_INTERFACE_IN_NAME=$1
CONFIG_INTERFACE_OUT_NAME=$2
network_check_interface_existence "${CONFIG_INTERFACE_IN_NAME}" || exit
network_check_interface_existence "${CONFIG_INTERFACE_OUT_NAME}" || exit

router_check_prerequisites || exit
router_get_initial_state || exit
router_prepare_state || router_restore_initial_state_and_exit
router_start_dnsmasq || router_restore_initial_state_and_exit
router_start_hostapd || router_restore_initial_state_and_exit
router_wait_forever || router_restore_initial_state_and_exit
router_restore_initial_state_and_exit
