#!/usr/bin/env bash

### BEGIN SCRIPT HEADER
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPT_NAME=$(basename "${SCRIPT_PATH}")
DIR_SCRIPT=$(dirname "${SCRIPT_PATH}")
COMMON="${DIR_SCRIPT}/common.sh"
source "$COMMON" || exit
COMMON_NETWORK="${DIR_SCRIPT}/common_network.sh"
source "$COMMON_NETWORK" || exit
### END SCRIPT HEADER

### BEGIN COMMON
function print_usage_and_exit() {
    print_info "Usage: ${SCRIPT_NAME} <INT_AP> <INT_WAN> [SSID] [PASSPHRASE] [CHANNEL]"
    exit
}

check_argc $# 2 || print_usage_and_exit
### END COMMON

# Customizable parameters
INT_AP=$1 # e.g. wlan0
INT_WAN=$2 # e.g. eth0
AP_SSID="TEST_AP"
AP_PASSPHRASE="SuperP@ss123"
AP_CHANNEL=11

if [ $# -ge 3 ];
then
    AP_SSID=$3
    print_info "Using custom SSID: ${AP_SSID}"
else
    print_info "Using default SSID: ${AP_SSID}"
fi

if [ $# -ge 4 ];
then
    AP_PASSPHRASE=$4
    print_info "Using custom passphrase: ${AP_PASSPHRASE}"
else
    print_info "Using default passphrase: ${AP_PASSPHRASE}"
fi

if [ $# -ge 5 ];
then
    AP_CHANNEL=$5
    print_info "Using custom channel: ${AP_CHANNEL}"
else
    print_info "Using default channel: ${AP_CHANNEL}"
fi

function generate_hostapd_config_file() {
    config=""
    config="${config}interface=$INT_AP\n"
    # config="${config}driver=nl80211\n"
    config="${config}ssid=$AP_SSID\n"
    config="${config}hw_mode=g\n"
    config="${config}channel=$AP_CHANNEL\n"
    config="${config}wpa=2\n"
    config="${config}wpa_passphrase=$AP_PASSPHRASE\n"
    config="${config}wpa_key_mgmt=WPA-PSK\n"

    echo -e $config > $CONFIG_HOSTAPD

    if [ ! -f $CONFIG_HOSTAPD ];
    then
        print_error "Failed to create hostapd config file: ${CONFIG_HOSTAPD}"
        return 1
    fi

    print_success "Created dnsmasq config file: ${CONFIG_HOSTAPD}"
}

function start_access_point() {
    print_info "Starting hostapd. Use Ctrl+C to exit."
    hostapd "${CONFIG_HOSTAPD}"
}

check_network_initial_state
check_network_prerequisites || exit
prepare_network || cleanup_and_exit
configure_ap_interface || cleanup_and_exit
generate_dnsmasq_config_file || cleanup_and_exit
generate_hostapd_config_file || cleanup_and_exit
start_dhcp_server_and_continue
start_access_point
restore_network