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
    print_info "Usage: ${SCRIPT_NAME} <INT_GW> <INT_WAN>"
    exit
}

check_argc $# 2 || print_usage_and_exit
### END COMMON

# Customizable parameters
INT_AP=$1 # e.g. eth0
INT_WAN=$2 # e.g. eth1

check_network_initial_state
check_network_prerequisites || exit
prepare_network || cleanup_and_exit
configure_ap_interface || cleanup_and_exit
generate_dnsmasq_config_file || cleanup_and_exit
start_dhcp_server
restore_network