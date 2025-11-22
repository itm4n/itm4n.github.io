#!/usr/bin/env -S bash --posix

function network_test_network_manager_is_running() {

    for s in "network-manager" "NetworkManager"; do
        if systemctl status ${s} 1>/dev/null 2>&1; then
            return 0  
        fi
    done

    return 1
}

function network_test_ip_forward_enabled() {

    if ! (sysctl 'net.ipv4.ip_forward' | grep -q 'net.ipv4.ip_forward = 1'); then
        return 1
    fi

    return 0
}

function network_test_interface_is_wireless() {

    if ! iwconfig "${1}" >/dev/null 2>&1; then
        return 1
    fi

    return 0
}

function network_test_interface_is_unmanaged() {

    if ! nmcli device | grep "${1}" | grep -q unmanaged; then
        return 1
    fi

    return 0
}

function network_test_nat_masquerading_is_enabled() {

    # Attempting to delete the target rule is reliable for checking
    # whether it is already present. It's not elegant, but it works. :/
    interface_name="${1}"
    if ! iptables -t nat -D POSTROUTING -o "${1}" -j MASQUERADE 2>/dev/null; then
        return 1
    else
        # Since the delete action worked, we need to restore the rule.
        iptables -t nat -A POSTROUTING -o "${1}" -j MASQUERADE
    fi

    return 0
}

function network_test_interface_forwarding_is_enabled() {

    # Attempting to delete the target rule is reliable for checking
    # whether it is already present. It's not elegant, but it works. :/
    if ! iptables -D FORWARD -i "${1}" -j ACCEPT 2>/dev/null; then
        return 1
    else
        # Since the delete action worked, we need to restore the rule.
        iptables -A FORWARD -i "${1}" -j ACCEPT
    fi

    return 0
}

function network_set_ip_forwarding() {

    sysctl -w "net.ipv4.ip_forward=${1}" >/dev/null
    return $?
}

function network_set_interface_unmanaged() {

    nmcli device set "${1}" managed no >/dev/null
    return $?
}

function network_unset_interface_unmanaged() {

    nmcli device set "${1}" managed yes >/dev/null
    return $?
}

function network_set_nat_masquerading() {

    iptables -t nat -A POSTROUTING -o "${1}" -j MASQUERADE >/dev/null
    return $?
}

function network_unset_nat_masquerading() {

    iptables -t nat -D POSTROUTING -o "${1}" -j MASQUERADE >/dev/null
    return $?
}

function network_set_interface_forwarding() {

    iptables -A FORWARD -i "${1}" -j ACCEPT >/dev/null
    return $?
}

function network_unset_interface_forwarding() {

    iptables -D FORWARD -i "${1}" -j ACCEPT >/dev/null
    return $?
}

function network_check_interface_existence() {

    if ! ip link show $1 >/dev/null 2>&1; then
        print_error "Network interface '${1}' does not exist"
        return 1
    fi

    return 0
}

function network_check_internet_connection() {

    if ! curl -s ifconfig.io >/dev/null; then
        print_error "Internet connection test failed"
        return 1
    fi

    return 0
}

# Some of the code is taken from:
# https://gist.github.com/thom-nic/2556a6cc3865fba6330f61b802438c05
function network_test_ip_in_subnet() {

    net=(${1//\// }) # extract subnet IP
    net_ip=(${net[0]//./ }) # extract IP address from subnet as array
    net_suffix=32 # assume CIDR suffix is 32 if no suffix is provided
    [[ $((${#net[@]})) -gt 1 ]] && net_suffix=${net[1]} # otherwise use the provided suffix

    # Convert mask to array (e.g. 255 255 255 0).
    if [[ ${net_suffix} = '\.' ]]; then  # already mask format like 255.255.255.0
        net_mask_arr=(${net_suffix//./ })
    else # assume CIDR like /24, convert to mask
        if [[ $((net_suffix)) -lt 8 ]]; then
            net_mask_arr=($((256-2**(8-net_suffix))) 0 0 0)
        elif  [[ $((net_suffix)) -lt 16 ]]; then
            net_mask_arr=(255 $((256-2**(16-net_suffix))) 0 0)
        elif  [[ $((net_suffix)) -lt 24 ]]; then
            net_mask_arr=(255 255 $((256-2**(24-net_suffix))) 0)
        elif [[ $((net_suffix)) -lt 32 ]]; then
            net_mask_arr=(255 255 255 $((256-2**(32-net_suffix))))
        elif [[ ${net_suffix} == 32 ]]; then
            net_mask_arr=(255 255 255 255)
        fi
    fi

    # Fix mask (e.g. 240.192.255.0 to 255.255.255.0).
    [[ ${net_mask_arr[2]} == 255 ]] && net_mask_arr[1]=255
    [[ ${net_mask_arr[1]} == 255 ]] && net_mask_arr[0]=255

    # apply mask to IP address and check whether the bytes of the masked IP
    # match the bytes of the subnet IP.
    ip_arr=(${2//./ }) # IP address to array
    ip_masked=($(( net_mask_arr[0] & ip_arr[0] )) $(( net_mask_arr[1] & ip_arr[1] )) $(( net_mask_arr[2] & ip_arr[2] )) $(( net_mask_arr[3] & ip_arr[3] )))
    if [ ${ip_masked[0]} -eq ${net_ip[0]} ] && [ ${ip_masked[1]} -eq ${net_ip[1]} ] && [ ${ip_masked[2]} -eq ${net_ip[2]} ] && [ ${ip_masked[3]} -eq ${net_ip[3]} ]; then
        return 0
    fi

    return 1
}