#!/usr/bin/env -S bash --posix

### BEGIN INCLUDE
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPT_NAME=$(basename "${SCRIPT_PATH}")
SCRIPT_DIR=$(dirname "${SCRIPT_PATH}")
source "${SCRIPT_DIR}/../common.sh" || exit
### END INCLUDE

function nmap_host_print_usage_and_exit() {
    print_info "Usage: ${SCRIPT_NAME} <HOSTNAME>"
    exit
}

util_check_argc $# 1 || nmap_host_print_usage_and_exit
util_check_command_existence "nmap" || exit

FOLDER_NAME_NMAP="nmap"
TIMESTAMP=$(util_get_timestamp)
HOSTNAME=$(echo -n $1 | tr '[:upper:]' '[:lower:]')
OUT_FILE_NMAP_PREFIX="./${FOLDER_NAME_NMAP}/nmap_host_${HOSTNAME}_${TIMESTAMP}"

if ! util_test_directory_existence "${FOLDER_NAME_NMAP}"; then
    print_error "Nmap folder doesn't exist: ${FOLDER_NAME_NMAP}"
    exit
fi

host "${HOSTNAME}" >/dev/null 2>&1
if [ $? -ne 0 ]
then
    print_warning "Failed to resolve hostname: ${HOSTNAME}"
    sleep 3
fi

if sudo nmap -vv -A -T5 -sT -O --reason --open -p- --script *-vuln-* -oA "${OUT_FILE_NMAP_PREFIX}" "${HOSTNAME}"; then
    print_success "Scan completed, result written to: ${OUT_FILE_NMAP_PREFIX}.nmap"
else
    print_warning "Scan failed."
fi
