#!/usr/bin/env -S bash --posix

### BEGIN INCLUDE
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPT_NAME=$(basename "${SCRIPT_PATH}")
SCRIPT_DIR=$(dirname "${SCRIPT_PATH}")
source "${SCRIPT_DIR}/../common.sh" || exit
### END INCLUDE

function masscan_print_usage_and_exit() {
    print_info "Usage: ${SCRIPT_NAME} <PORT> <TARGET_FILE> [RATE]"
    exit
}

util_check_argc $# 2 || masscan_print_usage_and_exit

PORT=$1
FILE=$2
RATE=1000
FOLDER_NAME_NMAP="nmap"
FOLDER_NAME_RECON="recon"

util_test_file_existence "${FILE}" || exit
util_check_command_existence "masscan" || exit
util_check_command_existence "nmap" || exit
util_test_directory_existence "./${FOLDER_NAME_NMAP}" || exit
util_test_directory_existence "./${FOLDER_NAME_RECON}" || exit

if [ $# -gt 2 ]; then
    print_info "Using custom rate value: ${3}"
    RATE=${3}
else
    print_info "Using default rate value: ${RATE}"
fi

TIMESTAMP=$(util_get_timestamp)
OUT_FILE_MASSCAN="./${FOLDER_NAME_NMAP}/masscan_tcp_${PORT}_${TIMESTAMP}.txt"
OUT_FILE_IP_PORT="./${FOLDER_NAME_NMAP}/ips_${PORT}_${TIMESTAMP}.txt"
OUT_FILE_NMAP_PREFIX="./${FOLDER_NAME_NMAP}/nmap_${PORT}_${TIMESTAMP}"

sudo masscan -p${PORT} --open --rate=${RATE} -oL "${OUT_FILE_MASSCAN}" -iL "${FILE}"
print_info "Masscan result written to: ${OUT_FILE_MASSCAN}"
if [ $? -eq 0 ]; then
    candidates=$(grep 'open' "${OUT_FILE_MASSCAN}")
    if [ $? -eq 0 ]; then
        echo "$candidates" | cut -d' ' -f4 > $OUT_FILE_IP_PORT
        nmap -v -p${PORT} -sT -T4 -sVC -Pn --open --reason -iL "${OUT_FILE_IP_PORT}" -oA "${OUT_FILE_NMAP_PREFIX}"
        print_info "Nmap result written to: ${OUT_FILE_NMAP_PREFIX}.nmap"
    else
        print_warning "No host found for TCP port ${PORT}."
    fi
fi