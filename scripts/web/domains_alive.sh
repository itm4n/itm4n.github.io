#!/usr/bin/env -S bash --posix

### BEGIN INCLUDE
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPT_NAME=$(basename "${SCRIPT_PATH}")
SCRIPT_DIR=$(dirname "${SCRIPT_PATH}")
source "${SCRIPT_DIR}/../common.sh" || exit
### END INCLUDE

function domains_alive_print_usage_and_exit() {
    print_info "Usage: ${SCRIPT_NAME} <DOMAINS_FILE>"
    exit
}

util_check_command_existence "host" || exit
util_check_argc $# 1 || domains_alive_print_usage_and_exit

DOMAINS_FILE="${1}"

if ! util_test_file_existence "${DOMAINS_FILE}"; then
    print_error "File not found: ${DOMAINS_FILE}"
    exit
fi

for h in $(cat "${DOMAINS_FILE}"); do
    host "$h" >/dev/null && echo $h
done
