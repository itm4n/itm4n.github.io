#!/usr/bin/env -S bash --posix

### BEGIN INCLUDE
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPT_NAME=$(basename "${SCRIPT_PATH}")
SCRIPT_DIR=$(dirname "${SCRIPT_PATH}")
source "${SCRIPT_DIR}/../common.sh" || exit
### END INCLUDE

pwnbox_install_or_update