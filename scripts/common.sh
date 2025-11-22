#!/usr/bin/env -S bash --posix

COMMON_SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
COMMON_SCRIPT_NAME=$(basename "${COMMON_SCRIPT_PATH}")
COMMON_SCRIPT_DIR=$(dirname "${COMMON_SCRIPT_PATH}")
for f in $(find "${COMMON_SCRIPT_DIR}/common/" -name "*.sh" ); do
    if [ -f "${f}" ] && [ "${f}" != "${COMMON_SCRIPT_NAME}" ]; then
        source "${f}"
    fi
done
