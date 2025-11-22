#!/usr/bin/env -S bash --posix

### BEGIN SECTION GET INFO
function util_get_timestamp() {

    date "+%F_%H-%M-%S"
}

function util_get_root_directory_path() {

    script_path=$(readlink -f "${BASH_SOURCE[0]}")
    script_dir=$(dirname "${script_path}")
    root_dir=$(realpath "${script_dir}/../")
    echo -n "${root_dir}"
}

function util_get_user_home_directory_path() {

    if [[ $SUDO_USER == "" ]]; then
        echo -n $HOME
    else
        echo -n $(getent passwd $SUDO_USER | cut -d: -f6)
    fi
}

function util_get_current_user_name() {
    
    if [[ $SUDO_USER == "" ]]; then
        echo -n "$(whoami)"
    else
        echo -n "${SUDO_USER}"
    fi
}
### END SECTION GET INFO

### BEGIN SECTION TEST
function util_test_is_root() {

    if [ $(id -u) -ne 0 ]; then
        return 1
    fi

    return 0
}

function util_test_is_not_root() {

    if util_test_is_root; then
        return 1
    fi

    return 0
}

function util_test_file_existence() {

    if [ ! -f "${1}" ]; then
        return 1;
    fi

    return 0
}

function util_test_directory_existence() {

    if [ ! -d "${1}" ]; then
        return 1;
    fi

    return 0
}
### END SECTION TEST

### BEGIN SECTION CHECK
function util_check_argc() {

    if [ $1 -lt $2 ]; then
        print_error "Invalid number of arguments: ${1} (${2} expected)"
        return 1
    fi

    return 0
}

function util_check_is_root() {

    if ! util_test_is_root; then
        print_error "Current user is not root."
        return 1
    fi

    return 0
}

function util_check_is_not_root() {

    if util_test_is_root; then
        print_error "Current user is root."
        return 1
    fi

    return 0
}

function util_check_command_existence() {

    if ! which "${1}" >/dev/null 2>&1; then
        print_error "The following command does not exist: ${1}"
        return 1
    fi

    return 0
}
### END SECTION CHECK

### BEGIN SECTION MISC
function util_kill_process_and_wait() {

    if kill ${1} 2>/dev/null; then
        wait ${1} 2>/dev/null
    fi
}

function util_run_command_as_user() {

    command="${1}"
    current_user="$(whoami)"
    current_user_sudo="${SUDO_USER}"
    if [ "${current_user}" == "root" ]; then
        if [ "${current_user_sudo}" != "" ]; then
            sudo -u "${current_user_sudo}" bash -c "${command}"
        else
            bash -c "${command}"
        fi
    else
        bash -c "${command}"
    fi
    return $?
}
### END SECTION MISC