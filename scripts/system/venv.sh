#!/usr/bin/env -S bash --posix

### BEGIN INCLUDE
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPT_NAME=$(basename "${SCRIPT_PATH}")
SCRIPT_DIR=$(dirname "${SCRIPT_PATH}")
source "${SCRIPT_DIR}/../common.sh" || exit
### END INCLUDE

function venv_check_prerequisites() {
    nb_errors=0

    util_check_is_not_root || ((nb_errors=nb_errors+1))
    util_check_command_existence "python" || ((nb_errors=nb_errors+1))
    util_check_command_existence "virtualenv" || ((nb_errors=nb_errors+1))

    return $nb_errors
}

function venv_create_virtual_env_cwd() {
    nb_errors=0

    # The option '--copies' is used here to copy required binaries instead of
    # creating symbolic links which might not be handled properly on samba file
    # shares.
    if ! virtualenv . --copies;
    then
        print_error "Failed to create virtual Python environment."
        return 1
    fi

    print_success "Created virtual Python environment in: $(realpath .)"
    print_info "Use the command 'source ./bin/activate' to enter the virtual environment."
    print_info "Use the command 'deactivate' to exit the virtual environment."

    return 0
}

venv_check_prerequisites || exit
venv_create_virtual_env_cwd || exit
