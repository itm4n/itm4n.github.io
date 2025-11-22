#!/usr/bin/env -S bash --posix

function pwnbox_system_package_install_all() {

    echo ""
    print_info "----------------------------------------------------------------"
    print_info "Installing APT packages..."
    print_info "----------------------------------------------------------------"

    config_file_path="${SCRIPT_DIR}/pkg_apt.txt"
    if util_test_file_existence "${config_file_path}"; then
        package_list=""
        for p in $(cat "${config_file_path}"); do
            if pwnbox_system_package_exists "${p}"; then
                package_list="${package_list}${p} "
            else
                print_warning "System package '${p}' not found, ignoring..."
            fi
        done
        if [ "${package_list}" != "" ]; then
            print_info "Installing system packages: ${package_list}"
            if pwnbox_system_package_install ${package_list}; then
                print_success "Successfully installed system packages!"
            else
                print_error "The 'apt install' command failed."
            fi
        else
            print_warning "No system package to install".
        fi
    else
        print_error "System package list file not found: ${config_file_path}"
    fi
}

function pwnbox_system_package_update_all() {

    echo ""
    print_info "----------------------------------------------------------------"
    print_info "Updating system package list..."
    print_info "----------------------------------------------------------------"

    apt update -y

    return $?
}

function pwnbox_system_package_autoremove_all() {

    echo ""
    print_info "----------------------------------------------------------------"
    print_info "Removing unused system packages..."
    print_info "----------------------------------------------------------------"

    apt autoremove -y

    return $?
}

function pwnbox_system_package_upgrade_all() {

    echo ""
    print_info "----------------------------------------------------------------"
    print_info "Upgrading system packages..."
    print_info "----------------------------------------------------------------"

    apt upgrade -y

    return $?
}

function pwnbox_system_package_install() {

    apt install -y $@

    return $?
}

function pwnbox_system_package_exists() {

    apt-cache show "${1}" 1>/dev/null 2>&1

    return $?
}

function pwnbox_pipx_package_upgrade_all() {

    echo ""
    print_info "----------------------------------------------------------------"
    print_info "Upgrading pipx packages..."
    print_info "----------------------------------------------------------------"

    if [[ $SUDO_USER == "" ]]; then
        if ! util_test_is_not_root; then
            return 1
        fi
        pipx upgrade-all
    else
        if ! util_test_is_root; then
            return 2
        fi
        sudo -u "${SUDO_USER}" pipx upgrade-all
    fi

    return $?
}

function pwnbox_pipx_package_install() {

    if [[ $SUDO_USER == "" ]]; then
        if ! util_test_is_not_root; then
            return 1
        fi
        pipx install "${1}"
    else
        if ! util_test_is_root; then
            return 2
        fi
        sudo -u "${SUDO_USER}" pipx install "${1}"
    fi

    return $?
}

function pwnbox_pipx_package_install_all() {

    echo ""
    print_info "----------------------------------------------------------------"
    print_info "Installing pipx packages..."
    print_info "----------------------------------------------------------------"

    cnt_package_install_success=0
    cnt_package_install_failure=0
    config_file_path="${SCRIPT_DIR}/pkg_pipx.txt"
    if util_test_file_existence "${config_file_path}"; then
        for p in $(cat "${config_file_path}"); do
            if pwnbox_pipx_package_install "${p}"; then
                cnt_package_install_success=$((cnt_package_install_success+1))
            else
                cnt_package_install_failure=$((cnt_package_install_failure+1))
            fi
        done
    else
        print_error "Pipx package list file not found: ${config_file_path}"
    fi

    print_success "Number of pipx packages installed or updated: ${cnt_package_install_success}"
    if [ $cnt_package_install_failure -eq 0 ]; then
        print_info "Number of pipx package install failures: ${cnt_package_install_failure}"
    else
        print_warning "Number of pipx package install failures: ${cnt_package_install_failure}"
    fi
}

function pwnbox_go_check_environment() {
    
    echo ""
    print_info "----------------------------------------------------------------"
    print_info "Checking Go environment..."
    print_info "----------------------------------------------------------------"

    if apt list --installed 2>/dev/null | grep -wq "golang-go"; then
        if util_check_command_existence "go"; then
            print_info "Go command exists: $(which "go")"
            home_path="$(util_get_user_home_directory_path)"
            print_info "Current user home directory: ${home_path}"
            shell_rc_file=""
            shell_rc_file_tmp=$(realpath "${home_path}/.zshrc")
            if util_test_file_existence "${shell_rc_file_tmp}"; then
                shell_rc_file="${shell_rc_file_tmp}"
            else
                shell_rc_file_tmp=$(realpath "${home_path}/.bashrc")
                if util_test_file_existence "${shell_rc_file_tmp}"; then
                    shell_rc_file="${shell_rc_file_tmp}"
                fi
            fi
            if [ "${shell_rc_file}" != "" ]; then
                print_info "Found shell rc file: ${shell_rc_file}"
                pattern="export PATH=\$PATH:\$HOME/go/bin"
                if grep -q "${pattern}" "${shell_rc_file}"; then
                    print_info "Go user path found in shell rc file: $(grep "${pattern}" "${shell_rc_file}")"
                else
                    print_info "Go user path not found in shell rc file, adding it..."
                    echo -e "\nexport PATH=\$PATH:\$HOME/go/bin" >> $shell_rc_file_tmp
                fi
                print_success "Go environment ready!"
                return 0
            else
                print_warning "Shell rc file not found in home folder: ${home_path}"
            fi
        fi
    else
        print_warning "Golang is not installed."
    fi

    return 1
}

function pwnbox_go_package_install() {

    command="go install ${1}"
    util_run_command_as_user "${command}"
    return $?
}

function pwnbox_go_package_install_all() {

    echo ""
    print_info "----------------------------------------------------------------"
    print_info "Installing Go packages..."
    print_info "----------------------------------------------------------------"

    cnt_package_install_success=0
    cnt_package_install_failure=0
    config_file_path="${SCRIPT_DIR}/pkg_go.txt"
    if util_test_file_existence "${config_file_path}"; then
        for p in $(cat "${config_file_path}"); do
            if pwnbox_go_package_install "${p}"; then
                cnt_package_install_success=$((cnt_package_install_success+1))
            else
                cnt_package_install_failure=$((cnt_package_install_failure+1))
            fi
        done
    else
        print_error "Go package list file not found: ${config_file_path}"
    fi

    print_success "Number of Go packages installed or updated: ${cnt_package_install_success}"
    if [ $cnt_package_install_failure -eq 0 ]; then
        print_info "Number of Go package install failures: ${cnt_package_install_failure}"
    else
        print_warning "Number of Go package install failures: ${cnt_package_install_failure}"
    fi
}

function pwnbox_symlink_create_or_update_all() {

    echo ""
    print_info "----------------------------------------------------------------"
    print_info "Creating and/or updating symbolic links to pentest tools..."
    print_info "----------------------------------------------------------------"

    local_bin_dir="/usr/local/bin"
    root_dir=$(realpath "${SCRIPT_DIR}/../")
    print_info "Script root directory: ${root_dir}"
    config_file_path="${SCRIPT_DIR}/cfg_symlinks.txt"
    if util_test_file_existence "${config_file_path}"; then
        for s in $(cat "${config_file_path}"); do
            symlink_name=$(echo "${s}" | cut -d'=' -f1)
            symlink_target=$(echo "${s}" | cut -d'=' -f2)
            symlink_target="${root_dir}/${symlink_target}"
            if util_test_file_existence "${symlink_target}"; then
                symlink_source="${local_bin_dir}/${symlink_name}"
                symlink_str="${symlink_source} -> ${symlink_target}"
                create=0
                if [[ -L "${symlink_source}" ]]; then
                    symlink_target_current=$(readlink -f "${symlink_source}")
                    symlink_current_str="${symlink_source} -> ${symlink_target_current}"
                    if [[ "${symlink_target_current}" == "${symlink_target}" ]]; then
                        print_info "Found existing symlink: ${symlink_current_str}"
                    else
                        print_warning "Removing obsolete symlink: ${symlink_current_str}"
                        rm -f "${symlink_source}"
                        create=1
                    fi
                else
                    create=1
                fi
                if [[ $create == 1 ]]; then
                    if ln -s "${symlink_target}" "${symlink_source}"; then
                        print_info "Created symlink: ${symlink_str}"
                    else
                        print_error "Failed to create symlink: ${symlink_str}"
                    fi
                fi
            else
                print_warning "Symlink target file not found: ${symlink_target}"
            fi
        done
    else
        print_error "Symlink list file not found: ${config_file_path}"
    fi
}

function pwnbox_install_or_update() {
    util_check_is_root || exit
    network_check_internet_connection || exit
    pwnbox_system_package_update_all || exit
    pwnbox_system_package_upgrade_all || exit
    pwnbox_system_package_autoremove_all || exit
    pwnbox_system_package_install_all
    pwnbox_pipx_package_install_all
    pwnbox_pipx_package_upgrade_all
    pwnbox_go_check_environment && pwnbox_go_package_install_all
    pwnbox_symlink_create_or_update_all
}
