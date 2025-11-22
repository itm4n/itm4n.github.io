#!/usr/bin/env -S bash --posix

### BEGIN INCLUDE
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPT_NAME=$(basename "${SCRIPT_PATH}")
SCRIPT_DIR=$(dirname "${SCRIPT_PATH}")
source "${SCRIPT_DIR}/../common.sh" || exit
### END INCLUDE

function project_print_usage_and_exit() {
    print_info "Usage: ${SCRIPT_NAME} <CLIENT_NAME> <PROJECT_NAME>"
    exit
}

util_check_argc $# 2 || project_print_usage_and_exit

PROJECT_FOLDER="${HOME}/VirtShare/Audit"

if ! util_test_directory_existence "${PROJECT_FOLDER}"; then
    print_error "Project folder doesn't exist: ${PROJECT_FOLDER}"
    exit
fi

date=$(date +%F)
client_name="${1,,}"
project_name="${2,,}"
folder_name="${date}_${client_name}_${project_name}"
folder_path="${PROJECT_FOLDER}/${folder_name}"

if util_test_directory_existence "${folder_path}"; then
    print_warning "Workspace folder already exists: ${folder_path}"
    exit
fi

if ! mkdir "${folder_path}"; then
    print_error "Failed to create workspace folder: ${folder_path}"
    exit
fi

print_success "Created workspace folder: ${folder_path}"

for d in "hosts" "loot" "nmap" "recon" "resources" "screenshots" "wordlists"; do
    if ! mkdir "${folder_path}/${d}"; then
        print_error "Failed to create subdirectory: ${folder_path}/${d}"
        exit
    fi
done

print_info "Created workspace subdirectories."

ni=1
for n in "notes" "recon" "vulnerabilities" "misc" "summaries"; do
    note_path="${folder_path}/notes_${ni}_${n}.md"
    if ! touch "${note_path}"; then
        print_error "Failed to create note file: ${note_path}"
        exit
    fi
    echo -e "# ${n^}\n\n" > ${note_path}
    ni=$((ni+1))
done

print_info "Populated workspace with note files."

exegol_cmd="exegol start -w \"${folder_path}\" \"${client_name}-${project_name}\" \"free\""
print_info "Use the following command to start or create an Exegol container."
print_info "  ${exegol_cmd}"
print_warning "Exegol dependency deprecated, will soon be removed."
