#!/usr/bin/env -S bash --posix

### BEGIN INCLUDE
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPT_NAME=$(basename "${SCRIPT_PATH}")
SCRIPT_DIR=$(dirname "${SCRIPT_PATH}")
source "${SCRIPT_DIR}/../common.sh" || exit
### END INCLUDE

function domains_in_scope_print_usage_and_exit() {
    print_info "Usage: ${SCRIPT_NAME} <DOMAINS_FILE> <SCOPE_FILE> <OUTPUT_FILE>"
    exit
}

util_check_argc $# 3 || domains_in_scope_print_usage_and_exit

CNT_DOMAINS_NOT_RESOLVED=0
CNT_DOMAINS_NO_IPV4=0
CNT_DOMAINS_SCOPE_OUT=0
CNT_DOMAINS_SCOPE_IN=0

FILE_DOMAINS=$1
FILE_SCOPE=$2
FILE_OUTPUT=$3

if ! util_test_file_existence "${FILE_DOMAINS}"; then
    print_error "Domains file not found: ${DOMAINS_FILE}"
    exit
fi

if ! util_test_file_existence "${FILE_SCOPE}"; then
    print_error "Scope file not found: ${FILE_SCOPE}"
    exit
fi

if util_test_file_existence "${FILE_OUTPUT}"; then
    print_warning "Output file already exists: ${FILE_OUTPUT}"
    exit
fi

file_scope_content=$(sort -u "$FILE_SCOPE")
file_scope_content_count=$(echo "$file_scope_content" | wc -l)

print_info "Number of unique scope entries in '${FILE_SCOPE}': ${file_scope_content_count}"

file_domains_content=$(sort -u "$FILE_DOMAINS")
file_domains_content_count=$(echo "$file_domains_content" | wc -l)

print_info "Number of unique domain names to check: ${file_domains_content_count}"

domains_in_scope=""

for domain in $file_domains_content
do
    host_result=$(host "$domain") # try to resolve domain name
    if [ $? == 0 ]; then
        echo "$host_result" | grep -q "has address"
        if [ $? == 0 ]; then
            ip=$(echo "$host_result" | grep "has address" | head -n1 | cut -d' ' -f4)
            print_info "Domain name '${domain}' was resolved to IP address: ${ip}"
            domains_resolved="${domains_resolved}${domain} ${ip}"$'\n'
        else
            print_warning "Failed to extract IP address for resolved domain: ${domain}"
            CNT_DOMAINS_NO_IPV4=$((CNT_DOMAINS_NO_IPV4+1))
        fi
    else
        print_warning "Failed to resolve domain name: ${domain}"
        CNT_DOMAINS_NOT_RESOLVED=$((CNT_DOMAINS_NOT_RESOLVED+1))
    fi
done

domains_resolved_count=$(echo -n "$domains_resolved" | wc -l)

print_info "Number of domains that could be resolved: ${domains_resolved_count}"

OLDIFS=$IFS # save IFS
IFS=$'\n' # set new IFS
for domain_resolved in $domains_resolved; do
    in_scope=0 # assume domain is not in scope
    IFS=$OLDIFS # restore IFS
    OLDIFS=$IFS # save IFS
    IFS=' ' # set new IFS
    entry_arr=(${domain_resolved// / }) # convert entry "domain ip" to array { domain, ip }
    IFS=$OLDIFS # restore IFS
    entry_ip=${entry_arr[1]} # extract IP address from entry
    entry_domain=${entry_arr[0]} # extract domain name from entry
    for scope_item in $file_scope_content; do
        if network_test_ip_in_subnet $scope_item $entry_ip; then
            in_scope=1 # ... if yes, mark entry as "in scope" ...
            break # ... and stop the search
        fi
    done

    if [ $in_scope -eq 1 ]; then
        print_success "Domain name '${entry_arr[0]}' with IP address ${entry_arr[1]} is in scope."
        domains_in_scope="${domains_in_scope}${domain_resolved}"$'\n'
        CNT_DOMAINS_SCOPE_IN=$((CNT_DOMAINS_SCOPE_IN+1))
    else
        print_warning "Domain name '${entry_arr[0]}' with IP address ${entry_arr[1]} is not in scope."
        CNT_DOMAINS_SCOPE_OUT=$((CNT_DOMAINS_SCOPE_OUT+1))
    fi
done
IFS=$OLDIFS # restore IFS

domains_in_scope_count=$(echo "$domains_in_scope" | wc -l)

print_info "Domain names not resolved...............: ${CNT_DOMAINS_NOT_RESOLVED}"
print_info "Domain names with no IPv4 address.......: ${CNT_DOMAINS_NO_IPV4}"
print_info "Domain names that are not in the scope..: ${CNT_DOMAINS_SCOPE_OUT}"
print_info "Domain names that are in the scope......: ${CNT_DOMAINS_SCOPE_IN}"

if [ $CNT_DOMAINS_SCOPE_IN -gt 0 ]; then
    print_success "All done! Writing result to '${FILE_OUTPUT}'."
    echo "$domains_in_scope" > $FILE_OUTPUT
else
    print_warning "The script finished but nothing was found."
fi
