#!/usr/bin/env -S bash --posix

COLOR_CYAN_BOLD="\e[1;36m"
COLOR_GREEN_BOLD="\e[1;32m"
COLOR_YELLOW_BOLD="\e[1;33m"
COLOR_RED_BOLD="\e[1;31m"
COLOR_RST="\e[0m"

SIGN_INFO="[*]"
SIGN_SUCCESS="[+]"
SIGN_WARNING="[!]"
SIGN_ERROR="[-]"

function print_info() {
    echo -e "${COLOR_CYAN_BOLD}${SIGN_INFO}${COLOR_RST} $1"
}

function print_success() {
    echo -e "${COLOR_GREEN_BOLD}${SIGN_SUCCESS}${COLOR_RST} $1"
}

function print_warning() {
    echo -e "${COLOR_YELLOW_BOLD}${SIGN_WARNING}${COLOR_RST} $1" >&2
}

function print_error() {
    echo -e "${COLOR_RED_BOLD}${SIGN_ERROR}${COLOR_RST} $1" >&2
}