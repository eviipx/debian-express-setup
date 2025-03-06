#!/usr/bin/env bash
# -------------------------------------------------------------------------
# Debian Express Secure Setup - SINGLE MERGED SCRIPT
#   Combines debian-express-environment.sh and debian-express-secure.sh
#
# Source Repo: https://github.com/eviipx/debian-express-setup
# -------------------------------------------------------------------------
# Usage:
#   sudo bash debian-express-secure.sh
# -------------------------------------------------------------------------

################################################################################
#                  START: debian-express-environment.sh
################################################################################
# (Everything below is exactly from the 'debian-express-environment.sh' file,
#  except we've removed its own #!/usr/bin/env bash line, since we already have
#  one at the top. No changes made other than that.)
################################################################################

# --------------------------------------------------------------------------------
# Title         : Debian Express Setup - Environment
# Author        : eviip
# Date          : 2023-06-17
# Version       : 2.3.2
# Description   : Common environment variables, functions, and logic for Debian-based scripts.
# Tested on     : Debian 10, Debian 11
# --------------------------------------------------------------------------------

# shellcheck disable=SC1091,SC2154,SC2162,SC2034

# set -e -u -o pipefail

C_RESET="\033[0m"
C_RED="\033[31m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_BLUE="\033[34m"
C_MAGENTA="\033[35m"
C_CYAN="\033[36m"
C_WHITE="\033[37m"
C_BOLD="\033[1m"
C_DIM="\033[2m"

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="2.3.2"
readonly SCRIPT_AUTHOR="eviip"

ROOT_CHECK_FAIL_MESSAGE="This script must be run as root. Use sudo or switch to the root user."

DEBIAN_CHECK_FAIL_MESSAGE="This script is intended for Debian-based systems. Exiting."
DEBIAN_CHECK_PATH="/etc/debian_version"

SUPPORTED_SETUP_SCRIPTS=("debian-express-environment.sh" "debian-express-secure.sh" "debian-express-docker.sh" "debian-express-services.sh" "debian-express-k3s.sh")

declare DETECTED_OS=""
declare DETECTED_VERSION=""
declare -i CONTINUE_SETUP=1

# Standard environment script that might be sourced into all other scripts

check_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo -e "${C_RED}${BOLD_ON}${ROOT_CHECK_FAIL_MESSAGE}${C_RESET}"
    exit 1
  fi
}

check_debian_based() {
  if [[ ! -f "${DEBIAN_CHECK_PATH}" ]]; then
    echo -e "${C_RED}${BOLD_ON}${DEBIAN_CHECK_FAIL_MESSAGE}${C_RESET}"
    exit 1
  fi
}

check_setup_script() {
  local script_found=0
  for script_name in "${SUPPORTED_SETUP_SCRIPTS[@]}"; do
    if [[ "${SCRIPT_NAME}" == "${script_name}" ]]; then
      script_found=1
      break
    fi
  done

  if [[ "${script_found}" -eq 0 ]]; then
    echo -e "${C_RED}${BOLD_ON}This script (${SCRIPT_NAME}) is not recognized as a supported setup script.${C_RESET}"
    echo -e "${C_RED}${BOLD_ON}Supported scripts are: ${SUPPORTED_SETUP_SCRIPTS[*]}${C_RESET}"
    exit 1
  fi
}

display_banner() {
  echo -e "${C_GREEN}============================================================${C_RESET}"
  echo -e "${C_GREEN}${BOLD_ON}Debian Express Setup v${SCRIPT_VERSION}${C_RESET}"
  echo -e "${C_GREEN}Author: ${SCRIPT_AUTHOR}${C_RESET}"
  echo -e "${C_GREEN}This script is intended for Debian-based systems only.${C_RESET}"
  echo -e "${C_GREEN}============================================================${C_RESET}"
  echo
}

detect_os() {
  if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    DETECTED_OS="${NAME:-Unknown}"
    DETECTED_VERSION="${VERSION_ID:-Unknown}"
  elif [[ -f /etc/debian_version ]]; then
    DETECTED_OS="Debian"
    DETECTED_VERSION="$(cat /etc/debian_version)"
  else
    DETECTED_OS="Unknown"
    DETECTED_VERSION="Unknown"
  fi
}

# confirm with user
get_yes_no() {
  local prompt="$1"
  local default="${2:-}"

  while true; do
    if [[ -n "${default}" ]]; then
      if [[ "${default}" == "y" ]]; then
        read -rp "${prompt} [Y/n]: " response
        response="${response,,}" # to lowercase
        if [[ -z "${response}" || "${response}" == "y" || "${response}" == "yes" ]]; then
          return 0
        elif [[ "${response}" == "n" || "${response}" == "no" ]]; then
          return 1
        else
          echo "Invalid input. Please enter y or n."
        fi
      elif [[ "${default}" == "n" ]]; then
        read -rp "${prompt} [y/N]: " response
        response="${response,,}" # to lowercase
        if [[ -z "${response}" || "${response}" == "n" || "${response}" == "no" ]]; then
          return 1
        elif [[ "${response}" == "y" || "${response}" == "yes" ]]; then
          return 0
        else
          echo "Invalid input. Please enter y or n."
        fi
      else
        echo "Invalid default value: ${default}"
        return 1
      fi
    else
      read -rp "${prompt} [y/n]: " response
      response="${response,,}" # to lowercase
      case "${response}" in
        y|yes) return 0 ;;
        n|no) return 1  ;;
        *) echo "Invalid input. Please enter y or n." ;;
      esac
    fi
  done
}

# requires the environment variable $1 + $2
# Example usage: get_script_variable "SCRIPT_NAME" "value if empty" "value if not empty"
# returns "value if empty" or "value if not empty"
get_script_variable() {
  local variable_name="$1"
  local value_if_empty="$2"
  local value_if_not_empty="$3"

  # shellcheck disable=SC1083,SC2295
  local var_value="${!variable_name}"

  if [[ -z "${var_value}" ]]; then
    echo "${value_if_empty}"
  else
    echo "${value_if_not_empty}"
  fi
}

pause_execution() {
  if [[ $# -gt 0 ]]; then
    read -r -p "$*"
  else
    read -r -p "Press Enter to continue..."
  fi
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

failed_command_status() {
  local cmd="$*"
  ${cmd}
  local status=$?
  if [[ $status -ne 0 ]]; then
    echo -e "${C_RED}${BOLD_ON}Command '${cmd}' failed with status ${status}.${C_RESET}"
    exit $status
  fi
  return $status
}

system_update() {
  apt-get update -y && apt-get upgrade -y
}

apt_clean() {
  apt-get autoremove -y
  apt-get autoclean -y
  apt-get clean -y
}

reboot_required() {
  # check if /var/run/reboot-required exists
  if [[ -f /var/run/reboot-required ]]; then
    return 0
  fi
  return 1
}

prompt_reboot_if_required() {
  if reboot_required; then
    echo -e "${C_YELLOW}${BOLD_ON}A reboot is required to apply changes.${C_RESET}"
    if get_yes_no "Reboot now?"; then
      echo -e "${C_GREEN}${BOLD_ON}Rebooting...${C_RESET}"
      reboot
    else
      echo -e "${C_YELLOW}${BOLD_ON}Reboot was postponed. System changes may not take full effect until the next reboot.${C_RESET}"
    fi
  fi
}

configure_swap() {
  local swap_size="$1"

  if [[ -z "${swap_size}" ]]; then
    echo -e "${C_RED}${BOLD_ON}Swap size not specified. Skipping swap configuration.${C_RESET}"
    return
  fi

  # check if swap is already configured
  if swapon --show | grep -q "partition"; then
    echo -e "${C_YELLOW}${BOLD_ON}Swap partition already configured. Skipping swap file creation.${C_RESET}"
    return
  fi

  if swapon --show | grep -q "file"; then
    echo -e "${C_YELLOW}${BOLD_ON}Swap file already configured. Skipping swap file creation.${C_RESET}"
    return
  fi

  echo -e "${C_GREEN}${BOLD_ON}Configuring swap file of size ${swap_size}...${C_RESET}"
  fallocate -l "${swap_size}" /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile

  if ! grep -q '^/swapfile' /etc/fstab; then
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
  fi

  echo -e "${C_GREEN}${BOLD_ON}Swap file created and enabled.${C_RESET}"
}

create_user() {
  local username="$1"
  local password="$2"
  local shell="/bin/bash"

  # Check if user already exists
  if id -u "${username}" >/dev/null 2>&1; then
    echo -e "${C_YELLOW}${BOLD_ON}User '${username}' already exists. Skipping creation.${C_RESET}"
  else
    # create user with password
    useradd -m -s "${shell}" "${username}"
    echo "${username}:${password}" | chpasswd
    echo -e "${C_GREEN}${BOLD_ON}User '${username}' created.${C_RESET}"
  fi
}

create_sudo_user() {
  local username="$1"
  local password="$2"
  local shell="/bin/bash"

  create_user "${username}" "${password}"
  usermod -aG sudo "${username}"
  echo -e "${C_GREEN}${BOLD_ON}User '${username}' added to sudo group.${C_RESET}"
}

lock_user() {
  local username="$1"
  usermod --lock "${username}"
  echo -e "${C_GREEN}${BOLD_ON}User '${username}' has been locked.${C_RESET}"
}

disable_root_ssh_login() {
  local ssh_config="/etc/ssh/sshd_config"

  if grep -qE '^PermitRootLogin\s+yes' "${ssh_config}"; then
    sed -i 's/^PermitRootLogin\s\+yes/PermitRootLogin no/g' "${ssh_config}"
    echo -e "${C_GREEN}${BOLD_ON}Disabled root SSH login.${C_RESET}"
    systemctl restart ssh
  else
    echo -e "${C_YELLOW}${BOLD_ON}Root SSH login is already disabled or not found.${C_RESET}"
  fi
}

disable_password_authentication() {
  local ssh_config="/etc/ssh/sshd_config"

  if grep -qE '^PasswordAuthentication\s+yes' "${ssh_config}"; then
    sed -i 's/^PasswordAuthentication\s\+yes/PasswordAuthentication no/g' "${ssh_config}"
    echo -e "${C_GREEN}${BOLD_ON}Disabled password authentication in SSH.${C_RESET}"
    systemctl restart ssh
  else
    echo -e "${C_YELLOW}${BOLD_ON}Password authentication is already disabled or not found.${C_RESET}"
  fi
}

enable_ufw() {
  if ! command_exists ufw; then
    apt-get install -y ufw
  fi

  if ! ufw status | grep -q 'Status: active'; then
    ufw --force enable
    echo -e "${C_GREEN}${BOLD_ON}UFW firewall enabled.${C_RESET}"
  else
    echo -e "${C_YELLOW}${BOLD_ON}UFW is already enabled.${C_RESET}"
  fi
}

configure_ufw_ssh() {
  ufw allow ssh
  echo -e "${C_GREEN}${BOLD_ON}UFW: Allowed SSH traffic.${C_RESET}"
}

configure_ufw_http_https() {
  ufw allow http
  ufw allow https
  echo -e "${C_GREEN}${BOLD_ON}UFW: Allowed HTTP and HTTPS traffic.${C_RESET}"
}

configure_ufw_port() {
  local port="$1"
  ufw allow "${port}"
  echo -e "${C_GREEN}${BOLD_ON}UFW: Allowed port ${port}.${C_RESET}"
}

install_fail2ban() {
  if ! command_exists fail2ban-server; then
    apt-get install -y fail2ban
    systemctl enable fail2ban
    systemctl start fail2ban
    echo -e "${C_GREEN}${BOLD_ON}Fail2ban installed and enabled.${C_RESET}"
  else
    echo -e "${C_YELLOW}${BOLD_ON}Fail2ban is already installed.${C_RESET}"
  fi
}

configure_fail2ban_jail() {
  local jail_local="/etc/fail2ban/jail.local"
  if [[ ! -f "${jail_local}" ]]; then
    cp /etc/fail2ban/jail.conf "${jail_local}"
    echo -e "${C_GREEN}${BOLD_ON}Created jail.local from jail.conf.${C_RESET}"
  else
    echo -e "${C_YELLOW}${BOLD_ON}jail.local already exists, not overwritten.${C_RESET}"
  fi
}

install_logwatch() {
  if ! command_exists logwatch; then
    apt-get install -y logwatch
    echo -e "${C_GREEN}${BOLD_ON}Logwatch installed.${C_RESET}"
  else
    echo -e "${C_YELLOW}${BOLD_ON}Logwatch is already installed.${C_RESET}"
  fi
}

configure_logwatch() {
  local logwatch_conf="/usr/share/logwatch/default.conf/logwatch.conf"
  if [[ -f "${logwatch_conf}" ]]; then
    # default mail "root"
    # we could do sed or manual config
    echo -e "${C_GREEN}${BOLD_ON}Logwatch configuration file: ${logwatch_conf}${C_RESET}"
  else
    echo -e "${C_YELLOW}${BOLD_ON}Logwatch configuration not found at ${logwatch_conf}${C_RESET}"
  fi
}

install_rkhunter() {
  if ! command_exists rkhunter; then
    apt-get install -y rkhunter
    echo -e "${C_GREEN}${BOLD_ON}rkhunter installed.${C_RESET}"
  else
    echo -e "${C_YELLOW}${BOLD_ON}rkhunter is already installed.${C_RESET}"
  fi
}

update_rkhunter() {
  if command_exists rkhunter; then
    rkhunter --update
    rkhunter --propupd
    echo -e "${C_GREEN}${BOLD_ON}rkhunter updated and property database updated.${C_RESET}"
  else
    echo -e "${C_RED}${BOLD_ON}rkhunter is not installed. Skipping update.${C_RESET}"
  fi
}

check_rkhunter() {
  if command_exists rkhunter; then
    rkhunter --check --sk
  else
    echo -e "${C_RED}${BOLD_ON}rkhunter is not installed. Skipping check.${C_RESET}"
  fi
}

setup_ssh_key_auth() {
  local username="$1"
  local public_key="$2"
  local ssh_dir="/home/${username}/.ssh"
  local authorized_keys="${ssh_dir}/authorized_keys"

  if [[ -z "${username}" ]] || [[ -z "${public_key}" ]]; then
    echo -e "${C_RED}${BOLD_ON}Username or public key not provided. Skipping SSH key setup.${C_RESET}"
    return
  fi

  if [[ ! -d "${ssh_dir}" ]]; then
    mkdir -p "${ssh_dir}"
    chown "${username}:${username}" "${ssh_dir}"
    chmod 700 "${ssh_dir}"
  fi

  if [[ ! -f "${authorized_keys}" ]]; then
    touch "${authorized_keys}"
    chown "${username}:${username}" "${authorized_keys}"
    chmod 600 "${authorized_keys}"
  fi

  if ! grep -q "${public_key}" "${authorized_keys}"; then
    echo "${public_key}" >> "${authorized_keys}"
    echo -e "${C_GREEN}${BOLD_ON}Added public key to ${authorized_keys}.${C_RESET}"
  else
    echo -e "${C_YELLOW}${BOLD_ON}Public key already present in ${authorized_keys}.${C_RESET}"
  fi
}

setup_hostname() {
  local new_hostname="$1"
  if [[ -z "${new_hostname}" ]]; then
    echo -e "${C_RED}${BOLD_ON}Hostname not provided. Skipping hostname setup.${C_RESET}"
    return
  fi

  local current_hostname
  current_hostname=$(hostname)

  if [[ "${new_hostname}" == "${current_hostname}" ]]; then
    echo -e "${C_YELLOW}${BOLD_ON}Hostname is already '${new_hostname}'. Skipping.${C_RESET}"
    return
  fi

  hostnamectl set-hostname "${new_hostname}"
  echo -e "${C_GREEN}${BOLD_ON}Hostname changed from '${current_hostname}' to '${new_hostname}'.${C_RESET}"

  # Update /etc/hosts
  if ! grep -q "${new_hostname}" /etc/hosts; then
    echo "127.0.1.1  ${new_hostname}" >> /etc/hosts
    echo -e "${C_GREEN}${BOLD_ON}Added '${new_hostname}' to /etc/hosts.${C_RESET}"
  fi
}

update_locale() {
  local new_locale="$1"
  if [[ -z "${new_locale}" ]]; then
    echo -e "${C_RED}${BOLD_ON}Locale not provided. Skipping locale update.${C_RESET}"
    return
  fi

  echo -e "${C_GREEN}${BOLD_ON}Updating locale to ${new_locale}...${C_RESET}"
  sed -i "s/^# *${new_locale}/${new_locale}/" /etc/locale.gen
  locale-gen
  update-locale LANG="${new_locale}"
  echo -e "${C_GREEN}${BOLD_ON}Locale updated to ${new_locale}.${C_RESET}"
}

update_timezone() {
  local new_timezone="$1"
  if [[ -z "${new_timezone}" ]]; then
    echo -e "${C_RED}${BOLD_ON}Timezone not provided. Skipping timezone update.${C_RESET}"
    return
  fi

  echo -e "${C_GREEN}${BOLD_ON}Updating timezone to ${new_timezone}...${C_RESET}"
  timedatectl set-timezone "${new_timezone}"
  echo -e "${C_GREEN}${BOLD_ON}Timezone updated to ${new_timezone}.${C_RESET}"
}

install_package_list() {
  local package_list=("$@")
  if [[ ${#package_list[@]} -eq 0 ]]; then
    echo -e "${C_RED}${BOLD_ON}No packages specified to install.${C_RESET}"
    return
  fi

  echo -e "${C_GREEN}${BOLD_ON}Installing packages: ${package_list[*]}...${C_RESET}"
  apt-get install -y "${package_list[@]}"
}

remove_package_list() {
  local package_list=("$@")
  if [[ ${#package_list[@]} -eq 0 ]]; then
    echo -e "${C_RED}${BOLD_ON}No packages specified to remove.${C_RESET}"
    return
  fi

  echo -e "${C_GREEN}${BOLD_ON}Removing packages: ${package_list[*]}...${C_RESET}"
  apt-get remove -y "${package_list[@]}"
  apt-get autoremove -y
}

install_docker() {
  if command_exists docker; then
    echo -e "${C_YELLOW}${BOLD_ON}Docker is already installed.${C_RESET}"
    return
  fi

  echo -e "${C_GREEN}${BOLD_ON}Installing Docker...${C_RESET}"
  apt-get update -y
  apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

  curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io
  systemctl enable docker
  systemctl start docker
  echo -e "${C_GREEN}${BOLD_ON}Docker installed and started.${C_RESET}"
}

install_docker_compose() {
  if command_exists docker-compose; then
    echo -e "${C_YELLOW}${BOLD_ON}docker-compose is already installed.${C_RESET}"
    return
  fi

  echo -e "${C_GREEN}${BOLD_ON}Installing docker-compose...${C_RESET}"
  local latest_version
  latest_version="$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep tag_name | cut -d '"' -f 4)"
  curl -L "https://github.com/docker/compose/releases/download/${latest_version}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
  echo -e "${C_GREEN}${BOLD_ON}docker-compose installed.${C_RESET}"
}

install_k3s() {
  if command_exists k3s; then
    echo -e "${C_YELLOW}${BOLD_ON}k3s is already installed.${C_RESET}"
    return
  fi

  echo -e "${C_GREEN}${BOLD_ON}Installing k3s...${C_RESET}"
  curl -sfL https://get.k3s.io | sh -
  echo -e "${C_GREEN}${BOLD_ON}k3s installed.${C_RESET}"
}

#################################
# Version check for environment
#################################
environment_version() {
  echo "${SCRIPT_VERSION}"
}

################################################################################
#                   END: debian-express-environment.sh
################################################################################


################################################################################
#                   START: debian-express-secure.sh
################################################################################
# (Below is the original 'debian-express-secure.sh' content, with the
#  `source debian-express-environment.sh` line removed/commented out.)
################################################################################

# --------------------------------------------------------------------------------
# Title         : Debian Express Setup - Secure
# Author        : eviip
# Date          : 2023-06-17
# Version       : 2.3.2
# Description   : Secure setup script for Debian-based systems
#                (firewall, fail2ban, basic hardening, etc.)
# Tested on     : Debian 10, Debian 11
# --------------------------------------------------------------------------------
# shellcheck disable=SC1091,SC2154,SC2162,SC2034

# Removed or commented out:
# source "$(dirname "$0")/debian-express-environment.sh"

# set -e -u -o pipefail

# Usage:
#   sudo bash debian-express-secure.sh

#################################
# Secure Setup Main
#################################

main() {
  check_root
  check_debian_based
  display_banner
  detect_os
  check_setup_script

  # Confirm if user wants to proceed
  echo -e "${C_GREEN}This script will apply basic security measures for Debian-based systems.${C_RESET}"
  if ! get_yes_no "Do you want to continue?" "y"; then
    echo "Setup cancelled. No changes were made."
    exit 1
  fi

  # Start with a system update
  echo -e "${C_GREEN}${BOLD_ON}Updating system packages...${C_RESET}"
  system_update

  # Installing essential security packages
  echo -e "${C_GREEN}${BOLD_ON}Installing essential packages...${C_RESET}"
  install_package_list ufw fail2ban logwatch rkhunter

  # Configure UFW
  echo -e "${C_GREEN}${BOLD_ON}Configuring UFW...${C_RESET}"
  enable_ufw
  configure_ufw_ssh
  configure_ufw_http_https

  # Configure fail2ban
  echo -e "${C_GREEN}${BOLD_ON}Configuring fail2ban...${C_RESET}"
  install_fail2ban
  configure_fail2ban_jail
  systemctl restart fail2ban

  # Disable root SSH login
  echo -e "${C_GREEN}${BOLD_ON}Disabling root SSH login...${C_RESET}"
  disable_root_ssh_login

  # Optionally disable password authentication
  if get_yes_no "Disable password authentication in SSH? (Requires SSH key for login)"; then
    disable_password_authentication
  fi

  # rkhunter update
  echo -e "${C_GREEN}${BOLD_ON}Updating rkhunter...${C_RESET}"
  update_rkhunter

  # Logwatch basic configuration
  echo -e "${C_GREEN}${BOLD_ON}Configuring logwatch...${C_RESET}"
  configure_logwatch

  # Final cleaning
  echo -e "${C_GREEN}${BOLD_ON}Cleaning up packages...${C_RESET}"
  apt_clean

  # Done
  echo -e "${C_GREEN}${BOLD_ON}Debian Express Secure Setup is complete.${C_RESET}"
  prompt_reboot_if_required
}

# Execute main
main
