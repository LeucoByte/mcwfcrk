# MCWFCRK — Marco Calvo WiFi Cracker

Automated WPA/WPA2 security auditing tool for Linux. One script handles monitor mode, target selection, capture, cracking, and cleanup.

## Attack modes

### HANDSHAKE (default)

Captures the WPA four-way handshake on the target channel and forces a reconnect with deauth frames. **Requires a client connected to the AP.** Cracked with `aircrack-ng`. Default: 5 deauth packets (`-d` to increase).

### PMKID

Captures a PMKID from the access point **without any connected clients**. Runs `hcxdumptool` on the detected channel, converts to `.hc22000`, filters to your target BSSID, and cracks with `hashcat`. Not every router exposes a usable PMKID.

## Compatibility

WPA/WPA2 **PSK** networks only. No WPA3, enterprise (802.1X), or open networks.

| Target | HANDSHAKE | PMKID |
|--------|-----------|-------|
| WPA2-PSK | Yes | Often |
| WPA-PSK | Yes | Sometimes |
| WPA3 / Enterprise / Open | No | No |

## Features

- Non-disruptive — does not stop NetworkManager
- Interactive scan or fully scripted with `-b` / `-e`
- Automatic channel detection and monitor cleanup on exit
- Auto-install of missing tools on Debian/Ubuntu (`apt-get`)

## Network interface note

One adapter in monitor mode cannot stay on your WiFi at the same time. A **USB adapter** for the attack is recommended. If the script enabled monitor mode, it deactivates it on exit.

## Installation

```bash
curl -LO https://raw.githubusercontent.com/LeucoByte/mcwfcrk/main/mcwfcrk.sh
chmod +x mcwfcrk.sh
```

## Usage

```bash
# Minimum — interactive scan, you pick BSSID or ESSID at the prompt
sudo bash mcwfcrk.sh -w /usr/share/wordlists/rockyou.txt

# PMKID with defaults (45 s timeout)
sudo bash mcwfcrk.sh -w /usr/share/wordlists/rockyou.txt -a PMKID

# PMKID — interface, ESSID, custom timeout
sudo bash mcwfcrk.sh -w /usr/share/wordlists/rockyou.txt -a PMKID -t 60 -i wlp0s20f3 -e H3601P_DA00

# HANDSHAKE — more deauth packets, same target
sudo bash mcwfcrk.sh -w /usr/share/wordlists/rockyou.txt -a HANDSHAKE -d 10 -i wlp0s20f3 -e H3601P_DA00

# BSSID known — skip scan and prompt
sudo bash mcwfcrk.sh -w /usr/share/wordlists/rockyou.txt -b 48:22:54:B1:6E:03 -i wlp0s20f3

# Save captures for later
sudo bash mcwfcrk.sh -w /usr/share/wordlists/rockyou.txt -a PMKID -e H3601P_DA00 -o ./captures
```

| Option | Description |
|--------|-------------|
| `-w`, `--wordlist` | Path to wordlist (**required**) |
| `-b`, `--bssid` | Target MAC — skips scan window and prompt |
| `-e`, `--essid` | Network name — silent scan resolves ESSID → BSSID |
| `-i`, `--interface` | WiFi interface (activates monitor mode if needed) |
| `-a`, `--attack-mode` | `HANDSHAKE` (default) or `PMKID` |
| `-d`, `--deauth` | Deauth packets in HANDSHAKE mode (default: 5, max: 256) |
| `-t`, `--timeout` | PMKID capture timeout in seconds (default: 45) |
| `-o`, `--output` | Directory to keep `.cap` / `.pcapng` / `.hc22000` files |
| `-h`, `--help` | Show usage |

Use `-b` or `-e`, not both. Without either, the script opens a scan window and prompts for BSSID or ESSID.

### Channel detection

After the BSSID is known, a targeted `airodump-ng` scan runs for up to **30 seconds** to read the channel from CSV. PMKID capture then locks `hcxdumptool` to that channel (e.g. `6a` on 2.4 GHz).

If detection fails: weak signal, wrong BSSID (dual-band routers have one MAC per band), or ESSID name mismatch with `-e`.

### Saving captures (`-o`)

Without `-o`, files live in `/tmp` and are removed on exit. With `-o`, keep them to retry hashcat/aircrack with another wordlist without recapturing.

## How it works

1. Monitor mode on the chosen interface (`-i` or auto-detect).
2. Target: interactive prompt, `-b`, or `-e` (silent scan).
3. Channel detection from BSSID.
4. **HANDSHAKE** — `airodump-ng` + directed/broadcast deauth, then `aircrack-ng`.
5. **PMKID** — `hcxdumptool` on target channel → `hcxpcapngtool` → filter hash to your BSSID → `hashcat`.
6. Password printed in the main terminal; cleanup on exit.

## Requirements

- Linux with X11
- Root / `sudo`
- WiFi adapter with monitor mode (packet injection needed for HANDSHAKE)
- Your own wordlist

## Disclaimer

**For authorized security testing only.** Use only on networks you own or have explicit written permission to test. The author provides this tool as-is with no warranty and accepts no liability for misuse or consequences.
