# mcwfcrk — Marco Calvo WiFi Cracker

Bash script that automates WPA/WPA2-PSK audits on Linux: monitor mode, pick a target, capture, crack, cleanup. One run, less babysitting.

Only use this on networks you own or have **explicit permission** to test. Seriously.

## Install

```bash
curl -LO https://raw.githubusercontent.com/LeucoByte/mcwfcrk/main/mcwfcrk.sh
chmod +x mcwfcrk.sh
```

## Quick run

```bash
sudo ./mcwfcrk.sh -w /usr/share/wordlists/rockyou.txt
```

Opens a scan window, you type a BSSID or ESSID, it does the rest.

**Heads up:** one card in monitor mode can't stay on your normal WiFi at the same time. USB adapter for the attack, built-in for internet, works great.

---

## Modes

### HANDSHAKE (default)

Needs someone connected to the AP (or you wait until someone connects). Cracks with `aircrack-ng`. Also needs `tcpdump` (auto-installed on Debian/Ubuntu if missing).

What it actually does:

1. `airodump-ng` on the target channel in an xterm. CSV updates every second.
2. Main loop keeps watching for **new clients** and **handshakes** at the same time.
3. New client shows up → deauth **once per MAC**, queued so only one `aireplay-ng` runs at a time. Each attack gets its own xterm; window closes when done.
4. Handshake lands → every deauth xterm dies on the spot. Script tries to print which client it came from (EAPOL in the `.cap` via `tcpdump`, CSV as backup).
5. All known clients deauthed and nothing running → **30s countdown** in the terminal (`No clients detected… until broadcast deauth`). Timer resets if a new client appears or the last deauth just finished.
6. Still nothing → **broadcast deauth**, then **30s last opportunity** (countdown starts when that xterm closes, not before).
7. Got the handshake → `aircrack-ng` in xterm with your wordlist. Password shows up in the main terminal.

Default is 5 deauth packets per attack. Bump with `-d` (max 256).

### PMKID

No client required. Sniffs a PMKID from the AP itself. Cracks with `hashcat` mode 22000. Not every router plays nice with this.

1. Same channel detection as HANDSHAKE.
2. `hcxdumptool` on that channel (xterm).
3. Countdown in the main terminal (`-t`, default 45s). Stops early if your BSSID's PMKID shows up.
4. `hcxpcapngtool` → `.hc22000`, trimmed to your AP only.
5. `hashcat` in xterm, password in the main terminal.

---

WPA/WPA2 **PSK** only. No WPA3, no enterprise/802.1X, no open networks.

| | HANDSHAKE | PMKID |
|---|-----------|-------|
| Client needed | Usually yes | No |
| Cracker | aircrack-ng | hashcat |
| Extra tools | tcpdump | hcxdumptool, hcxpcapngtool, hashcat |

---

## Examples

```bash
# Minimum. Interactive scan, you pick target at the prompt
sudo ./mcwfcrk.sh -w /usr/share/wordlists/rockyou.txt

# PMKID, defaults (45s timeout)
sudo ./mcwfcrk.sh -w /usr/share/wordlists/rockyou.txt -a PMKID

# PMKID. Your interface, ESSID, longer wait
sudo ./mcwfcrk.sh -w /usr/share/wordlists/rockyou.txt -a PMKID -t 60 -i wlp0s20f3 -e H3601P_DA00

# HANDSHAKE. Less deauth packets, same target
sudo ./mcwfcrk.sh -w /usr/share/wordlists/rockyou.txt -a HANDSHAKE -d 3 -i wlp0s20f3 -e H3601P_DA00

# BSSID already known, skip the prompt
sudo ./mcwfcrk.sh -w /usr/share/wordlists/rockyou.txt -b 30:1F:48:0E:DA:00 -i wlp0s20f3

# Save captures instead of /tmp cleanup
sudo ./mcwfcrk.sh -w /usr/share/wordlists/rockyou.txt -a PMKID -e MiFibra-7BE7 -o ./captures
```

## Options

| Flag | What it does |
|------|----------------|
| `-w`, `--wordlist` | Wordlist path. Required. |
| `-b`, `--bssid` | Target MAC. Skips scan window and prompt. |
| `-e`, `--essid` | Network name. Silent scan finds the BSSID for you. |
| `-i`, `--interface` | WiFi iface (e.g. `wlp0s20f3`). Monitor mode if needed. |
| `-a`, `--attack-mode` | `HANDSHAKE` or `PMKID` |
| `-d`, `--deauth` | Packets per deauth in HANDSHAKE mode (default 5) |
| `-t`, `--timeout` | PMKID capture seconds (default 45) |
| `-o`, `--output` | Folder to keep `.cap` / `.pcapng` / `.hc22000` files |
| `-h`, `--help` | Help |

`-b` or `-e`, not both.

## Misc

**Channel:** after the BSSID is known, script runs a short `airodump-ng` on that AP and reads the channel from CSV. PMKID passes it to `hcxdumptool` as `${channel}a` (20 MHz width, e.g. channel 6 → `6a`, channel 36 → `36a`).

**Files:** no `-o` → everything in `/tmp`, deleted on exit. With `-o` → keep captures and retry hashcat/aircrack with another wordlist without capturing again.

**Cleanup:** kills xterm windows, stops monitor mode if the script started it, cursor back to normal.

**Deps:** Linux, X11, xterm, root/sudo, monitor-capable WiFi (injection needed for HANDSHAKE deauth). Missing packages on Debian/Ubuntu get pulled via `apt-get` when possible.

## Disclaimer

Tool provided as-is. No warranty. Author not liable for misuse or whatever breaks because you pointed this at the wrong network.
