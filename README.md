# MCWFCRK — Marco Calvo WiFi Cracker

Automated WPA/WPA2 security auditing tool for Linux. MCWFCRK wraps the full attack workflow into a single guided script: interface setup, target selection, capture, cracking, and cleanup.

Designed for penetration testers and security researchers who need a straightforward way to run handshake or PMKID attacks without juggling multiple terminals manually.

## Attack modes

### HANDSHAKE (default)

The classic WPA attack. When a device connects to an access point, they exchange a four-way handshake that contains the material needed to verify the password offline.

MCWFCRK captures that handshake by listening on the target channel and sending deauthentication frames to force a connected client to reconnect. **A client must be associated with the AP during the attack** — if nobody is connected, there is no handshake to capture.

Cracked with `aircrack-ng`.

### PMKID

A clientless alternative. Many routers expose a PMKID in their beacon or response frames. That identifier can be captured directly from the access point **without any connected clients**.

MCWFCRK filters capture to your target AP, waits for the PMKID, converts it to a hash, and cracks it with `hashcat`. Faster to set up when the AP supports it, but not every router exposes a usable PMKID.

## Compatibility

MCWFCRK targets **WPA/WPA2 networks using a pre-shared key (PSK)** — the kind secured with a password you would find in a wordlist. It does **not** support WPA3, enterprise networks, or open networks.

| Target | HANDSHAKE | PMKID | Notes |
|--------|-----------|-------|-------|
| **WPA2-PSK** | Yes | Often | Most common case. PMKID depends on the router exposing it. |
| **WPA-PSK** | Yes | Sometimes | Handshake works; PMKID support varies by device. |
| **WPA3 / WPA3-SAE** | No | No | Different key exchange. These attacks do not apply. |
| **WPA2/WPA3 mixed** | Unreliable | Unreliable | May work only if the AP falls back to WPA2; not guaranteed. |
| **WPA2-Enterprise (802.1X)** | No | No | Uses per-user credentials, not a shared password. A wordlist will not help. |
| **Open (no password)** | No | No | There is nothing to crack. |

**HANDSHAKE** will fail if no client is connected to the target AP at the time of the attack, even on a compatible network.

**PMKID** will fail if the access point does not broadcast a capturable PMKID, even on WPA2-PSK.

Cracking success also depends on password strength and wordlist quality — a valid capture does not guarantee the password will be found.

## Features

- **Non-disruptive** — does not stop or restart NetworkManager
- **Guided workflow** — scan window, target prompts, automatic timing and cleanup
- **Clear results** — cracked password printed in the main terminal on success or failure
- **Auto-install** — missing dependencies installed via `apt-get` on Debian/Ubuntu

## Network interface note

If you only have **one WiFi adapter** and use it for the attack, you will likely **lose internet connectivity** while it is in monitor mode — that interface cannot stay connected to your network and capture packets at the same time.

The recommended setup is a **USB WiFi adapter** for the attack, keeping your built-in card connected as usual.

When the script finishes, it restores your system to how it was:

- Monitor mode was **already active** before you ran the script → left as-is
- Monitor mode was **enabled by the script** → deactivated on exit

NetworkManager is never touched. Your connection comes back once the interface is out of monitor mode.

## Installation

```bash
curl -LO https://raw.githubusercontent.com/LeucoByte/mcwfcrk/main/mcwfcrk.sh
chmod +x mcwfcrk.sh
```

## Usage

```bash
sudo ./mcwfcrk.sh -w /path/to/your/wordlist.txt
sudo ./mcwfcrk.sh -w /path/to/your/wordlist.txt -a PMKID
sudo ./mcwfcrk.sh -w /path/to/your/wordlist.txt -a PMKID -t 60
sudo ./mcwfcrk.sh -w /path/to/your/wordlist.txt -o ./captures
```

| Option | Description |
|--------|-------------|
| `-w`, `--wordlist` | Path to wordlist (required) |
| `-a`, `--attack-mode` | `HANDSHAKE` (default) or `PMKID` |
| `-t`, `--timeout` | PMKID capture timeout **in seconds** (default: 45) |
| `-o`, `--output` | Directory to save capture and hash files |
| `-h`, `--help` | Show usage |

During the scan you will be asked for the **BSSID** (the MAC address of the access point, e.g. `30:1F:48:0E:DA:00`) and the **channel**.

### Saving captures (`-o`)

By default, temporary files are stored in `/tmp` and deleted when the script exits. Use `-o` to keep them — useful if you want to retry cracking with a different wordlist without capturing again, archive evidence from an authorized audit, or inspect the `.cap` / `.hc22000` files manually.

## How it works

1. Enables monitor mode on the selected interface, or reuses one already active.
2. Opens an `airodump-ng` scan window; you enter the target BSSID and channel.
3. Runs the chosen attack and opens a cracking window in `xterm`.
4. Prints the result in the main terminal (`Password cracked` or `Password not found in wordlist`).
5. Cleans up processes and temporary files on exit.

## Requirements

- Linux with X11 (desktop environment)
- Root or `sudo` privileges
- WiFi adapter with monitor mode and packet injection (required for HANDSHAKE mode)
- Your own wordlist

## Disclaimer

This software is provided **for educational purposes and authorized security testing only**.

You may only use MCWFCRK against networks you **own** or have **explicit written permission** to test. Unauthorized access to computer networks and wireless communications is illegal in most jurisdictions and may result in civil or criminal penalties.

**The author is not responsible for any use, misuse, or consequences arising from this software.** This includes, without limitation, unauthorized network access, data interception, service disruption, legal action, or any damage caused by running this script.

By using MCWFCRK, you acknowledge that:

- You act entirely at your own risk and under your own legal responsibility.
- You will comply with all applicable local, national, and international laws.
- The author provides this tool **as-is**, with no warranty of any kind, express or implied.

If you do not agree with these terms, do not use this software.
