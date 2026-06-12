# MCWFCRK — Marco Calvo WiFi Cracker

Bash script that automates the full WPA/WPA2 audit workflow with the **Aircrack-ng** suite: network scan, handshake capture, deauthentication, and wordlist cracking.

<video autoplay loop muted playsinline width="100%">
  <source src="https://raw.githubusercontent.com/LeucoByte/mcwfcrk/main/demo.mp4" type="video/mp4">
  <source src="./demo.mp4" type="video/mp4">
</video>

## Download

```bash
curl -LO https://raw.githubusercontent.com/LeucoByte/mcwfcrk/main/mcwfcrk.sh
chmod +x mcwfcrk.sh
bash mcwfcrk.sh -w path/to/your/wordlist
```

## What it does

`mcwfcrk.sh` walks you through the entire process without running each tool manually:

1. **Checks requirements** — root/sudo access, wordlist, and dependencies (`aircrack-ng`, `xterm`).
2. **Monitor mode** — detects an existing monitor interface or enables one with `airmon-ng`.
3. **Network scan** — opens an `xterm` window with `airodump-ng` to list BSSIDs and channels.
4. **Target selection** — you enter the BSSID and channel; the scan window closes automatically.
5. **Capture + deauth** — orchestrates two windows with automatic timing:
   - Packet capture filtered by BSSID and channel.
   - Deauthentication attack using the broadcast MAC (`FF:FF:FF:FF:FF:FF`) to force reconnection and capture the WPA handshake.
6. **Cracking** — runs `aircrack-ng` with your wordlist against the generated `.cap` file.
7. **Cleanup** — on exit, disables monitor mode and removes temporary files.

## Requirements

- Linux (tested on Debian/Ubuntu-based systems)
- `sudo` or root execution
- WiFi adapter with monitor mode and packet injection support
- Your own wordlist (`-w /path/to/wordlist.txt`)

The script can auto-install `aircrack-ng` and `xterm` if missing (via `apt-get`).

## Usage

```bash
./mcwfcrk.sh -w /path/to/your/wordlist.txt
```

### Options

| Option | Description |
|--------|-------------|
| `-w`, `--wordlist` | Path to the wordlist (required) |
| `-h`, `--help`     | Show basic help |

### Example

```bash
./mcwfcrk.sh -w ~/wordlists/rockyou.txt
```

The script will prompt for the interface (if needed), the target BSSID, and channel. The rest of the workflow runs automatically.

## Important considerations

> **Legal and authorized use only.** This project is intended for security audits on **your own networks** or with **explicit written permission** from the owner. Unauthorized access to third-party networks is illegal in most jurisdictions.

- **Own networks or authorized audits only.** Do not use this tool against networks you do not own or have permission to test.
- **Handshake capture is not guaranteed.** Clients must be connected to the AP during the attack; without reconnection, there is no handshake to crack.
- **Wordlist quality matters most.** Cracking success depends mainly on your wordlist, not the script.
- **Compatible hardware required.** Not all WiFi chipsets support monitor mode or injection; verify your adapter before use.
- **X11 graphical environment.** The script uses `xterm` windows; you need a desktop environment or accessible X display.
- **User responsibility.** You are solely responsible for how you use this tool.

## Timing flow (capture / deauth)

The script synchronizes windows to maximize handshake capture:

```
Capture opens → wait 3s → Deauth (5 packets, broadcast)
→ deauth finishes → wait 3s → close deauth window
→ wait 3s → close capture window
```

Those final 3 seconds give the client time to reconnect and capture the WPA key.

## Disclaimer

This tool is provided for **educational purposes and authorized security testing only**.

The developer is **not responsible** for how this software is used, nor for any damage, legal action, prosecution, or consequences arising from its misuse — including unauthorized access to networks, privacy violations, or any other illegal activity.

If you use this tool for anything other than legitimate, authorized testing, **you do so entirely at your own risk**. Any illegal use is solely your responsibility.

---

*Educational and audit tool. Use responsibly.*
