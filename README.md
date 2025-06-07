# BSV Magic Guard

`bsv_magic_guard.py` monitors incoming Bitcoin SV peer-to-peer traffic and blocks any connection that does not present a valid magic header and version banner. It uses scapy to inspect packets and iptables/ip6tables to immediately drop offending hosts.

## Requirements

- Python 3
- [scapy](https://scapy.net/)
- `iptables` and `ip6tables` (for managing firewall rules)
- Root privileges (required for packet capture and firewall changes)

## Usage

1. Install the Python dependencies:
   ```bash
   pip install scapy
   ```
2. Run the script as root so it can sniff traffic and modify firewall rules:
   ```bash
   sudo python3 bsv_magic_guard.py
   ```

If your Bitcoin SV data directory is not the default location, set the `DATADIR`
constant in `bsv_magic_guard.py` so the script can invoke `bsv-cli` correctly.

The script listens on interface `ens3` and port `8333` by default. Adjust these values at the top of `bsv_magic_guard.py` if your setup differs. Offending IPv4 and IPv6 addresses are added to your firewall with a DROP rule, while two addresses are whitelisted by default.

Log messages are written to `/var/log/bsv_magic_guard.log` and to stdout. Ensure the process has permission to create or append to this file.

## How it Works

- Captures TCP packets destined for port 8333 on both IPv4 and IPv6.
- Checks that the first four bytes match Bitcoin SV's magic header (`E8 F3 E1 E3`).
- Searches the first 160 bytes of the payload for one of the allowed version banners (`/Bitcoin SV:1.1.0/` or `/Bitcoin SV:1.0.16/`).
- Any peer failing these checks is immediately blocked via `iptables` or `ip6tables`.
- Every minute the script queries the local block height with `bsv-cli getblockcount`
  and bans peers whose `synced_blocks` or `synced_headers` are behind this height.

## Disclaimer

This tool modifies your system firewall. Review the code and understand the implications before running it in production.
