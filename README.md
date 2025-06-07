# BSV Magic Guard

`bsv_magic_guard.py` monitors incoming Bitcoin SV peer‑to‑peer traffic and blocks any connection that does not present a valid magic header and version banner.  It uses scapy to inspect packets and iptables/ip6tables to immediately drop offending hosts.  In addition it polls your node via JSON‑RPC to eject peers that are lagging behind or responding too slowly.

## Requirements

- Python 3
- [scapy](https://scapy.net/)
- [requests](https://docs.python-requests.org/)
- `iptables` and `ip6tables` (for managing firewall rules)
- Root privileges (required for packet capture and firewall changes)
- A running BSV node with JSON-RPC enabled

## Usage

### 1. Install prerequisites (Ubuntu)

```bash
sudo apt-get update
sudo apt-get install python3 python3-pip iptables ip6tables
sudo pip3 install scapy requests
```

### 2. Configure the script

Edit `bsv_magic_guard.py` and set the variables near the top:
- `NETWORK_INTERFACE` – interface to monitor (default `ens3`)
- `CLIENT_PORT` – peer-to-peer port (default `5333`)
- RPC credentials (`RPC_USER`, `RPC_PASSWORD`, `RPC_HOST`, `RPC_PORT`)
- `WHITELIST_V4` / `WHITELIST_V6` – peers that should never be blocked
- `PING_THRESHOLD` – drop peers exceeding this ping time

### 3. Run the guard

Run the script with root privileges so it can sniff packets and manipulate the firewall:

```bash
sudo python3 bsv_magic_guard.py
```
Log output is sent to `/var/log/bsv_magic_guard.log` and to the console. The script listens on the configured interface and port and drops offending IPv4 and IPv6 addresses. Two example addresses are whitelisted by default.

## How it Works

- Captures TCP packets destined for `CLIENT_PORT` (default `5333`) on both IPv4 and IPv6.
- Checks that the first four bytes match Bitcoin SV's magic header (`E8 F3 E1 E3`).
- Searches the first 160 bytes of the payload for one of the allowed version banners (`/Bitcoin SV:1.1.0/` or `/Bitcoin SV:1.0.16/`).
- Any peer failing these checks is immediately blocked via `iptables` or `ip6tables`.
- Every `SYNC_CHECK_INTERVAL` seconds the script calls the node's RPC interface
  to obtain `getblockcount` and `getpeerinfo`.
- Peers whose `synced_blocks` or `synced_headers` are behind the local height are
  blocked and disconnected.
- Peers reporting `pingtime` longer than `PING_THRESHOLD` are also dropped.

## Disclaimer

This tool modifies your system firewall. Review the code and understand the implications before running it in production.
